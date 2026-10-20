"""Stateful, local-only digital-twin simulation service for the ACCDS dashboard."""

from __future__ import annotations

import copy
import json
import queue
import threading
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.asset_intelligence.layer1_asset_intelligence import Layer1AssetIntelligence
from src.compliance.access import AccessController
from src.compliance.audit_store import TamperEvidentAuditStore
from src.compliance.contracts import AccessRole, Outcome, RecordClass, ViewKind, new_audit_event
from src.compliance.evidence import export_evidence_package
from src.compliance.ingest import (
    asset_context_to_audit,
    decision_to_audit,
    enforcement_to_audit,
    findings_to_audit,
    observations_to_audit,
    proposal_to_audit,
    rollback_to_audit,
)
from src.compliance.metrics import layer6_metrics
from src.compliance.pipeline import REPO_ROOT
from src.compliance.redaction import DEFAULT_PSEUDONYM_KEY, RedactionEngine
from src.compliance.reporting import build_report, render_markdown
from src.compliance.timeline import build_timeline, collect_case_records
from src.decision_gate.decision_logic import Layer5DecisionGate
from src.enforcement.layer4_executor import Layer4Executor
from src.ingestion.layer0_ingestion import Layer0Ingestion
from src.layer_2.accds_layer2.features import build_windows
from src.layer_2.accds_layer2.model import score_window, train_baseline
from src.layer_2.accds_layer2.schemas import Baseline, EnrichedEvent
from src.layer_2.accds_layer2.synthetic import generate_normal
from src.orchestration.layer3_orchestrator import Layer3Orchestrator
from src.schemas.contracts import (
    ActionDetail,
    ApprovalLevel,
    AssetContext,
    ClinicalTier,
    DecisionOutcome,
    DetectionFinding,
    EnforcementStatus,
    ResponseProposal,
    SystemSafetyMode,
)

from .catalog import DEVICE_BY_ID, DEVICE_BY_IP, DEVICES, PRESETS, SCENARIOS, WIRES

LAYER_ORDER = [0, 1, 2, 3, 5, 4, 6]
LAYER_NAMES = {
    0: "Ingestion",
    1: "Asset Intel",
    2: "ML Detection",
    3: "Orchestration",
    5: "Decision Gate",
    4: "Enforcement",
    6: "Compliance",
}
ANOMALY_THRESHOLD = 0.55


class SimulationError(RuntimeError):
    """A safe, user-facing simulation state or request error."""


@dataclass
class Runtime:
    layer0: Layer0Ingestion
    layer1: Layer1AssetIntelligence
    layer3: Layer3Orchestrator
    layer4: Layer4Executor
    layer5: Layer5DecisionGate
    audit_store: TamperEvidentAuditStore
    redaction: RedactionEngine
    baseline: Baseline
    output_dir: Path
    observations: List[Any] = field(default_factory=list)
    contexts: Dict[str, AssetContext] = field(default_factory=dict)
    enriched_events: List[EnrichedEvent] = field(default_factory=list)
    findings: List[Any] = field(default_factory=list)
    proposal: Optional[ResponseProposal] = None
    decision: Any = None
    enforcement: Optional[Dict[str, Any]] = None
    operational_records: List[Dict[str, Any]] = field(default_factory=list)
    report_markdown: str = ""
    evidence_manifest: Optional[Dict[str, Any]] = None
    zip_path: Optional[Path] = None


class SimulationService:
    """One active simulator run, streamed to browsers with server-sent events."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._session: Optional[Dict[str, Any]] = None
        self._runtime: Optional[Runtime] = None
        self._subscribers: set[queue.Queue[str]] = set()
        self._baseline = self._load_baseline()

    @staticmethod
    def _load_baseline() -> Baseline:
        path = REPO_ROOT / "layer_2" / "artifacts" / "demo" / "baseline.json"
        if path.exists():
            return Baseline.load(str(path))
        normal = generate_normal(days=3, seed=7)
        return train_baseline(build_windows(normal))

    def catalog(self) -> Dict[str, Any]:
        return {
            "devices": DEVICES,
            "wires": WIRES,
            "scenarios": SCENARIOS,
            "presets": PRESETS,
            "layer_order": LAYER_ORDER,
            "layers": [{"id": layer, "name": LAYER_NAMES[layer]} for layer in LAYER_ORDER],
            "simulation_only": True,
        }

    def subscribe(self) -> queue.Queue[str]:
        subscriber: queue.Queue[str] = queue.Queue(maxsize=64)
        with self._lock:
            self._subscribers.add(subscriber)
            subscriber.put_nowait(json.dumps(self._snapshot(), separators=(",", ":")))
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue[str]) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)

    def _publish(self) -> None:
        if not self._subscribers:
            return
        message = json.dumps(self._snapshot(), separators=(",", ":"))
        for subscriber in tuple(self._subscribers):
            try:
                subscriber.put_nowait(message)
            except queue.Full:
                try:
                    subscriber.get_nowait()
                    subscriber.put_nowait(message)
                except (queue.Empty, queue.Full):
                    pass

    def _snapshot(self) -> Dict[str, Any]:
        if self._session is None:
            return {
                "active": False,
                "simulation_only": True,
                "devices": DEVICES,
                "wires": WIRES,
                "layer_order": LAYER_ORDER,
                "current_layer": None,
                "system_status": "NORMAL",
                "ledger_integrity": {"valid": True, "label": "CHAIN VALID", "head_hash": "0" * 64},
                "message": "Digital twin ready. No live network controls are connected.",
            }
        snapshot = copy.deepcopy(self._session)
        snapshot["devices"] = DEVICES
        snapshot["wires"] = WIRES
        snapshot["layer_order"] = LAYER_ORDER
        snapshot["simulation_only"] = True
        snapshot["ledger_integrity"] = self._ledger_state()
        # Keep the response compatible with the seven-layer payload contract
        # while retaining grouped layer details for the dashboard.
        snapshot.update(copy.deepcopy(snapshot.get("payloads", {})))
        result = snapshot.get("layer_4_result")
        if isinstance(result, dict):
            result["applied_rules"] = [
                f"{rule.get('type', 'CONTROL')}:{rule.get('target', 'unknown')}"
                for rule in result.get("applied_controls", [])
                if isinstance(rule, dict)
            ]
        return snapshot

    def state(self) -> Dict[str, Any]:
        with self._lock:
            return self._snapshot()

    def _ledger_state(self) -> Dict[str, Any]:
        if self._runtime is None:
            return {"valid": True, "label": "CHAIN VALID", "head_hash": "0" * 64}
        verification = self._runtime.audit_store.verify().to_dict()
        return {
            "valid": bool(verification["ok"]),
            "label": "CHAIN VALID" if verification["ok"] else "TAMPER DETECTED",
            "head_hash": verification["head_hash"],
            "records_checked": verification["records_checked"],
            "reason": verification["reason"],
        }

    @staticmethod
    def _iso_after(seconds: int = 0) -> str:
        return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()

    def _resolve_attack(self, request: Dict[str, Any]) -> Dict[str, Any]:
        scenario = str(request.get("scenario") or "custom_attack")
        if scenario not in SCENARIOS and scenario != "custom_attack":
            raise ValueError(f"Unknown scenario: {scenario}")

        preset = dict(PRESETS.get(scenario, {}))
        source = str(request.get("source") or preset.get("source") or "office-ws")
        target = str(request.get("target") or preset.get("target") or "radiology-ws")
        vector = str(request.get("vector") or preset.get("vector") or "PORT_SCAN").upper()
        allowed_vectors = {
            "PORT_SCAN", "LATERAL_MOVEMENT", "MALWARE_STAGING", "CREDENTIAL_DUMP",
            "EXFILTRATION", "OFF_HOURS_ACCESS", "NEW_PEER", "CLINICAL_BURST",
        }
        if vector not in allowed_vectors:
            raise ValueError(f"Unknown attack vector: {vector}")
        byte_count = request.get("bytes", preset.get("bytes", 1200))
        try:
            byte_count = max(0, min(int(byte_count), 10_000_000))
        except (TypeError, ValueError) as error:
            raise ValueError("bytes must be a non-negative integer") from error

        chain_value = request.get("chain") or []
        if isinstance(chain_value, str):
            chain_value = [part.strip() for part in chain_value.split(",") if part.strip()]
        if not isinstance(chain_value, list):
            raise ValueError("chain must be a list of device ids")
        chain = [str(item) for item in chain_value]
        if chain:
            if len(chain) < 2:
                raise ValueError("a chained attack requires at least two devices")
            source, target = chain[0], chain[-1]
        for device_id in [source, target, *chain]:
            if device_id not in DEVICE_BY_ID:
                raise ValueError(f"Unknown device: {device_id}")
        if source == target and not chain:
            raise ValueError("source and target must be different devices")

        count = preset.get("count", 3)
        if scenario == "custom_attack":
            count = 12 if vector == "PORT_SCAN" else 3
        if vector == "PORT_SCAN":
            count = 12
        if vector in {"LATERAL_MOVEMENT", "MALWARE_STAGING", "NEW_PEER"}:
            count = max(3, int(count))
        if request.get("bytes") is not None:
            byte_count = max(0, min(int(request["bytes"]), 10_000_000))

        analysis_side = "source" if scenario in {"exfiltration", "credential_misuse", "off_hours", "diagnostic_drift", "benign_clinical_burst"} else "destination"
        if scenario == "custom_attack":
            analysis_side = "source" if vector in {"EXFILTRATION", "CREDENTIAL_DUMP"} else "destination"

        return {
            "scenario_id": scenario,
            "source": source,
            "target": target,
            "vector": vector,
            "bytes": byte_count,
            "count": count,
            "chain": chain,
            "analysis_side": analysis_side,
        }

    @staticmethod
    def _attack_pairs(plan: Dict[str, Any]) -> List[tuple[str, str]]:
        chain = plan["chain"]
        if chain:
            return list(zip(chain[:-1], chain[1:]))
        return [(plan["source"], plan["target"])]

    def launch_attack(self, request: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            plan = self._resolve_attack(request)
            run_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
            output_dir = REPO_ROOT.parent / "artifacts" / "simulations" / run_id
            audit_store = TamperEvidentAuditStore(output_dir / "audit_chain.jsonl", key=DEFAULT_PSEUDONYM_KEY)
            runtime = Runtime(
                layer0=Layer0Ingestion(),
                layer1=Layer1AssetIntelligence(),
                layer3=Layer3Orchestrator(),
                layer4=Layer4Executor(),
                layer5=Layer5DecisionGate(),
                audit_store=audit_store,
                redaction=RedactionEngine(key=DEFAULT_PSEUDONYM_KEY),
                baseline=self._baseline,
                output_dir=output_dir,
            )
            event_specs = self._make_event_specs(plan)
            observations = []
            for spec in event_specs:
                event = runtime.layer0.process_raw_log(spec)
                if event is not None:
                    observations.append(event)
            if not observations:
                raise SimulationError("Layer 0 rejected all events as duplicates")
            runtime.observations = observations
            observation_dicts = [event.model_dump(mode="json") for event in observations]
            runtime.audit_store.extend(observations_to_audit(observation_dicts))

            self._runtime = runtime
            self._session = {
                "active": True,
                "simulation_id": run_id,
                "scenario_id": plan["scenario_id"],
                "scenario_label": plan["scenario_id"].replace("_", " ").upper(),
                "source": plan["source"],
                "target": plan["target"],
                "vector": plan["vector"],
                "chain": plan["chain"],
                "source_ip": DEVICE_BY_ID[plan["source"]]["ip"],
                "event_ids": [event.event_id for event in observations],
                "related_event_ids": [event.event_id for event in observations],
                "current_layer": 0,
                "system_status": "HEIGHTENED_MONITORING",
                "status": "ready",
                "status_message": f"{len(observations)} normalized event(s) delivered to Layer 0.",
                "pending_approval": False,
                "started_at": self._iso_after(),
                "finished_at": None,
                "layers": {
                    str(layer): {"status": "waiting", "name": LAYER_NAMES[layer], "summary": "Awaiting prior layer."}
                    for layer in LAYER_ORDER
                },
                "payloads": {},
                "layer0_events": observation_dicts,
                "layer1_contexts": [],
                "layer2_findings": [],
                "attack_path": self._attack_pairs(plan),
                "blast_radius": sorted({target for _, target in self._attack_pairs(plan)}),
                "blocked_flows": [],
                "preserved_flows": [],
                "redacted_timeline_md": "",
                "timeline_entries": [],
                "narrative_buckets": {
                    "observed_fact": [],
                    "model_inference": [],
                    "human_decision": [],
                    "action_taken": [],
                },
                "evidence_manifest": None,
                "evidence_ready": False,
                "rollback_available": False,
                "decision": None,
                "proposal": None,
                "enforcement": None,
                "metrics": None,
                "layers_completed": [0],
                "analysis_side": plan["analysis_side"],
                "bytes": plan["bytes"],
            }
            self._session["layers"]["0"] = {
                "status": "complete",
                "name": LAYER_NAMES[0],
                "summary": f"{len(observations)} event(s) normalized and deduplicated.",
                "data": observation_dicts,
            }
            self._session["payloads"]["layer_0_event"] = observation_dicts[0]
            self._publish()
            return self._snapshot()

    def _make_event_specs(self, plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        specs: List[Dict[str, Any]] = []
        scenario = plan["scenario_id"]
        vector = plan["vector"]
        base_time = datetime.now(timezone.utc)
        pairs = self._attack_pairs(plan)
        for pair_index, (source_id, target_id) in enumerate(pairs):
            count = plan["count"] if len(pairs) == 1 else max(3, plan["count"] if vector == "PORT_SCAN" else 3)
            if scenario == "benign_clinical_burst":
                count = 5
            if scenario == "low_confidence":
                count = 1
            if vector == "PORT_SCAN" or scenario == "diagnostic_drift":
                count = 12
            source = DEVICE_BY_ID[source_id]
            target = DEVICE_BY_ID[target_id]
            for index in range(count):
                timestamp = base_time + timedelta(seconds=(pair_index * count + index))
                if scenario == "off_hours":
                    timestamp = timestamp.replace(hour=2, minute=15, second=index, microsecond=0)
                event_type = {
                    "PORT_SCAN": "PORT_SCAN_SWEEP",
                    "LATERAL_MOVEMENT": "LATERAL_MOVEMENT",
                    "MALWARE_STAGING": "MALWARE_STAGING",
                    "CREDENTIAL_DUMP": "CREDENTIAL_DUMP",
                    "EXFILTRATION": "DATA_EXFILTRATION",
                    "OFF_HOURS_ACCESS": "OFF_HOURS_ACCESS",
                    "NEW_PEER": "NEW_PEER_CONNECTION",
                    "CLINICAL_BURST": "CLINICAL_DATA_FLOW",
                }.get(vector, vector)
                event_bytes = plan["bytes"]
                protocol = "TCP"
                if scenario == "credential_misuse" or vector == "CREDENTIAL_DUMP":
                    event_type = "AUTH_FAILURE" if index < 5 else "AUTHENTICATION"
                    protocol = "TLS"
                elif scenario == "off_hours":
                    event_type = "SENSITIVE_RECORD_ACCESS"
                elif scenario == "benign_clinical_burst":
                    event_type = "CLINICAL_DATA_FLOW"
                specs.append({
                    "timestamp": timestamp.isoformat(),
                    "source": f"{source['zone_id']}_digital_twin_sensor",
                    "event_type": event_type,
                    "src": source["ip"],
                    "dst": target["ip"],
                    "protocol": protocol,
                    "bytes": event_bytes,
                    "zone": target["zone_id"],
                    "scenario_id": scenario,
                    "simulated_port": 445 if vector in {"PORT_SCAN", "MALWARE_STAGING"} else None,
                    "simulated_sequence": index,
                })
        return specs

    def step(self) -> Dict[str, Any]:
        with self._lock:
            if self._session is None or self._runtime is None:
                raise SimulationError("Launch an attack before stepping the pipeline")
            if self._session["pending_approval"]:
                raise SimulationError("Layer 5 is paused for a human decision")
            if self._session["current_layer"] == 6:
                return self._snapshot()
            position = LAYER_ORDER.index(self._session["current_layer"])
            layer = LAYER_ORDER[position + 1]
            handler = {
                1: self._run_layer1,
                2: self._run_layer2,
                3: self._run_layer3,
                5: self._run_layer5,
                4: self._run_layer4,
                6: self._run_layer6,
            }[layer]
            handler()
            self._session["current_layer"] = layer
            self._session["layers_completed"].append(layer)
            self._publish()
            return self._snapshot()

    def run_full(self) -> Dict[str, Any]:
        with self._lock:
            if self._session is None:
                raise SimulationError("Launch an attack before running the pipeline")
            while self._session["current_layer"] != 6 and not self._session["pending_approval"]:
                before = self._session["current_layer"]
                self.step()
                if self._session["current_layer"] == before:
                    break
            return self._snapshot()

    def _mark_layer(self, layer: int, summary: str, data: Any) -> None:
        assert self._session is not None
        self._session["layers"][str(layer)] = {
            "status": "complete",
            "name": LAYER_NAMES[layer],
            "summary": summary,
            "data": data,
        }

    def _run_layer1(self) -> None:
        assert self._session is not None and self._runtime is not None
        runtime = self._runtime
        contexts: List[Dict[str, Any]] = []
        for observation in runtime.observations:
            prefer_destination = self._session["analysis_side"] != "source"
            context = runtime.layer1.enrich(observation, prefer_destination=prefer_destination)
            if context is None:
                continue
            if self._session["scenario_id"] == "low_confidence":
                context = context.model_copy(update={"identity_confidence": 0.35})
            runtime.contexts[observation.event_id] = context
            item = context.model_dump(mode="json")
            item.update({"event_id": observation.event_id, "timestamp": observation.timestamp, "scenario_id": observation.scenario_id})
            contexts.append(item)
        if not contexts:
            raise SimulationError("Layer 1 could not resolve any simulated assets")
        runtime.audit_store.extend(asset_context_to_audit(contexts))
        unique_contexts = {item["asset_id"]: item for item in contexts}
        resolved = list(unique_contexts.values())
        self._session["layer1_contexts"] = resolved
        self._session["blast_radius"] = sorted(unique_contexts)
        primary = resolved[0]
        self._session["payloads"]["layer_1_context"] = primary
        self._mark_layer(1, f"Resolved {len(resolved)} asset context(s); clinical tiers applied.", resolved)

    def _layer2_event(self, observation: Any, context: AssetContext, index: int) -> EnrichedEvent:
        assert self._session is not None
        source_id = self._session["source"]
        scenario = self._session["scenario_id"]
        vector = self._session["vector"]
        if vector == "PORT_SCAN" or scenario == "diagnostic_drift":
            destination = f"port-{index + 1}"
        elif scenario == "exfiltration":
            destination = "external-cloud"
        elif scenario == "low_confidence":
            destination = "unrecognized-peer"
        elif self._session["analysis_side"] == "source":
            destination = next((pair[1] for pair in self._session["attack_path"] if pair[0] == context.asset_id), self._session["target"])
        else:
            destination = source_id

        if scenario == "benign_clinical_burst":
            event_type = "network_flow"
            event_bytes = 900
            label = "normal"
            stage = None
        elif scenario == "credential_misuse":
            event_type = observation.event_type.lower()
            event_bytes = observation.bytes
            label = "anomaly"
            stage = "credential_access"
        else:
            event_type = observation.event_type.lower()
            event_bytes = observation.bytes
            label = "anomaly"
            stage = {
                "PORT_SCAN": "discovery",
                "LATERAL_MOVEMENT": "lateral_movement",
                "MALWARE_STAGING": "execution",
                "CREDENTIAL_DUMP": "credential_access",
                "EXFILTRATION": "exfiltration",
                "OFF_HOURS_ACCESS": "credential_access",
                "NEW_PEER": "lateral_movement",
            }.get(vector, "discovery")

        return EnrichedEvent(
            event_id=observation.event_id,
            timestamp=datetime.fromisoformat(observation.timestamp.replace("Z", "+00:00")),
            event_type=event_type,
            subject=context.asset_id,
            src=context.asset_id,
            dst=destination,
            protocol=observation.protocol,
            bytes=event_bytes,
            zone=context.owner_zone,
            scenario_id=observation.scenario_id,
            raw_reference=observation.raw_reference,
            asset_id=context.asset_id,
            asset_type=context.asset_type,
            owner_zone=context.owner_zone,
            vendor=context.vendor,
            software_version=context.software_version,
            clinical_tier=int(context.clinical_tier),
            known_constraints=context.known_constraints,
            allowed_peers=[DEVICE_BY_IP[peer]["id"] for peer in context.allowed_peers if peer in DEVICE_BY_IP],
            normal_services=[service.lower() for service in context.normal_services],
            fallback_mode=context.fallback_mode or "simulated",
            identity_confidence=context.identity_confidence,
            label=label,
            attack_stage=stage,
        )

    def _run_layer2(self) -> None:
        assert self._session is not None and self._runtime is not None
        runtime = self._runtime
        for index, observation in enumerate(runtime.observations):
            context = runtime.contexts.get(observation.event_id)
            if context is not None:
                runtime.enriched_events.append(self._layer2_event(observation, context, index))
        windows = build_windows(runtime.enriched_events)
        if not windows:
            raise SimulationError("Layer 2 received no enriched behavior windows")
        runtime.findings = [score_window(window, runtime.baseline, sequence=index) for index, window in enumerate(windows)]
        finding_dicts = [finding.to_dict() for finding in runtime.findings]
        runtime.audit_store.extend(findings_to_audit(finding_dicts))
        self._session["layer2_findings"] = finding_dicts
        selected = max(runtime.findings, key=lambda item: item.risk_score)
        self._session["payloads"]["layer_2_finding"] = {
            "finding_id": selected.finding_id,
            "asset_id": selected.asset_id,
            "anomaly_score": selected.anomaly_score,
            "risk_score": selected.risk_score,
            "indicators": [
                str(item.get("code", "anomaly")) if isinstance(item, dict) else str(item)
                for item in selected.indicators
            ],
        }
        self._session["system_status"] = "HEIGHTENED_MONITORING" if selected.anomaly_score >= ANOMALY_THRESHOLD else "NORMAL"
        self._mark_layer(2, f"Scored {len(runtime.findings)} behavior window(s); max risk {selected.risk_score:.2f}.", finding_dicts)

    def _run_layer3(self) -> None:
        assert self._session is not None and self._runtime is not None
        runtime = self._runtime
        if not runtime.findings:
            raise SimulationError("Layer 2 has not produced a finding")
        ordered = sorted(runtime.findings, key=lambda item: item.behavior_window["start"])
        proposals: List[ResponseProposal] = []
        for finding in ordered:
            context = next((candidate for candidate in runtime.contexts.values() if candidate.asset_id == finding.asset_id), None)
            if context is None:
                continue
            detection = DetectionFinding(
                finding_id=finding.finding_id,
                asset_id=finding.asset_id,
                attacker_src=self._session["source"],
                behavior_window=f"{finding.behavior_window['start']}/{finding.behavior_window['end']}",
                anomaly_score=finding.anomaly_score,
                risk_score=finding.risk_score,
                indicators=[str(item.get("code", "anomaly")) for item in finding.indicators],
                baseline_version=finding.baseline_version,
                confidence=finding.confidence,
                related_events=finding.related_events,
                recommended_observation_period=finding.recommended_observation_period,
                timestamp=finding.behavior_window["end"],
            )
            proposals.append(runtime.layer3.process(detection, context, SystemSafetyMode.HEIGHTENED_MONITORING))
        if not proposals:
            raise SimulationError("Layer 3 could not correlate the detections to asset context")
        proposal = proposals[-1]
        top_finding = max(runtime.findings, key=lambda item: item.risk_score)
        monitor_only = (
            top_finding.anomaly_score < ANOMALY_THRESHOLD
            or top_finding.confidence < 0.65
            or self._session["scenario_id"] in {"low_confidence", "benign_clinical_burst"}
        )
        if monitor_only:
            proposal = proposal.model_copy(update={
                "candidate_actions": [ActionDetail(
                    action_type="MONITOR_ONLY",
                    target_asset=top_finding.asset_id,
                    preserved_flows=[{"protocol": "ANY", "port": "ANY", "direction": "BIDIRECTIONAL"}],
                )],
                "approval_level": ApprovalLevel.AUTO_APPROVED,
                "clinical_impact": "Monitoring only. Evidence is below the containment threshold or identity confidence is low.",
                "reason": "Safety policy selected monitoring only; automated containment is not recommended for this evidence.",
            })
        runtime.proposal = proposal
        tier_one = [item.target_asset for item in proposal.candidate_actions if item.target_asset in DEVICE_BY_ID and DEVICE_BY_ID[item.target_asset]["tier"] == 1]
        if tier_one:
            self._session["system_status"] = "EMERGENCY_CONTAINMENT"
        proposal_data = proposal.model_dump(mode="json")
        proposal_data["scope_hash"] = runtime.layer5.compute_scope_hash(proposal)
        runtime.audit_store.append(proposal_to_audit(proposal_data, scenario_id=self._session["scenario_id"]))
        self._session["proposal"] = proposal_data
        self._session["payloads"]["layer_3_proposal"] = proposal_data
        self._session["attack_path"] = [[source, target] for source, target in self._attack_pairs_from_session()]
        related_ids = list(dict.fromkeys(event.event_id for event in runtime.observations))
        self._session["related_event_ids"] = related_ids
        self._session["event_ids"] = related_ids
        self._mark_layer(3, f"Case {proposal.case_id} correlated {len(proposal.affected_assets)} affected asset(s).", proposal_data)

    def _attack_pairs_from_session(self) -> List[tuple[str, str]]:
        assert self._session is not None
        chain = self._session["chain"]
        if chain:
            return list(zip(chain[:-1], chain[1:]))
        return [(self._session["source"], self._session["target"])]

    def _run_layer5(self) -> None:
        assert self._session is not None and self._runtime is not None and self._runtime.proposal is not None
        runtime = self._runtime
        decision = runtime.layer5.evaluate_proposal(runtime.proposal)
        if decision is None:
            self._session["pending_approval"] = True
            self._session["status"] = "awaiting_human_approval"
            self._session["status_message"] = "Layer 5 paused the pipeline. A reviewer must approve or reject this exact scope."
            pending = {
                "decision": "PENDING",
                "reviewer": None,
                "case_id": runtime.proposal.case_id,
                "scope_hash": f"sha256:{runtime.layer5.compute_scope_hash(runtime.proposal)}",
                "target_asset": self._critical_target(runtime.proposal),
            }
            self._session["decision"] = pending
            self._session["payloads"]["layer_5_decision"] = pending
            self._mark_layer(5, "Paused for human review before Layer 4 enforcement.", pending)
        else:
            runtime.decision = decision
            decision_data = self._decision_dict(decision, runtime.proposal)
            runtime.audit_store.append(decision_to_audit(decision_data, scenario_id=self._session["scenario_id"]))
            self._session["decision"] = decision_data
            self._session["payloads"]["layer_5_decision"] = decision_data
            self._session["status"] = "running"
            self._session["status_message"] = "Automated policy approved the proposal; Layer 4 remains scope-bound."
            self._mark_layer(5, "Automated decision recorded; scope hash binds the approved actions.", decision_data)

    @staticmethod
    def _critical_target(proposal: ResponseProposal) -> str:
        return next(
            (item.target_asset for item in proposal.candidate_actions if item.target_asset in DEVICE_BY_ID and DEVICE_BY_ID[item.target_asset]["tier"] == 1),
            proposal.candidate_actions[0].target_asset if proposal.candidate_actions else "unknown",
        )

    @staticmethod
    def _decision_dict(decision: Any, proposal: ResponseProposal) -> Dict[str, Any]:
        result = decision.model_dump(mode="json")
        result["asset_id"] = SimulationService._critical_target(proposal)
        result["scope_hash"] = f"sha256:{result['scope_hash']}"
        return result

    def record_decision(self, request: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if self._session is None or self._runtime is None or not self._session["pending_approval"]:
                raise SimulationError("There is no pending Layer 5 review")
            choice = str(request.get("decision", "")).upper()
            if choice not in {"APPROVED", "REJECTED"}:
                raise ValueError("decision must be APPROVED or REJECTED")
            reviewer = str(request.get("reviewer", "")).strip()
            if not reviewer:
                raise ValueError("reviewer is required")
            reason = str(request.get("reason") or ("Approved surgical containment after scope review." if choice == "APPROVED" else "Rejected to preserve clinical availability."))
            result = self._record_human_decision(choice, reviewer, reason)
            self._session["pending_approval"] = False
            self._session["status"] = "running"
            self._session["status_message"] = f"{choice.title()} by {reviewer}; resuming the gated pipeline."
            self._publish()
            return self.run_full() if result else self._snapshot()

    def _record_human_decision(self, choice: str, reviewer: str, reason: str) -> bool:
        assert self._session is not None and self._runtime is not None and self._runtime.proposal is not None
        runtime = self._runtime
        outcome = DecisionOutcome.APPROVED if choice == "APPROVED" else DecisionOutcome.REJECTED
        decision = runtime.layer5.record_human_decision(runtime.proposal.case_id, reviewer, outcome, reason)
        if choice == "APPROVED":
            expected = runtime.layer5.compute_scope_hash(runtime.proposal)
            if decision.scope_hash != expected or decision.approved_action is None:
                raise SimulationError("Approval scope did not match the pending proposal")
        runtime.decision = decision
        decision_data = self._decision_dict(decision, runtime.proposal)
        runtime.audit_store.append(decision_to_audit(decision_data, scenario_id=self._session["scenario_id"]))
        self._session["decision"] = decision_data
        self._session["payloads"]["layer_5_decision"] = decision_data
        self._mark_layer(5, f"Human reviewer {choice.lower()} this scope-bound proposal.", decision_data)
        return True

    def _run_layer4(self) -> None:
        assert self._session is not None and self._runtime is not None and self._runtime.proposal is not None
        runtime = self._runtime
        decision = runtime.decision
        approved = bool(decision and decision.decision == DecisionOutcome.APPROVED)
        action_types = [item.action_type for item in runtime.proposal.candidate_actions]
        if not approved or action_types == ["MONITOR_ONLY"]:
            timestamp = self._iso_after()
            status = "NOT_APPLIED" if not approved else "MONITOR_ONLY"
            explanation = "Layer 4 did not change any controls." if not approved else "Layer 4 recorded monitoring only; no control was changed."
            enforcement = {
                "action_id": f"ACT-SKIP-{uuid.uuid4().hex[:6].upper()}",
                "case_id": runtime.proposal.case_id,
                "decision_id": decision.decision_id if decision else None,
                "target_asset": self._critical_target(runtime.proposal),
                "status": status,
                "applied_controls": [],
                "blocked_flows": [],
                "preserved_flows": [],
                "start_time": timestamp,
                "expiry_time": runtime.proposal.expiry_time,
                "verification": explanation,
                "rollback_token": runtime.proposal.rollback_plan.rollback_token_spec,
            }
            runtime.audit_store.append(new_audit_event(
                layer=4,
                actor="layer4.digital_twin",
                action="enforcement.skipped",
                input_reference=f"decision://{enforcement['decision_id'] or 'none'}",
                output_reference=f"action://{enforcement['action_id']}",
                record_class=RecordClass.ACTION_TAKEN,
                outcome=Outcome.REJECTED if not approved else Outcome.SUCCESS,
                timestamp=datetime.now(timezone.utc),
                case_id=runtime.proposal.case_id,
                scenario_id=self._session["scenario_id"],
                asset_id=enforcement["target_asset"],
                payload=enforcement,
            ))
            self._session["rollback_available"] = False
        else:
            result = runtime.layer4.execute_proposal(runtime.proposal, force_execution=decision.reviewer != "SYSTEM_AUTO_POLICY")
            enforcement = result.model_dump(mode="json")
            runtime.audit_store.append(enforcement_to_audit({
                **enforcement,
                "decision_id": decision.decision_id,
            }, scenario_id=self._session["scenario_id"]))
            if result.status == EnforcementStatus.APPLIED:
                self._session["rollback_available"] = True
                self._session["blocked_flows"] = list(result.blocked_flows)
                self._session["preserved_flows"] = list(result.preserved_flows)
            else:
                self._session["rollback_available"] = False
        runtime.enforcement = enforcement
        self._session["enforcement"] = enforcement
        self._session["payloads"]["layer_4_result"] = enforcement
        self._mark_layer(4, enforcement.get("verification", "Layer 4 recorded the result."), enforcement)

    def trigger_rollback(self, request: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if self._session is None or self._runtime is None:
                raise SimulationError("There is no active simulation")
            if self._session["pending_approval"]:
                self._record_human_decision(
                    "REJECTED",
                    str(request.get("reviewer") or "SOC operator").strip() or "SOC operator",
                    "Proposal canceled before enforcement; no live or simulated control needed rollback.",
                )
                self._session["pending_approval"] = False
                self._session["status"] = "running"
                self._session["status_message"] = "Proposal canceled before enforcement; continuing to the audit record."
                self._publish()
                return self.run_full()
            runtime = self._runtime
            enforcement = runtime.enforcement
            if not self._session["rollback_available"] or not enforcement:
                raise SimulationError("No applied digital-twin action is available to roll back")
            token = enforcement.get("rollback_token")
            if not runtime.layer4.rollback_rule(token):
                raise SimulationError("The rollback token is no longer active")
            rollback = {
                "case_id": enforcement["case_id"],
                "action_id": enforcement["action_id"],
                "target_asset": enforcement["target_asset"],
                "rollback_token": token,
                "trigger": "manual_operator",
                "timestamp": self._iso_after(),
                "restored_controls": enforcement.get("applied_controls", []),
            }
            runtime.audit_store.append(rollback_to_audit(rollback, scenario_id=self._session["scenario_id"]))
            enforcement["status"] = "ROLLED_BACK"
            enforcement["verification"] = "Digital-twin rules restored; clinical continuity remains active."
            self._session["enforcement"] = enforcement
            self._session["payloads"]["layer_4_result"] = enforcement
            self._session["rollback_available"] = False
            self._session["blocked_flows"] = []
            if self._session["system_status"] == "EMERGENCY_CONTAINMENT":
                self._session["system_status"] = "HEIGHTENED_MONITORING"
            self._session["status_message"] = "Simulated rules restored and rollback recorded; no external device was contacted."
            if self._session["current_layer"] == 6:
                self._run_layer6()
            self._publish()
            return self._snapshot()

    def _run_layer6(self) -> None:
        assert self._session is not None and self._runtime is not None and self._runtime.proposal is not None
        runtime = self._runtime
        case_id = runtime.proposal.case_id
        scenario_id = self._session["scenario_id"]
        runtime.audit_store.append(new_audit_event(
            layer=6,
            actor="layer6.compliance",
            action="evidence.package.assembly_started",
            input_reference=f"case://{case_id}",
            output_reference=f"evidence-package://EVID-{case_id}",
            record_class=RecordClass.ACTION_TAKEN,
            outcome=Outcome.SUCCESS,
            case_id=case_id,
            scenario_id=scenario_id,
            asset_id=self._critical_target(runtime.proposal),
            payload={"view": "operational", "forensic_records_exported": False},
        ))
        all_device_ids = [item["id"] for item in DEVICES]
        all_ips = [item["ip"] for item in DEVICES]
        runtime.redaction.learn(all_device_ids, domain="asset")
        runtime.redaction.learn(all_ips, domain="network")
        runtime.redaction.learn(runtime.observations and [item.event_id for item in runtime.observations], domain="event")
        case_records = collect_case_records(runtime.audit_store, case_id, include_scenario=scenario_id)
        controller = AccessController(runtime.audit_store, runtime.redaction)
        forensic = controller.read(
            AccessRole.FORENSIC_INVESTIGATOR,
            actor="digital-twin-review",
            records=case_records,
            purpose="simulation evidence package assembly",
            case_id=case_id,
            scenario_id=scenario_id,
        )
        operational = controller.read(
            AccessRole.ANALYST,
            actor="soc-simulator",
            records=case_records,
            purpose="operational simulation review",
            case_id=case_id,
            scenario_id=scenario_id,
        )
        verification = runtime.audit_store.verify()
        timeline = build_timeline(
            operational.records,
            case_id=case_id,
            scenario_id=scenario_id,
            view=ViewKind.OPERATIONAL,
            chain_verification=verification,
        )
        metrics = layer6_metrics(
            store=runtime.audit_store,
            engine=runtime.redaction,
            operational_records=operational.records,
            forensic_records=forensic.records,
            extra_leak_terms=all_device_ids + all_ips,
        )
        report = build_report(timeline, metrics)
        markdown = render_markdown(report)
        runtime.output_dir.mkdir(parents=True, exist_ok=True)
        report_path = runtime.output_dir / f"{case_id}.md"
        report_path.write_text(markdown, encoding="utf-8")
        manifest = export_evidence_package(
            runtime.output_dir / "evidence_package",
            store=runtime.audit_store,
            timeline=timeline,
            operational_records=operational.records,
            forensic_records=None,
            metrics=metrics,
            report_files=[report_path],
        )
        zip_path = runtime.output_dir / f"{case_id}-evidence.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file_path in sorted((runtime.output_dir / "evidence_package").iterdir()):
                if file_path.is_file():
                    archive.write(file_path, arcname=f"evidence_package/{file_path.name}")

        runtime.operational_records = operational.records
        runtime.report_markdown = markdown
        runtime.evidence_manifest = manifest
        runtime.zip_path = zip_path
        self._session["redacted_timeline_md"] = markdown
        self._session["timeline_entries"] = [entry.to_dict() for entry in timeline.entries]
        self._session["narrative_buckets"] = {
            name: [entry.to_dict() for entry in timeline.entries if entry.record_class == name]
            for name in ("observed_fact", "model_inference", "human_decision", "action_taken")
        }
        self._session["evidence_manifest"] = manifest
        self._session["metrics"] = metrics
        self._session["evidence_ready"] = True
        self._session["status"] = "complete"
        self._session["status_message"] = "Layer 6 report and self-verifying evidence package are ready."
        self._session["finished_at"] = self._iso_after()
        self._session["payloads"]["layer_6_audit"] = {
            "chain_valid": bool(verification.ok),
            "latest_hash": verification.head_hash,
            "redacted_timeline_md": markdown,
            "manifest": manifest,
            "metrics": metrics,
        }
        self._mark_layer(6, f"Chain {'valid' if verification.ok else 'invalid'}; {verification.records_checked} records verified.", self._session["payloads"]["layer_6_audit"])

    def reset(self) -> Dict[str, Any]:
        with self._lock:
            self._session = None
            self._runtime = None
            self._publish()
            return self._snapshot()

    def evidence_path(self) -> Optional[Path]:
        with self._lock:
            if self._runtime is None:
                return None
            path = self._runtime.zip_path
            return path if path and path.exists() else None
