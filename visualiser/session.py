"""A live ACCDS pipeline that survives between requests.

The static topology view can only replay a run that already happened. To let
someone launch an attack and watch the system respond, the layers have to stay
resident: Layer 2 keeps its learned baseline, and Layer 3 keeps its open cases
so a second attack can be recognised as a continuation of the first rather than
a fresh incident.

That accumulation is the whole point. Firing one exploit at the ICU looks like
an isolated event; firing it *after* compromising the lab server is the sixth
hop of a campaign, and only a session that remembers the earlier hops can tell
the difference.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from digital_twin import hospital, scenarios
from src.asset_intelligence.layer1_asset_intelligence import Layer1AssetIntelligence
from src.decision_gate.decision_logic import Layer5DecisionGate
from src.detection.layer2_detector import Layer2Detector
from src.enforcement.layer4_executor import Layer4Executor
from src.ingestion.layer0_ingestion import Layer0Ingestion
from src.orchestration.layer3_orchestrator import Layer3Orchestrator
from src.schemas.contracts import (
    ApprovalLevel,
    DecisionOutcome,
    SystemSafetyMode,
)

#: Attack types the UI offers, with the indicator they usually produce.
ATTACK_TYPES: List[Dict[str, Any]] = [
    {"id": "SMB_FLOW", "label": "SMB probe", "bytes": 80,
     "hint": "Quiet reconnaissance over file sharing"},
    {"id": "PORT_SCAN", "label": "Port scan", "bytes": 1200,
     "hint": "Sweep a host for open services"},
    {"id": "CREDENTIAL_DUMP", "label": "Credential dump", "bytes": 3400,
     "hint": "Harvest credentials from the target"},
    {"id": "MALWARE_STAGING", "label": "Stage malware", "bytes": 8192,
     "hint": "Drop a payload - compromises the target for later hops"},
    {"id": "EXPLOIT_ATTEMPT", "label": "Exploit", "bytes": 4096,
     "hint": "Attempt remote code execution"},
    {"id": "C2_BEACON", "label": "C2 beacon", "bytes": 1024,
     "hint": "Call home from inside the network"},
    {"id": "DATA_UPLOAD", "label": "Exfiltrate", "bytes": 250000,
     "hint": "Bulk upload of collected data"},
    {"id": "HL7_BULK", "label": "HL7 bulk transfer (legitimate)", "bytes": 120000,
     "hint": "Authorised clinical traffic - should NOT trigger containment"},
]


@dataclass
class AttackResult:
    """What one launched attack produced, layer by layer."""

    ok: bool
    stage: int
    src: str
    dst: str
    event_type: str
    timestamp: str
    observation: Dict[str, Any] = field(default_factory=dict)
    asset: Dict[str, Any] = field(default_factory=dict)
    attacker_asset_id: Optional[str] = None
    identity_known: bool = True
    finding: Optional[Dict[str, Any]] = None
    proposal: Optional[Dict[str, Any]] = None
    awaiting_approval: bool = False
    decision: Optional[Dict[str, Any]] = None
    enforcement: Optional[Dict[str, Any]] = None
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok, "stage": self.stage, "src": self.src, "dst": self.dst,
            "event_type": self.event_type, "timestamp": self.timestamp,
            "observation": self.observation, "asset": self.asset,
            "attacker_asset_id": self.attacker_asset_id,
            "identity_known": self.identity_known,
            "finding": self.finding, "proposal": self.proposal,
            "awaiting_approval": self.awaiting_approval,
            "decision": self.decision, "enforcement": self.enforcement,
            "message": self.message,
        }


class AttackSession:
    """One live run of Layers 0-5 that accumulates state across attacks."""

    def __init__(self, baseline_hours: int = 24) -> None:
        self.layer0 = Layer0Ingestion()
        self.layer1 = Layer1AssetIntelligence()
        self.layer2 = Layer2Detector()
        self.layer3 = Layer3Orchestrator()
        self.layer4 = Layer4Executor()
        self.layer5 = Layer5DecisionGate()

        # Train once; the baseline is what makes the scores mean anything.
        self.baseline_events = scenarios.generate_normal(hours=baseline_hours)
        self.layer2.learn_from_events(self.baseline_events)

        self.clock = scenarios.CAMPAIGN_START
        self.stages: List[Dict[str, Any]] = []
        self.pending_case: Optional[str] = None
        self.pending_proposal = None
        self.last_decision: Optional[Dict[str, Any]] = None
        self.last_enforcement: Optional[Dict[str, Any]] = None
        #: Devices an attacker has taken, so the UI can show who can attack next.
        self.compromised: List[str] = []

    # -- introspection -----------------------------------------------------
    def hospital_state(self) -> Dict[str, Any]:
        return {
            "zones": [
                {"name": z.name, "label": z.label, "rect": list(z.rect), "accent": z.accent}
                for z in hospital.all_zones()
            ],
            "devices": [
                {
                    "asset_id": d.asset_id, "asset_type": d.asset_type, "zone": d.zone,
                    "tier": d.tier, "ip": d.ip, "pos": list(d.pos), "peers": d.peers,
                    "services": d.services, "vendor": d.vendor,
                    "software_version": d.software_version,
                    "fallback_mode": d.fallback_mode, "constraints": d.known_constraints,
                }
                for d in hospital.all_devices()
            ],
            "baseline_edges": [list(e) for e in hospital.baseline_edges()],
            "attack_types": ATTACK_TYPES,
            "campaigns": [
                {"id": name, "title": scenarios.get_campaign(name).title,
                 "stages": len(scenarios.get_campaign(name).stages)}
                for name in scenarios.campaign_names()
            ],
        }

    def state(self) -> Dict[str, Any]:
        return {
            "stages": self.stages,
            "compromised": self.compromised,
            "awaiting_approval": self.pending_case is not None,
            "pending_case": self.pending_case,
            "pending_proposal": (self.pending_proposal.model_dump()
                                 if self.pending_proposal else None),
            "last_decision": self.last_decision,
            "last_enforcement": self.last_enforcement,
            "visibility": self.layer1.visibility_report(),
            "baseline": {
                "events": len(self.baseline_events),
                "devices": len(self.layer2.baselines),
                "threshold": self.layer2.threshold,
            },
        }

    # -- the main action ---------------------------------------------------
    def launch(self, src: str, dst: str, event_type: str,
               byte_count: Optional[int] = None) -> AttackResult:
        """Push one attack through Layers 0-5 and report what each one did."""
        if self.pending_case:
            return AttackResult(
                ok=False, stage=len(self.stages), src=src, dst=dst,
                event_type=event_type, timestamp=self.clock.isoformat(),
                awaiting_approval=True,
                message="A decision is pending. Approve or reject it before attacking again.",
            )

        defaults = {a["id"]: a["bytes"] for a in ATTACK_TYPES}
        byte_count = byte_count or defaults.get(event_type, 1024)
        self.clock += timedelta(minutes=2)
        stage_index = len(self.stages) + 1

        destination = hospital.get(dst)
        source = hospital.get(src)
        zone = destination.zone if destination else (source.zone if source else "external")

        raw_log = {
            "timestamp": self.clock.isoformat().replace("+00:00", "Z"),
            "source": f"{zone.split('_')[0]}_pcap_sensor",
            "event_type": event_type, "src": src, "dst": dst,
            "protocol": "TCP", "bytes": byte_count, "zone": zone,
            "scenario_id": "interactive_session",
        }

        # --- LAYER 0 ------------------------------------------------------
        observation = self.layer0.process_raw_log(raw_log)
        if observation is None:
            return AttackResult(
                ok=False, stage=stage_index, src=src, dst=dst, event_type=event_type,
                timestamp=self.clock.isoformat(),
                message="Layer 0 dropped this as a duplicate of an earlier event.",
            )

        # --- LAYER 1 ------------------------------------------------------
        enrichment = self.layer1.enrich_full(observation)
        asset = enrichment.asset
        result = AttackResult(
            ok=True, stage=stage_index, src=src, dst=dst, event_type=event_type,
            timestamp=observation.timestamp,
            observation=observation.model_dump(),
            asset=asset.model_dump(),
            attacker_asset_id=enrichment.attacker_asset_id,
            identity_known=enrichment.identity_known,
        )

        # --- LAYER 2 ------------------------------------------------------
        counterpart = observation.src if enrichment.resolved_from == "dst" else observation.dst
        finding = self.layer2.analyze_observation(
            asset_context=asset, event_id=observation.event_id,
            event_type=observation.event_type, src=observation.src,
            counterpart=counterpart, byte_count=observation.bytes,
            timestamp=self.clock, attacker_asset_id=enrichment.attacker_asset_id,
        )

        if finding is None:
            result.message = (
                f"Scored below the {self.layer2.threshold} threshold - "
                "behaviour is within this device's baseline. No finding raised."
            )
            self._record_stage(result)
            return result

        result.finding = finding.model_dump()

        # --- LAYER 3 ------------------------------------------------------
        proposal = self.layer3.process(finding=finding, asset=asset,
                                       safety_mode=SystemSafetyMode.NORMAL)
        result.proposal = proposal.model_dump()

        # A device that has been successfully attacked can be used for the next
        # hop, which is what makes the chain rule fire on a later attack.
        if asset.asset_id not in self.compromised and hospital.by_asset_id(asset.asset_id):
            self.compromised.append(asset.asset_id)

        # --- LAYER 5 ------------------------------------------------------
        decision = self.layer5.evaluate_proposal(proposal)
        if decision is None:
            self.pending_case = proposal.case_id
            self.pending_proposal = proposal
            result.awaiting_approval = True
            result.message = (
                f"Tier {int(asset.clinical_tier)} asset involved - "
                "Layer 5 is holding this for a human decision."
            )
            self._record_stage(result)
            return result

        result.decision = decision.model_dump()
        self.last_decision = result.decision

        # --- LAYER 4 ------------------------------------------------------
        enforcement = self.layer4.execute_proposal(proposal, force_execution=True)
        result.enforcement = enforcement.model_dump()
        self.last_enforcement = result.enforcement
        result.message = f"Auto-approved by policy. Enforcement: {enforcement.status.value}."
        self._record_stage(result)
        return result

    # -- the human in the loop --------------------------------------------
    def decide(self, approve: bool, reviewer: str, reason: str) -> Dict[str, Any]:
        if not self.pending_case or self.pending_proposal is None:
            return {"ok": False, "message": "There is no decision waiting."}

        proposal = self.pending_proposal
        outcome = DecisionOutcome.APPROVED if approve else DecisionOutcome.REJECTED
        record = self.layer5.record_human_decision(
            case_id=self.pending_case,
            reviewer_id=(reviewer or "analyst_dr_smith").strip()[:64],
            decision=outcome,
            reason=(reason or ("Approved after review." if approve
                               else "Rejected: clinical disruption risk.")).strip()[:300],
        )
        self.pending_case = None
        self.pending_proposal = None
        self.last_decision = record.model_dump()

        enforcement = self.layer4.execute_proposal(proposal, force_execution=approve)
        self.last_enforcement = enforcement.model_dump()

        if self.stages:
            self.stages[-1]["decision"] = self.last_decision
            self.stages[-1]["enforcement"] = self.last_enforcement

        return {
            "ok": True,
            "decision": self.last_decision,
            "enforcement": self.last_enforcement,
            "message": (
                f"{outcome.value}. Enforcement: {enforcement.status.value}."
                + ("" if approve else " No controls were applied; the attack continues.")
            ),
        }

    def run_campaign(self, name: str) -> List[Dict[str, Any]]:
        """Replay a scripted campaign through the same live session."""
        results = []
        for event in scenarios.generate_campaign(name):
            results.append(self.launch(event.src, event.dst, event.event_type).to_dict())
            if self.pending_case:
                break  # stop at the gate, as a real operator would
        return results

    def reset(self) -> None:
        self.__init__(baseline_hours=24)

    # -- internals ---------------------------------------------------------
    def _record_stage(self, result: AttackResult) -> None:
        finding = result.finding or {}
        self.stages.append({
            "stage": result.stage, "src": result.src, "dst": result.dst,
            "asset_id": result.asset.get("asset_id"),
            "tier": int(result.asset.get("clinical_tier", 3)),
            "event_type": result.event_type, "zone": result.observation.get("zone"),
            "timestamp": result.timestamp,
            "attacker_asset_id": result.attacker_asset_id,
            "identity_known": result.identity_known,
            "finding": ({
                "finding_id": finding.get("finding_id"),
                "anomaly_score": finding.get("anomaly_score"),
                "risk_score": finding.get("risk_score"),
                "indicators": finding.get("indicators", []),
                "confidence": finding.get("confidence"),
            } if finding else None),
            "case_id": (result.proposal or {}).get("case_id"),
            "approval_level": (result.proposal or {}).get("approval_level"),
            "correlated_findings": len((result.proposal or {}).get("correlated_finding_ids", [])),
            "attack_chain": (result.proposal or {}).get("attack_chain", []),
            "decision": result.decision,
            "enforcement": result.enforcement,
            "message": result.message,
        })
