"""End-to-end Layer 6 run over the artifacts the other layers have produced.

Reads real Layer 0/1/2 records from the repository's demo artifacts, fills the
Layer 3/4/5 gap with clearly marked stand-ins, and produces the chain, both
views, the timeline, the metrics, the evidence package and the report.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .access import AccessController
from .audit_store import TamperEvidentAuditStore
from .contracts import AccessRole, ViewKind
from .evidence import export_evidence_package
from .ingest import (
    annotation_to_audit,
    asset_context_to_audit,
    decision_to_audit,
    enforcement_to_audit,
    findings_to_audit,
    load_json,
    observations_to_audit,
    proposal_to_audit,
    rollback_to_audit,
    select_findings,
)
from .metrics import layer6_metrics
from .redaction import DEFAULT_PSEUDONYM_KEY, RedactionEngine
from .reporting import build_report, get_adapter, render_markdown
from .timeline import build_timeline, collect_case_records
from .upstream_stubs import build_annotation, build_decision, build_enforcement, build_proposal

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Layer6Result:
    case_id: str
    scenario_id: str
    store_path: str
    manifest: Dict[str, Any]
    metrics: Dict[str, Any]
    report_files: List[str]
    timeline_entries: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "scenario_id": self.scenario_id,
            "audit_store": self.store_path,
            "timeline_entries": self.timeline_entries,
            "evidence_manifest": self.manifest,
            "metrics": self.metrics,
            "report_files": self.report_files,
        }


def run_pipeline(
    output_dir: str | Path,
    scenario: str = "port_scan",
    findings_path: Optional[str | Path] = None,
    events_path: Optional[str | Path] = None,
    adapter_name: str = "file",
    pseudonym_key: bytes = DEFAULT_PSEUDONYM_KEY,
    reviewer_decision: str = "APPROVED",
) -> Layer6Result:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    findings_path = Path(findings_path or REPO_ROOT / "findings.json")
    events_path = Path(events_path or REPO_ROOT / f"scenario_{scenario}.json")

    all_events: List[Dict[str, Any]] = load_json(events_path)
    all_findings: List[Dict[str, Any]] = load_json(findings_path)

    scenario_findings = select_findings(all_findings, scenario_id=scenario)
    if not scenario_findings:
        raise ValueError(f"no Layer 2 findings carry scenario_id '{scenario}' in {findings_path}")
    finding = max(scenario_findings, key=lambda item: item["anomaly_score"])

    # The observations behind this finding, plus the asset context Layer 1 would resolve.
    related = set(finding.get("related_events", []))
    case_events = [event for event in all_events if event.get("event_id") in related]
    if not case_events:  # fall back to the scenario's injected events
        case_events = [event for event in all_events if event.get("scenario_id") == scenario]
    asset_events = [event for event in all_events if event.get("asset_id") == finding["asset_id"]]
    asset_context = asset_events[0] if asset_events else case_events[0]

    # Layers 3, 4 and 5 do not exist yet; these are marked stand-ins.
    proposal = build_proposal(finding, asset_context)
    case_id = proposal["case_id"]
    decision = build_decision(proposal, decision=reviewer_decision)
    enforcement, rollback = build_enforcement(proposal, decision)
    annotation = build_annotation(case_id)

    store = TamperEvidentAuditStore(output / "audit_chain.jsonl", key=pseudonym_key)
    store.extend(observations_to_audit(case_events, case_id=case_id))
    store.extend(asset_context_to_audit(asset_events, case_id=case_id))
    store.extend(findings_to_audit([finding], case_id=case_id))
    store.append(proposal_to_audit(proposal, scenario_id=scenario))
    store.append(decision_to_audit(decision, scenario_id=scenario))
    store.append(enforcement_to_audit(enforcement, scenario_id=scenario))
    store.append(rollback_to_audit(rollback, scenario_id=scenario))
    store.append(annotation_to_audit(annotation))

    engine = RedactionEngine(key=pseudonym_key)
    # Pre-seed the scrubber with the whole asset inventory so free text in one
    # record is scrubbed using identifiers first seen in another.
    engine.learn({event.get("asset_id") for event in all_events}, domain="asset")
    engine.learn({event.get("subject") for event in all_events}, domain="subject")
    engine.learn({event.get("dst") for event in all_events}, domain="network")
    engine.learn({event.get("src") for event in all_events}, domain="network")

    controller = AccessController(store, engine)
    case_records = collect_case_records(store, case_id, include_scenario=scenario)

    forensic = controller.read(
        AccessRole.FORENSIC_INVESTIGATOR,
        actor="j.alvarez",
        records=case_records,
        purpose="chain-of-custody review",
        case_id=case_id,
        scenario_id=scenario,
    )
    operational = controller.read(
        AccessRole.ANALYST,
        actor="soc-shift-b",
        records=case_records,
        purpose="operational triage",
        case_id=case_id,
        scenario_id=scenario,
    )

    timeline = build_timeline(
        operational.records,
        case_id=case_id,
        scenario_id=scenario,
        view=ViewKind.OPERATIONAL,
        chain_verification=store.verify(),
    )

    extra_terms = {
        finding["asset_id"],
        finding["finding_id"],
        decision["reviewer"],
        annotation["analyst"],
    } | {event["event_id"] for event in case_events}
    metrics = layer6_metrics(
        store=store,
        engine=engine,
        operational_records=operational.records,
        forensic_records=forensic.records,
        extra_leak_terms=extra_terms,
    )

    report = build_report(timeline, metrics)
    markdown = render_markdown(report)
    adapter = get_adapter(adapter_name, output_dir=output) if adapter_name == "file" else get_adapter(adapter_name)
    dispatch = adapter.dispatch(report, markdown)
    report_files = [Path(item) for item in dispatch.get("files", [])]

    manifest = export_evidence_package(
        output / "evidence_package",
        store=store,
        timeline=timeline,
        operational_records=operational.records,
        forensic_records=forensic.records,
        metrics=metrics,
        report_files=report_files,
    )

    return Layer6Result(
        case_id=case_id,
        scenario_id=scenario,
        store_path=str(store.path),
        manifest=manifest,
        metrics=metrics,
        report_files=[str(item) for item in report_files],
        timeline_entries=len(timeline.entries),
    )
