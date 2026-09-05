"""Incident timeline reconstruction.

The roadmap requires reports to keep observed facts, model inferences, human
decisions and actions taken clearly apart, so the timeline carries both an
ordered narrative and those four buckets over the same records.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from .audit_store import ChainedRecord, TamperEvidentAuditStore
from .contracts import (
    LAYER_NAMES,
    ChainVerification,
    IncidentTimeline,
    RecordClass,
    TimelineEntry,
    ViewKind,
)


def summarize(event_payload: Dict[str, Any], action: str, layer: int) -> str:
    """One human-readable line per record, built from the already-viewed payload."""
    get = event_payload.get
    if layer == 0:
        return (
            f"{get('subject')} -> {get('dst')} via {get('protocol')} "
            f"({get('bytes')} bytes) in zone {get('zone')}"
        )
    if layer == 1:
        return (
            f"Asset {get('asset_id')} identified as {get('asset_type')} in "
            f"{get('owner_zone')}, clinical tier {get('clinical_tier')}, "
            f"identity confidence {get('identity_confidence')}"
        )
    if layer == 2:
        indicators = ", ".join(item.get("code", "?") for item in (get("indicators") or []))
        return (
            f"Finding {get('finding_id')} on {get('asset_id')}: anomaly "
            f"{get('anomaly_score')}, risk {get('risk_score')}, indicators [{indicators}]"
        )
    if layer == 3:
        actions = ", ".join(item.get("action_type", "?") for item in (get("candidate_actions") or []))
        return (
            f"Case {get('case_id')} proposes [{actions}] at approval level "
            f"{get('approval_level')}; {get('clinical_impact')}"
        )
    if layer == 4:
        if action.endswith("rolled_back"):
            return f"Rollback {get('rollback_token')} on {get('target_asset')} ({get('trigger')})"
        return (
            f"{', '.join(get('applied_controls') or [])} on {get('target_asset')}: "
            f"{len(get('blocked_flows') or [])} flow(s) blocked, "
            f"{len(get('preserved_flows') or [])} preserved, status {get('status')}"
        )
    if layer == 5:
        return (
            f"Reviewer {get('reviewer')} recorded {get('decision')} for case "
            f"{get('case_id')} (scope {get('scope_hash')}): {get('reason')}"
        )
    if action == "annotation.added":
        return f"Analyst {get('analyst')} noted: {get('note')}"
    return f"{action}: {get('purpose') or get('view') or ''}".strip(": ")


def build_timeline(
    records: Sequence[Dict[str, Any]],
    case_id: str,
    scenario_id: Optional[str] = None,
    view: ViewKind = ViewKind.OPERATIONAL,
    chain_verification: Optional[ChainVerification] = None,
) -> IncidentTimeline:
    """Assemble an ordered timeline from already-viewed (raw or redacted) records."""
    entries: List[TimelineEntry] = []
    buckets: Dict[str, List[str]] = {item.value: [] for item in RecordClass}
    coverage: Dict[str, int] = {}

    ordered = sorted(records, key=lambda item: (item["event"]["timestamp"], item["sequence"]))
    for record in ordered:
        event = record["event"]
        layer = int(event["layer"])
        entry = TimelineEntry(
            sequence=int(record["sequence"]),
            audit_id=event["audit_id"],
            timestamp=event["timestamp"],
            layer=layer,
            layer_name=LAYER_NAMES.get(layer, "unknown"),
            actor=event["actor"],
            action=event["action"],
            outcome=event["outcome"],
            record_class=event["record_class"],
            summary=summarize(event.get("payload") or {}, event["action"], layer),
            input_reference=event["input_reference"],
            output_reference=event["output_reference"],
        )
        entries.append(entry)
        buckets.setdefault(event["record_class"], []).append(event["audit_id"])
        key = f"layer_{layer}"
        coverage[key] = coverage.get(key, 0) + 1

    return IncidentTimeline(
        case_id=case_id,
        scenario_id=scenario_id,
        view=view.value,
        generated_at=datetime.now(timezone.utc).isoformat(),
        entries=entries,
        buckets=buckets,
        layer_coverage=coverage,
        chain_verification=(chain_verification.to_dict() if chain_verification else {}),
    )


def collect_case_records(
    store: TamperEvidentAuditStore,
    case_id: str,
    include_scenario: Optional[str] = None,
) -> List[ChainedRecord]:
    """Everything belonging to a case, plus the scenario observations behind it."""
    selected = {record.sequence: record for record in store.for_case(case_id)}
    if include_scenario:
        for record in store.for_scenario(include_scenario):
            selected.setdefault(record.sequence, record)
    return [selected[key] for key in sorted(selected)]
