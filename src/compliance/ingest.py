"""Adapters that turn each layer's native record into an ACCDS audit event.

Layer 6 stays schema-tolerant on purpose: it consumes whatever the other layers
emit today and keeps the payload verbatim. When Layers 0, 1, 4 and 5 are built
for real, only the small functions in this module change.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from .contracts import AuditEvent, Outcome, RecordClass, new_audit_event, parse_timestamp


def enum_text(value: Any) -> str:
    """The wire value of a field that may arrive as an Enum member.

    ``BaseModel.model_dump()`` returns enum *members*, not their values, and
    since Python 3.12 ``str(SomeStrEnum.MEMBER)`` renders as
    "DecisionOutcome.APPROVED" rather than "APPROVED". Coercing with str() made
    every decision and enforcement status fail its lookup and silently fall back
    to the default outcome, so an approved containment was recorded as escalated
    and a failed one as a success.
    """
    return str(getattr(value, "value", value) if value is not None else "")


def load_json(path: str | Path) -> Any:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


# --------------------------------------------------------------------------
# Layer 0 - normalized observations
# --------------------------------------------------------------------------
def observations_to_audit(
    events: Iterable[Dict[str, Any]],
    case_id: Optional[str] = None,
) -> List[AuditEvent]:
    audit: List[AuditEvent] = []
    for event in events:
        audit.append(
            new_audit_event(
                layer=0,
                actor="layer0.ingestion",
                action="observation.normalized",
                input_reference=event.get("raw_reference", "unknown://raw"),
                output_reference=f"event://{event.get('event_id')}",
                record_class=RecordClass.OBSERVED_FACT,
                outcome=Outcome.SUCCESS,
                timestamp=parse_timestamp(event["timestamp"]),
                case_id=case_id,
                scenario_id=event.get("scenario_id"),
                asset_id=event.get("asset_id"),
                payload={
                    key: event.get(key)
                    for key in (
                        "event_id", "event_type", "subject", "src", "dst",
                        "protocol", "bytes", "zone", "raw_reference",
                    )
                },
            )
        )
    return audit


# --------------------------------------------------------------------------
# Layer 1 - asset context
# --------------------------------------------------------------------------
def asset_context_to_audit(
    events: Sequence[Dict[str, Any]],
    case_id: Optional[str] = None,
) -> List[AuditEvent]:
    """Emit one asset-context record per distinct asset seen in the events.

    Layer 1 does not exist yet; the context is currently baked into the Layer 2
    generator's events, so this reads it back out into a proper Layer 1 handoff.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    for event in events:
        asset_id = event.get("asset_id")
        if asset_id and asset_id not in seen:
            seen[asset_id] = event

    audit: List[AuditEvent] = []
    for asset_id, event in seen.items():
        audit.append(
            new_audit_event(
                layer=1,
                actor="layer1.asset_intelligence",
                action="asset.context.resolved",
                input_reference=f"event://{event.get('event_id')}",
                output_reference=f"asset://{asset_id}",
                record_class=RecordClass.OBSERVED_FACT,
                outcome=Outcome.SUCCESS,
                timestamp=parse_timestamp(event["timestamp"]),
                case_id=case_id,
                scenario_id=event.get("scenario_id"),
                asset_id=asset_id,
                payload={
                    key: event.get(key)
                    for key in (
                        "asset_id", "asset_type", "owner_zone", "vendor",
                        "software_version", "clinical_tier", "known_constraints",
                        "allowed_peers", "normal_services", "fallback_mode",
                        "identity_confidence",
                    )
                },
            )
        )
    return audit


# --------------------------------------------------------------------------
# Layer 2 - findings
# --------------------------------------------------------------------------
def findings_to_audit(
    findings: Iterable[Dict[str, Any]],
    case_id: Optional[str] = None,
) -> List[AuditEvent]:
    audit: List[AuditEvent] = []
    for finding in findings:
        # Two Layer 2 implementations disagree on `behavior_window`: the batch
        # model emits {"start": ..., "end": ...} while the streaming detector
        # emits a duration label like "5m". Layer 6 is schema-tolerant on input
        # by design - it records what the other layers actually produce - so
        # accept both and fall back to the finding's own timestamp.
        window = finding.get("behavior_window")
        if isinstance(window, dict):
            stamp = window.get("end") or window.get("start")
        else:
            stamp = finding.get("timestamp")
        timestamp = parse_timestamp(stamp) if stamp else datetime.now(timezone.utc)
        audit.append(
            new_audit_event(
                layer=2,
                actor=f"layer2.model:{finding.get('baseline_version')}",
                action="finding.emitted",
                input_reference=f"events://{len(finding.get('related_events', []))}-related",
                output_reference=f"finding://{finding.get('finding_id')}",
                record_class=RecordClass.MODEL_INFERENCE,
                outcome=Outcome.SUCCESS,
                timestamp=timestamp,
                case_id=case_id,
                scenario_id=(finding.get("evidence") or {}).get("scenario_id"),
                asset_id=finding.get("asset_id"),
                payload=finding,
            )
        )
    return audit


def select_findings(
    findings: Sequence[Dict[str, Any]],
    scenario_id: Optional[str] = None,
    min_anomaly_score: float = 0.0,
) -> List[Dict[str, Any]]:
    selected = []
    for finding in findings:
        evidence = finding.get("evidence") or {}
        if scenario_id and evidence.get("scenario_id") != scenario_id:
            continue
        if float(finding.get("anomaly_score", 0.0)) < min_anomaly_score:
            continue
        selected.append(finding)
    return selected


# --------------------------------------------------------------------------
# Layer 3 - response proposal
# --------------------------------------------------------------------------
def proposal_to_audit(proposal: Dict[str, Any], scenario_id: Optional[str] = None) -> AuditEvent:
    raw_ts = (
        proposal.get("generated_at")
        or proposal.get("timestamp")
        or datetime.now(timezone.utc).isoformat()
    )
    return new_audit_event(
        layer=3,
        actor="layer3.orchestrator",
        action="proposal.generated",
        input_reference=f"finding://{proposal.get('source_finding_id', 'unknown')}",
        output_reference=f"case://{proposal.get('case_id')}",
        record_class=RecordClass.MODEL_INFERENCE,
        outcome=Outcome.ESCALATED
        if proposal.get("approval_level") == "REQUIRES_HUMAN_APPROVAL"
        else Outcome.SUCCESS,
        timestamp=parse_timestamp(raw_ts),
        case_id=proposal.get("case_id"),
        scenario_id=scenario_id,
        asset_id=(proposal.get("affected_assets") or [None])[0],
        payload=proposal,
    )


# --------------------------------------------------------------------------
# Layer 5 - decision record
# --------------------------------------------------------------------------
def decision_to_audit(decision: Dict[str, Any], scenario_id: Optional[str] = None) -> AuditEvent:
    mapping = {
        "APPROVED": Outcome.SUCCESS,
        "REJECTED": Outcome.REJECTED,
        "ESCALATED": Outcome.ESCALATED,
        "TIMEOUT": Outcome.EXPIRED,
    }
    return new_audit_event(
        layer=5,
        actor=f"layer5.reviewer:{decision.get('reviewer')}",
        action="decision.recorded",
        input_reference=f"case://{decision.get('case_id')}",
        output_reference=f"decision://{decision.get('decision_id')}",
        record_class=RecordClass.HUMAN_DECISION,
        outcome=mapping.get(enum_text(decision.get("decision")).upper(), Outcome.ESCALATED),
        timestamp=parse_timestamp(decision["timestamp"]),
        case_id=decision.get("case_id"),
        scenario_id=scenario_id,
        asset_id=decision.get("asset_id"),
        payload=decision,
    )


# --------------------------------------------------------------------------
# Layer 4 - enforcement result and rollback
# --------------------------------------------------------------------------
def enforcement_to_audit(result: Dict[str, Any], scenario_id: Optional[str] = None) -> AuditEvent:
    mapping = {
        "APPLIED": Outcome.SUCCESS,
        "VERIFIED": Outcome.SUCCESS,
        "FAILED": Outcome.ERROR,
        "EXPIRED": Outcome.EXPIRED,
        "ROLLED_BACK": Outcome.ROLLED_BACK,
    }
    return new_audit_event(
        layer=4,
        actor="layer4.enforcement",
        action=f"enforcement.{enum_text(result.get('status') or 'applied').lower()}",
        input_reference=f"decision://{result.get('decision_id')}",
        output_reference=f"action://{result.get('action_id')}",
        record_class=RecordClass.ACTION_TAKEN,
        outcome=mapping.get(enum_text(result.get("status")).upper(), Outcome.SUCCESS),
        timestamp=parse_timestamp(result["start_time"]),
        case_id=result.get("case_id"),
        scenario_id=scenario_id,
        asset_id=result.get("target_asset"),
        payload=result,
    )


def rollback_to_audit(rollback: Dict[str, Any], scenario_id: Optional[str] = None) -> AuditEvent:
    return new_audit_event(
        layer=4,
        actor="layer4.enforcement",
        action="enforcement.rolled_back",
        input_reference=f"action://{rollback.get('action_id')}",
        output_reference=f"rollback://{rollback.get('rollback_token')}",
        record_class=RecordClass.ACTION_TAKEN,
        outcome=Outcome.ROLLED_BACK,
        timestamp=parse_timestamp(rollback["timestamp"]),
        case_id=rollback.get("case_id"),
        scenario_id=scenario_id,
        asset_id=rollback.get("target_asset"),
        payload=rollback,
    )


# --------------------------------------------------------------------------
# Analyst annotations
# --------------------------------------------------------------------------
def annotation_to_audit(annotation: Dict[str, Any]) -> AuditEvent:
    return new_audit_event(
        layer=6,
        actor=f"analyst:{annotation.get('analyst')}",
        action="annotation.added",
        input_reference=f"case://{annotation.get('case_id')}",
        output_reference=f"annotation://{annotation.get('annotation_id')}",
        record_class=RecordClass.HUMAN_DECISION,
        outcome=Outcome.SUCCESS,
        timestamp=parse_timestamp(annotation["timestamp"]),
        case_id=annotation.get("case_id"),
        payload=annotation,
    )


# --------------------------------------------------------------------------
# Layer 5 - the real decision_gate package
# --------------------------------------------------------------------------
#: decision_gate emits lowercase verbs; the audit contract uses outcomes.
DECISION_GATE_OUTCOMES = {
    "approve": Outcome.SUCCESS,
    "approved": Outcome.SUCCESS,
    "reject": Outcome.REJECTED,
    "rejected": Outcome.REJECTED,
    "modify": Outcome.ESCALATED,
    "escalate": Outcome.ESCALATED,
    "escalated": Outcome.ESCALATED,
    "timeout": Outcome.EXPIRED,
}


def decision_gate_to_audit(record: Any, scenario_id: Optional[str] = None) -> AuditEvent:
    """Adapt a ``decision_gate.models.DecisionRecord`` into an audit event.

    Accepts the dataclass or any object/dict with the same fields. Two mismatches
    are absorbed here rather than pushed onto Layer 5:

    * ``decision_gate`` stamps records with ``datetime.utcnow()``, which is naive;
      the audit contract requires timezone-aware timestamps, so a naive value is
      read as UTC.
    * its decision verbs are lowercase (``approve``), while outcomes are a fixed
      vocabulary; unknown verbs escalate rather than silently succeeding.
    """
    data = record if isinstance(record, dict) else {
        name: getattr(record, name, None)
        for name in ("decision_id", "case_id", "reviewer", "decision",
                     "scope_hash", "reason", "approved_action", "timestamp")
    }
    verb = enum_text(data.get("decision")).lower()
    outcome = DECISION_GATE_OUTCOMES.get(verb, Outcome.ESCALATED)
    return new_audit_event(
        layer=5,
        actor=f"layer5.reviewer:{data.get('reviewer')}",
        action="decision.recorded",
        input_reference=f"case://{data.get('case_id')}",
        output_reference=f"decision://{data.get('decision_id')}",
        record_class=RecordClass.HUMAN_DECISION,
        outcome=outcome,
        timestamp=parse_timestamp(data["timestamp"]),
        case_id=data.get("case_id"),
        scenario_id=scenario_id,
        payload={
            "decision_id": data.get("decision_id"),
            "case_id": data.get("case_id"),
            "reviewer": data.get("reviewer"),
            "decision": verb,
            "scope_hash": data.get("scope_hash"),
            "reason": data.get("reason"),
            "approved_action": data.get("approved_action"),
        },
    )
