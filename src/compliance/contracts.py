"""ACCDS Layer 6 contracts.

Layer 6 is the only layer with an ``all layers -> me`` handoff, so the audit
event defined here is a cross-cutting contract that every other layer emits.
It is deliberately stdlib-only (dataclasses) so that Layer 6 runs with no
third-party dependency; ``src/schemas/contracts.py`` carries a pydantic mirror
of the same wire format for the layers that already use pydantic.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

AUDIT_CONTRACT_VERSION = "accds-audit-v1"

# The roadmap's "All layers -> Layer 6" row marks these as must-never-be-omitted.
REQUIRED_AUDIT_FIELDS = ("actor", "timestamp", "input_reference", "output_reference", "outcome")


class RecordClass(str, Enum):
    """Reports must keep these four apart and never blur them into one narrative."""

    OBSERVED_FACT = "observed_fact"
    MODEL_INFERENCE = "model_inference"
    HUMAN_DECISION = "human_decision"
    ACTION_TAKEN = "action_taken"


class Outcome(str, Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    EXPIRED = "expired"
    ROLLED_BACK = "rolled_back"
    DEGRADED = "degraded"  # e.g. Layer 0 reporting reduced visibility
    ERROR = "error"


class AccessRole(str, Enum):
    ANALYST = "analyst"
    AUDITOR = "auditor"
    FORENSIC_INVESTIGATOR = "forensic_investigator"
    EXTERNAL_REPORTER = "external_reporter"


class ViewKind(str, Enum):
    OPERATIONAL = "operational"  # minimised and redacted
    FORENSIC = "forensic"  # full fidelity, access controlled


#: Only the forensic investigator may read unredacted records.
ROLE_VIEW: Dict[AccessRole, ViewKind] = {
    AccessRole.ANALYST: ViewKind.OPERATIONAL,
    AccessRole.AUDITOR: ViewKind.OPERATIONAL,
    AccessRole.EXTERNAL_REPORTER: ViewKind.OPERATIONAL,
    AccessRole.FORENSIC_INVESTIGATOR: ViewKind.FORENSIC,
}

LAYER_NAMES = {
    0: "Data Ingestion",
    1: "Asset Intelligence",
    2: "ML Behavioral Model",
    3: "Multi-Agent Orchestration",
    4: "Containment & Enforcement",
    5: "Decision Gate",
    6: "Compliance & Privacy",
}


@dataclass(frozen=True)
class AuditEvent:
    """One immutable entry in the ACCDS chain of custody.

    ``payload`` holds the layer-specific record verbatim (a normalized event, a
    finding, a proposal, a decision record, an enforcement result). Layer 6 never
    rewrites a payload in the forensic store; redaction produces a separate view.
    """

    audit_id: str
    timestamp: datetime
    layer: int
    actor: str
    action: str
    outcome: str
    record_class: str
    input_reference: str
    output_reference: str
    case_id: Optional[str] = None
    scenario_id: Optional[str] = None
    asset_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    contract_version: str = AUDIT_CONTRACT_VERSION

    def validate(self) -> None:
        for name in REQUIRED_AUDIT_FIELDS:
            if not getattr(self, name):
                raise ValueError(f"audit event field '{name}' must not be empty")
        if not self.audit_id:
            raise ValueError("audit_id is required")
        if self.layer not in LAYER_NAMES:
            raise ValueError("layer must be 0-6")
        if self.record_class not in {item.value for item in RecordClass}:
            raise ValueError(f"unknown record_class: {self.record_class}")
        if self.outcome not in {item.value for item in Outcome}:
            raise ValueError(f"unknown outcome: {self.outcome}")
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "AuditEvent":
        data = dict(value)
        data["timestamp"] = parse_timestamp(data["timestamp"])
        event = cls(**data)
        event.validate()
        return event


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def new_audit_event(
    *,
    layer: int,
    actor: str,
    action: str,
    input_reference: str,
    output_reference: str,
    record_class: RecordClass,
    outcome: Outcome = Outcome.SUCCESS,
    timestamp: Optional[datetime] = None,
    case_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """Build a validated audit event. This is the entry point other layers call."""
    event = AuditEvent(
        audit_id=f"audit-{uuid.uuid4().hex[:12]}",
        timestamp=timestamp or datetime.now(timezone.utc),
        layer=layer,
        actor=actor,
        action=action,
        outcome=outcome.value if isinstance(outcome, Outcome) else str(outcome),
        record_class=record_class.value if isinstance(record_class, RecordClass) else str(record_class),
        input_reference=input_reference,
        output_reference=output_reference,
        case_id=case_id,
        scenario_id=scenario_id,
        asset_id=asset_id,
        payload=payload or {},
    )
    event.validate()
    return event


@dataclass(frozen=True)
class ChainVerification:
    """Result of replaying the hash chain over the audit store."""

    ok: bool
    records_checked: int
    head_hash: str
    first_broken_sequence: Optional[int] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEntry:
    sequence: int
    audit_id: str
    timestamp: str
    layer: int
    layer_name: str
    actor: str
    action: str
    outcome: str
    record_class: str
    summary: str
    input_reference: str
    output_reference: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentTimeline:
    case_id: str
    scenario_id: Optional[str]
    view: str
    generated_at: str
    entries: List[TimelineEntry]
    buckets: Dict[str, List[str]]
    layer_coverage: Dict[str, int]
    chain_verification: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["entries"] = [entry.to_dict() for entry in self.entries]
        return result
