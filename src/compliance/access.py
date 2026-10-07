"""Role-gated access to the two views, with the access itself audited.

Reading forensic evidence is a privileged act, so every read appends its own
audit event to the same chain. An investigator cannot quietly pull raw records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from .audit_store import ChainedRecord, TamperEvidentAuditStore
from .contracts import (
    ROLE_VIEW,
    AccessRole,
    Outcome,
    RecordClass,
    ViewKind,
    new_audit_event,
)
from .redaction import RedactionEngine


class AccessDenied(PermissionError):
    """Raised when a role asks for a view it may not hold."""


@dataclass
class AccessResult:
    role: str
    actor: str
    view: str
    purpose: str
    records: List[Dict[str, Any]]
    access_audit_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "actor": self.actor,
            "view": self.view,
            "purpose": self.purpose,
            "record_count": len(self.records),
            "access_audit_id": self.access_audit_id,
        }


class AccessController:
    """Resolves role -> view, applies redaction, and logs the access."""

    def __init__(self, store: TamperEvidentAuditStore, engine: RedactionEngine) -> None:
        self.store = store
        self.engine = engine

    def view_for(self, role: AccessRole) -> ViewKind:
        try:
            return ROLE_VIEW[role]
        except KeyError as error:  # pragma: no cover - guarded by the enum
            raise AccessDenied(f"unknown role: {role}") from error

    def read(
        self,
        role: AccessRole,
        actor: str,
        records: Sequence[ChainedRecord],
        purpose: str = "incident review",
        case_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
    ) -> AccessResult:
        view = self.view_for(role)
        raw = [record.to_dict() for record in records]
        if view is ViewKind.FORENSIC:
            payload = raw
        else:
            payload = self.engine.redact_many(raw)

        access_event = new_audit_event(
            layer=6,
            actor=f"{role.value}:{actor}",
            action=f"evidence.read.{view.value}",
            input_reference=f"audit-store://{self.store.path.name}",
            output_reference=f"view://{view.value}/{len(payload)}-records",
            record_class=RecordClass.ACTION_TAKEN,
            outcome=Outcome.SUCCESS,
            case_id=case_id,
            scenario_id=scenario_id,
            payload={
                "purpose": purpose,
                "records_released": len(payload),
                "view": view.value,
                "role": role.value,
            },
        )
        self.store.append(access_event)
        return AccessResult(
            role=role.value,
            actor=actor,
            view=view.value,
            purpose=purpose,
            records=payload,
            access_audit_id=access_event.audit_id,
        )

    def deny(self, role: AccessRole, actor: str, requested: ViewKind, reason: str) -> None:
        """Record a refused access attempt; refusals are evidence too."""
        event = new_audit_event(
            layer=6,
            actor=f"{role.value}:{actor}",
            action=f"evidence.read.{requested.value}",
            input_reference=f"audit-store://{self.store.path.name}",
            output_reference="view://denied",
            record_class=RecordClass.ACTION_TAKEN,
            outcome=Outcome.REJECTED,
            payload={"reason": reason, "requested_view": requested.value},
        )
        self.store.append(event)
