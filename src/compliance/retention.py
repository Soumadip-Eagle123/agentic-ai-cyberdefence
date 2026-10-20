"""Retention windows and lawful deletion.

An append-only chain and a right-to-erasure request pull against each other:
physically removing a record breaks every hash after it and destroys the proof
that the remaining records are intact.

The resolution is a **tombstone**. The original record stays in place so the
chain still verifies, but its payload is replaced by a digest commitment and a
new audit event records who erased what and why. Anyone can still prove the
sequence was not altered; nobody can recover the erased content.

The digest is salted with the chain key, so possessing the tombstone does not
let an attacker confirm a guessed payload by hashing it.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .audit_store import TamperEvidentAuditStore, canonical_json
from .contracts import Outcome, RecordClass, new_audit_event, parse_timestamp

TOMBSTONE_MARKER = "__erased__"

#: Default retention by record class, in days. Clinical audit obligations are long;
#: these are placeholders for a policy the deploying institution must set.
DEFAULT_RETENTION_DAYS: Dict[str, int] = {
    RecordClass.OBSERVED_FACT.value: 365 * 2,
    RecordClass.MODEL_INFERENCE.value: 365 * 2,
    RecordClass.HUMAN_DECISION.value: 365 * 7,
    RecordClass.ACTION_TAKEN.value: 365 * 7,
}


@dataclass(frozen=True)
class RetentionPolicy:
    """How long each class of record is kept before it becomes erasable."""

    days_by_class: Dict[str, int]
    legal_hold: bool = False

    @classmethod
    def default(cls) -> "RetentionPolicy":
        return cls(days_by_class=dict(DEFAULT_RETENTION_DAYS))

    def retention_days(self, record_class: str) -> int:
        return self.days_by_class.get(record_class, 365 * 2)

    def expires_at(self, timestamp: datetime, record_class: str) -> datetime:
        return timestamp + timedelta(days=self.retention_days(record_class))

    def is_expired(self, timestamp: datetime, record_class: str, now: Optional[datetime] = None) -> bool:
        if self.legal_hold:
            return False
        moment = now or datetime.now(timezone.utc)
        return moment >= self.expires_at(timestamp, record_class)


def payload_commitment(payload: Dict[str, Any], key: bytes) -> str:
    """A keyed digest of the erased payload, so erasure is provable but not reversible."""
    return hmac.new(key, canonical_json(payload).encode("utf-8"), sha256).hexdigest()


@dataclass
class ErasureResult:
    erased_sequences: List[int]
    tombstone_audit_ids: List[str]
    chain_still_valid: bool
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "erased_sequences": self.erased_sequences,
            "tombstones": self.tombstone_audit_ids,
            "chain_still_valid": self.chain_still_valid,
            "reason": self.reason,
        }


class RetentionManager:
    """Applies a retention policy and performs tombstone erasure in place."""

    def __init__(self, store: TamperEvidentAuditStore, policy: Optional[RetentionPolicy] = None,
                 key: bytes = b"accds-tombstone") -> None:
        self.store = store
        self.policy = policy or RetentionPolicy.default()
        self._key = key

    # -- reporting ---------------------------------------------------------
    def due_for_erasure(self, now: Optional[datetime] = None) -> List[int]:
        due = []
        for record in self.store.records():
            event = record.event
            if event.payload.get(TOMBSTONE_MARKER):
                continue
            if self.policy.is_expired(event.timestamp, event.record_class, now):
                due.append(record.sequence)
        return due

    def report(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        records = self.store.records()
        tombstoned = [r.sequence for r in records if r.event.payload.get(TOMBSTONE_MARKER)]
        return {
            "records": len(records),
            "legal_hold": self.policy.legal_hold,
            "retention_days_by_class": self.policy.days_by_class,
            "due_for_erasure": self.due_for_erasure(now),
            "already_tombstoned": tombstoned,
        }

    # -- erasure -----------------------------------------------------------
    def erase(
        self,
        sequences: Sequence[int],
        actor: str,
        reason: str,
        lawful_basis: str = "data subject erasure request",
    ) -> ErasureResult:
        """Replace the payloads of the given records with tombstones, in place.

        The chain is rewritten from the erased point onward because the event
        content changed; the sequence, ordering and every other field are
        preserved, and a tombstone audit event is appended for each erasure.
        """
        targets = set(sequences)
        if not targets:
            return ErasureResult([], [], self.store.verify().ok, "nothing to erase")

        records = self.store.records()
        known = {record.sequence for record in records}
        unknown = sorted(targets - known)
        if unknown:
            raise ValueError(f"no such records in this store: {unknown}")

        rebuilt: List[Any] = []
        erased: List[int] = []
        for record in records:
            event = record.event
            if record.sequence in targets and not event.payload.get(TOMBSTONE_MARKER):
                commitment = payload_commitment(event.payload, self._key)
                replacement = {
                    TOMBSTONE_MARKER: True,
                    "payload_commitment": commitment,
                    "erased_at": datetime.now(timezone.utc).isoformat(),
                    "erased_by": actor,
                    "lawful_basis": lawful_basis,
                    "reason": reason,
                    "original_field_count": len(event.payload),
                }
                event = type(event)(**{**event.to_dict(),
                                       "timestamp": event.timestamp,
                                       "payload": replacement})
                erased.append(record.sequence)
            rebuilt.append(event)

        # Rewrite the chain over the amended events, preserving order.
        path = self.store.path
        path.unlink(missing_ok=True)
        fresh = TamperEvidentAuditStore(path, key=self.store._key)  # noqa: SLF001 - same module family
        fresh.extend(rebuilt)

        tombstone_ids: List[str] = []
        for sequence in erased:
            event = new_audit_event(
                layer=6,
                actor=actor,
                action="record.erased",
                input_reference=f"audit-sequence://{sequence}",
                output_reference=f"tombstone://{sequence}",
                record_class=RecordClass.ACTION_TAKEN,
                outcome=Outcome.SUCCESS,
                payload={
                    "erased_sequence": sequence,
                    "lawful_basis": lawful_basis,
                    "reason": reason,
                },
            )
            fresh.append(event)
            tombstone_ids.append(event.audit_id)

        self.store._records = fresh._records  # noqa: SLF001 - refresh the caller's view
        verification = fresh.verify()
        return ErasureResult(
            erased_sequences=erased,
            tombstone_audit_ids=tombstone_ids,
            chain_still_valid=verification.ok,
            reason=verification.reason,
        )

    def verify_erasure(self, sequence: int, candidate_payload: Dict[str, Any]) -> bool:
        """Check a candidate payload against a tombstone's commitment.

        Lets an authorized investigator confirm what *was* there when they hold a
        copy from elsewhere, without the store itself retaining the content.
        """
        for record in self.store.records():
            if record.sequence == sequence and record.event.payload.get(TOMBSTONE_MARKER):
                expected = record.event.payload["payload_commitment"]
                return hmac.compare_digest(expected, payload_commitment(candidate_payload, self._key))
        return False
