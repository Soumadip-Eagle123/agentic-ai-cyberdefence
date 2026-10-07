"""Append-only, hash-chained audit store.

Each record commits to the one before it, so deleting, reordering or editing any
record breaks every hash after it and ``verify()`` names the first bad sequence.
Supplying a ``key`` upgrades the chain from SHA-256 to keyed HMAC, which also
defeats an attacker who can rewrite the file and recompute the plain hashes.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from .contracts import AuditEvent, ChainVerification

GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    """Byte-stable JSON so a hash depends on content, not on key order."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_hash(previous_hash: str, event_dict: Dict[str, Any], key: Optional[bytes] = None) -> str:
    material = f"{previous_hash}|{canonical_json(event_dict)}".encode("utf-8")
    if key:
        return hmac.new(key, material, sha256).hexdigest()
    return sha256(material).hexdigest()


@dataclass(frozen=True)
class ChainedRecord:
    sequence: int
    previous_hash: str
    record_hash: str
    event: AuditEvent

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
            "event": self.event.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "ChainedRecord":
        return cls(
            sequence=int(value["sequence"]),
            previous_hash=value["previous_hash"],
            record_hash=value["record_hash"],
            event=AuditEvent.from_dict(value["event"]),
        )


class TamperEvidentAuditStore:
    """The forensic store. Full fidelity, append-only, never rewritten."""

    def __init__(self, path: str | os.PathLike[str], key: Optional[bytes] = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = key
        self._records: List[ChainedRecord] = []
        if self.path.exists():
            self._records = list(self._read_file())

    # -- writing -----------------------------------------------------------
    @property
    def head_hash(self) -> str:
        return self._records[-1].record_hash if self._records else GENESIS_HASH

    def append(self, event: AuditEvent) -> ChainedRecord:
        event.validate()
        payload = event.to_dict()
        previous = self.head_hash
        record = ChainedRecord(
            sequence=len(self._records),
            previous_hash=previous,
            record_hash=compute_hash(previous, payload, self._key),
            event=event,
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(record.to_dict()) + "\n")
        self._records.append(record)
        return record

    def extend(self, events: Sequence[AuditEvent]) -> List[ChainedRecord]:
        return [self.append(event) for event in events]

    # -- reading -----------------------------------------------------------
    def _read_file(self) -> Iterator[ChainedRecord]:
        with self.path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield ChainedRecord.from_dict(json.loads(line))

    def records(self) -> List[ChainedRecord]:
        return list(self._records)

    def events(self) -> List[AuditEvent]:
        return [record.event for record in self._records]

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[ChainedRecord]:
        return iter(self._records)

    def for_case(self, case_id: str) -> List[ChainedRecord]:
        return [record for record in self._records if record.event.case_id == case_id]

    def for_scenario(self, scenario_id: str) -> List[ChainedRecord]:
        return [record for record in self._records if record.event.scenario_id == scenario_id]

    # -- integrity ---------------------------------------------------------
    def verify(self) -> ChainVerification:
        """Replay the chain from disk and report the first inconsistency."""
        previous = GENESIS_HASH
        checked = 0
        try:
            records = list(self._read_file())
        except (json.JSONDecodeError, KeyError, ValueError) as error:
            return ChainVerification(False, 0, GENESIS_HASH, 0, f"unreadable audit record: {error}")

        for index, record in enumerate(records):
            if record.sequence != index:
                return ChainVerification(False, checked, previous, index, "sequence numbers are not contiguous")
            if record.previous_hash != previous:
                return ChainVerification(False, checked, previous, index, "previous_hash does not match the prior record")
            expected = compute_hash(previous, record.event.to_dict(), self._key)
            if expected != record.record_hash:
                return ChainVerification(False, checked, previous, index, "record content does not match its hash")
            previous = record.record_hash
            checked += 1
        return ChainVerification(True, checked, previous, None, "chain intact")

    @classmethod
    def load(cls, path: str | os.PathLike[str], key: Optional[bytes] = None) -> "TamperEvidentAuditStore":
        return cls(path, key)
