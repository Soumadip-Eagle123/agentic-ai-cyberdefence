"""The one call every other layer makes.

Layer 6 only works if Layers 0-5 actually report into it. That adoption has to be
cheap, so this module exposes a process-wide audit sink:

    from compliance import emitter

    emitter.configure("artifacts/accds/audit_chain.jsonl")
    emitter.emit(
        layer=4, actor="layer4.enforcement", action="enforcement.applied",
        input_reference="decision://DEC-9f2c", output_reference="action://ACT-71ab",
        record_class="action_taken", payload=result,
    )

Design choices that matter for adoption:

* ``emit`` never raises on a bad record by default. A malformed audit call must
  not take down enforcement or detection; it is captured and counted instead, and
  ``failures()`` reports them. Set ``strict=True`` in tests to surface mistakes.
* Until ``configure`` is called, records buffer in memory rather than being lost,
  so importing a layer before Layer 6 is wired up is harmless.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from .audit_store import TamperEvidentAuditStore
from .contracts import AuditEvent, Outcome, RecordClass, new_audit_event
from .keys import KeyRing

_lock = threading.Lock()
_store: Optional[TamperEvidentAuditStore] = None
_buffer: List[AuditEvent] = []
_failures: List[Dict[str, Any]] = []
_strict = False


def configure(path: str, keyring: Optional[KeyRing] = None, strict: bool = False) -> TamperEvidentAuditStore:
    """Point the sink at a chain on disk and flush anything buffered so far."""
    global _store, _strict
    ring = keyring or KeyRing.resolve()
    with _lock:
        _strict = strict
        _store = TamperEvidentAuditStore(path, key=ring.chain_key)
        if _buffer:
            _store.extend(_buffer)
            _buffer.clear()
    return _store


def reset() -> None:
    """Drop all state. For tests."""
    global _store, _strict
    with _lock:
        _store = None
        _strict = False
        _buffer.clear()
        _failures.clear()


def store() -> Optional[TamperEvidentAuditStore]:
    return _store


def pending() -> int:
    """Records buffered because no store is configured yet."""
    return len(_buffer)


def failures() -> List[Dict[str, Any]]:
    return list(_failures)


def emit(
    *,
    layer: int,
    actor: str,
    action: str,
    input_reference: str,
    output_reference: str,
    record_class: str | RecordClass,
    outcome: str | Outcome = Outcome.SUCCESS,
    timestamp: Optional[datetime] = None,
    case_id: Optional[str] = None,
    scenario_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> Optional[AuditEvent]:
    """Record one step. Returns the event, or None if it could not be recorded."""
    try:
        event = new_audit_event(
            layer=layer,
            actor=actor,
            action=action,
            input_reference=input_reference,
            output_reference=output_reference,
            record_class=RecordClass(record_class) if isinstance(record_class, str) else record_class,
            outcome=Outcome(outcome) if isinstance(outcome, str) else outcome,
            timestamp=timestamp,
            case_id=case_id,
            scenario_id=scenario_id,
            asset_id=asset_id,
            payload=payload,
        )
    except (ValueError, KeyError) as error:
        record = {"actor": actor, "action": action, "error": str(error)}
        with _lock:
            _failures.append(record)
        if _strict:
            raise
        return None

    with _lock:
        if _store is None:
            _buffer.append(event)
        else:
            _store.append(event)
    return event
