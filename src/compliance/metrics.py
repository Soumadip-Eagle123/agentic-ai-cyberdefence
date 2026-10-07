"""Layer 6 measurements: redaction coverage, leak scanning, audit completeness."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from .audit_store import TamperEvidentAuditStore, canonical_json
from .contracts import REQUIRED_AUDIT_FIELDS, RecordClass
from .redaction import RedactionEngine

#: A complete incident should show every layer that participated in it.
EXPECTED_LAYERS = (0, 1, 2, 3, 4, 5, 6)


def leak_scan(
    operational_records: Sequence[Dict[str, Any]],
    engine: RedactionEngine,
    extra_terms: Iterable[str] = (),
) -> Dict[str, Any]:
    """Serialize the operational view and look for any raw identifier still in it.

    This is the acceptance test for the privacy boundary: the result must be zero.
    """
    rendered = canonical_json(operational_records)
    leaked = engine.scan_for_leaks(rendered, extra_terms)
    return {
        "records_scanned": len(operational_records),
        "terms_checked": len(engine.known_literals) + len(list(extra_terms)),
        "leaked_terms": leaked,
        "leak_count": len(leaked),
        "clean": not leaked,
    }


def redaction_metrics(engine: RedactionEngine, leaks: Dict[str, Any]) -> Dict[str, Any]:
    stats = engine.stats
    handled = stats.sensitive_instances
    total = handled + len(leaks.get("leaked_terms", []))
    coverage = 1.0 if total == 0 else round(handled / total, 4)
    return {
        **stats.to_dict(),
        "leak_scan": leaks,
        "operational_records_correctly_redacted": coverage,
    }


def audit_completeness(
    records: Sequence[Dict[str, Any]],
    expected_layers: Sequence[int] = EXPECTED_LAYERS,
) -> Dict[str, Any]:
    """Contract-field completeness plus which layers actually reported."""
    total = len(records)
    complete = 0
    missing_fields: Dict[str, int] = {}
    seen_layers = set()
    class_counts: Dict[str, int] = {item.value: 0 for item in RecordClass}

    for record in records:
        event = record["event"] if "event" in record else record
        seen_layers.add(int(event.get("layer", -1)))
        class_counts[event.get("record_class", "")] = class_counts.get(event.get("record_class", ""), 0) + 1
        gaps = [name for name in REQUIRED_AUDIT_FIELDS if not event.get(name)]
        if gaps:
            for name in gaps:
                missing_fields[name] = missing_fields.get(name, 0) + 1
        else:
            complete += 1

    present = sorted(layer for layer in seen_layers if layer in expected_layers)
    missing_layers = sorted(set(expected_layers) - set(present))
    return {
        "records": total,
        "records_with_all_required_fields": complete,
        "field_completeness": round(complete / total, 4) if total else 0.0,
        "missing_field_counts": missing_fields,
        "layers_present": present,
        "layers_missing": missing_layers,
        "layer_coverage": round(len(present) / len(expected_layers), 4),
        "records_by_class": class_counts,
    }


def traceability(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Every record must name where it came from and what it produced."""
    total = len(records)
    traceable = 0
    for record in records:
        event = record["event"] if "event" in record else record
        if event.get("input_reference") and event.get("output_reference"):
            traceable += 1
    return {
        "records": total,
        "records_traceable_to_source": traceable,
        "traceability": round(traceable / total, 4) if total else 0.0,
    }


def layer6_metrics(
    store: TamperEvidentAuditStore,
    engine: RedactionEngine,
    operational_records: Sequence[Dict[str, Any]],
    forensic_records: Sequence[Dict[str, Any]],
    extra_leak_terms: Iterable[str] = (),
) -> Dict[str, Any]:
    verification = store.verify()
    leaks = leak_scan(operational_records, engine, extra_leak_terms)
    return {
        "chain_verification": verification.to_dict(),
        "privacy": redaction_metrics(engine, leaks),
        "audit_completeness": audit_completeness(forensic_records),
        "explainability": traceability(forensic_records),
        "store": {
            "path": str(store.path),
            "records": len(store),
            "head_hash": store.head_hash,
        },
    }
