"""Evidence package export with a hash manifest.

A package is self-verifying: the manifest carries a SHA-256 of every file plus
the chain verification result and the store head hash at export time, so a
recipient can prove the package was not altered after it left Layer 6.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .audit_store import TamperEvidentAuditStore, canonical_json
from .contracts import AUDIT_CONTRACT_VERSION, IncidentTimeline


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")


def _write_jsonl(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")


def export_evidence_package(
    output_dir: str | Path,
    store: TamperEvidentAuditStore,
    timeline: IncidentTimeline,
    operational_records: Sequence[Dict[str, Any]],
    forensic_records: Optional[Sequence[Dict[str, Any]]] = None,
    metrics: Optional[Dict[str, Any]] = None,
    report_files: Sequence[Path] = (),
) -> Dict[str, Any]:
    """Write a package for one case and return its manifest.

    ``forensic_records`` is omitted from packages destined for an operational or
    external recipient; pass it only when the package is for authorized forensic use.
    """
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)

    written: List[Path] = []

    timeline_path = root / "incident_timeline.json"
    _write_json(timeline_path, timeline.to_dict())
    written.append(timeline_path)

    operational_path = root / "operational_view.jsonl"
    _write_jsonl(operational_path, operational_records)
    written.append(operational_path)

    if forensic_records is not None:
        forensic_path = root / "forensic_records.jsonl"
        _write_jsonl(forensic_path, forensic_records)
        written.append(forensic_path)

    if metrics is not None:
        metrics_path = root / "layer6_metrics.json"
        _write_json(metrics_path, metrics)
        written.append(metrics_path)

    # Copy any report in, so the package verifies standalone once it is moved.
    for item in report_files:
        source = Path(item)
        if not source.exists():
            continue
        destination = root / source.name
        if source.resolve() != destination.resolve():
            destination.write_bytes(source.read_bytes())
        written.append(destination)

    verification = store.verify()
    manifest = {
        "package_id": f"EVID-{timeline.case_id}",
        "case_id": timeline.case_id,
        "scenario_id": timeline.scenario_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contract_version": AUDIT_CONTRACT_VERSION,
        "view": timeline.view,
        "contains_forensic_records": forensic_records is not None,
        "audit_chain": {
            **verification.to_dict(),
            "store_path": str(store.path),
            "store_records": len(store),
        },
        "files": [
            {
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
            for path in written
        ],
    }
    manifest_path = root / "manifest.json"
    _write_json(manifest_path, manifest)
    return manifest


def verify_evidence_package(package_dir: str | Path) -> Dict[str, Any]:
    """Recompute every file hash in a package against its manifest."""
    root = Path(package_dir)
    manifest_path = root / "manifest.json"
    if not manifest_path.exists():
        return {"ok": False, "reason": "manifest.json is missing"}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mismatches: List[str] = []
    missing: List[str] = []
    for entry in manifest.get("files", []):
        path = root / entry["name"]
        if not path.exists():
            missing.append(entry["name"])
            continue
        if _sha256_file(path) != entry["sha256"]:
            mismatches.append(entry["name"])

    ok = not mismatches and not missing
    return {
        "ok": ok,
        "package_id": manifest.get("package_id"),
        "files_checked": len(manifest.get("files", [])),
        "missing_files": missing,
        "modified_files": mismatches,
        "reason": "package intact" if ok else "package contents do not match the manifest",
    }
