"""Command-line entry point for ACCDS Layer 6.

    python3 -m compliance.cli demo --scenario port_scan --output artifacts/layer6
    python3 -m compliance.cli verify --store artifacts/layer6/audit_chain.jsonl
    python3 -m compliance.cli verify-package --package artifacts/layer6/evidence_package
    python3 -m compliance.cli report --scenario exfiltration --adapter stdout
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit_store import TamperEvidentAuditStore
from .evidence import verify_evidence_package
from .pipeline import run_pipeline
from .redaction import DEFAULT_PSEUDONYM_KEY

SCENARIOS = (
    "port_scan", "new_peer", "exfiltration", "credential_misuse",
    "off_hours", "diagnostic_drift", "benign_clinical_burst", "low_confidence",
)


def _demo(args: argparse.Namespace) -> int:
    result = run_pipeline(
        output_dir=args.output,
        scenario=args.scenario,
        adapter_name=args.adapter,
        reviewer_decision=args.decision,
    )
    summary = result.to_dict()
    privacy = summary["metrics"]["privacy"]
    chain = summary["metrics"]["chain_verification"]
    print(json.dumps(summary, indent=2, default=str))
    print()
    print(f"case             : {result.case_id}")
    print(f"timeline entries : {result.timeline_entries}")
    print(f"audit chain      : {'VERIFIED' if chain['ok'] else 'FAILED'} ({chain['records_checked']} records)")
    print(f"leak scan        : {'clean' if privacy['leak_scan']['clean'] else privacy['leak_scan']['leaked_terms']}")
    print(f"evidence package : {Path(args.output) / 'evidence_package'}")
    return 0 if chain["ok"] and privacy["leak_scan"]["clean"] else 1


def _verify(args: argparse.Namespace) -> int:
    store = TamperEvidentAuditStore(args.store, key=DEFAULT_PSEUDONYM_KEY)
    result = store.verify()
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.ok else 1


def _verify_package(args: argparse.Namespace) -> int:
    result = verify_evidence_package(args.package)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def _all_scenarios(args: argparse.Namespace) -> int:
    rows = []
    failures = 0
    for scenario in SCENARIOS:
        try:
            result = run_pipeline(
                output_dir=Path(args.output) / scenario,
                scenario=scenario,
                adapter_name="file",
            )
        except ValueError as error:
            rows.append({"scenario": scenario, "status": f"skipped: {error}"})
            continue
        chain = result.metrics["chain_verification"]
        leaks = result.metrics["privacy"]["leak_scan"]
        ok = chain["ok"] and leaks["clean"]
        failures += 0 if ok else 1
        rows.append({
            "scenario": scenario,
            "case_id": result.case_id,
            "entries": result.timeline_entries,
            "chain_ok": chain["ok"],
            "leaks": leaks["leak_count"],
            "layer_coverage": result.metrics["audit_completeness"]["layer_coverage"],
        })
    print(json.dumps(rows, indent=2))
    return 0 if failures == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="ACCDS Layer 6 - Compliance & Privacy")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the full Layer 6 pipeline for one scenario")
    demo.add_argument("--output", default="artifacts/layer6")
    demo.add_argument("--scenario", default="port_scan", choices=SCENARIOS)
    demo.add_argument("--adapter", default="file", choices=("file", "stdout", "null"))
    demo.add_argument("--decision", default="APPROVED", choices=("APPROVED", "REJECTED", "ESCALATED", "TIMEOUT"))
    demo.set_defaults(func=_demo)

    every = sub.add_parser("all", help="run the pipeline across every Layer 2 scenario")
    every.add_argument("--output", default="artifacts/layer6-all")
    every.set_defaults(func=_all_scenarios)

    verify = sub.add_parser("verify", help="verify an audit chain on disk")
    verify.add_argument("--store", default="artifacts/layer6/audit_chain.jsonl")
    verify.set_defaults(func=_verify)

    package = sub.add_parser("verify-package", help="verify an exported evidence package")
    package.add_argument("--package", default="artifacts/layer6/evidence_package")
    package.set_defaults(func=_verify_package)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
