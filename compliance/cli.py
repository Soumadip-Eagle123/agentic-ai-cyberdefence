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
from .datasources import DataSourceNotFound, find_data_dir, search_paths
from .evidence import verify_evidence_package
from .keys import InsecureKeyError, KeyRing
from .pipeline import run_pipeline
from .retention import RetentionManager, RetentionPolicy
from .signing import mldsa_available

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
        signer_kind=args.signer,
        require_managed_keys=args.require_managed_keys,
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
    cp = result.checkpoint
    print(f"checkpoint       : {cp['algorithm']} (third-party verifiable: {cp['third_party_verifiable']})")
    if result.key_provenance["development_keys_in_use"]:
        print("keys             : DEVELOPMENT DEFAULTS - set ACCDS_CHAIN_KEY / ACCDS_PSEUDONYM_KEY")
    print(f"evidence package : {Path(args.output) / 'evidence_package'}")
    return 0 if chain["ok"] and privacy["leak_scan"]["clean"] else 1


def _verify(args: argparse.Namespace) -> int:
    store = TamperEvidentAuditStore(args.store, key=KeyRing.resolve().chain_key)
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
                signer_kind=args.signer,
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


def _keys(args: argparse.Namespace) -> int:
    ring = KeyRing.resolve()
    info = dict(ring.provenance())
    info["mldsa_available"] = mldsa_available()
    try:
        info["data_dir"] = str(find_data_dir())
    except DataSourceNotFound:
        info["data_dir"] = None
        info["searched"] = [str(item) for item in search_paths()]
    print(json.dumps(info, indent=2))
    if ring.is_development:
        print("\nWARNING: development keys are in use. Set ACCDS_CHAIN_KEY and "
              "ACCDS_PSEUDONYM_KEY (or ACCDS_KEY_FILE) for anything beyond synthetic data.")
    return 0


def _retention(args: argparse.Namespace) -> int:
    ring = KeyRing.resolve()
    store = TamperEvidentAuditStore(args.store, key=ring.chain_key)
    manager = RetentionManager(store, RetentionPolicy.default(), key=ring.chain_key)
    if args.erase:
        result = manager.erase(args.erase, actor=args.actor, reason=args.reason)
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.chain_still_valid else 1
    print(json.dumps(manager.report(), indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ACCDS Layer 6 - Compliance & Privacy")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run the full Layer 6 pipeline for one scenario")
    demo.add_argument("--output", default="artifacts/layer6")
    demo.add_argument("--scenario", default="port_scan", choices=SCENARIOS)
    demo.add_argument("--adapter", default="file", choices=("file", "stdout", "null"))
    demo.add_argument("--decision", default="APPROVED", choices=("APPROVED", "REJECTED", "ESCALATED", "TIMEOUT"))
    demo.add_argument("--signer", default="hmac", choices=("hmac", "mldsa"),
                      help="mldsa = FIPS 204 ML-DSA-65; third-party verifiable, needs 'cryptography'")
    demo.add_argument("--require-managed-keys", action="store_true",
                      help="fail rather than fall back to development key material")
    demo.set_defaults(func=_demo)

    every = sub.add_parser("all", help="run the pipeline across every Layer 2 scenario")
    every.add_argument("--output", default="artifacts/layer6-all")
    every.add_argument("--signer", default="hmac", choices=("hmac", "mldsa"))
    every.set_defaults(func=_all_scenarios)

    verify = sub.add_parser("verify", help="verify an audit chain on disk")
    verify.add_argument("--store", default="artifacts/layer6/audit_chain.jsonl")
    verify.set_defaults(func=_verify)

    package = sub.add_parser("verify-package", help="verify an exported evidence package")
    package.add_argument("--package", default="artifacts/layer6/evidence_package")
    package.set_defaults(func=_verify_package)

    keys = sub.add_parser("keys", help="show key provenance, data location and ML-DSA availability")
    keys.set_defaults(func=_keys)

    retention = sub.add_parser("retention", help="report retention status, or erase records via tombstone")
    retention.add_argument("--store", default="artifacts/layer6/audit_chain.jsonl")
    retention.add_argument("--erase", nargs="*", type=int, help="sequence numbers to erase")
    retention.add_argument("--actor", default="dpo:unspecified")
    retention.add_argument("--reason", default="retention policy erasure")
    retention.set_defaults(func=_retention)

    args = parser.parse_args()
    try:
        return args.func(args)
    except (InsecureKeyError, DataSourceNotFound) as error:
        # Expected, actionable failures: report them plainly, not as a traceback.
        print(f"error: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
