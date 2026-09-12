from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List

from .features import build_windows
from .model import score_window, train_baseline
from .synthetic import fingerprint, generate_normal, inject_scenario, load_events, save_events


def _metrics(findings) -> dict:
    evaluated = [finding for finding in findings if finding.evidence.get("scenario_id") != "normal"]
    by_tier = {}
    for tier in (1, 2, 3):
        subset = [finding for finding in evaluated if finding.clinical_tier == tier]
        positives = [finding for finding in subset if finding.label == "anomaly"]
        predicted = [finding for finding in subset if finding.anomaly_score >= 0.55]
        tp = sum(1 for finding in positives if finding.anomaly_score >= 0.55)
        fp = sum(1 for finding in subset if finding.label == "normal" and finding.anomaly_score >= 0.55)
        fn = sum(1 for finding in positives if finding.anomaly_score < 0.55)
        by_tier[str(tier)] = {
            "windows": len(subset), "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(tp / max(1, tp + fp), 4), "recall": round(tp / max(1, tp + fn), 4),
        }
    return {"by_clinical_tier": by_tier, "evaluated_windows": len(evaluated), "finding_count": len(findings)}


def run_demo(output_dir: str, scenarios: List[str], seed: int = 7) -> dict:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    normal = generate_normal(days=3, seed=seed)
    train_windows = build_windows(normal)
    baseline = train_baseline(train_windows)
    baseline.save(str(output / "baseline.json"))
    save_events(normal, str(output / "normal_training.json"))
    all_findings = []
    scenario_summaries = []
    for scenario in scenarios:
        events = inject_scenario(normal, scenario, seed=seed + len(scenario))
        save_events(events, str(output / f"scenario_{scenario}.json"))
        windows = build_windows(events)
        findings = [score_window(window, baseline, sequence=index) for index, window in enumerate(windows)]
        all_findings.extend(findings)
        scenario_summaries.append({"scenario": scenario, "events": len(events), "windows": len(windows), "findings": sum(1 for finding in findings if finding.anomaly_score >= 0.55), "fingerprint": fingerprint(events)})
    findings_path = output / "findings.json"
    findings_path.write_text(json.dumps([finding.to_dict() for finding in all_findings], indent=2), encoding="utf-8")
    report = {"baseline_version": baseline.version, "scenarios": scenario_summaries, "metrics": _metrics(all_findings)}
    (output / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone ACCDS Layer 2 synthetic-data workflow")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="generate, train, replay, and evaluate synthetic scenarios")
    demo.add_argument("--output", default="artifacts/demo")
    demo.add_argument("--seed", type=int, default=7)
    demo.add_argument("--scenarios", nargs="+", default=["port_scan", "new_peer", "exfiltration", "credential_misuse", "off_hours", "diagnostic_drift", "benign_clinical_burst", "low_confidence"])
    generate = sub.add_parser("generate", help="generate normal or scenario JSON data")
    generate.add_argument("--output", required=True)
    generate.add_argument("--scenario", default="normal")
    generate.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    if args.command == "demo":
        print(json.dumps(run_demo(args.output, args.scenarios, args.seed), indent=2))
    else:
        events = generate_normal(seed=args.seed) if args.scenario == "normal" else inject_scenario(generate_normal(seed=args.seed), args.scenario, args.seed + 1)
        save_events(events, args.output)
        print(json.dumps({"output": args.output, "events": len(events), "fingerprint": fingerprint(events)}, indent=2))


if __name__ == "__main__":
    main()
