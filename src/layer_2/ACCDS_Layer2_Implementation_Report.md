# ACCDS Layer 2 Implementation Report

## Result

A standalone ACCDS Layer 2 behavioral-model prototype has been implemented in `/home/ubuntu/accds-layer2`. It does not require the other ACCDS layers or a user-provided dataset. Instead, it generates reproducible synthetic hospital telemetry, trains a versioned normal-behavior baseline, injects labeled evaluation scenarios, replays the data, and emits explainable findings.

## How the dataset is created

The project defines a small simulated hospital environment with intensive care, laboratory, radiology, administration, guest, and security-operations zones. The generator creates Tier 1, Tier 2, and Tier 3 assets with normal peers, services, traffic volumes, and time patterns.

The clean generated events are used to train the baseline. Separate scenario data then injects port scanning, new-peer lateral movement, data exfiltration, credential misuse, off-hours access, diagnostic-device behavior drift, a benign clinical burst, and a low-confidence identity case. The scorer does not use the labels while detecting; labels are retained only for evaluation.

## Implemented components

| Component | Implementation |
|---|---|
| Contracts | Typed enriched events, findings, and immutable baseline metadata |
| Sample-data insertion | JSON and CSV loading with validation and duplicate-ID checks |
| Synthetic generator | Deterministic normal traffic and seeded attack scenarios |
| Features | Event count, peers, fan-out, bytes, authentication, off-hours, peer/service deviations, and protocol diversity |
| Baseline | Robust per-asset and peer-group statistics with configuration and source fingerprints |
| Scoring | Explainable statistical, peer, and rule-based anomaly components plus contextual risk and confidence |
| Replay | Timestamp-ordered deterministic processing with scenario fingerprints |
| Evaluation | Precision/recall-style results and anomaly counts by clinical tier |
| Safety boundary | Evidence-only output; no containment or enforcement commands |

## Acceptance run

The final acceptance command was:

```bash
cd /home/ubuntu/accds-layer2
PYTHONPATH=. python3 -m accds_layer2.cli demo --output artifacts/demo
PYTHONPATH=. pytest -q
```

The test suite completed with **5 passed**. The demo generated a versioned `layer2-baseline-v1`, scenario datasets, findings, and metrics under `artifacts/demo/`.

| Scenario | Injected windows detected | Result |
|---|---:|---|
| Port scan | 1 | Detected |
| New peer | 1 | Detected |
| Exfiltration | 1 | Detected |
| Credential misuse | 1 | Detected |
| Off-hours access | 1 | Detected |
| Diagnostic drift | 1 | Detected |
| Benign clinical burst | 0 | Correctly kept below the finding threshold |
| Low-confidence identity | 0 | Conservatively kept below the finding threshold |

Across the eight evaluated scenario windows, Tier 2 achieved 1.00 precision and 1.00 recall in this synthetic run. Tier 3 achieved 1.00 precision and 0.80 recall. The Tier 1 evaluated case was the benign clinical-burst scenario and produced no false positive. These are prototype results on generated data, not evidence of real-world clinical accuracy.

## Files to inspect first

Start with `README.md` for commands, then review `accds_layer2/synthetic.py`, `accds_layer2/features.py`, `accds_layer2/model.py`, and `accds_layer2/cli.py`. The generated demonstration outputs are in `artifacts/demo/`, especially `baseline.json`, `findings.json`, and `metrics.json`.

## Limitations and next steps

The synthetic generator is intentionally small and transparent. It is suitable for architecture development, regression testing, and demonstrating the Layer 2 contract. It is not a substitute for validation on representative cybersecurity telemetry. Future Layers 0 and 1 can replace the temporary fixture generator through the same enriched-event contract, while Layer 3 can consume the validated finding contract.
