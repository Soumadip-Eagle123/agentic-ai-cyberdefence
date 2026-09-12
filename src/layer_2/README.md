# ACCDS Layer 2 — Standalone Behavioral Model

This prototype implements the ACCDS Layer 2 behavioral model without requiring the other ACCDS layers. It generates synthetic hospital telemetry, learns a versioned baseline from normal activity, injects labeled test scenarios, produces explainable findings, and reports evaluation metrics by clinical tier.

## Run the synthetic training and evaluation workflow

From this directory:

```bash
python3 -m accds_layer2.cli demo --output artifacts/demo
```

The command creates a clean training dataset, trains `baseline.json`, generates scenario files, writes `findings.json`, and produces `metrics.json`.

To create one dataset for inspection:

```bash
python3 -m accds_layer2.cli generate --output data/normal.json --scenario normal
python3 -m accds_layer2.cli generate --output data/scan.json --scenario port_scan
```

## Data workflow

The synthetic generator is a temporary substitute for Layers 0 and 1. It emits enriched events with normalized telemetry and asset context. The same `load_events` interface accepts JSON and CSV records later, so externally supplied data can replace the fixtures without changing the model contract.

The baseline is trained only from normal behavior. Attack scenarios are replayed after training. Scenario labels are used only by the evaluation harness; the scoring engine receives telemetry and asset context and emits evidence, anomaly score, risk score, confidence, baseline version, related events, and recommended observation period.

## Safety boundary

This package is evidence-only. It contains no firewall, isolation, containment, approval, or enforcement implementation. Layer 2 does not issue commands to a network or clinical system.

## Main modules

| Module | Purpose |
|---|---|
| `schemas.py` | Versioned event, finding, and baseline contracts |
| `synthetic.py` | Deterministic hospital telemetry and attack scenario generation; JSON/CSV loading |
| `features.py` | Behavioral-window feature extraction |
| `model.py` | Baseline training and explainable anomaly/risk scoring |
| `cli.py` | End-to-end generation, training, replay, and evaluation |
