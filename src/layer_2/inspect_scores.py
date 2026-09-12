from accds_layer2.synthetic import generate_normal, inject_scenario
from accds_layer2.features import build_windows
from accds_layer2.model import train_baseline, score_window

normal = generate_normal(days=3, seed=7)
baseline = train_baseline(build_windows(normal))
for scenario in ["port_scan", "new_peer", "exfiltration", "credential_misuse", "off_hours", "diagnostic_drift", "benign_clinical_burst", "low_confidence"]:
    windows = build_windows(inject_scenario(normal, scenario, seed=7 + len(scenario)))
    target = [window for window in windows if window.label != "normal"]
    scored = [score_window(window, baseline, i) for i, window in enumerate(target)]
    print(scenario)
    for finding in scored:
        print(finding.asset_id, finding.anomaly_score, finding.risk_score, finding.confidence, finding.indicators, finding.evidence["features"])
