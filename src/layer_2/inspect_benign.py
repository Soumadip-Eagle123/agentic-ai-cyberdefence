from accds_layer2.synthetic import generate_normal, inject_scenario
from accds_layer2.features import build_windows
from accds_layer2.model import train_baseline, score_window
normal = generate_normal(days=3, seed=7)
baseline = train_baseline(build_windows(normal))
for window in build_windows(inject_scenario(normal, 'benign_clinical_burst', seed=20)):
    if window.scenario_id == 'benign_clinical_burst':
        finding = score_window(window, baseline)
        print(finding.anomaly_score, finding.risk_score, finding.indicators, finding.evidence)
