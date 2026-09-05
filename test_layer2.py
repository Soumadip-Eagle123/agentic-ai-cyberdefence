import json
from pathlib import Path

from accds_layer2.features import build_windows
from accds_layer2.model import score_window, train_baseline
from accds_layer2.synthetic import generate_normal, inject_scenario, load_events, save_events


def test_normal_generation_is_deterministic():
    first = [event.to_dict() for event in generate_normal(days=1, seed=9)]
    second = [event.to_dict() for event in generate_normal(days=1, seed=9)]
    assert first == second


def test_json_round_trip(tmp_path: Path):
    events = generate_normal(days=1, seed=3)
    path = tmp_path / "events.json"
    save_events(events, str(path))
    loaded = load_events(str(path))
    assert [event.event_id for event in loaded] == [event.event_id for event in events]


def test_baseline_and_findings_have_required_contract():
    normal = generate_normal(days=2, seed=7)
    baseline = train_baseline(build_windows(normal))
    events = inject_scenario(normal, "port_scan")
    windows = build_windows(events)
    findings = [score_window(window, baseline, index) for index, window in enumerate(windows)]
    injected = [finding for finding in findings if finding.evidence["scenario_id"] == "port_scan"]
    assert injected
    assert any(finding.anomaly_score >= 0.55 for finding in injected)
    finding = injected[0]
    assert finding.baseline_version == baseline.version
    assert finding.related_events
    assert finding.evidence["features"]
    assert not hasattr(finding, "action")


def test_seeded_scenarios_detected_and_benign_burst_is_not_high_confidence_attack():
    normal = generate_normal(days=3, seed=7)
    baseline = train_baseline(build_windows(normal))
    attack_scenarios = ["port_scan", "new_peer", "exfiltration", "credential_misuse", "off_hours", "diagnostic_drift"]
    for scenario in attack_scenarios:
        windows = build_windows(inject_scenario(normal, scenario, seed=7 + len(scenario)))
        findings = [score_window(window, baseline, index) for index, window in enumerate(windows) if window.scenario_id == scenario]
        assert findings, scenario
        assert any(finding.anomaly_score >= 0.55 for finding in findings), scenario
    benign = build_windows(inject_scenario(normal, "benign_clinical_burst", seed=20))
    benign_findings = [score_window(window, baseline, index) for index, window in enumerate(benign) if window.scenario_id == "benign_clinical_burst"]
    assert benign_findings
    assert all(finding.anomaly_score < 0.55 for finding in benign_findings)


def test_low_identity_confidence_is_conservative():
    normal = generate_normal(days=3, seed=7)
    baseline = train_baseline(build_windows(normal))
    windows = [window for window in build_windows(inject_scenario(normal, "low_confidence")) if window.scenario_id == "low_confidence"]
    finding = score_window(windows[0], baseline)
    assert finding.identity_confidence < 0.7
    assert finding.confidence < 0.7
    assert any(indicator["code"] == "low_identity_confidence" for indicator in finding.indicators)
