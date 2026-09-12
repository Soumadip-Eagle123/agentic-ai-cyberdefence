from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List

from .features import FEATURE_NAMES, FeatureWindow
from .schemas import Baseline, Finding

DEFAULT_THRESHOLDS = {"anomaly": 0.55, "high_anomaly": 0.75}
DEFAULT_WEIGHTS = {"statistical": 0.55, "peer": 0.25, "rules": 0.20}


def _median(values: List[float]) -> float:
    return statistics.median(values) if values else 0.0


def _mad(values: List[float], median: float) -> float:
    return _median([abs(value - median) for value in values]) if values else 0.0


def _stats(values: List[float]) -> Dict[str, float]:
    med = _median(values)
    mad = _mad(values, med)
    return {"median": med, "mad": mad, "p05": min(values) if values else 0.0, "p95": max(values) if values else 0.0}


def train_baseline(windows: Iterable[FeatureWindow], version: str = "layer2-baseline-v1") -> Baseline:
    windows = list(windows)
    normal = [window for window in windows if window.label == "normal"]
    if not normal:
        raise ValueError("baseline training requires at least one normal window")
    asset_values: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    peer_values: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for window in normal:
        for feature in FEATURE_NAMES:
            asset_values[window.asset_id][feature].append(window.values[feature])
            peer_values[str(window.clinical_tier)][feature].append(window.values[feature])
    asset_stats = {asset: {feature: _stats(values) for feature, values in features.items()} for asset, features in asset_values.items()}
    peer_stats = {tier: {feature: _stats(values) for feature, values in features.items()} for tier, features in peer_values.items()}
    config = {"thresholds": DEFAULT_THRESHOLDS, "weights": DEFAULT_WEIGHTS, "features": FEATURE_NAMES}
    config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    source_fingerprint = hashlib.sha256(json.dumps([(window.asset_id, window.start.isoformat(), window.values) for window in normal], sort_keys=True).encode()).hexdigest()
    return Baseline(version=version, created_at=datetime.now(timezone.utc).isoformat(), feature_names=FEATURE_NAMES, asset_stats=asset_stats, peer_stats=peer_stats, thresholds=DEFAULT_THRESHOLDS, weights=DEFAULT_WEIGHTS, source_fingerprint=source_fingerprint, config_hash=config_hash)


def _deviation(value: float, stats: Dict[str, float]) -> float:
    scale = max(stats["mad"] * 1.4826, (stats["p95"] - stats["p05"]) / 4.0, 1.0)
    return min(1.0, abs(value - stats["median"]) / (scale * 4.0))


def score_window(window: FeatureWindow, baseline: Baseline, sequence: int = 0) -> Finding:
    asset_stats = baseline.asset_stats.get(window.asset_id, {})
    peer_stats = baseline.peer_stats.get(str(window.clinical_tier), {})
    contributions = []
    stat_scores = []
    peer_scores = []
    for feature in baseline.feature_names:
        value = window.values.get(feature, 0.0)
        if feature in asset_stats:
            stat_scores.append(_deviation(value, asset_stats[feature]))
        if feature in peer_stats:
            peer_scores.append(_deviation(value, peer_stats[feature]))
    statistical = sum(stat_scores) / max(1, len(stat_scores))
    peer = sum(peer_scores) / max(1, len(peer_scores))
    rules = min(1.0, 0.38 * window.values["new_peer_ratio"] + 0.22 * window.values["unapproved_peer_ratio"] + 0.12 * window.values["off_hours_ratio"] + 0.18 * min(1.0, window.values["port_fanout"] / 10.0) + 0.10 * min(1.0, window.values["failed_auth"] / 3.0))
    if window.values["port_fanout"] >= 8:
        rules = max(rules, 0.88)
    if window.values["new_peer_ratio"] >= 1.0 and window.values["event_count"] >= 3:
        rules = max(rules, 0.72)
    if window.values["total_bytes"] >= 100000 and window.values["unapproved_peer_ratio"] > 0:
        rules = max(rules, 0.78)
    if window.values["failed_auth"] >= 3:
        rules = max(rules, 0.70)
    anomaly = min(1.0, baseline.weights["statistical"] * statistical + baseline.weights["peer"] * peer + baseline.weights["rules"] * rules)
    if window.values["port_fanout"] >= 8 or (window.values["total_bytes"] >= 100000 and window.values["unapproved_peer_ratio"] > 0) or window.values["failed_auth"] >= 3:
        anomaly = max(anomaly, 0.62)
    if window.values["new_peer_ratio"] >= 1.0 and window.values["event_count"] >= 3:
        anomaly = max(anomaly, 0.58)
    if window.values["off_hours_ratio"] >= 1.0 and window.values["event_count"] >= 3 and window.values["new_peer_ratio"] == 0 and window.clinical_tier != 1:
        anomaly = max(anomaly, 0.56)
    confidence = min(1.0, 0.45 + 0.15 * min(1.0, len(window.event_ids) / 5.0) + 0.40 * window.identity_confidence)
    tier_multiplier = {1: 1.0, 2: 0.85, 3: 0.70}[window.clinical_tier]
    risk = min(1.0, anomaly * tier_multiplier + 0.15 * rules)
    indicators: List[Dict[str, object]] = []
    if window.values["new_peer_ratio"] > 0:
        indicators.append({"code": "new_peer", "message": "Observed destination peers outside the asset allow-list.", "value": window.values["new_peer_ratio"]})
    if window.values["port_fanout"] >= 8:
        indicators.append({"code": "port_fanout", "message": "Destination fan-out is consistent with discovery or scanning behavior.", "value": window.values["port_fanout"]})
    if window.values["total_bytes"] > 100000 and window.values["unapproved_peer_ratio"] > 0:
        indicators.append({"code": "volume_spike", "message": "Outbound or aggregate data volume is unusually high toward an unapproved peer.", "value": window.values["total_bytes"]})
    if window.values["off_hours_ratio"] > 0.5:
        indicators.append({"code": "off_hours", "message": "A large share of activity occurred outside the normal operating window.", "value": window.values["off_hours_ratio"]})
    if window.values["failed_auth"] >= 3:
        indicators.append({"code": "auth_burst", "message": "Repeated authentication failures were observed in the behavior window.", "value": window.values["failed_auth"]})
    if window.identity_confidence < 0.7:
        indicators.append({"code": "low_identity_confidence", "message": "Asset identity confidence is low; conclusions should remain conservative.", "value": window.identity_confidence})
    if not indicators and anomaly > baseline.thresholds["anomaly"]:
        indicators.append({"code": "statistical_deviation", "message": "Multiple behavioral features deviated from the asset and peer baselines.", "value": anomaly})
    finding = Finding(
        finding_id=f"finding-{sequence:06d}-{window.asset_id}-{window.start.strftime('%Y%m%d%H%M')}",
        asset_id=window.asset_id,
        behavior_window={"start": window.start.isoformat(), "end": window.end.isoformat()},
        anomaly_score=round(anomaly, 4),
        risk_score=round(risk, 4),
        indicators=indicators,
        baseline_version=baseline.version,
        confidence=round(confidence, 4),
        related_events=window.event_ids,
        recommended_observation_period=30 if anomaly < baseline.thresholds["anomaly"] else (10 if confidence < 0.7 else 5),
        clinical_tier=window.clinical_tier,
        known_constraints=["preserve-clinical-flow"] if window.clinical_tier == 1 else [],
        affected_zone=window.zone,
        suspected_attack_stage=window.attack_stage,
        identity_confidence=window.identity_confidence,
        evidence={"features": window.values, "components": {"statistical": statistical, "peer": peer, "rules": rules}, "observed_label": window.label, "scenario_id": window.scenario_id},
        label=window.label,
    )
    finding.validate()
    return finding
