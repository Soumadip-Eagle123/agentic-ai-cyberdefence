import uuid
from typing import Dict, List, Optional
from src.schemas.contracts import AssetContext, DetectionFinding


class BaselineProfile:
    """Stores learned normal communication boundaries per asset."""

    def __init__(self, asset_id: str, allowed_peers: List[str]):
        self.asset_id = asset_id
        self.allowed_peers = set(allowed_peers)


class Layer2Detector:
    """Layer 2 ML Behavioral Detection Engine.

    Parses normalized flow telemetry enriched with Layer 1 Asset Context,
    evaluates network behavior against established baselines, and generates
    explainable DetectionFinding contracts for downstream orchestration.
    """

    def __init__(self, baseline_version: str = "v1.0.0"):
        self.baseline_version = baseline_version
        self.baselines: Dict[str, BaselineProfile] = {}

    def register_baseline(self, asset_context: AssetContext) -> None:
        """Registers expected peer networks from Layer 1 Asset Context."""
        self.baselines[asset_context.asset_id] = BaselineProfile(
            asset_id=asset_context.asset_id,
            allowed_peers=asset_context.allowed_peers,
        )

    def analyze_flows(
        self,
        asset_context: AssetContext,
        flow_logs: List[dict],
        window_label: str = "5m",
    ) -> Optional[DetectionFinding]:
        """Analyzes a window of flow logs for a specific asset to detect behavioral deviations."""
        if asset_context.asset_id not in self.baselines:
            self.register_baseline(asset_context)

        baseline = self.baselines[asset_context.asset_id]
        unauthorized_peers = set()
        suspicious_payload_count = 0
        related_events = []

        for log in flow_logs:
            dst = log.get("dst")
            payload_bytes = log.get("bytes", 0)
            event_id = log.get("event_id")

            # 1. Peer violation check
            if dst and dst not in baseline.allowed_peers:
                unauthorized_peers.add(dst)
                if event_id:
                    related_events.append(event_id)

            # 2. Fixed payload scanning signature check (e.g., 90-byte discovery probes)
            if payload_bytes == 90:
                suspicious_payload_count += 1

        # Evaluate if an anomaly threshold is reached
        if unauthorized_peers:
            indicators = []
            if len(unauthorized_peers) > 1:
                indicators.append("PORT_SCAN_SWEEP")
            indicators.append("UNAUTHORIZED_PEER_COMMUNICATION")

            if suspicious_payload_count > 0:
                indicators.append("UNIFORM_PROBE_PAYLOAD_DETECTED")

            # Compute transparent risk and anomaly scores
            anomaly_score = min(0.5 + (len(unauthorized_peers) * 0.05) + (suspicious_payload_count * 0.02), 0.99)
            risk_score = round(anomaly_score * asset_context.identity_confidence, 2)

            return DetectionFinding(
                finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                asset_id=asset_context.asset_id,
                behavior_window=window_label,
                anomaly_score=round(anomaly_score, 2),
                risk_score=risk_score,
                indicators=indicators,
                baseline_version=self.baseline_version,
                confidence=round(asset_context.identity_confidence, 2),
                related_events=related_events,
                recommended_observation_period=60,
            )

        return None