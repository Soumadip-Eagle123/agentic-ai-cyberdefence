"""Layer 2 - ML Behavioural Detection.

Learns what normal looks like for each device, then scores live telemetry
against it. The scores this module produces used to be a hardcoded list indexed
by stage number, which meant the "detection" in a demo run was a constant: the
same stage scored the same no matter what the event contained.

Transparency is deliberate. The roadmap asks for explainable features over a
black box at this stage, so every score decomposes into named components that
appear on the finding. A reviewer can see *why* something scored 0.94.

The detector never sees ground-truth labels. Scenario labels exist only so the
evaluation harness can measure precision and recall afterwards.
"""

from __future__ import annotations

import statistics
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

from src.schemas.contracts import AssetContext, DetectionFinding

#: Score at or above which a finding is emitted at all.
FINDING_THRESHOLD = 0.45

#: Ceiling on the purely behavioural part of a score, leaving headroom for the
#: clinical-tier weight so criticality is never lost to saturation.
MAX_BEHAVIOURAL_SCORE = 0.84

#: How suspicious each event type is on its own, before context.
#: These are priors, not verdicts - context can raise or lower the final score.
EVENT_TYPE_WEIGHT: Dict[str, float] = {
    "NETWORK_FLOW": 0.00,
    "HL7_BULK": 0.00,
    "SMB_FLOW": 0.20,
    "BULK_QUERY": 0.25,
    "PORT_SCAN": 0.40,
    "CREDENTIAL_DUMP": 0.50,
    "MALWARE_STAGING": 0.55,
    "DATA_UPLOAD": 0.50,
    "C2_BEACON": 0.60,
    "EXPLOIT_ATTEMPT": 0.65,
}

INDICATOR_FOR_EVENT: Dict[str, str] = {
    "SMB_FLOW": "UNEXPECTED_SMB_TRAFFIC",
    "PORT_SCAN": "PORT_SCAN_SWEEP",
    "CREDENTIAL_DUMP": "CREDENTIAL_DUMPING_ATTEMPT",
    "MALWARE_STAGING": "MALWARE_STAGING_PAYLOAD",
    "EXPLOIT_ATTEMPT": "EXPLOIT_ATTEMPT_SMB",
    "C2_BEACON": "C2_BEACONING_ATTEMPT",
    "DATA_UPLOAD": "BULK_DATA_EGRESS",
    "BULK_QUERY": "SUSPICIOUS_DB_QUERY",
}


@dataclass
class BaselineProfile:
    """What normal looks like for one device."""

    asset_id: str
    allowed_peers: set = field(default_factory=set)
    observed_peers: set = field(default_factory=set)
    byte_samples: List[int] = field(default_factory=list)
    active_hours: set = field(default_factory=set)
    event_count: int = 0

    @property
    def mean_bytes(self) -> float:
        return statistics.fmean(self.byte_samples) if self.byte_samples else 0.0

    @property
    def stdev_bytes(self) -> float:
        if len(self.byte_samples) < 2:
            return 0.0
        return statistics.pstdev(self.byte_samples)

    def volume_zscore(self, byte_count: int) -> float:
        """How many standard deviations from this device's usual volume."""
        if not self.byte_samples:
            return 0.0
        spread = self.stdev_bytes or (self.mean_bytes * 0.25) or 1.0
        return (byte_count - self.mean_bytes) / spread

    def is_known_peer(self, peer: str) -> bool:
        return peer in self.allowed_peers or peer in self.observed_peers

    def is_usual_hour(self, hour: int) -> bool:
        return not self.active_hours or hour in self.active_hours


class Layer2Detector:
    """Behavioural scoring against a learned per-device baseline."""

    def __init__(self, baseline_version: str = "v2.0.0", threshold: float = FINDING_THRESHOLD):
        self.baseline_version = baseline_version
        self.threshold = threshold
        self.baselines: Dict[str, BaselineProfile] = {}
        self.trained_on = 0

    # -- training ----------------------------------------------------------
    def register_baseline(self, asset_context: AssetContext) -> BaselineProfile:
        profile = self.baselines.get(asset_context.asset_id)
        if profile is None:
            profile = BaselineProfile(
                asset_id=asset_context.asset_id,
                allowed_peers=set(asset_context.allowed_peers),
            )
            self.baselines[asset_context.asset_id] = profile
        else:
            profile.allowed_peers |= set(asset_context.allowed_peers)
        return profile

    def learn_from_events(self, events: Iterable) -> int:
        """Train on normal traffic.

        ``events`` are twin events (or anything with ``src``/``dst``/``bytes``/
        ``timestamp``). Only normal traffic should be passed here - training on
        an attack would teach the model that the attack is normal.
        """
        learned = 0
        for event in events:
            src = getattr(event, "src", None)
            dst = getattr(event, "dst", None)
            byte_count = int(getattr(event, "bytes", 0))
            timestamp = getattr(event, "timestamp", None)

            # Record the flow against BOTH endpoints. A device's baseline has to
            # describe traffic in both directions: training only on what a
            # device sends leaves its inbound volumes unlearned, so ordinary
            # received traffic later reads as hundreds of standard deviations
            # from a distribution that was never measured.
            for asset_id, counterpart in ((src, dst), (dst, src)):
                if not asset_id:
                    continue
                profile = self.baselines.get(asset_id)
                if profile is None:
                    profile = BaselineProfile(asset_id=asset_id)
                    self.baselines[asset_id] = profile
                if counterpart:
                    profile.observed_peers.add(counterpart)
                profile.byte_samples.append(byte_count)
                if isinstance(timestamp, datetime):
                    profile.active_hours.add(timestamp.hour)
                profile.event_count += 1
            learned += 1
        self.trained_on += learned
        return learned

    @property
    def is_trained(self) -> bool:
        return self.trained_on > 0

    # -- scoring -----------------------------------------------------------
    def score_observation(
        self,
        *,
        asset_context: AssetContext,
        event_type: str,
        counterpart: str,
        byte_count: int,
        timestamp: Optional[datetime] = None,
    ) -> Tuple[float, List[str], Dict[str, float]]:
        """Return (anomaly_score, indicators, component breakdown).

        ``counterpart`` is the device at the *other* end of the flow, relative
        to the asset being scored. Passing the destination unconditionally asks
        "is this device allowed to talk to itself" whenever the asset under
        assessment is the destination, which flags every inbound flow as an
        unauthorised peer.
        """
        profile = self.register_baseline(asset_context)
        components: Dict[str, float] = {}
        indicators: List[str] = []

        # 1. What kind of activity is this, before any context?
        type_weight = EVENT_TYPE_WEIGHT.get(event_type.upper(), 0.30)
        components["event_type"] = type_weight
        named = INDICATOR_FOR_EVENT.get(event_type.upper())
        if named:
            indicators.append(named)

        # 2. Is the other end a peer this device is supposed to talk to?
        peer_penalty = 0.0
        if counterpart and counterpart != asset_context.asset_id \
                and not profile.is_known_peer(counterpart):
            peer_penalty = 0.25
            indicators.append("UNAUTHORIZED_PEER_COMMUNICATION")
        components["unknown_peer"] = peer_penalty

        # 3. Is the volume unusual for this specific device?
        volume_penalty = 0.0
        zscore = profile.volume_zscore(byte_count)
        if zscore > 3.0:
            volume_penalty = 0.20
            indicators.append("ANOMALOUS_DATA_VOLUME")
        elif zscore > 1.5:
            volume_penalty = 0.08
        components["volume"] = volume_penalty
        components["volume_zscore"] = round(zscore, 2)

        # 4. Off-hours activity, judged per device. A Tier 1 monitor working at
        #    03:00 is normal; a reception desk endpoint doing so is not.
        hours_penalty = 0.0
        if timestamp is not None and not profile.is_usual_hour(timestamp.hour):
            hours_penalty = 0.10
            indicators.append("OFF_HOURS_ACTIVITY")
        components["off_hours"] = hours_penalty

        # 5. Clinical consequence. Identical behaviour against a life-critical
        #    device matters more, because the cost of missing it is a patient.
        tier_weight = {1: 0.15, 2: 0.07, 3: 0.0}.get(int(asset_context.clinical_tier), 0.0)
        components["clinical_tier"] = tier_weight
        if int(asset_context.clinical_tier) == 1 and type_weight >= 0.4:
            indicators.append("CRITICAL_FLOW_INTERRUPTION_RISK")

        # Cap the behavioural part *before* adding clinical weight, so clinical
        # criticality always moves the score. Capping the sum instead lets a
        # severe-but-ordinary attack saturate at the ceiling, after which an
        # exploit against a patient monitor ranks identically to one against a
        # printer - which is exactly the distinction this system exists to make.
        behaviour = min(type_weight + peer_penalty + volume_penalty + hours_penalty,
                        MAX_BEHAVIOURAL_SCORE)
        components["behaviour"] = round(behaviour, 2)
        score = round(min(behaviour + tier_weight, 0.99), 2)
        components["total"] = score

        if not indicators:
            indicators.append("BEHAVIOUR_WITHIN_BASELINE")
        return score, indicators, components

    # -- finding construction ---------------------------------------------
    def analyze_observation(
        self,
        *,
        asset_context: AssetContext,
        event_id: str,
        event_type: str,
        src: str,
        counterpart: str,
        byte_count: int,
        timestamp: Optional[datetime] = None,
        attacker_asset_id: Optional[str] = None,
        behavior_window: str = "5m",
        related_events: Optional[List[str]] = None,
    ) -> Optional[DetectionFinding]:
        """Score one observation; emit a finding only if it clears the threshold."""
        score, indicators, components = self.score_observation(
            asset_context=asset_context,
            event_type=event_type,
            counterpart=counterpart,
            byte_count=byte_count,
            timestamp=timestamp,
        )
        if score < self.threshold:
            return None

        # Identity uncertainty lowers confidence rather than raising aggression.
        confidence = round(asset_context.identity_confidence, 2)
        risk = round(score * asset_context.identity_confidence, 2)

        return DetectionFinding(
            finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
            asset_id=asset_context.asset_id,
            attacker_src=src,
            attacker_asset_id=attacker_asset_id,
            behavior_window=behavior_window,
            anomaly_score=score,
            risk_score=risk,
            indicators=indicators,
            baseline_version=self.baseline_version,
            confidence=confidence,
            related_events=related_events or [event_id],
            recommended_observation_period=60,
            timestamp=timestamp.isoformat() if timestamp else datetime.now().isoformat(),
        )

    def baseline_summary(self) -> Dict[str, Dict[str, float]]:
        return {
            asset_id: {
                "events_seen": profile.event_count,
                "known_peers": len(profile.allowed_peers | profile.observed_peers),
                "mean_bytes": round(profile.mean_bytes, 1),
                "active_hours": len(profile.active_hours),
            }
            for asset_id, profile in sorted(self.baselines.items())
        }
