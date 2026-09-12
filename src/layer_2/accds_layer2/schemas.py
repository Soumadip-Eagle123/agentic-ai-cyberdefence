from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
import json

CLINICAL_TIERS = {1, 2, 3}


@dataclass(frozen=True)
class EnrichedEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    subject: str
    src: str
    dst: str
    protocol: str
    bytes: int
    zone: str
    scenario_id: str
    raw_reference: str
    asset_id: str
    asset_type: str
    owner_zone: str
    vendor: str
    software_version: str
    clinical_tier: int
    known_constraints: List[str] = field(default_factory=list)
    allowed_peers: List[str] = field(default_factory=list)
    normal_services: List[str] = field(default_factory=list)
    fallback_mode: str = "unknown"
    identity_confidence: float = 1.0
    label: str = "normal"
    attack_stage: Optional[str] = None

    def validate(self) -> None:
        if not self.event_id or not self.asset_id:
            raise ValueError("event_id and asset_id are required")
        if self.bytes < 0:
            raise ValueError("bytes must be non-negative")
        if self.clinical_tier not in CLINICAL_TIERS:
            raise ValueError("clinical_tier must be 1, 2, or 3")
        if not 0.0 <= self.identity_confidence <= 1.0:
            raise ValueError("identity_confidence must be between 0 and 1")
        if not self.timestamp.tzinfo:
            raise ValueError("timestamp must be timezone-aware")

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "EnrichedEvent":
        data = dict(value)
        data["timestamp"] = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
        event = cls(**data)
        event.validate()
        return event


@dataclass
class Finding:
    finding_id: str
    asset_id: str
    behavior_window: Dict[str, str]
    anomaly_score: float
    risk_score: float
    indicators: List[Dict[str, Any]]
    baseline_version: str
    confidence: float
    related_events: List[str]
    recommended_observation_period: int
    clinical_tier: int
    known_constraints: List[str]
    affected_zone: str
    suspected_attack_stage: Optional[str]
    identity_confidence: float
    evidence: Dict[str, Any]
    label: str = "unknown"

    def validate(self) -> None:
        required = [self.finding_id, self.asset_id, self.baseline_version]
        if any(not value for value in required):
            raise ValueError("finding_id, asset_id, and baseline_version are required")
        if not 0.0 <= self.anomaly_score <= 1.0:
            raise ValueError("anomaly_score must be between 0 and 1")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not self.related_events:
            raise ValueError("related_events cannot be empty")
        if self.clinical_tier not in CLINICAL_TIERS:
            raise ValueError("clinical_tier must be 1, 2, or 3")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Baseline:
    version: str
    created_at: str
    feature_names: List[str]
    asset_stats: Dict[str, Dict[str, Dict[str, float]]]
    peer_stats: Dict[str, Dict[str, Dict[str, float]]]
    thresholds: Dict[str, float]
    weights: Dict[str, float]
    source_fingerprint: str
    config_hash: str

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(asdict(self), handle, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> "Baseline":
        with open(path, encoding="utf-8") as handle:
            return cls(**json.load(handle))
