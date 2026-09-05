"""
Data models for Layer 5 — Decision Gate.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional
import hashlib
import json


@dataclass
class ResponseProposal:
    case_id: str
    threat_summary: str
    affected_assets: List[str]
    candidate_actions: List[str]
    clinical_impact: str
    confidence: float
    reason: str
    approval_level: str
    proposed_action: str
    expiry_minutes: int
    rollback_plan: str
    created_at: datetime = field(default_factory=datetime.utcnow)

    def expiry_time(self) -> datetime:
        return self.created_at + timedelta(minutes=self.expiry_minutes)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.utcnow()
        return now >= self.expiry_time()

    def action_hash(self) -> str:
        payload = json.dumps(
            {
                "case_id": self.case_id,
                "proposed_action": self.proposed_action,
                "affected_assets": sorted(self.affected_assets),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class DecisionRecord:
    decision_id: str
    case_id: str
    reviewer: str
    decision: str
    scope_hash: str
    reason: str
    approved_action: Optional[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)