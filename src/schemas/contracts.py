from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ClinicalTier(int, Enum):
    TIER_1 = 1 
    TIER_2 = 2  
    TIER_3 = 3 


class SystemSafetyMode(str, Enum):
    NORMAL = "NORMAL"
    HEIGHTENED_MONITORING = "HEIGHTENED_MONITORING"
    EMERGENCY_CONTAINMENT = "EMERGENCY_CONTAINMENT"


class ApprovalLevel(str, Enum):
    AUTO_APPROVED = "AUTO_APPROVED"
    REQUIRES_HUMAN_APPROVAL = "REQUIRES_HUMAN_APPROVAL"


class AssetContext(BaseModel):
    asset_id: str
    asset_type: str
    owner_zone: str
    vendor: str
    software_version: str
    clinical_tier: ClinicalTier
    known_constraints: List[str] = Field(default_factory=list)
    allowed_peers: List[str] = Field(default_factory=list)
    normal_services: List[str] = Field(default_factory=list)
    fallback_mode: Optional[str] = None
    identity_confidence: float

class DetectionFinding(BaseModel):
    finding_id: str
    asset_id: str
    behavior_window: str
    anomaly_score: float
    risk_score: float
    indicators: List[str]
    baseline_version: str
    confidence: float
    related_events: List[str]
    recommended_observation_period: int  

class ActionDetail(BaseModel):
    action_type: str  
    target_asset: str
    blocked_flows: List[Dict[str, Any]] = Field(default_factory=list)
    preserved_flows: List[Dict[str, Any]] = Field(default_factory=list)


class RollbackPlan(BaseModel):
    rollback_token_spec: str
    steps: List[str]
    auto_rollback_seconds: int


class ResponseProposal(BaseModel):
    case_id: str
    threat_summary: str
    affected_assets: List[str]
    candidate_actions: List[ActionDetail]
    clinical_impact: str
    confidence: float
    reason: str
    approval_level: ApprovalLevel
    expiry_time: str
    rollback_plan: RollbackPlan