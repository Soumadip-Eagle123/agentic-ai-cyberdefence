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
    attacker_src: Optional[str] = None
    behavior_window: str
    anomaly_score: float
    risk_score: float
    indicators: List[str]
    baseline_version: str
    confidence: float
    related_events: List[str]
    recommended_observation_period: int
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

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
    correlated_finding_ids: List[str] = Field(default_factory=list)

# ---------------------------------------------------------------------------
# Layer 6 handoff - "All layers -> Layer 6" audit event
#
# Every layer emits one of these for each meaningful step it takes. This is the
# pydantic mirror of compliance/contracts.py::AuditEvent; both sides share one
# JSON wire format, so a record produced here can be appended to the Layer 6
# tamper-evident chain unchanged.
# ---------------------------------------------------------------------------
AUDIT_CONTRACT_VERSION = "accds-audit-v1"


class RecordClass(str, Enum):
    """Reports must keep these four apart and never blur them into one narrative."""
    OBSERVED_FACT = "observed_fact"
    MODEL_INFERENCE = "model_inference"
    HUMAN_DECISION = "human_decision"
    ACTION_TAKEN = "action_taken"


class AuditOutcome(str, Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    EXPIRED = "expired"
    ROLLED_BACK = "rolled_back"
    DEGRADED = "degraded"
    ERROR = "error"


class AuditEvent(BaseModel):
    """One immutable entry in the ACCDS chain of custody.

    None of actor, timestamp, input_reference, output_reference or outcome may be
    empty; the roadmap marks them as must-never-be-omitted for this handoff.
    """
    audit_id: str
    timestamp: datetime
    layer: int = Field(ge=0, le=6)
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    outcome: AuditOutcome
    record_class: RecordClass
    input_reference: str = Field(min_length=1)
    output_reference: str = Field(min_length=1)
    case_id: Optional[str] = None
    scenario_id: Optional[str] = None
    asset_id: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    contract_version: str = AUDIT_CONTRACT_VERSION

class EnforcementStatus(str, Enum):
    APPLIED = "APPLIED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class EnforcementResult(BaseModel):
    action_id: str
    case_id: str
    target_asset: str
    status: EnforcementStatus
    applied_controls: List[Dict[str, Any]] = Field(default_factory=list)
    blocked_flows: List[Dict[str, Any]] = Field(default_factory=list)
    preserved_flows: List[Dict[str, Any]] = Field(default_factory=list)
    start_time: str
    expiry_time: str
    verification: str
    rollback_token: str

# Add to src/schemas/contracts.py

class DecisionOutcome(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class DecisionRecord(BaseModel):
    decision_id: str
    case_id: str
    reviewer: str
    decision: DecisionOutcome
    scope_hash: str
    reason: str
    timestamp: str
    expiry: str
    approved_action: Optional[ResponseProposal] = None

# Add to src/schemas/contracts.py

class AuditEvent(BaseModel):
    audit_id: str
    timestamp: str
    layer_source: str
    actor: str
    event_type: str
    summary: str
    payload_hash: str
    redacted_payload: Dict[str, Any]


class IncidentReport(BaseModel):
    report_id: str
    generated_at: str
    case_id: str
    target_asset: str
    clinical_tier: int
    observed_facts: List[str]
    model_inferences: List[str]
    human_decisions: List[str]
    actions_taken: List[str]
    audit_chain: List[str]

class ObservationEvent(BaseModel):
    event_id: str
    timestamp: str
    source: str
    event_type: str
    subject: str
    src: str
    dst: str
    protocol: str
    bytes: int
    zone: str
    scenario_id: str
    raw_reference: str
