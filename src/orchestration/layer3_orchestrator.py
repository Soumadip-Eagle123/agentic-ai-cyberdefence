import uuid
from datetime import datetime, timedelta, timezone
from typing import List
from schemas.contracts import (
    AssetContext,
    DetectionFinding,
    ResponseProposal,
    ClinicalTier,
    SystemSafetyMode,
    ApprovalLevel,
    ActionDetail,
    RollbackPlan,
)


class ZoneAnalystAgent:
    """Analyzes threat severity and zone impact."""
    def analyze(self, finding: DetectionFinding, asset: AssetContext) -> str:
        return f"Detected anomalous behavior ({', '.join(finding.indicators)}) in zone '{asset.owner_zone}' for asset {asset.asset_id}."


class ClinicalSafetyAgent:
    """Evaluates impact on patient safety and determines if human approval is required."""
    def evaluate_safety(self, asset: AssetContext, risk_score: float) -> tuple[str, ApprovalLevel]:
        if asset.clinical_tier == ClinicalTier.TIER_1:
            impact = f"CRITICAL: System is Tier 1 ({asset.asset_type}). Interventions must preserve critical flows."
            approval = ApprovalLevel.REQUIRES_HUMAN_APPROVAL
        elif asset.clinical_tier == ClinicalTier.TIER_2:
            impact = f"MODERATE: System is Tier 2. Surgical blocking preferred over full isolation."
            approval = ApprovalLevel.REQUIRES_HUMAN_APPROVAL if risk_score > 0.7 else ApprovalLevel.AUTO_APPROVED
        else:
            impact = "LOW: Non-clinical Tier 3 asset. Rapid isolation allowed."
            approval = ApprovalLevel.AUTO_APPROVED
        return impact, approval


class ResponsePlannerAgent:
    """Generates targeted action and non-negotiable rollback plan."""
    def plan_response(self, asset: AssetContext, finding: DetectionFinding) -> tuple[List[ActionDetail], RollbackPlan]:
        if asset.clinical_tier == ClinicalTier.TIER_1:
            # Surgical blocking for Tier 1
            actions = [
                ActionDetail(
                    action_type="SURGICAL_BLOCK",
                    target_asset=asset.asset_id,
                    blocked_flows=[{"protocol": "TCP", "port": 445, "direction": "INBOUND"}],
                    preserved_flows=[{"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"}]
                )
            ]
        else:
            # Coarse isolation for Tier 3
            actions = [
                ActionDetail(
                    action_type="COARSE_ISOLATION",
                    target_asset=asset.asset_id
                )
            ]

        rollback = RollbackPlan(
            rollback_token_spec=f"RB-{asset.asset_id}-{uuid.uuid4().hex[:6]}",
            steps=[f"Restore firewall rule table for {asset.asset_id}", "Verify telemetry heartbeat"],
            auto_rollback_seconds=300
        )
        return actions, rollback


class Layer3Orchestrator:
    """Coordinates specialized agents to generate an explainable response proposal."""
    def __init__(self):
        self.zone_analyst = ZoneAnalystAgent()
        self.safety_agent = ClinicalSafetyAgent()
        self.planner = ResponsePlannerAgent()

    def process(
        self,
        finding: DetectionFinding,
        asset: AssetContext,
        safety_mode: SystemSafetyMode = SystemSafetyMode.NORMAL
    ) -> ResponseProposal:
        case_id = f"CASE-{uuid.uuid4().hex[:8]}"
        threat_summary = self.zone_analyst.analyze(finding, asset)
        clinical_impact, approval_level = self.safety_agent.evaluate_safety(asset, finding.risk_score)
        actions, rollback_plan = self.planner.plan_response(asset, finding)

        # Synthesize combined confidence score
        combined_confidence = round(finding.confidence * asset.identity_confidence, 2)
        
        expiry_dt = datetime.now(timezone.utc) + timedelta(minutes=15)
        
        reason = (
            f"Finding {finding.finding_id} passed risk threshold ({finding.risk_score}). "
            f"Safety mode: {safety_mode.value}. Policy applied based on Tier {asset.clinical_tier.value} rules."
        )

        return ResponseProposal(
            case_id=case_id,
            threat_summary=threat_summary,
            affected_assets=[asset.asset_id],
            candidate_actions=actions,
            clinical_impact=clinical_impact,
            confidence=combined_confidence,
            reason=reason,
            approval_level=approval_level,
            expiry_time=expiry_dt.isoformat(),
            rollback_plan=rollback_plan
        )