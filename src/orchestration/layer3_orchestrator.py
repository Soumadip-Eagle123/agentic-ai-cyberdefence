# src/orchestration/layer3_orchestrator.py
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Tuple, Optional

from src.schemas.contracts import (
    AssetContext,
    DetectionFinding,
    ResponseProposal,
    ClinicalTier,
    SystemSafetyMode,
    ApprovalLevel,
    ActionDetail,
    RollbackPlan,
)


class ThreatCorrelationAgent:
    """Correlates multiple findings into unified cases based on shared attackers, 
    overlapping events, or lateral movement chains.
    """
    def __init__(self, time_window_minutes: int = 15):
        self.time_window_minutes = time_window_minutes
        # Store active cases: case_id -> dict of case info
        self.active_cases: Dict[str, Dict] = {}

    def correlate(self, finding: DetectionFinding, asset: AssetContext) -> str:
        """Finds an existing active case_id or creates a new one."""
        now = datetime.now(timezone.utc)

        # 1. Check active cases for correlation match
        for case_id, case in list(self.active_cases.items()):
            # Check window expiration
            case_time = datetime.fromisoformat(case["last_updated"])
            if (now - case_time) > timedelta(minutes=self.time_window_minutes):
                continue  # Expired window

            # Match Condition 1: Same attacker source
            if finding.attacker_src and finding.attacker_src in case["attacker_sources"]:
                self._add_to_case(case_id, finding, asset)
                return case_id

            # Match Condition 2: Overlapping related events
            if set(finding.related_events) & case["related_events"]:
                self._add_to_case(case_id, finding, asset)
                return case_id

            # Match Condition 3: Lateral movement chain
            if finding.asset_id in case["affected_assets"] or finding.attacker_src in case["affected_assets"]:
                self._add_to_case(case_id, finding, asset)
                return case_id

        # 2. If no match found, create a new correlated case
        new_case_id = f"CASE-CORR-{uuid.uuid4().hex[:6].upper()}"
        self.active_cases[new_case_id] = {
            "case_id": new_case_id,
            "created_at": now.isoformat(),
            "last_updated": now.isoformat(),
            "attacker_sources": {finding.attacker_src} if finding.attacker_src else set(),
            "affected_assets": {finding.asset_id},
            "asset_contexts": {finding.asset_id: asset},
            "findings": [finding],
            "related_events": set(finding.related_events),
            "max_risk_score": finding.risk_score,
            "has_tier1": asset.clinical_tier == ClinicalTier.TIER_1,
        }
        return new_case_id

    def _add_to_case(self, case_id: str, finding: DetectionFinding, asset: AssetContext):
        case = self.active_cases[case_id]
        case["last_updated"] = datetime.now(timezone.utc).isoformat()
        if finding.attacker_src:
            case["attacker_sources"].add(finding.attacker_src)
        case["affected_assets"].add(finding.asset_id)
        case["asset_contexts"][finding.asset_id] = asset
        case["findings"].append(finding)
        case["related_events"].update(finding.related_events)
        case["max_risk_score"] = max(case["max_risk_score"], finding.risk_score)
        if asset.clinical_tier == ClinicalTier.TIER_1:
            case["has_tier1"] = True


class ZoneAnalystAgent:
    """Analyzes threat severity and blast radius across correlated assets."""
    def analyze(self, case_data: Dict) -> str:
        asset_list = ", ".join(case_data["affected_assets"])
        finding_count = len(case_data["findings"])
        attackers = ", ".join(case_data["attacker_sources"]) or "Unknown"
        
        if finding_count > 1:
            return (
                f"LATERAL CAMPAIGN DETECTED: Correlated {finding_count} anomalies across assets [{asset_list}]. "
                f"Attacker origin(s): [{attackers}]. Potential multi-stage attack chain in progress."
            )
        else:
            finding = case_data["findings"][0]
            asset_id = finding.asset_id
            return f"Detected anomalous behavior ({', '.join(finding.indicators)}) targeting asset {asset_id}."


class ClinicalSafetyAgent:
    """Evaluates safety across all affected assets in a case."""
    def evaluate_case_safety(self, case_data: Dict) -> Tuple[str, ApprovalLevel]:
        has_tier1 = False
        has_tier2 = False

        for asset in case_data["asset_contexts"].values():
            if asset.clinical_tier == ClinicalTier.TIER_1:
                has_tier1 = True
            elif asset.clinical_tier == ClinicalTier.TIER_2:
                has_tier2 = True

        if has_tier1:
            impact = (
                f"CRITICAL: Campaign involves Tier 1 Life-Critical asset(s). "
                f"Surgical containment required to preserve vital data feeds."
            )
            approval = ApprovalLevel.REQUIRES_HUMAN_APPROVAL
        elif has_tier2:
            impact = f"MODERATE: Campaign involves Tier 2 Workflow-Critical assets. Surgical blocking preferred."
            approval = ApprovalLevel.REQUIRES_HUMAN_APPROVAL if case_data["max_risk_score"] > 0.7 else ApprovalLevel.AUTO_APPROVED
        else:
            impact = "LOW: All affected assets are non-clinical Tier 3. Rapid isolation allowed."
            approval = ApprovalLevel.AUTO_APPROVED

        return impact, approval


class ResponsePlannerAgent:
    """Generates consolidated actions and rollback plan for all assets in the campaign."""
    def plan_case_response(self, case_data: Dict) -> Tuple[List[ActionDetail], RollbackPlan]:
        actions = []
        rollback_steps = []

        for asset_id, asset in case_data["asset_contexts"].items():
            if asset.clinical_tier in (ClinicalTier.TIER_1, ClinicalTier.TIER_2):
                actions.append(
                    ActionDetail(
                        action_type="SURGICAL_BLOCK",
                        target_asset=asset_id,
                        blocked_flows=[{"protocol": "TCP", "port": 445, "direction": "INBOUND"}],
                        preserved_flows=[{"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"}]
                    )
                )
                rollback_steps.append(f"Restore firewall table for Tier {asset.clinical_tier.value} asset '{asset_id}'")
            else:
                actions.append(
                    ActionDetail(
                        action_type="COARSE_ISOLATION",
                        target_asset=asset_id
                    )
                )
                rollback_steps.append(f"Reconnect isolated endpoint '{asset_id}'")

        rollback_steps.append("Verify telemetry heartbeat across all restored hosts")

        rollback = RollbackPlan(
            rollback_token_spec=f"RB-CAMPAIGN-{uuid.uuid4().hex[:6].upper()}",
            steps=rollback_steps,
            auto_rollback_seconds=300
        )
        return actions, rollback


class Layer3Orchestrator:
    """Stateful Layer 3 Orchestrator with Multi-Finding Correlation Engine."""
    def __init__(self):
        self.correlation_agent = ThreatCorrelationAgent(time_window_minutes=15)
        self.zone_analyst = ZoneAnalystAgent()
        self.safety_agent = ClinicalSafetyAgent()
        self.planner = ResponsePlannerAgent()

    def process(
        self,
        finding: DetectionFinding,
        asset: AssetContext,
        safety_mode: SystemSafetyMode = SystemSafetyMode.NORMAL
    ) -> ResponseProposal:
        # 1. Correlate finding into a case
        case_id = self.correlation_agent.correlate(finding, asset)
        case_data = self.correlation_agent.active_cases[case_id]

        # 2. Analyze threat across whole case
        threat_summary = self.zone_analyst.analyze(case_data)
        clinical_impact, approval_level = self.safety_agent.evaluate_case_safety(case_data)
        actions, rollback_plan = self.planner.plan_response_case(case_data) if hasattr(self.planner, 'plan_response_case') else self.planner.plan_case_response(case_data)

        # 3. Calculate combined metrics
        finding_ids = [f.finding_id for f in case_data["findings"]]
        avg_confidence = round(
            sum(f.confidence for f in case_data["findings"]) / len(case_data["findings"]), 2
        )

        expiry_dt = datetime.now(timezone.utc) + timedelta(minutes=15)

        reason = (
            f"Case {case_id} contains {len(finding_ids)} correlated finding(s). "
            f"Max Risk Score: {case_data['max_risk_score']}. Safety mode: {safety_mode.value}."
        )

        return ResponseProposal(
            case_id=case_id,
            threat_summary=threat_summary,
            affected_assets=list(case_data["affected_assets"]),
            candidate_actions=actions,
            clinical_impact=clinical_impact,
            confidence=avg_confidence,
            reason=reason,
            approval_level=approval_level,
            expiry_time=expiry_dt.isoformat(),
            rollback_plan=rollback_plan,
            correlated_finding_ids=finding_ids
        )