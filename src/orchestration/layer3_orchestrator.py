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


#: Clinical services mapped to the flow that carries them. Containment must let
#: these through, or a "surgical" block quietly becomes an outage.
SERVICE_FLOWS: Dict[str, Dict] = {
    "HL7_Vitals": {"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"},
    "clinical-data": {"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"},
    "monitoring": {"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"},
    "control": {"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"},
    "DICOM_PACS": {"protocol": "DICOM", "port": 104, "direction": "BIDIRECTIONAL"},
    "imaging-store": {"protocol": "DICOM", "port": 104, "direction": "BIDIRECTIONAL"},
    "lab-results": {"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"},
    "database": {"protocol": "TCP", "port": 5432, "direction": "BIDIRECTIONAL"},
}


def _clinical_flows_for(asset: AssetContext) -> List[Dict]:
    """The flows this specific device needs to keep doing its clinical job."""
    flows: List[Dict] = []
    seen = set()
    for service in asset.normal_services:
        flow = SERVICE_FLOWS.get(service)
        if flow and (key := (flow["protocol"], flow["port"])) not in seen:
            seen.add(key)
            flows.append(dict(flow))
    if not flows:
        # Nothing recognised: keep a management path open so the device can
        # still be reached and rolled back.
        flows.append({"protocol": "TCP", "port": 443, "direction": "OUTBOUND",
                      "purpose": "management"})
    return flows


class ThreatCorrelationAgent:
    """Correlates multiple findings into unified cases based on shared attackers, 
    overlapping events, or lateral movement chains.
    """
    def __init__(self, time_window_minutes: int = 15):
        self.time_window_minutes = time_window_minutes
        # Store active cases: case_id -> dict of case info
        self.active_cases: Dict[str, Dict] = {}

    def _event_time(self, finding: DetectionFinding) -> datetime:
        """When the activity happened, not when we happened to process it.

        The window used to be measured against ``datetime.now()``. Replaying
        historical logs processes every stage within milliseconds, so the window
        never expired and correlation appeared to work by accident; a multi-day
        campaign would have collapsed into one case and a slow run would have
        split one campaign into several. Event time is the only stable basis.
        """
        try:
            return datetime.fromisoformat(str(finding.timestamp).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    def correlate(self, finding: DetectionFinding, asset: AssetContext) -> str:
        """Finds an existing active case_id or creates a new one."""
        now = self._event_time(finding)

        # 1. Check active cases for correlation match
        for case_id, case in list(self.active_cases.items()):
            # Check window expiration, in event time
            case_time = datetime.fromisoformat(case["last_updated"])
            if abs((now - case_time).total_seconds()) > self.time_window_minutes * 60:
                continue  # Expired window

            # Match Condition 1: Same attacker source
            if finding.attacker_src and finding.attacker_src in case["attacker_sources"]:
                self._add_to_case(case_id, finding, asset)
                return case_id

            # Match Condition 2: Overlapping related events
            if set(finding.related_events) & case["related_events"]:
                self._add_to_case(case_id, finding, asset)
                return case_id

            # Match Condition 3: Lateral movement chain.
            #
            # "The machine attacking us is one we already watched get
            # compromised." This compares asset ids on both sides. It used to
            # compare `finding.attacker_src` - a raw IP or hostname like
            # "10.0.2.10" - against a set of asset ids like "lab-server", which
            # are different namespaces and can never match. The chain rule was
            # therefore dead, and multi-stage campaigns split into unrelated
            # cases: the reviewer saw an isolated ICU incident rather than the
            # climax of a campaign that had already crossed three departments.
            if finding.asset_id in case["affected_assets"]:
                self._add_to_case(case_id, finding, asset)
                return case_id

            if finding.attacker_asset_id and finding.attacker_asset_id in case["affected_assets"]:
                self._add_to_case(case_id, finding, asset)
                return case_id

            # Fallback for findings whose attacker was never resolved: compare
            # the raw address against addresses seen in the case.
            if finding.attacker_src and finding.attacker_src in case["affected_addresses"]:
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
            # Network identities of the assets in this case, so a later finding
            # whose attacker was never resolved can still be matched by address.
            "affected_addresses": self._addresses_for(finding.asset_id),
            "asset_contexts": {finding.asset_id: asset},
            "findings": [finding],
            "related_events": set(finding.related_events),
            "max_risk_score": finding.risk_score,
            "has_tier1": asset.clinical_tier == ClinicalTier.TIER_1,
            # The ordered hops, so a reviewer can read the campaign as a path.
            "chain": [self._chain_hop(finding, asset)],
        }
        return new_case_id

    @staticmethod
    def _addresses_for(asset_id: str) -> set:
        """Every identifier an asset answers to, for address-level matching."""
        try:
            from digital_twin import hospital

            device = hospital.by_asset_id(asset_id)
            if device:
                return set(device.addresses)
        except ImportError:
            pass
        return {asset_id}

    @staticmethod
    def _chain_hop(finding: DetectionFinding, asset: AssetContext) -> Dict:
        return {
            "finding_id": finding.finding_id,
            "attacker": finding.attacker_asset_id or finding.attacker_src,
            "victim": finding.asset_id,
            "victim_tier": asset.clinical_tier.value,
            "indicators": list(finding.indicators),
            "timestamp": str(finding.timestamp),
        }

    def _add_to_case(self, case_id: str, finding: DetectionFinding, asset: AssetContext):
        case = self.active_cases[case_id]
        case["last_updated"] = self._event_time(finding).isoformat()
        if finding.attacker_src:
            case["attacker_sources"].add(finding.attacker_src)
        case["affected_assets"].add(finding.asset_id)
        case["affected_addresses"] |= self._addresses_for(finding.asset_id)
        case["asset_contexts"][finding.asset_id] = asset
        case["findings"].append(finding)
        case["related_events"].update(finding.related_events)
        case["max_risk_score"] = max(case["max_risk_score"], finding.risk_score)
        case["chain"].append(self._chain_hop(finding, asset))
        if asset.clinical_tier == ClinicalTier.TIER_1:
            case["has_tier1"] = True


class ZoneAnalystAgent:
    """Analyzes threat severity and blast radius across correlated assets."""
    def analyze(self, case_data: Dict) -> str:
        asset_list = ", ".join(case_data["affected_assets"])
        finding_count = len(case_data["findings"])
        attackers = ", ".join(case_data["attacker_sources"]) or "Unknown"
        
        if finding_count > 1:
            chain = case_data.get("chain", [])
            path = " -> ".join(
                [str(chain[0]["attacker"])] + [str(hop["victim"]) for hop in chain]
            ) if chain else asset_list
            tier1 = sorted({
                hop["victim"] for hop in chain if hop.get("victim_tier") == 1
            })
            escalation = (
                f" Reached Tier 1 life-critical asset(s): [{', '.join(tier1)}]."
                if tier1 else ""
            )
            return (
                f"LATERAL CAMPAIGN DETECTED: Correlated {finding_count} anomalies across assets [{asset_list}]. "
                f"Attacker origin(s): [{attackers}]. Attack path: {path}.{escalation}"
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
                        # Preserve the flows THIS device actually needs. Blanket
                        # HL7 preservation would cut DICOM imaging on a PACS
                        # server while carefully protecting a protocol it does
                        # not speak - the containment would look surgical and
                        # still take a clinical service offline.
                        preserved_flows=_clinical_flows_for(asset),
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
            correlated_finding_ids=finding_ids,
            attack_chain=list(case_data["chain"]),
        )