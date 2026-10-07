import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from src.schemas.contracts import (
    ResponseProposal,
    EnforcementResult,
    EnforcementStatus,
    ApprovalLevel,
)


class ActiveRule:
    """Tracks an enforced rule state in memory."""

    def __init__(self, action_id: str, rollback_token: str, target_asset: str, details: dict):
        self.action_id = action_id
        self.rollback_token = rollback_token
        self.target_asset = target_asset
        self.details = details
        self.applied_at = datetime.now(timezone.utc).isoformat()


class Layer4Executor:
    """Layer 4 Containment & Enforcement Engine.
    
    Translates approved ResponseProposals into targeted network controls (coarse or surgical)
    and manages active rollback tokens for automated or manual rule reversal.
    """

    def __init__(self):
        self.active_rules: Dict[str, ActiveRule] = {}

    def execute_proposal(
        self,
        proposal: ResponseProposal,
        force_execution: bool = False,
    ) -> EnforcementResult:
        """Executes an approved response proposal.
        
        If an action requires human approval and has not been approved via Layer 5,
        execution will fail unless force_execution is set.
        """
        # Safety Check: Verify approval level
        if proposal.approval_level == ApprovalLevel.REQUIRES_HUMAN_APPROVAL and not force_execution:
            return EnforcementResult(
                action_id=f"ACT-REJECTED-{uuid.uuid4().hex[:6]}",
                case_id=proposal.case_id,
                target_asset=proposal.affected_assets[0] if proposal.affected_assets else "UNKNOWN",
                status=EnforcementStatus.FAILED,
                applied_controls=[],
                blocked_flows=[],
                preserved_flows=[],
                start_time=datetime.now(timezone.utc).isoformat(),
                expiry_time=proposal.expiry_time,
                verification="FAILED: Action requires human approval (Layer 5 Decision Gate).",
                rollback_token="NONE",
            )

        action_id = f"ACT-{uuid.uuid4().hex[:8].upper()}"
        target_asset = proposal.affected_assets[0] if proposal.affected_assets else "UNKNOWN"
        rollback_token = proposal.rollback_plan.rollback_token_spec

        all_blocked_flows = []
        all_preserved_flows = []
        applied_controls = []

        # Process actions inside proposal
        for action in proposal.candidate_actions:
            applied_controls.append({"type": action.action_type, "target": action.target_asset})
            all_blocked_flows.extend(action.blocked_flows)
            all_preserved_flows.extend(action.preserved_flows)

        # Store in active rules registry
        rule_entry = ActiveRule(
            action_id=action_id,
            rollback_token=rollback_token,
            target_asset=target_asset,
            details={
                "blocked": all_blocked_flows,
                "preserved": all_preserved_flows,
                "case_id": proposal.case_id,
            },
        )
        self.active_rules[rollback_token] = rule_entry

        verification_msg = (
            f"SUCCESS: Applied {len(applied_controls)} control(s) on {target_asset}. "
            f"Blocked {len(all_blocked_flows)} flow pattern(s); preserved {len(all_preserved_flows)} clinical path(s)."
        )

        return EnforcementResult(
            action_id=action_id,
            case_id=proposal.case_id,
            target_asset=target_asset,
            status=EnforcementStatus.APPLIED,
            applied_controls=applied_controls,
            blocked_flows=all_blocked_flows,
            preserved_flows=all_preserved_flows,
            start_time=datetime.now(timezone.utc).isoformat(),
            expiry_time=proposal.expiry_time,
            verification=verification_msg,
            rollback_token=rollback_token,
        )

    def rollback_rule(self, rollback_token: str) -> bool:
        """Reverts an active firewall rule using its rollback token."""
        if rollback_token in self.active_rules:
            del self.active_rules[rollback_token]
            return True
        return False