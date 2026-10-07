import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from src.schemas.contracts import (
    ApprovalLevel,
    DecisionOutcome,
    DecisionRecord,
    ResponseProposal,
)


class Layer5DecisionGate:
    """Layer 5 Decision Gate (The Human Override Checkpoint).

    Intercepts proposals from Layer 3, evaluates risk boundaries, computes cryptographic
    scope hashes for audit integrity, and captures time-bound SOC analyst approval decisions.
    """

    def __init__(self, default_validity_minutes: int = 15):
        self.default_validity_minutes = default_validity_minutes
        self.pending_proposals: Dict[str, ResponseProposal] = {}

    def compute_scope_hash(self, proposal: ResponseProposal) -> str:
        """Computes a SHA-256 hash of proposal contents to prevent old approvals from being reused."""
        payload = {
            "case_id": proposal.case_id,
            "affected_assets": proposal.affected_assets,
            "actions": [a.model_dump() for a in proposal.candidate_actions],
            "clinical_impact": proposal.clinical_impact,
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def evaluate_proposal(self, proposal: ResponseProposal) -> Optional[DecisionRecord]:
        """Evaluates whether a proposal can proceed automatically or requires human review.

        Returns a DecisionRecord for auto-approved items, or None if held for human approval.
        """
        scope_hash = self.compute_scope_hash(proposal)

        if proposal.approval_level == ApprovalLevel.AUTO_APPROVED:
            now = datetime.now(timezone.utc)
            expiry = now + timedelta(minutes=self.default_validity_minutes)

            return DecisionRecord(
                decision_id=f"DEC-AUTO-{uuid.uuid4().hex[:6].upper()}",
                case_id=proposal.case_id,
                reviewer="SYSTEM_AUTO_POLICY",
                decision=DecisionOutcome.APPROVED,
                scope_hash=scope_hash,
                reason="Pre-approved by automated policy for non-critical assets.",
                timestamp=now.isoformat(),
                expiry=expiry.isoformat(),
                approved_action=proposal,
            )

        # High-risk / Tier 1 actions pause for human review
        self.pending_proposals[proposal.case_id] = proposal
        return None

    def record_human_decision(
        self,
        case_id: str,
        reviewer_id: str,
        decision: DecisionOutcome,
        reason: str,
    ) -> DecisionRecord:
        """Records a manual decision (APPROVED / REJECTED) from a SOC analyst."""
        proposal = self.pending_proposals.get(case_id)
        if not proposal:
            raise ValueError(f"No pending proposal found for case_id: {case_id}")

        scope_hash = self.compute_scope_hash(proposal)
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(minutes=self.default_validity_minutes)

        del self.pending_proposals[case_id]

        return DecisionRecord(
            decision_id=f"DEC-HUMAN-{uuid.uuid4().hex[:6].upper()}",
            case_id=case_id,
            reviewer=reviewer_id,
            decision=decision,
            scope_hash=scope_hash,
            reason=reason,
            timestamp=now.isoformat(),
            expiry=expiry.isoformat(),
            approved_action=proposal if decision == DecisionOutcome.APPROVED else None,
        )