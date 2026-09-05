"""
Core Layer 5 decision logic.
"""

import uuid
from typing import Optional

from .models import ResponseProposal, DecisionRecord

VALID_DECISIONS = {"approve", "reject", "modify", "escalate"}
HIGH_IMPACT = {"high", "critical"}


def requires_human_approval(proposal: ResponseProposal) -> bool:
    if proposal.approval_level in ("HUMAN_REQUIRED", "ESCALATE"):
        return True
    if proposal.clinical_impact.lower() in HIGH_IMPACT:
        return True
    return False


def process_decision(
    proposal: ResponseProposal,
    decision: str,
    reviewer: str,
    submitted_hash: str,
    reason: str = "",
) -> DecisionRecord:
    decision = decision.lower()
    if decision not in VALID_DECISIONS:
        raise ValueError(f"Invalid decision '{decision}', must be one of {VALID_DECISIONS}")

    if proposal.is_expired():
        raise ValueError(f"Proposal {proposal.case_id} expired — cannot record a decision.")

    if submitted_hash != proposal.action_hash():
        raise ValueError("Action hash mismatch — the proposal changed since this decision was prepared.")

    return DecisionRecord(
        decision_id=str(uuid.uuid4()),
        case_id=proposal.case_id,
        reviewer=reviewer,
        decision=decision,
        scope_hash=submitted_hash,
        reason=reason,
        approved_action=proposal.proposed_action if decision == "approve" else None,
    )


def handle_timeout(proposal: ResponseProposal, reviewer: str = "system") -> DecisionRecord:
    return DecisionRecord(
        decision_id=str(uuid.uuid4()),
        case_id=proposal.case_id,
        reviewer=reviewer,
        decision="escalate",
        scope_hash=proposal.action_hash(),
        reason="Timed out with no reviewer decision — auto-escalated.",
        approved_action=None,
    )