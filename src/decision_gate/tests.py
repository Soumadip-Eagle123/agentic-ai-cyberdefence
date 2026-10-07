from datetime import datetime, timedelta
import pytest

from decision_gate.models import ResponseProposal
from decision_gate.decision_logic import (
    requires_human_approval,
    process_decision,
    handle_timeout,
)


def _make_proposal(**overrides):
    defaults = dict(
        case_id="CASE-001",
        threat_summary="Lateral movement detected from compromised endpoint",
        affected_assets=["ICU-MON-01"],
        candidate_actions=["BLOCK_SOURCE", "MONITOR_ONLY"],
        clinical_impact="high",
        confidence=0.94,
        reason="Anomalous scanning behavior toward a Tier 1 device",
        approval_level="HUMAN_REQUIRED",
        proposed_action="BLOCK_SOURCE",
        expiry_minutes=10,
        rollback_plan="Remove firewall rule and restore prior routing",
    )
    defaults.update(overrides)
    return ResponseProposal(**defaults)


def test_tier1_action_requires_approval():
    assert requires_human_approval(_make_proposal()) is True


def test_low_impact_auto_action_skips_review():
    p = _make_proposal(clinical_impact="low", approval_level="AUTO")
    assert requires_human_approval(p) is False


def test_approve_produces_decision_record_with_action():
    p = _make_proposal()
    r = process_decision(p, "approve", "dr_iyer", p.action_hash(), reason="Confirmed threat")
    assert r.decision == "approve"
    assert r.approved_action == "BLOCK_SOURCE"


def test_reject_produces_no_approved_action():
    p = _make_proposal()
    r = process_decision(p, "reject", "dr_iyer", p.action_hash(), reason="False positive")
    assert r.approved_action is None


def test_invalid_decision_string_raises():
    p = _make_proposal()
    with pytest.raises(ValueError):
        process_decision(p, "maybe", "dr_iyer", p.action_hash())


def test_expired_proposal_cannot_be_decided():
    p = _make_proposal(expiry_minutes=10)
    p.created_at = datetime.utcnow() - timedelta(minutes=15)
    with pytest.raises(ValueError):
        process_decision(p, "approve", "dr_iyer", p.action_hash())


def test_mismatched_hash_is_rejected():
    p = _make_proposal()
    with pytest.raises(ValueError):
        process_decision(p, "approve", "dr_iyer", "wrong-hash")


def test_timeout_never_silently_disappears():
    r = handle_timeout(_make_proposal())
    assert r.decision == "escalate"
    assert r.reviewer == "system"