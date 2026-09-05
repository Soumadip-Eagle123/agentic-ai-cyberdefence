"""Stand-in records for Layers 3, 4 and 5 so Layer 6 can be built and demonstrated now.

Every dict here mirrors the field names already agreed elsewhere in the repo:
the proposal matches ``ResponseProposal`` in ``src/schemas/contracts.py``, and the
decision and enforcement records match the roadmap's Layer 5 and Layer 4 handoffs.
Swapping in the real layers should be a change of import, not of shape.

NOTHING in this module is a security control. It fabricates plausible upstream
records purely so the audit, redaction and reporting path has something to carry.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple

STUB_MARKER = "placeholder-until-layer-implemented"


def _scope_hash(action: Dict[str, Any]) -> str:
    """Approval is bound to a specific action, so an old approval cannot be reused."""
    material = f"{action['action_type']}|{action['target_asset']}|{action['blocked_flows']}"
    return sha256(material.encode("utf-8")).hexdigest()[:16]


def build_proposal(
    finding: Dict[str, Any],
    asset_context: Dict[str, Any],
    safety_mode: str = "NORMAL",
) -> Dict[str, Any]:
    """Layer 3 stand-in: a response proposal derived from a real Layer 2 finding."""
    tier = int(asset_context.get("clinical_tier", 3))
    asset_id = finding["asset_id"]
    generated_at = datetime.now(timezone.utc)

    if tier == 1:
        action = {
            "action_type": "SURGICAL_BLOCK",
            "target_asset": asset_id,
            "blocked_flows": [{"protocol": "TCP", "port": 445, "direction": "INBOUND"}],
            "preserved_flows": [{"protocol": "HL7", "port": 2575, "direction": "BIDIRECTIONAL"}],
        }
        approval = "REQUIRES_HUMAN_APPROVAL"
        impact = f"CRITICAL: Tier 1 {asset_context.get('asset_type')}. Clinical flows must be preserved."
    elif tier == 2:
        action = {
            "action_type": "SCOPED_BLOCK",
            "target_asset": asset_id,
            "blocked_flows": [{"protocol": "TCP", "port": 445, "direction": "OUTBOUND"}],
            "preserved_flows": [{"protocol": "TCP", "port": 443, "direction": "OUTBOUND"}],
        }
        approval = "REQUIRES_HUMAN_APPROVAL" if finding["risk_score"] > 0.7 else "AUTO_APPROVED"
        impact = "MODERATE: Tier 2 clinical system. Narrow containment with controlled fallback."
    else:
        action = {
            "action_type": "COARSE_ISOLATION",
            "target_asset": asset_id,
            "blocked_flows": [{"protocol": "ANY", "port": "ANY", "direction": "BIDIRECTIONAL"}],
            "preserved_flows": [{"protocol": "TCP", "port": 443, "direction": "OUTBOUND", "purpose": "management"}],
        }
        approval = "AUTO_APPROVED"
        impact = "LOW: Tier 3 non-clinical endpoint. Rapid isolation permitted by policy."

    alternative = {
        "action_type": "MONITOR_ONLY",
        "target_asset": asset_id,
        "blocked_flows": [],
        "preserved_flows": [{"protocol": "ANY", "port": "ANY", "direction": "BIDIRECTIONAL"}],
    }

    indicators = [item.get("code") for item in finding.get("indicators", [])]
    return {
        "case_id": f"CASE-{uuid.uuid4().hex[:8]}",
        "source_finding_id": finding["finding_id"],
        "generated_at": generated_at.isoformat(),
        "threat_summary": (
            f"Asset {asset_id} in zone '{finding.get('affected_zone')}' showed "
            f"{', '.join(indicators)} against baseline {finding.get('baseline_version')}."
        ),
        "affected_assets": [asset_id],
        "candidate_actions": [action, alternative],
        "clinical_impact": impact,
        "confidence": round(finding["confidence"] * float(asset_context.get("identity_confidence", 1.0)), 3),
        "reason": (
            f"Finding {finding['finding_id']} scored anomaly={finding['anomaly_score']} "
            f"risk={finding['risk_score']}. Safety mode {safety_mode}. Tier {tier} policy applied."
        ),
        "approval_level": approval,
        "safety_mode": safety_mode,
        "expiry_time": (generated_at + timedelta(minutes=15)).isoformat(),
        "scope_hash": _scope_hash(action),
        "rollback_plan": {
            "rollback_token_spec": f"RB-{asset_id}-{uuid.uuid4().hex[:6]}",
            "steps": [f"Restore firewall rule table for {asset_id}", "Verify clinical heartbeat"],
            "auto_rollback_seconds": 300,
        },
        "_source": STUB_MARKER,
    }


def build_decision(
    proposal: Dict[str, Any],
    reviewer: str = "dr.okafor@hospital.example",
    decision: str = "APPROVED",
    reason: str = "Evidence supports containment; preserved flows verified against the care plan.",
) -> Dict[str, Any]:
    """Layer 5 stand-in: a decision record bound to the proposal's scope hash."""
    now = datetime.now(timezone.utc)
    return {
        "decision_id": f"DEC-{uuid.uuid4().hex[:8]}",
        "case_id": proposal["case_id"],
        "reviewer": reviewer,
        "decision": decision,
        "scope_hash": proposal["scope_hash"],
        "reason": reason,
        "timestamp": now.isoformat(),
        "expiry": (now + timedelta(minutes=30)).isoformat(),
        "asset_id": proposal["affected_assets"][0],
        "approved_action": proposal["candidate_actions"][0],
        "_source": STUB_MARKER,
    }


def build_enforcement(
    proposal: Dict[str, Any],
    decision: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Layer 4 stand-in: an enforcement result plus the matching rollback event."""
    now = datetime.now(timezone.utc)
    action = decision["approved_action"]
    token = proposal["rollback_plan"]["rollback_token_spec"]
    result = {
        "action_id": f"ACT-{uuid.uuid4().hex[:8]}",
        "case_id": proposal["case_id"],
        "decision_id": decision["decision_id"],
        "target_asset": action["target_asset"],
        "status": "VERIFIED",
        "applied_controls": [action["action_type"]],
        "blocked_flows": action["blocked_flows"],
        "preserved_flows": action["preserved_flows"],
        "start_time": now.isoformat(),
        "expiry_time": (now + timedelta(seconds=proposal["rollback_plan"]["auto_rollback_seconds"])).isoformat(),
        "verification": {
            "malicious_flow_blocked": True,
            "preserved_clinical_flows_available": True,
            "checked_at": (now + timedelta(seconds=5)).isoformat(),
        },
        "rollback_token": token,
        "_source": STUB_MARKER,
    }
    rollback = {
        "case_id": proposal["case_id"],
        "action_id": result["action_id"],
        "target_asset": action["target_asset"],
        "rollback_token": token,
        "trigger": "automatic_expiry",
        "timestamp": (now + timedelta(seconds=proposal["rollback_plan"]["auto_rollback_seconds"])).isoformat(),
        "restored_controls": result["applied_controls"],
        "_source": STUB_MARKER,
    }
    return result, rollback


def build_annotation(case_id: str, analyst: str = "s.mehta@hospital.example") -> Dict[str, Any]:
    return {
        "annotation_id": f"ANN-{uuid.uuid4().hex[:8]}",
        "case_id": case_id,
        "analyst": analyst,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "Confirmed true positive. Endpoint reimaged; no patient data was accessed.",
        "disposition": "true_positive",
        "_source": STUB_MARKER,
    }
