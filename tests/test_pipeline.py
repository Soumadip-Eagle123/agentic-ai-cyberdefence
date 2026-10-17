"""Regression tests for the Layers 0-5 pipeline and the hospital digital twin.

Each test pins down one of the defects fixed in this branch, so none of them can
come back quietly. Run with no third-party test runner:

    PYTHONPATH=. agentic_venv/bin/python -m unittest discover -s tests -t .
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from digital_twin import hospital, scenarios
from src.asset_intelligence.layer1_asset_intelligence import Layer1AssetIntelligence
from src.detection.layer2_detector import Layer2Detector
from src.enforcement.layer4_executor import Layer4Executor
from src.ingestion.layer0_ingestion import Layer0Ingestion
from src.decision_gate.decision_logic import Layer5DecisionGate
from src.orchestration.layer3_orchestrator import Layer3Orchestrator
from src.schemas.contracts import (
    ApprovalLevel,
    ClinicalTier,
    DecisionOutcome,
    EnforcementStatus,
    SystemSafetyMode,
)


def observe(src: str, dst: str, event_type: str = "EXPLOIT_ATTEMPT", byte_count: int = 4096):
    """Push one raw log through Layer 0 and return the normalized event."""
    return Layer0Ingestion().process_raw_log({
        "timestamp": "2026-10-07T10:00:00Z",
        "source": "test_sensor", "event_type": event_type,
        "src": src, "dst": dst, "protocol": "TCP",
        "bytes": byte_count, "zone": "test", "scenario_id": "unit_test",
    })


def trained_detector(hours: int = 24) -> Layer2Detector:
    detector = Layer2Detector()
    detector.learn_from_events(scenarios.generate_normal(hours=hours))
    return detector


# ---------------------------------------------------------------------------
# The digital twin
# ---------------------------------------------------------------------------
class TwinTests(unittest.TestCase):
    def test_every_scenario_address_is_in_the_inventory(self):
        """Unresolvable addresses are what made attack stages disappear."""
        for name in scenarios.campaign_names():
            for event in scenarios.generate_campaign(name):
                with self.subTest(campaign=name, stage=event.stage_index):
                    # External destinations are intentional (exfiltration), but
                    # the source must always be a device we know.
                    self.assertIsNotNone(
                        hospital.get(event.src),
                        f"source '{event.src}' is not in the inventory",
                    )

    def test_devices_resolve_by_both_name_and_ip(self):
        device = hospital.by_asset_id("icu-monitor-gw")
        self.assertIs(hospital.get("icu-monitor-gw"), device)
        self.assertIs(hospital.get(device.ip), device)

    def test_tier_1_devices_exist_and_are_marked_life_critical(self):
        tier1 = [d for d in hospital.all_devices() if d.tier == hospital.TIER_1]
        self.assertGreaterEqual(len(tier1), 2)
        self.assertTrue(all(d.is_life_critical for d in tier1))

    def test_baseline_edges_are_reachability_not_proximity(self):
        """ehr-core shares no room with the ICU yet must reach it; guest-device
        is Tier 3 and must not, whatever the floor plan looks like."""
        edges = {frozenset(e) for e in hospital.baseline_edges()}
        self.assertIn(frozenset(("ehr-core", "icu-monitor-gw")), edges)
        self.assertNotIn(frozenset(("guest-device", "icu-monitor-gw")), edges)

    def test_campaign_stages_form_a_chain(self):
        """Stage N's destination must become stage N+1's source somewhere, or
        there is nothing for correlation to correlate."""
        stages = scenarios.get_campaign("lateral_to_icu").stages
        victims = set()
        chained = 0
        for stage in stages:
            if stage.src in victims:
                chained += 1
            victims.add(stage.dst)
        self.assertGreaterEqual(chained, 3, "campaign has no lateral chain")


# ---------------------------------------------------------------------------
# Bug 1 - Layer 1 resolved the attacker instead of the victim
# ---------------------------------------------------------------------------
class VictimResolutionTests(unittest.TestCase):
    def setUp(self):
        self.layer1 = Layer1AssetIntelligence()

    def test_attack_on_tier1_resolves_to_the_tier1_device(self):
        """The bug that let a life-critical exploit be auto-approved."""
        event = observe("10.0.3.15", "10.0.1.45")       # attacker -> ICU gateway
        result = self.layer1.enrich_full(event)
        self.assertEqual(result.asset.asset_id, "icu-monitor-gw")
        self.assertEqual(result.asset.clinical_tier, ClinicalTier.TIER_1)

    def test_attacker_is_reported_separately_not_lost(self):
        event = observe("10.0.3.15", "10.0.1.45")
        result = self.layer1.enrich_full(event)
        self.assertEqual(result.attacker_asset_id, "office-ws")

    def test_scanner_resolves_to_the_sender_when_target_is_not_an_asset(self):
        """A port sweep's destination is not a hospital device, so the device
        worth reporting is the one doing the scanning."""
        event = observe("office-ws", "port-4242", event_type="PORT_SCAN")
        result = self.layer1.enrich_full(event)
        self.assertEqual(result.asset.asset_id, "office-ws")
        self.assertEqual(result.resolved_from, "src")

    def test_exfiltration_resolves_to_the_leaking_device(self):
        event = observe("office-ws", "external-cloud", event_type="DATA_UPLOAD")
        self.assertEqual(self.layer1.enrich_full(event).asset.asset_id, "office-ws")


# ---------------------------------------------------------------------------
# Bug 3 - unknown devices were silently dropped
# ---------------------------------------------------------------------------
class VisibilityTests(unittest.TestCase):
    def setUp(self):
        self.layer1 = Layer1AssetIntelligence()

    def test_unknown_address_still_produces_an_asset(self):
        result = self.layer1.enrich_full(observe("1.2.3.4", "5.6.7.8"))
        self.assertIsNotNone(result.asset)
        self.assertFalse(result.identity_known)

    def test_unknown_device_gets_low_identity_confidence(self):
        """Uncertain identity must lower response confidence, not raise it."""
        result = self.layer1.enrich_full(observe("1.2.3.4", "5.6.7.8"))
        self.assertLess(result.asset.identity_confidence, 0.5)

    def test_unknown_device_is_not_assumed_harmless(self):
        """We cannot prove an unidentified device is non-clinical, and guessing
        'Tier 3, isolate freely' is the dangerous direction to be wrong in."""
        result = self.layer1.enrich_full(observe("1.2.3.4", "5.6.7.8"))
        self.assertNotEqual(result.asset.clinical_tier, ClinicalTier.TIER_3)

    def test_unresolved_addresses_are_reported(self):
        self.layer1.enrich_full(observe("1.2.3.4", "5.6.7.8"))
        report = self.layer1.visibility_report()
        self.assertEqual(report["unresolved_count"], 1)
        self.assertFalse(report["fully_visible"])


# ---------------------------------------------------------------------------
# Bug 2 - the lateral-movement chain rule could never fire
# ---------------------------------------------------------------------------
class CorrelationTests(unittest.TestCase):
    def _run_campaign(self, name: str):
        layer0, layer1 = Layer0Ingestion(), Layer1AssetIntelligence()
        layer2, layer3 = trained_detector(), Layer3Orchestrator()
        proposals = []
        for event in scenarios.generate_campaign(name):
            obs = layer0.process_raw_log(event.to_raw_log())
            enrichment = layer1.enrich_full(obs)
            counterpart = obs.src if enrichment.resolved_from == "dst" else obs.dst
            finding = layer2.analyze_observation(
                asset_context=enrichment.asset, event_id=obs.event_id,
                event_type=obs.event_type, src=obs.src, counterpart=counterpart,
                byte_count=obs.bytes, timestamp=event.timestamp,
                attacker_asset_id=enrichment.attacker_asset_id,
            )
            if finding:
                proposals.append(layer3.process(finding, enrichment.asset,
                                                SystemSafetyMode.NORMAL))
        return proposals

    def test_whole_campaign_collapses_into_one_case(self):
        """Six stages across four zones are one attack, not six incidents."""
        proposals = self._run_campaign("lateral_to_icu")
        self.assertEqual(len({p.case_id for p in proposals}), 1)

    def test_final_proposal_carries_every_finding(self):
        proposals = self._run_campaign("lateral_to_icu")
        self.assertEqual(len(proposals[-1].correlated_finding_ids), len(proposals))

    def test_chain_links_a_victim_to_its_later_role_as_attacker(self):
        """lab-server is compromised, then attacks the ICU. That is the link."""
        chain = self._run_campaign("lateral_to_icu")[-1].attack_chain
        victims = [hop["victim"] for hop in chain]
        attackers = [hop["attacker"] for hop in chain]
        self.assertIn("lab-server", victims)
        self.assertIn("lab-server", attackers)
        self.assertLess(victims.index("lab-server"), attackers.index("lab-server") + 1)

    def test_campaign_reaching_tier1_requires_human_approval(self):
        final = self._run_campaign("lateral_to_icu")[-1]
        self.assertEqual(final.approval_level, ApprovalLevel.REQUIRES_HUMAN_APPROVAL)

    def test_reviewer_sees_the_whole_path_not_one_incident(self):
        final = self._run_campaign("lateral_to_icu")[-1]
        self.assertGreaterEqual(len(final.attack_chain), 5)
        self.assertIn("office-ws", final.threat_summary)
        self.assertIn("icu-controller", final.threat_summary)

    def test_correlation_window_uses_event_time_not_wall_clock(self):
        """Replaying history processes every stage in milliseconds, so a window
        measured against datetime.now() never expires and only appears to work."""
        layer3 = Layer3Orchestrator()
        self.assertEqual(
            layer3.correlation_agent._event_time(
                type("F", (), {"timestamp": "2026-10-07T10:00:00+00:00"})()
            ),
            datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc),
        )


# ---------------------------------------------------------------------------
# Layer 2 - real scoring instead of a hardcoded list
# ---------------------------------------------------------------------------
class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.detector = trained_detector()
        self.layer1 = Layer1AssetIntelligence()

    def _score(self, src, dst, event_type, byte_count=4096):
        event = observe(src, dst, event_type, byte_count)
        enrichment = self.layer1.enrich_full(event)
        counterpart = event.src if enrichment.resolved_from == "dst" else event.dst
        return self.detector.score_observation(
            asset_context=enrichment.asset, event_type=event_type,
            counterpart=counterpart, byte_count=byte_count,
            timestamp=datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc),
        )

    def test_detector_learns_a_baseline(self):
        self.assertTrue(self.detector.is_trained)
        self.assertGreater(len(self.detector.baselines), 5)

    def test_scores_differ_by_event_type(self):
        """The old implementation returned a constant per stage index."""
        exploit, _, _ = self._score("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        flow, _, _ = self._score("lab-server", "ehr-core", "NETWORK_FLOW")
        self.assertGreater(exploit, flow)

    def test_identical_attack_scores_higher_against_tier1(self):
        tier1, _, _ = self._score("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        tier3, _, _ = self._score("office-ws", "admin-print", "EXPLOIT_ATTEMPT")
        self.assertGreater(tier1, tier3)

    def test_legitimate_clinical_burst_is_not_flagged(self):
        """A large but authorised transfer must not trigger containment."""
        score, _, _ = self._score("icu-monitor-gw", "ehr-core", "HL7_BULK", 120000)
        self.assertLess(score, self.detector.threshold)

    def test_inbound_flow_from_a_known_peer_is_not_an_unauthorised_peer(self):
        """Checking the destination when the asset IS the destination asks
        whether a device may talk to itself, and flags all inbound traffic."""
        _, indicators, _ = self._score("icu-monitor-gw", "ehr-core", "HL7_BULK", 2000)
        self.assertNotIn("UNAUTHORIZED_PEER_COMMUNICATION", indicators)

    def test_scores_are_explainable(self):
        _, _, components = self._score("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        for key in ("event_type", "unknown_peer", "volume", "off_hours", "clinical_tier"):
            self.assertIn(key, components)

    def test_low_identity_confidence_lowers_risk_not_raises_it(self):
        event = observe("1.2.3.4", "9.9.9.9", "EXPLOIT_ATTEMPT")
        enrichment = self.layer1.enrich_full(event)
        finding = self.detector.analyze_observation(
            asset_context=enrichment.asset, event_id=event.event_id,
            event_type="EXPLOIT_ATTEMPT", src=event.src, counterpart=event.src,
            byte_count=4096, timestamp=datetime.now(timezone.utc),
        )
        self.assertIsNotNone(finding)
        self.assertLess(finding.risk_score, finding.anomaly_score)


# ---------------------------------------------------------------------------
# Bug 4 - the approval signature signed nothing
# ---------------------------------------------------------------------------
class DecisionGateTests(unittest.TestCase):
    def setUp(self):
        self.gate = Layer5DecisionGate()
        self.proposals = CorrelationTests()._run_campaign("lateral_to_icu")
        self.proposal = self.proposals[-1]

    def test_scope_hash_is_not_the_hash_of_nothing(self):
        import hashlib

        scope_hash = self.gate.compute_scope_hash(self.proposal)
        self.assertNotEqual(scope_hash, hashlib.sha256(b"").hexdigest())

    def test_scope_hash_changes_when_the_action_changes(self):
        """An approval must not survive a change to what it approved."""
        before = self.gate.compute_scope_hash(self.proposal)
        self.proposal.candidate_actions[0].action_type = "FULL_ISOLATION"
        self.assertNotEqual(before, self.gate.compute_scope_hash(self.proposal))

    def test_tier1_campaign_is_held_for_a_human(self):
        self.assertIsNone(self.gate.evaluate_proposal(self.proposal))

    def test_recorded_decision_binds_to_the_proposal(self):
        self.gate.evaluate_proposal(self.proposal)
        record = self.gate.record_human_decision(
            self.proposal.case_id, "dr.okafor", DecisionOutcome.APPROVED, "ok")
        self.assertEqual(record.scope_hash, self.gate.compute_scope_hash(self.proposal))

    def test_rejection_records_no_approved_action(self):
        self.gate.evaluate_proposal(self.proposal)
        record = self.gate.record_human_decision(
            self.proposal.case_id, "dr.okafor", DecisionOutcome.REJECTED, "dialysis in progress")
        self.assertIsNone(record.approved_action)

    def test_decision_timestamps_are_timezone_aware(self):
        from src.decision_gate.models import ResponseProposal as GateProposal

        proposal = GateProposal(
            case_id="C", threat_summary="t", affected_assets=["a"],
            candidate_actions=["X"], clinical_impact="low", confidence=0.9,
            reason="r", approval_level="AUTO", proposed_action="BLOCK",
            expiry_minutes=15, rollback_plan="rb")
        self.assertIsNotNone(proposal.created_at.tzinfo)


# ---------------------------------------------------------------------------
# Layer 4 - enforcement reads the proposal
# ---------------------------------------------------------------------------
class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.executor = Layer4Executor()
        self.proposal = CorrelationTests()._run_campaign("lateral_to_icu")[-1]

    def test_unapproved_tier1_action_is_refused(self):
        result = self.executor.execute_proposal(self.proposal, force_execution=False)
        self.assertEqual(result.status, EnforcementStatus.FAILED)
        self.assertEqual(result.applied_controls, [])

    def test_approved_action_is_applied(self):
        result = self.executor.execute_proposal(self.proposal, force_execution=True)
        self.assertEqual(result.status, EnforcementStatus.APPLIED)
        self.assertTrue(result.applied_controls)

    def test_reported_target_is_the_most_critical_asset(self):
        """affected_assets comes from a set, so element zero could name a Tier 3
        printer as the target of a campaign that reached intensive care."""
        result = self.executor.execute_proposal(self.proposal, force_execution=True)
        device = hospital.by_asset_id(result.target_asset)
        self.assertIsNotNone(device)
        self.assertEqual(device.tier, hospital.TIER_1)

    def test_tier1_containment_preserves_clinical_flows(self):
        result = self.executor.execute_proposal(self.proposal, force_execution=True)
        self.assertTrue(result.blocked_flows)
        self.assertTrue(result.preserved_flows)

    def test_preserved_flows_match_what_each_device_actually_speaks(self):
        """Blanket HL7 preservation would cut DICOM on a PACS server while
        carefully protecting a protocol it does not use."""
        protocols = set()
        for action in self.proposal.candidate_actions:
            if action.target_asset == "pacs":
                protocols = {f["protocol"] for f in action.preserved_flows}
        self.assertIn("DICOM", protocols)

    def test_rollback_token_is_tracked_and_reversible(self):
        result = self.executor.execute_proposal(self.proposal, force_execution=True)
        self.assertIn(result.rollback_token, self.executor.active_rules)
        self.assertTrue(self.executor.rollback_rule(result.rollback_token))
        self.assertNotIn(result.rollback_token, self.executor.active_rules)


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------
class EndToEndTests(unittest.TestCase):
    def test_tier1_attack_is_never_auto_approved(self):
        """The single most important property in the system."""
        proposals = CorrelationTests()._run_campaign("lateral_to_icu")
        reached_tier1 = [
            p for p in proposals
            if any(hop.get("victim_tier") == 1 for hop in p.attack_chain)
        ]
        self.assertTrue(reached_tier1)
        for proposal in reached_tier1:
            self.assertEqual(proposal.approval_level, ApprovalLevel.REQUIRES_HUMAN_APPROVAL)

    def test_no_campaign_stage_is_silently_lost(self):
        layer0, layer1 = Layer0Ingestion(), Layer1AssetIntelligence()
        events = scenarios.generate_campaign("lateral_to_icu")
        resolved = 0
        for event in events:
            obs = layer0.process_raw_log(event.to_raw_log())
            self.assertIsNotNone(obs)
            self.assertIsNotNone(layer1.enrich_full(obs).asset)
            resolved += 1
        self.assertEqual(resolved, len(events))

    def test_benign_campaign_triggers_no_containment(self):
        proposals = CorrelationTests()._run_campaign("benign_clinical_burst")
        self.assertEqual(proposals, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
