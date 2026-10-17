"""Tests for the live interactive attack session.

The point of a resident session is that state accumulates: a second attack
launched from a machine the attacker already took must be recognised as the
next hop of the same campaign, not as a fresh incident.
"""

from __future__ import annotations

import unittest

from digital_twin import hospital
from src.schemas.contracts import ApprovalLevel, EnforcementStatus
from visualiser.session import ATTACK_TYPES, AttackSession


class SessionBasicsTests(unittest.TestCase):
    def setUp(self):
        self.session = AttackSession(baseline_hours=12)

    def test_detector_is_trained_at_session_start(self):
        baseline = self.session.state()["baseline"]
        self.assertGreater(baseline["events"], 0)
        self.assertGreater(baseline["devices"], 5)

    def test_hospital_state_exposes_everything_the_ui_needs(self):
        state = self.session.hospital_state()
        for key in ("zones", "devices", "baseline_edges", "attack_types", "campaigns"):
            self.assertIn(key, state)
        self.assertEqual(len(state["devices"]), len(hospital.all_devices()))

    def test_every_offered_attack_type_is_usable(self):
        for attack in ATTACK_TYPES:
            with self.subTest(attack=attack["id"]):
                session = AttackSession(baseline_hours=6)
                result = session.launch("office-ws", "admin-print", attack["id"])
                self.assertTrue(result.ok, result.message)

    def test_duplicate_attack_is_dropped_by_layer0(self):
        self.session.launch("office-ws", "admin-print", "SMB_FLOW")
        self.session.clock -= __import__("datetime").timedelta(minutes=2)
        repeat = self.session.launch("office-ws", "admin-print", "SMB_FLOW")
        self.assertFalse(repeat.ok)
        self.assertIn("duplicate", repeat.message.lower())


class VictimResolutionTests(unittest.TestCase):
    def setUp(self):
        self.session = AttackSession(baseline_hours=12)

    def test_attack_on_icu_reports_the_icu_not_the_attacker(self):
        result = self.session.launch("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        self.assertEqual(result.asset["asset_id"], "icu-monitor-gw")
        self.assertEqual(int(result.asset["clinical_tier"]), 1)

    def test_attacker_identity_is_resolved_alongside_the_victim(self):
        result = self.session.launch("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        self.assertEqual(result.attacker_asset_id, "office-ws")

    def test_unknown_device_is_visible_not_dropped(self):
        result = self.session.launch("9.9.9.9", "8.8.8.8", "EXPLOIT_ATTEMPT")
        self.assertTrue(result.ok)
        self.assertFalse(result.identity_known)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.session = AttackSession(baseline_hours=12)

    def test_tier1_attack_holds_for_a_human(self):
        result = self.session.launch("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        self.assertTrue(result.awaiting_approval)
        self.assertIsNone(result.decision)

    def test_further_attacks_are_blocked_while_a_decision_is_pending(self):
        self.session.launch("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        blocked = self.session.launch("office-ws", "lab-server", "PORT_SCAN")
        self.assertFalse(blocked.ok)
        self.assertIn("pending", blocked.message.lower())

    def test_approval_applies_containment(self):
        self.session.launch("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        outcome = self.session.decide(True, "dr.okafor", "confirmed")
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["enforcement"]["status"], EnforcementStatus.APPLIED.value)

    def test_rejection_applies_nothing(self):
        self.session.launch("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        outcome = self.session.decide(False, "dr.okafor", "dialysis in progress")
        self.assertEqual(outcome["enforcement"]["status"], EnforcementStatus.FAILED.value)
        self.assertEqual(outcome["enforcement"]["applied_controls"], [])

    def test_approval_preserves_the_right_clinical_flows(self):
        self.session.launch("radiology-ws", "pacs", "EXPLOIT_ATTEMPT")
        if self.session.pending_case:
            outcome = self.session.decide(True, "dr.okafor", "ok")
            protocols = {f["protocol"] for f in outcome["enforcement"]["preserved_flows"]}
            self.assertIn("DICOM", protocols)

    def test_deciding_with_nothing_pending_is_refused(self):
        self.assertFalse(self.session.decide(True, "x", "y")["ok"])

    def test_reviewer_and_reason_are_recorded(self):
        self.session.launch("office-ws", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        outcome = self.session.decide(False, "dr.okafor", "patient on dialysis")
        self.assertEqual(outcome["decision"]["reviewer"], "dr.okafor")
        self.assertEqual(outcome["decision"]["reason"], "patient on dialysis")


class ChainAccumulationTests(unittest.TestCase):
    """The reason the session has to be stateful at all."""

    def setUp(self):
        self.session = AttackSession(baseline_hours=12)

    def _hop(self, src, dst, event_type):
        result = self.session.launch(src, dst, event_type)
        if self.session.pending_case:
            self.session.decide(True, "dr.okafor", "test")
        return result

    def test_compromised_devices_are_tracked(self):
        self._hop("office-ws", "lab-server", "MALWARE_STAGING")
        self.assertIn("lab-server", self.session.compromised)

    def test_second_hop_joins_the_same_case(self):
        first = self._hop("office-ws", "lab-server", "MALWARE_STAGING")
        second = self._hop("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        self.assertEqual(first.proposal["case_id"], second.proposal["case_id"])

    def test_chain_records_victim_becoming_attacker(self):
        self._hop("office-ws", "lab-server", "MALWARE_STAGING")
        second = self._hop("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        chain = second.proposal["attack_chain"]
        self.assertIn("lab-server", [h["victim"] for h in chain])
        self.assertIn("lab-server", [h["attacker"] for h in chain])

    def test_case_grows_with_each_hop(self):
        first = self._hop("office-ws", "lab-server", "MALWARE_STAGING")
        second = self._hop("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        self.assertGreater(len(second.proposal["correlated_finding_ids"]),
                           len(first.proposal["correlated_finding_ids"]))

    def test_reaching_tier1_escalates_the_whole_case(self):
        self._hop("office-ws", "lab-server", "MALWARE_STAGING")
        second = self.session.launch("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT")
        self.assertEqual(second.proposal["approval_level"],
                         ApprovalLevel.REQUIRES_HUMAN_APPROVAL.value)


class FalsePositiveTests(unittest.TestCase):
    def test_legitimate_clinical_transfer_raises_nothing(self):
        session = AttackSession(baseline_hours=12)
        result = session.launch("icu-monitor-gw", "ehr-core", "HL7_BULK")
        self.assertIsNone(result.finding)
        self.assertFalse(result.awaiting_approval)
        self.assertIn("threshold", result.message)


class ResetTests(unittest.TestCase):
    def test_reset_clears_accumulated_state(self):
        session = AttackSession(baseline_hours=12)
        session.launch("office-ws", "lab-server", "MALWARE_STAGING")
        session.reset()
        state = session.state()
        self.assertEqual(state["stages"], [])
        self.assertEqual(state["compromised"], [])
        self.assertFalse(state["awaiting_approval"])

    def test_reset_retrains_the_detector(self):
        session = AttackSession(baseline_hours=12)
        session.reset()
        self.assertGreater(session.state()["baseline"]["events"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
