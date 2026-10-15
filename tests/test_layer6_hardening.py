"""Tests for the pieces that took Layer 6 from working to finished:
key management, retention and lawful erasure, checkpoint signing, the audit
emitter, data-source discovery, and the real Layer 5 bridge.

    python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from compliance import emitter
from compliance.audit_store import TamperEvidentAuditStore, canonical_json
from compliance.contracts import Outcome, RecordClass, new_audit_event
from compliance.datasources import DataSourceNotFound, findings_file, scenario_file
from compliance.evidence import verify_evidence_package
from compliance.keys import (
    DEV_CHAIN_KEY,
    ENV_CHAIN_KEY,
    ENV_PSEUDONYM_KEY,
    InsecureKeyError,
    KeyRing,
)
from compliance.pipeline import run_pipeline
from compliance.retention import RetentionManager, RetentionPolicy
from compliance.signing import (
    HmacSigner,
    MLDSASigner,
    build_signer,
    mldsa_available,
    sign_checkpoint,
    verify_checkpoint,
)


def observation(index: int, payload=None):
    return new_audit_event(
        layer=0,
        actor="layer0.ingestion",
        action="observation.normalized",
        input_reference=f"raw://{index}",
        output_reference=f"event://{index}",
        record_class=RecordClass.OBSERVED_FACT,
        outcome=Outcome.SUCCESS,
        timestamp=datetime(2026, 1, 8, 1, tzinfo=timezone.utc),
        payload=payload or {"subject": "office-ws", "note": f"content-{index}"},
    )


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="accds-l6h-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
class KeyManagementTests(unittest.TestCase):
    def tearDown(self):
        for name in (ENV_CHAIN_KEY, ENV_PSEUDONYM_KEY):
            os.environ.pop(name, None)

    def test_chain_and_pseudonym_keys_must_differ(self):
        """One key for both would let any chain verifier reverse every pseudonym."""
        with self.assertRaises(ValueError):
            KeyRing(chain_key=b"same-key-value", pseudonym_key=b"same-key-value")

    def test_development_defaults_are_flagged(self):
        ring = KeyRing.resolve()
        self.assertTrue(ring.is_development)
        with self.assertRaises(InsecureKeyError):
            ring.require_managed()

    def test_environment_overrides_defaults(self):
        os.environ[ENV_CHAIN_KEY] = "chain-secret-from-env"
        os.environ[ENV_PSEUDONYM_KEY] = "pseudo-secret-from-env"
        ring = KeyRing.resolve()
        self.assertFalse(ring.is_development)
        ring.require_managed()  # must not raise
        self.assertNotEqual(ring.chain_key, DEV_CHAIN_KEY)

    def test_key_file_is_read(self):
        directory = Path(tempfile.mkdtemp())
        path = directory / "keys.json"
        path.write_text(json.dumps({"chain_key": "from-file-a", "pseudonym_key": "from-file-b"}))
        os.environ["ACCDS_KEY_FILE"] = str(path)
        try:
            ring = KeyRing.resolve()
            self.assertEqual(ring.chain_key, b"from-file-a")
            self.assertFalse(ring.is_development)
        finally:
            os.environ.pop("ACCDS_KEY_FILE", None)
            shutil.rmtree(directory, ignore_errors=True)

    def test_fingerprint_does_not_reveal_the_key(self):
        ring = KeyRing.generate()
        fingerprint = ring.fingerprint("chain")
        self.assertNotIn(ring.chain_key.hex(), fingerprint)
        self.assertEqual(len(fingerprint), 16)
        self.assertNotEqual(ring.fingerprint("chain"), ring.fingerprint("pseudonym"))

    def test_generated_keys_differ_every_time(self):
        self.assertNotEqual(KeyRing.generate().chain_key, KeyRing.generate().chain_key)


# ---------------------------------------------------------------------------
class RetentionTests(TempDirTest):
    def _store(self, count=4):
        store = TamperEvidentAuditStore(self.tmp / "chain.jsonl", key=b"chain")
        for index in range(count):
            store.append(observation(index))
        return store

    def test_erasure_removes_content_but_keeps_the_chain_valid(self):
        """The erasure/immutability conflict: tombstone rather than delete."""
        store = self._store()
        manager = RetentionManager(store, key=b"tomb")
        result = manager.erase([1], actor="dpo:k.raman", reason="erasure request")

        self.assertEqual(result.erased_sequences, [1])
        self.assertTrue(result.chain_still_valid)
        raw = (self.tmp / "chain.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("content-1", raw)
        self.assertIn("content-0", raw)  # only the requested record went
        reloaded = TamperEvidentAuditStore(self.tmp / "chain.jsonl", key=b"chain")
        self.assertTrue(reloaded.verify().ok)

    def test_erasure_is_itself_audited(self):
        store = self._store()
        before = len(store)
        manager = RetentionManager(store, key=b"tomb")
        result = manager.erase([2], actor="dpo:k.raman", reason="erasure request #77")
        self.assertEqual(len(store), before + 1)
        self.assertEqual(len(result.tombstone_audit_ids), 1)
        last = store.records()[-1].event
        self.assertEqual(last.action, "record.erased")
        self.assertEqual(last.payload["erased_sequence"], 2)

    def test_commitment_proves_what_was_erased_without_retaining_it(self):
        store = self._store()
        original = dict(store.records()[1].event.payload)
        manager = RetentionManager(store, key=b"tomb")
        manager.erase([1], actor="dpo", reason="request")
        self.assertTrue(manager.verify_erasure(1, original))
        self.assertFalse(manager.verify_erasure(1, {"subject": "someone-else"}))

    def test_erasing_twice_is_harmless(self):
        store = self._store()
        manager = RetentionManager(store, key=b"tomb")
        manager.erase([1], actor="dpo", reason="first")
        second = manager.erase([1], actor="dpo", reason="second")
        self.assertEqual(second.erased_sequences, [])
        self.assertTrue(store.verify().ok)

    def test_unknown_sequence_is_rejected(self):
        manager = RetentionManager(self._store(), key=b"tomb")
        with self.assertRaises(ValueError):
            manager.erase([99], actor="dpo", reason="typo")

    def test_legal_hold_suspends_expiry(self):
        old = datetime.now(timezone.utc) - timedelta(days=5000)
        normal = RetentionPolicy.default()
        held = RetentionPolicy(days_by_class=dict(normal.days_by_class), legal_hold=True)
        self.assertTrue(normal.is_expired(old, RecordClass.OBSERVED_FACT.value))
        self.assertFalse(held.is_expired(old, RecordClass.OBSERVED_FACT.value))

    def test_decisions_are_retained_longer_than_observations(self):
        policy = RetentionPolicy.default()
        self.assertGreater(
            policy.retention_days(RecordClass.HUMAN_DECISION.value),
            policy.retention_days(RecordClass.OBSERVED_FACT.value),
        )


# ---------------------------------------------------------------------------
class SigningTests(unittest.TestCase):
    def test_hmac_checkpoint_round_trips(self):
        signer = HmacSigner(b"k")
        checkpoint = sign_checkpoint(signer, "a" * 64, 29, "CASE-x").to_dict()
        self.assertTrue(verify_checkpoint(checkpoint, signer)["ok"])

    def test_hmac_checkpoint_is_unverifiable_not_rejected_without_the_key(self):
        """'I cannot check this' must never be reported as 'this is forged'."""
        checkpoint = sign_checkpoint(HmacSigner(b"k"), "a" * 64, 29, "CASE-x").to_dict()
        result = verify_checkpoint(checkpoint)
        self.assertEqual(result["status"], "unverifiable")
        self.assertIsNone(result["ok"])

    def test_tampered_head_is_rejected(self):
        signer = HmacSigner(b"k")
        checkpoint = sign_checkpoint(signer, "a" * 64, 29, "CASE-x").to_dict()
        checkpoint["head_hash"] = "b" * 64
        self.assertFalse(verify_checkpoint(checkpoint, signer)["ok"])

    def test_checkpoint_is_domain_separated(self):
        """A signature over one case must not verify for another."""
        signer = HmacSigner(b"k")
        checkpoint = sign_checkpoint(signer, "a" * 64, 29, "CASE-x").to_dict()
        checkpoint["case_id"] = "CASE-y"
        self.assertFalse(verify_checkpoint(checkpoint, signer)["ok"])

    def test_unknown_signer_kind_is_rejected(self):
        with self.assertRaises(ValueError):
            build_signer("rot13")

    @unittest.skipUnless(mldsa_available(), "cryptography with ML-DSA is not installed")
    def test_mldsa_verifies_with_no_shared_secret(self):
        """FIPS 204: the whole point is a third party verifying without a secret."""
        signer = MLDSASigner("ML-DSA-65")
        checkpoint = sign_checkpoint(signer, "a" * 64, 29, "CASE-x").to_dict()
        result = verify_checkpoint(checkpoint)  # no signer passed
        self.assertTrue(result["ok"])
        self.assertTrue(result["third_party_verifiable"])

    @unittest.skipUnless(mldsa_available(), "cryptography with ML-DSA is not installed")
    def test_mldsa_rejects_a_forged_signature(self):
        checkpoint = sign_checkpoint(MLDSASigner("ML-DSA-44"), "a" * 64, 1, None).to_dict()
        forged = bytearray(bytes.fromhex(checkpoint["signature"]))
        forged[0] ^= 0xFF
        checkpoint["signature"] = bytes(forged).hex()
        self.assertEqual(verify_checkpoint(checkpoint)["status"], "rejected")

    @unittest.skipUnless(mldsa_available(), "cryptography with ML-DSA is not installed")
    def test_mldsa_signature_does_not_verify_under_another_key(self):
        one = sign_checkpoint(MLDSASigner("ML-DSA-44"), "a" * 64, 1, None).to_dict()
        other = sign_checkpoint(MLDSASigner("ML-DSA-44"), "a" * 64, 1, None).to_dict()
        one["public_key"] = other["public_key"]
        self.assertFalse(verify_checkpoint(one)["ok"])


# ---------------------------------------------------------------------------
class EmitterTests(TempDirTest):
    def setUp(self):
        super().setUp()
        emitter.reset()

    def tearDown(self):
        emitter.reset()
        super().tearDown()

    def test_records_emitted_before_configure_are_not_lost(self):
        emitter.emit(layer=0, actor="layer0", action="observation.normalized",
                     input_reference="raw://1", output_reference="event://1",
                     record_class="observed_fact")
        self.assertEqual(emitter.pending(), 1)
        store = emitter.configure(str(self.tmp / "chain.jsonl"))
        self.assertEqual(len(store), 1)
        self.assertEqual(emitter.pending(), 0)

    def test_a_bad_audit_call_does_not_break_the_calling_layer(self):
        """Enforcement must not crash because its audit call was malformed."""
        emitter.configure(str(self.tmp / "chain.jsonl"))
        result = emitter.emit(layer=4, actor="", action="enforcement.applied",
                              input_reference="", output_reference="",
                              record_class="action_taken")
        self.assertIsNone(result)
        self.assertEqual(len(emitter.failures()), 1)

    def test_strict_mode_surfaces_mistakes(self):
        emitter.configure(str(self.tmp / "chain.jsonl"), strict=True)
        with self.assertRaises(ValueError):
            emitter.emit(layer=4, actor="", action="x", input_reference="",
                         output_reference="", record_class="action_taken")

    def test_emitted_records_form_a_valid_chain(self):
        store = emitter.configure(str(self.tmp / "chain.jsonl"))
        for index in range(5):
            emitter.emit(layer=2, actor="layer2.model", action="finding.emitted",
                         input_reference=f"events://{index}", output_reference=f"finding://{index}",
                         record_class="model_inference")
        self.assertEqual(len(store), 5)
        self.assertTrue(store.verify().ok)


# ---------------------------------------------------------------------------
class DataSourceTests(unittest.TestCase):
    def test_layer2_artifacts_are_found_after_the_move(self):
        self.assertTrue(findings_file().is_file())
        self.assertTrue(scenario_file("port_scan").is_file())

    def test_missing_data_names_every_path_searched(self):
        os.environ["ACCDS_DATA_DIR"] = "/definitely/not/here"
        try:
            with self.assertRaises(DataSourceNotFound) as caught:
                findings_file()
            self.assertIn("/definitely/not/here", str(caught.exception))
        finally:
            os.environ.pop("ACCDS_DATA_DIR", None)


# ---------------------------------------------------------------------------
class Layer5BridgeTests(unittest.TestCase):
    def test_real_decision_gate_record_enters_the_chain(self):
        """Layer 5 exists now; its records must satisfy the audit contract."""
        from compliance.ingest import decision_gate_to_audit
        from decision_gate.decision_logic import process_decision
        from decision_gate.models import ResponseProposal

        proposal = ResponseProposal(
            case_id="CASE-real", threat_summary="lateral movement",
            affected_assets=["office-ws"], candidate_actions=["COARSE_ISOLATION"],
            clinical_impact="low", confidence=0.9, reason="scan detected",
            approval_level="AUTO", proposed_action="COARSE_ISOLATION",
            expiry_minutes=15, rollback_plan="restore rules",
        )
        record = process_decision(proposal, "approve", "dr.okafor@example.org",
                                  proposal.action_hash(), "evidence supports")
        event = decision_gate_to_audit(record)
        event.validate()
        self.assertEqual(event.layer, 5)
        self.assertEqual(event.outcome, Outcome.SUCCESS.value)

    def test_naive_timestamps_from_layer5_are_accepted_as_utc(self):
        """decision_gate uses datetime.utcnow(); the contract needs tz-aware."""
        from compliance.ingest import decision_gate_to_audit

        event = decision_gate_to_audit({
            "decision_id": "DEC-1", "case_id": "CASE-1", "reviewer": "r",
            "decision": "reject", "scope_hash": "abc", "reason": "unsafe",
            "approved_action": None, "timestamp": datetime(2026, 1, 8, 1, 0),
        })
        self.assertIsNotNone(event.timestamp.tzinfo)
        self.assertEqual(event.outcome, Outcome.REJECTED.value)

    def test_unknown_decision_verb_escalates_rather_than_succeeding(self):
        from compliance.ingest import decision_gate_to_audit

        event = decision_gate_to_audit({
            "decision_id": "DEC-2", "case_id": "CASE-1", "reviewer": "r",
            "decision": "banana", "scope_hash": "abc", "reason": "?",
            "approved_action": None, "timestamp": datetime.now(timezone.utc),
        })
        self.assertEqual(event.outcome, Outcome.ESCALATED.value)


# ---------------------------------------------------------------------------
class SignedPipelineTests(TempDirTest):
    @unittest.skipUnless(mldsa_available(), "cryptography with ML-DSA is not installed")
    def test_mldsa_package_verifies_standalone(self):
        run_pipeline(self.tmp / "run", scenario="port_scan",
                     adapter_name="null", signer_kind="mldsa")
        result = verify_evidence_package(self.tmp / "run" / "evidence_package")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["signature"]["status"], "valid")
        self.assertTrue(result["signature"]["third_party_verifiable"])

    def test_checkpoint_covers_the_final_chain_head(self):
        result = run_pipeline(self.tmp / "run", scenario="new_peer", adapter_name="null")
        store = TamperEvidentAuditStore(self.tmp / "run" / "audit_chain.jsonl",
                                        key=KeyRing.resolve().chain_key)
        self.assertEqual(result.checkpoint["head_hash"], store.head_hash)
        self.assertEqual(result.checkpoint["sequence_count"], len(store))

    def test_pipeline_reports_key_provenance(self):
        result = run_pipeline(self.tmp / "run", scenario="off_hours", adapter_name="null")
        self.assertIn("chain_key_fingerprint", result.key_provenance)
        self.assertTrue(result.key_provenance["development_keys_in_use"])

    def test_managed_keys_can_be_required(self):
        with self.assertRaises(InsecureKeyError):
            run_pipeline(self.tmp / "run", scenario="port_scan",
                         adapter_name="null", require_managed_keys=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
