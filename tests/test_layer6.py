"""Acceptance tests for ACCDS Layer 6.

Written with ``unittest`` so they run with no third-party install:

    python3 -m unittest discover -s tests -t .

They are also collected unchanged by pytest once it is available.

The roadmap's Layer 6 acceptance test is the pair at the centre of this file:
generate a complete incident timeline from one scenario, verify that sensitive
fields are redacted in the operational view, and verify that an authorized
forensic user can still trace every record to its source.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from compliance.access import AccessController
from compliance.audit_store import TamperEvidentAuditStore, canonical_json
from compliance.contracts import (
    AccessRole,
    Outcome,
    RecordClass,
    ViewKind,
    new_audit_event,
)
from compliance.evidence import verify_evidence_package
from compliance.pipeline import run_pipeline
from compliance.redaction import RedactionEngine
from compliance.reporting import build_report, get_adapter, render_markdown
from compliance.timeline import build_timeline

REPO_ROOT = Path(__file__).resolve().parent.parent


def sample_event(action: str = "finding.emitted", layer: int = 2, **kwargs):
    defaults = dict(
        layer=layer,
        actor="layer2.model:v1",
        action=action,
        input_reference="events://3-related",
        output_reference="finding://f-1",
        record_class=RecordClass.MODEL_INFERENCE,
        outcome=Outcome.SUCCESS,
        timestamp=datetime(2026, 1, 8, 1, 0, tzinfo=timezone.utc),
        case_id="CASE-test",
        asset_id="icu-monitor-gw",
        payload={"asset_id": "icu-monitor-gw", "subject": "icu-monitor-gw", "anomaly_score": 0.9},
    )
    defaults.update(kwargs)
    return new_audit_event(**defaults)


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="accds-layer6-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------
class AuditContractTests(unittest.TestCase):
    def test_required_fields_are_enforced(self):
        """The roadmap marks actor/timestamp/references/outcome as never-omit."""
        for missing in ("actor", "input_reference", "output_reference"):
            with self.subTest(field=missing):
                with self.assertRaises(ValueError):
                    sample_event(**{missing: ""})

    def test_naive_timestamps_are_rejected(self):
        with self.assertRaises(ValueError):
            sample_event(timestamp=datetime(2026, 1, 8, 1, 0))

    def test_round_trip_through_json(self):
        event = sample_event()
        restored = type(event).from_dict(json.loads(json.dumps(event.to_dict())))
        self.assertEqual(restored.audit_id, event.audit_id)
        self.assertEqual(restored.timestamp, event.timestamp)


# ---------------------------------------------------------------------------
# Tamper evidence
# ---------------------------------------------------------------------------
class TamperEvidenceTests(TempDirTest):
    def _store_with_records(self, count: int = 5, key: bytes | None = b"k"):
        store = TamperEvidentAuditStore(self.tmp / "chain.jsonl", key=key)
        for index in range(count):
            store.append(sample_event(output_reference=f"finding://f-{index}"))
        return store

    def test_intact_chain_verifies(self):
        store = self._store_with_records()
        result = store.verify()
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.records_checked, 5)

    def test_edited_record_is_detected(self):
        store = self._store_with_records()
        path = store.path
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[2])
        record["event"]["payload"]["anomaly_score"] = 0.01  # quietly downgrade a finding
        lines[2] = canonical_json(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = TamperEvidentAuditStore(path, key=b"k").verify()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_broken_sequence, 2)

    def test_deleted_record_is_detected(self):
        store = self._store_with_records()
        path = store.path
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = TamperEvidentAuditStore(path, key=b"k").verify()
        self.assertFalse(result.ok)

    def test_reordered_records_are_detected(self):
        store = self._store_with_records()
        path = store.path
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = TamperEvidentAuditStore(path, key=b"k").verify()
        self.assertFalse(result.ok)

    def test_keyed_chain_resists_recomputation(self):
        """Rewriting the file and recomputing hashes without the key still fails."""
        store = self._store_with_records(key=b"secret-key")
        path = store.path
        forged = TamperEvidentAuditStore(self.tmp / "forged.jsonl", key=None)
        for record in store.records():
            forged.append(record.event)
        shutil.copy(forged.path, path)

        self.assertFalse(TamperEvidentAuditStore(path, key=b"secret-key").verify().ok)


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------
class RedactionTests(unittest.TestCase):
    def test_pseudonyms_are_deterministic_and_correlatable(self):
        one = RedactionEngine(key=b"key-a")
        two = RedactionEngine(key=b"key-a")
        self.assertEqual(
            one.redact_record({"asset_id": "icu-monitor-gw"})["asset_id"],
            two.redact_record({"asset_id": "icu-monitor-gw"})["asset_id"],
        )

    def test_pseudonyms_change_with_the_key(self):
        a = RedactionEngine(key=b"key-a").redact_record({"asset_id": "icu-monitor-gw"})
        b = RedactionEngine(key=b"key-b").redact_record({"asset_id": "icu-monitor-gw"})
        self.assertNotEqual(a["asset_id"], b["asset_id"])

    def test_distinct_assets_get_distinct_tokens(self):
        engine = RedactionEngine(key=b"k")
        first = engine.redact_record({"asset_id": "icu-monitor-gw"})["asset_id"]
        second = engine.redact_record({"asset_id": "office-ws"})["asset_id"]
        self.assertNotEqual(first, second)

    def test_direct_patient_identifiers_are_dropped_not_pseudonymized(self):
        engine = RedactionEngine(key=b"k")
        result = engine.redact_record({"patient_id": "P-99812", "mrn": "MRN-4471"})
        self.assertNotIn("P-99812", canonical_json(result))
        self.assertNotIn("MRN-4471", canonical_json(result))
        self.assertIn("redacted", result["patient_id"])

    def test_identifiers_are_scrubbed_out_of_free_text(self):
        """Layer 3 writes prose containing asset IDs; structured rules alone miss it."""
        engine = RedactionEngine(key=b"k")
        record = {
            "asset_id": "icu-monitor-gw",
            "threat_summary": "Lateral movement from icu-monitor-gw toward 10.0.1.5",
        }
        result = engine.redact_record(record)
        self.assertNotIn("icu-monitor-gw", result["threat_summary"])
        self.assertNotIn("10.0.1.5", result["threat_summary"])

    def test_numeric_scores_are_not_mistaken_for_identifiers(self):
        """Layer 2 emits evidence.components.* as floats; they must survive intact."""
        engine = RedactionEngine(key=b"k")
        result = engine.redact_record({"evidence": {"components": {"peer": 0.4791666666666667}}})
        self.assertEqual(result["evidence"]["components"]["peer"], 0.4791666666666667)

    def test_operational_signal_is_retained(self):
        engine = RedactionEngine(key=b"k")
        result = engine.redact_record(
            {"asset_id": "office-ws", "clinical_tier": 3, "zone": "administration", "anomaly_score": 0.62}
        )
        self.assertEqual(result["clinical_tier"], 3)
        self.assertEqual(result["zone"], "administration")
        self.assertEqual(result["anomaly_score"], 0.62)


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------
class AccessControlTests(TempDirTest):
    def setUp(self) -> None:
        super().setUp()
        self.store = TamperEvidentAuditStore(self.tmp / "chain.jsonl", key=b"k")
        self.store.append(sample_event())
        self.engine = RedactionEngine(key=b"k")
        self.controller = AccessController(self.store, self.engine)

    def test_analyst_receives_a_redacted_view(self):
        result = self.controller.read(AccessRole.ANALYST, "soc", self.store.for_case("CASE-test"))
        self.assertEqual(result.view, ViewKind.OPERATIONAL.value)
        self.assertNotIn("icu-monitor-gw", canonical_json(result.records))

    def test_forensic_investigator_receives_raw_records(self):
        result = self.controller.read(AccessRole.FORENSIC_INVESTIGATOR, "j.a", self.store.for_case("CASE-test"))
        self.assertEqual(result.view, ViewKind.FORENSIC.value)
        self.assertIn("icu-monitor-gw", canonical_json(result.records))

    def test_every_access_is_itself_audited(self):
        before = len(self.store)
        result = self.controller.read(AccessRole.FORENSIC_INVESTIGATOR, "j.a", self.store.for_case("CASE-test"))
        self.assertEqual(len(self.store), before + 1)
        appended = self.store.records()[-1].event
        self.assertEqual(appended.audit_id, result.access_audit_id)
        self.assertEqual(appended.action, "evidence.read.forensic")
        self.assertTrue(self.store.verify().ok)

    def test_denied_access_is_recorded(self):
        before = len(self.store)
        self.controller.deny(AccessRole.ANALYST, "soc", ViewKind.FORENSIC, "role lacks forensic clearance")
        self.assertEqual(len(self.store), before + 1)
        self.assertEqual(self.store.records()[-1].event.outcome, Outcome.REJECTED.value)


# ---------------------------------------------------------------------------
# Timeline and reporting
# ---------------------------------------------------------------------------
class TimelineTests(unittest.TestCase):
    def test_records_are_ordered_and_bucketed_by_class(self):
        raw = [
            {"sequence": 1, "event": sample_event(layer=5, actor="layer5.reviewer:x",
                                                  record_class=RecordClass.HUMAN_DECISION,
                                                  timestamp=datetime(2026, 1, 8, 3, tzinfo=timezone.utc)).to_dict()},
            {"sequence": 0, "event": sample_event(layer=0, actor="layer0.ingestion",
                                                  record_class=RecordClass.OBSERVED_FACT,
                                                  timestamp=datetime(2026, 1, 8, 1, tzinfo=timezone.utc)).to_dict()},
        ]
        timeline = build_timeline(raw, case_id="CASE-test")
        self.assertEqual([entry.layer for entry in timeline.entries], [0, 5])
        self.assertEqual(len(timeline.buckets[RecordClass.OBSERVED_FACT.value]), 1)
        self.assertEqual(len(timeline.buckets[RecordClass.HUMAN_DECISION.value]), 1)


class ReportingTests(unittest.TestCase):
    def test_report_keeps_the_four_record_classes_apart(self):
        raw = [{"sequence": 0, "event": sample_event().to_dict()}]
        report = build_report(build_timeline(raw, case_id="CASE-test"))
        markdown = render_markdown(report)
        for title in ("Observed facts", "Model inferences", "Human decisions", "Actions taken"):
            self.assertIn(title, markdown)

    def test_no_network_adapter_is_available(self):
        """The reporting adapter must not be able to reach a real authority."""
        for adapter in get_adapter("null"), get_adapter("stdout"):
            self.assertFalse(adapter.performs_network_io)
        with self.assertRaises(ValueError):
            get_adapter("regulator_api")


# ---------------------------------------------------------------------------
# The roadmap's Layer 6 acceptance test, end to end
# ---------------------------------------------------------------------------
class AcceptanceTests(TempDirTest):
    @classmethod
    def setUpClass(cls):
        if not (REPO_ROOT / "findings.json").exists():
            raise unittest.SkipTest("Layer 2 artifacts are not present")

    def test_full_incident_timeline_from_one_scenario(self):
        result = run_pipeline(self.tmp / "run", scenario="port_scan", adapter_name="file")

        # A complete incident: every layer reported into the chain.
        completeness = result.metrics["audit_completeness"]
        self.assertEqual(completeness["layers_missing"], [])
        self.assertEqual(completeness["field_completeness"], 1.0)
        self.assertGreater(result.timeline_entries, 0)

        # Sensitive fields are redacted in the operational view.
        self.assertTrue(result.metrics["privacy"]["leak_scan"]["clean"],
                        result.metrics["privacy"]["leak_scan"]["leaked_terms"])

        # The chain of custody holds.
        self.assertTrue(result.metrics["chain_verification"]["ok"])

        # Authorized forensic users can trace each record to its source.
        self.assertEqual(result.metrics["explainability"]["traceability"], 1.0)

    def test_operational_view_hides_what_the_forensic_view_shows(self):
        run_pipeline(self.tmp / "run", scenario="port_scan", adapter_name="null")
        root = self.tmp / "run" / "evidence_package"
        operational = (root / "operational_view.jsonl").read_text(encoding="utf-8")
        forensic = (root / "forensic_records.jsonl").read_text(encoding="utf-8")

        self.assertIn("office-ws", forensic)
        self.assertNotIn("office-ws", operational)
        # The trace handle survives redaction so a record can still be looked up.
        first_audit_id = json.loads(operational.splitlines()[0])["event"]["audit_id"]
        self.assertIn(first_audit_id, forensic)

    def test_package_is_self_contained_and_verifies(self):
        """The report must live inside the package, not be referenced from outside."""
        result = run_pipeline(self.tmp / "run", scenario="port_scan", adapter_name="file")
        root = self.tmp / "run" / "evidence_package"
        verification = verify_evidence_package(root)
        self.assertTrue(verification["ok"], verification)
        self.assertEqual(verification["missing_files"], [])
        self.assertTrue((root / f"{result.case_id.replace('CASE', 'RPT-CASE')}.md").exists()
                        or any(path.suffix == ".md" for path in root.iterdir()))

    def test_evidence_package_detects_post_export_modification(self):
        result = run_pipeline(self.tmp / "run", scenario="exfiltration", adapter_name="null")
        root = self.tmp / "run" / "evidence_package"
        self.assertTrue(verify_evidence_package(root)["ok"])

        timeline_path = root / "incident_timeline.json"
        timeline_path.write_text(timeline_path.read_text(encoding="utf-8").replace("VERIFIED", "FAILED"),
                                 encoding="utf-8")
        verification = verify_evidence_package(root)
        self.assertFalse(verification["ok"])
        self.assertIn("incident_timeline.json", verification["modified_files"])

    def test_every_layer2_scenario_produces_a_clean_package(self):
        scenarios = ("port_scan", "new_peer", "exfiltration", "credential_misuse",
                     "off_hours", "diagnostic_drift", "benign_clinical_burst", "low_confidence")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result = run_pipeline(self.tmp / scenario, scenario=scenario, adapter_name="null")
                self.assertTrue(result.metrics["chain_verification"]["ok"])
                self.assertTrue(result.metrics["privacy"]["leak_scan"]["clean"],
                                result.metrics["privacy"]["leak_scan"]["leaked_terms"])
                self.assertEqual(result.metrics["audit_completeness"]["layers_missing"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
