# ACCDS Layer 6 Implementation Report

## Result

Layer 6 (Compliance & Privacy) is implemented in [`compliance/`](compliance/). It receives
records from every other layer, maintains a tamper-evident chain of custody, applies privacy
controls before anything reaches an operational view, reconstructs incident timelines, and
produces evidence packages and standardized reports.

It runs today against the artifacts Layer 2 already produced. It is stdlib-only — no
third-party dependency, no install step.

## Implemented components

| Component | Implementation |
|---|---|
| Audit contract | `AuditEvent`, the cross-cutting `All layers → Layer 6` handoff, with the roadmap's five must-never-omit fields validated as non-empty |
| Tamper-evident store | Append-only JSONL where each record hashes the previous one; SHA-256, or HMAC when keyed |
| Chain verification | Replays the chain from disk and names the first broken sequence number |
| Redaction engine | Field-level policy (keep / pseudonymize / mask / drop / generalize) applied at any depth |
| Pseudonymization | Keyed HMAC, deterministic, non-reversible; correlation survives, identity does not |
| Free-text scrubber | Removes known identifiers plus IPv4/email/MAC patterns from prose fields |
| Leak scanner | Re-serializes the finished operational view and asserts no raw identifier survived |
| Two-view separation | Forensic (full fidelity) and operational (minimized); `audit_id` is the operational trace handle |
| Access control | Role → view resolution, with every read *and every refusal* appended to the same chain |
| Timeline builder | Ordered narrative plus the roadmap's four record-class buckets |
| Evidence packages | Self-contained export with a SHA-256 manifest and standalone verification |
| Reporting | Markdown and JSON reports; `file`, `stdout` and `null` adapters |
| Metrics | Redaction coverage, leak count, audit completeness, layer coverage, traceability |
| Safety boundary | Record-keeping only; no enforcement, no approval, no network I/O, no regulatory adapter |

## Acceptance run

```bash
python3 -m compliance.cli demo --scenario port_scan --output artifacts/layer6
python3 -m compliance.cli all  --output artifacts/layer6-all
python3 -m unittest discover -s tests -t .
```

The test suite completed with **27 passed**. The full sweep across all eight Layer 2
scenarios exited 0.

### Roadmap acceptance test

> *"Generate a complete incident timeline from one scenario and verify that sensitive fields
> are redacted in the operational view while authorized forensic users can trace each record
> to its source."*

Result for the `port_scan` case (27 timeline records, 29 chain records including the two
audited accesses):

| Measure | Result |
|---|---|
| Audit chain | VERIFIED — 29 records, chain intact |
| Layer coverage | 1.0 — layers 0 through 6 all reported |
| Required-field completeness | 1.0 — 27/27 records |
| Traceability to source | 1.0 — 27/27 records carry input and output references |
| Sensitive instances handled | 195 (139 pseudonymized, 20 dropped, 35 free-text substitutions, 1 generalized) |
| Leak scan | **0 leaks** across 76 checked terms |

All eight scenarios pass with chain intact, layer coverage 1.0 and zero leaks.

### Worked example

The same Layer 0 observation, in each view:

```
forensic    {"subject": "office-ws", "src": "office-ws", "dst": "port-1",
             "event_id": "port_scan-office-ws-000001",
             "raw_reference": "synthetic://port_scan/1", "zone": "administration"}

operational {"subject": "subject~5b742933679e", "src": "network~c435e8c8d745",
             "dst": "network~ddc2e66e50ef", "event_id": "event~e6e5dbef37b0",
             "raw_reference": "[redacted: forensic pointer; trace via audit_id]",
             "zone": "administration"}
```

Clinical tier, zone and scores survive because they are what makes the operational view
useful. The `audit_id` is identical in both, so an authorized investigator can pivot from a
redacted record to its source.

Free-text scrubbing matters in practice: Layer 2's finding ID embeds the asset name, and it
is rewritten to `finding-000366-asset~6ca5b1ee26c5-202601080000` in the operational view.
Structured field rules alone would have leaked it.

## Verified failure modes

| Attack on the record | Detected by |
|---|---|
| Editing a finding's score in place | `verify()` — names sequence 2 |
| Deleting a record | `verify()` — chain break |
| Reordering records | `verify()` — chain break |
| Rewriting the file and recomputing plain hashes | keyed HMAC chain |
| Modifying an exported package after the fact | `verify_evidence_package()` |

## Files to inspect first

Start with [`compliance/README.md`](compliance/README.md), then `contracts.py` (the contract
other layers must adopt), `redaction.py` and `audit_store.py`. Generated output is under
`artifacts/layer6/`, especially `evidence_package/manifest.json` and the `RPT-*.md` report.

## Limitations and next steps

Layers 0, 1, 4 and 5 do not exist yet. Layer 0 and Layer 1 records are reconstructed from the
asset context the Layer 2 synthetic generator bakes into its events; Layer 3, 4 and 5 records
come from `compliance/upstream_stubs.py`, where every record carries
`"_source": "placeholder-until-layer-implemented"`. Their field names match
`src/schemas/contracts.py` and the roadmap handoffs, so replacing them should be a change of
import in `pipeline.py`, not a change of shape.

Three items are deferred deliberately and need a team decision:

1. **Key management.** `DEFAULT_PSEUDONYM_KEY` is a hard-coded demo constant. It must move to
   a configured secret before this is shown as a privacy control, and key rotation breaks
   correlation with previously exported material.
2. **Retention and deletion policy.** The store is append-only with no retention window. A
   real deployment needs a documented retention period and a lawful-deletion path that does
   not break the chain (tombstone records rather than removal).
3. **The audit contract is cross-cutting.** Every other layer must emit `AuditEvent`. Until
   they do, Layer 6 is reconstructing their records rather than receiving them.
