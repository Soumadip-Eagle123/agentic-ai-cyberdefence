# ACCDS Layer 6 — Compliance & Privacy

The secure diary and reporter. Layer 6 receives records from **every** other layer,
keeps a tamper-evident chain of custody, applies privacy controls before anything
reaches an operational view, reconstructs incident timelines, and produces evidence
packages and standardized reports.

**Safety boundary:** this package is record-keeping only. It issues no containment,
enforcement or approval commands, and it performs no network I/O. No reporting
adapter can reach a real authority.

## Run it

Stdlib only — Python 3.12+, no install required. From the repository root:

```bash
# Full pipeline for one scenario
python3 -m compliance.cli demo --scenario port_scan --output artifacts/layer6

# Every Layer 2 scenario
python3 -m compliance.cli all --output artifacts/layer6-all

# Verify a chain / an exported package
python3 -m compliance.cli verify --store artifacts/layer6/audit_chain.jsonl
python3 -m compliance.cli verify-package --package artifacts/layer6/evidence_package

# Acceptance tests
python3 -m unittest discover -s tests -t .
```

The demo exits non-zero if the audit chain fails verification or the leak scan finds
anything, so it works as a CI gate.

## Modules

| Module | Purpose |
|---|---|
| `contracts.py` | The cross-cutting `AuditEvent` every layer emits, plus roles, views and timeline types |
| `audit_store.py` | Append-only hash-chained store (SHA-256, or HMAC with a key) and `verify()` |
| `redaction.py` | Field policy, deterministic keyed pseudonyms, free-text scrubber, leak scanner |
| `access.py` | Role → view resolution; every read and refusal is itself audited |
| `ingest.py` | Adapters turning each layer's native record into an audit event |
| `timeline.py` | Incident timeline reconstruction and the four record-class buckets |
| `evidence.py` | Evidence package export with a SHA-256 manifest, and package verification |
| `reporting.py` | Standardized report, Markdown/JSON rendering, dispatch adapters |
| `metrics.py` | Redaction coverage, leak scan, audit completeness, traceability |
| `pipeline.py` | End-to-end run over the repository's existing artifacts |
| `upstream_stubs.py` | Marked stand-ins for Layers 3, 4 and 5 until those exist |

## The audit event

This is the `All layers → Layer 6` handoff. Every layer calls `new_audit_event(...)`.
`actor`, `timestamp`, `input_reference`, `output_reference` and `outcome` are validated
as non-empty because the roadmap marks them must-never-omit.

```python
from compliance import new_audit_event, RecordClass, Outcome

event = new_audit_event(
    layer=4,
    actor="layer4.enforcement",
    action="enforcement.applied",
    input_reference="decision://DEC-9f2c",
    output_reference="action://ACT-71ab",
    record_class=RecordClass.ACTION_TAKEN,
    outcome=Outcome.SUCCESS,
    case_id="CASE-b22e",
    payload=enforcement_result,
)
store.append(event)
```

Layers already using pydantic should import the mirror in
[`src/schemas/contracts.py`](../src/schemas/contracts.py) instead — same field names,
same JSON wire format.

## The two views

| | Forensic view | Operational view |
|---|---|---|
| Who | `forensic_investigator` only | `analyst`, `auditor`, `external_reporter` |
| Content | Full fidelity, unmodified | Pseudonymized and minimized |
| Raw pointers | `raw_reference` retained | Dropped; `audit_id` is the trace handle |

Pseudonyms are keyed HMAC and therefore **deterministic**: `office-ws` is always
`asset~6ca5b1ee26c5` under a given key, so an analyst can correlate across a thousand
records without learning which machine it is. Rotating the key breaks correlation
with previously exported material — intended, but plan rotations deliberately.

Structured field rules alone are not enough: Layer 3 writes prose such as
*"...in zone 'Intensive Care Unit' for asset DEV-ICU-MONITOR-01"*, so every surviving
string is also scrubbed against known identifiers plus IPv4/email/MAC patterns.
`metrics.leak_scan()` re-serializes the finished operational view and asserts that
no raw identifier survived. It must report zero.

## Tamper evidence

Each record commits to the one before it:

```
record_hash = H(previous_hash | canonical_json(event))
```

Editing, deleting or reordering any record breaks every hash after it, and
`verify()` names the first bad sequence number. Passing a `key` upgrades `H` from
SHA-256 to HMAC, which also defeats an attacker who can rewrite the file and
recompute the plain hashes.

## Acceptance status

The roadmap's Layer 6 acceptance test is *"generate a complete incident timeline from
one scenario and verify that sensitive fields are redacted in the operational view
while authorized forensic users can trace each record to its source."*

Verified for all eight Layer 2 scenarios: chain intact, layer coverage 1.0,
traceability 1.0, leak count 0. See `tests/test_layer6.py`.

## Known limitation

Layers 0, 1, 4 and 5 do not exist yet. Layer 0/1 records are reconstructed from the
Layer 2 synthetic generator's enriched events, and Layer 3/4/5 records come from
`upstream_stubs.py`, where every record is tagged `"_source":
"placeholder-until-layer-implemented"`. Replacing them is a change of import in
`pipeline.py`, not a change of shape.
