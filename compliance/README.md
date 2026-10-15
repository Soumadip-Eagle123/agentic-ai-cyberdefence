# ACCDS Layer 6 — Compliance & Privacy

The secure diary and reporter. Layer 6 receives records from **every** other layer,
keeps a tamper-evident chain of custody, applies privacy controls before anything
reaches an operational view, reconstructs incident timelines, and produces evidence
packages and standardized reports.

**Safety boundary:** this package is record-keeping only. It issues no containment,
enforcement or approval commands, and it performs no network I/O. No reporting
adapter can reach a real authority.

## Run it

Stdlib only — Python 3.12+, no install required (ML-DSA signing is the one optional
extra, and Layer 6 runs without it). From the repository root:

```bash
# Full pipeline for one scenario
python3 -m compliance.cli demo --scenario port_scan --output artifacts/layer6

# Every Layer 2 scenario
python3 -m compliance.cli all --output artifacts/layer6-all

# Verify a chain / an exported package
python3 -m compliance.cli verify --store artifacts/layer6/audit_chain.jsonl
python3 -m compliance.cli verify-package --package artifacts/layer6/evidence_package

# Acceptance tests (61)
python3 -m unittest discover -s tests -t .

# Key provenance, data location, ML-DSA availability
python3 -m compliance.cli keys

# Retention status, and lawful erasure by sequence number
python3 -m compliance.cli retention --store artifacts/layer6/audit_chain.jsonl
python3 -m compliance.cli retention --erase 3 --actor dpo:k.raman --reason "erasure request #4471"

# Post-quantum signed checkpoint (FIPS 204)
python3 -m compliance.cli demo --signer mldsa --output artifacts/layer6-pq
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
| `keys.py` | Separate chain and pseudonym keys, resolved from env/file, with a managed-key gate |
| `retention.py` | Retention windows and tombstone erasure that does not break the chain |
| `signing.py` | Pluggable checkpoint signer: HMAC by default, FIPS 204 ML-DSA optionally |
| `emitter.py` | The one call other layers make to report into Layer 6 |
| `datasources.py` | Locates Layer 2's artifacts wherever they currently live |
| `upstream_stubs.py` | Marked stand-ins for Layers 3 and 4 until those exist |

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
traceability 1.0, leak count 0. 61 tests across `tests/test_layer6.py` (contract,
tamper evidence, privacy, access control, reporting, acceptance) and
`tests/test_layer6_hardening.py` (keys, retention, signing, emitter, data sources,
the Layer 5 bridge).

## Key management

Two independent keys, and the code refuses to let them be the same value: anyone
who can verify the chain must not thereby be able to reverse every pseudonym.

```bash
export ACCDS_CHAIN_KEY="..."       # authenticates the audit chain
export ACCDS_PSEUDONYM_KEY="..."   # derives operational pseudonyms
# or: export ACCDS_KEY_FILE=/path/to/keys.json
```

Without them, Layer 6 falls back to clearly-labelled development keys and says so
in every run. Pass `--require-managed-keys` (or `require_managed_keys=True`) to
fail closed instead. Exports record a salted *fingerprint* of each key, never the key,
so two exports can be told apart without revealing the secret.

Rotating the pseudonym key breaks correlation with previously exported material.
That is intended, but plan rotations deliberately.

## Retention and lawful erasure

An append-only chain and a right-to-erasure request pull against each other:
deleting a record breaks every hash after it. Layer 6 resolves this with
**tombstones** — the record stays in place so the chain still verifies, its payload
is replaced by a keyed digest commitment, and the erasure is itself audited.

An authorized investigator holding a copy from elsewhere can confirm what *was*
there via `verify_erasure()`, without the store retaining the content.

One consequence to plan for: erasure rewrites the chain, so the head hash changes
and evidence packages exported *before* the erasure will no longer match the new head.

## Checkpoint signing

The chain already binds every record to its predecessor, so one signature over the
chain head certifies everything beneath it. Layer 6 signs checkpoints per case and
per export rather than signing every record.

| Signer | Proves | Third-party verifiable | Cost |
|---|---|---|---|
| `hmac` (default) | someone with the key wrote it | no | 32 B |
| `mldsa` (FIPS 204, ML-DSA-65) | *which layer* wrote it | **yes** | 3,309 B |

ML-DSA is optional: it needs `cryptography` built against OpenSSL 3.5+, and Layer 6
keeps working without it. Choosing a post-quantum scheme is deliberate — clinical
records carry multi-decade retention, and a classical signature on a record still
held in 2050 is a retroactive-forgery risk.

An ML-DSA package carries its own public key, so `verify-package` validates the
signature with no shared secret at all. Note the three-state result: `valid`,
`rejected`, and `unverifiable` — "I have no key to check this" is never reported
as "this is forged".

## How other layers report in

```python
from compliance import emitter

emitter.configure("artifacts/accds/audit_chain.jsonl")   # once, at startup
emitter.emit(
    layer=4, actor="layer4.enforcement", action="enforcement.applied",
    input_reference="decision://DEC-9f2c", output_reference="action://ACT-71ab",
    record_class="action_taken", payload=result,
)
```

`emit` does not raise on a malformed record by default — a bad audit call must not
take down enforcement or detection. Failures are counted and reported by
`emitter.failures()`; pass `strict=True` in tests to surface them.

## Known limitation

Layers 0, 1 and 4 do not exist yet. Layer 0/1 records are reconstructed from the
Layer 2 synthetic generator's enriched events, and Layer 3/4 records come from
`upstream_stubs.py`, where every record is tagged `"_source":
"placeholder-until-layer-implemented"`.

Layer 5 is real: `ingest.decision_gate_to_audit()` consumes an actual
`decision_gate.models.DecisionRecord`, absorbing two mismatches on Layer 5's behalf —
its naive `datetime.utcnow()` timestamps are read as UTC, and its lowercase decision
verbs map onto the outcome vocabulary, with unknown verbs escalating rather than
silently succeeding.
