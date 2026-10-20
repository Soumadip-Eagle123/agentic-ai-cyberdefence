# ACCDS — Pipeline Fixes, Digital Twin & Topology View

Branch: `fix/event-correlation` → targets `working-branch`

---

## The one-line version

**A life-critical ICU device could be attacked and the system would auto-approve containment without ever asking a human.** That is fixed, along with eleven other defects, and the hospital is now a real digital twin with a visual attack replay.

---

## Why this matters

The project exists to answer one question: *what is the least disruptive effective response to this threat, given what this device does for patient care — and when do we stop and ask a human?*

Clinical tier is what decides that. Before these changes, tier was being read off the **wrong device**, so the safety architecture was being bypassed silently.

---

## Before and after

Same attack, same code path, six stages from reception desk to intensive care.

| | Before | After |
|---|---|---|
| Stages producing findings | **4 of 6** | **6 of 6** |
| ICU devices identified | **0** | **2** (both Tier 1) |
| Correlated cases | **2** (campaign split) | **1** (one campaign) |
| Attack chain detected | **No** — rule could never fire | **Yes**, 7 hops |
| Tier of the ICU exploit | **Tier 3** (the attacker's laptop) | **Tier 1** (the patient monitor) |
| Human approval for Tier 1 | **Not asked** | **Required** |
| Layer 2 scores | hardcoded `[0.60, 0.72, …]` | computed, `0.45 → 0.99` |
| Approval signature | `sha256("")` — binds nothing | binds the actual action |
| Devices in inventory | 3 | 12 |
| Unresolved addresses | 2 silently dropped | 0 |

**The detected attack path, after the fix:**

```
office-ws → admin-print → radiology-ws → pacs → lab-server → icu-monitor-gw → icu-controller
  Tier 3       Tier 3        Tier 2       T2      Tier 2         TIER 1          TIER 1
```

One case. Six findings. Human approval demanded. That whole chain was previously invisible.

---

## The 12 fixes

### Bugs

**1. Layer 1 identified the attacker, not the victim** — *safety-critical*

[`src/asset_intelligence/layer1_asset_intelligence.py`](src/asset_intelligence/layer1_asset_intelligence.py)

```python
# before — src is the ATTACKER in an attack
asset = self.asset_registry.get(event.src) or self.asset_registry.get(event.dst)
# after — the device at risk is the destination
victim = hospital.get(event.dst); attacker = hospital.get(event.src)
```

An exploit fired at the ICU gateway resolved to the attacker's Tier 3 laptop, so Layer 3 concluded *"LOW: all affected assets are non-clinical Tier 3, rapid isolation allowed"* and auto-approved. The source fallback still matters: in a port sweep or an upload to the internet the destination isn't a hospital asset, and the device worth reporting is the sender.

**2. The lateral-movement chain rule could never fire**

[`src/orchestration/layer3_orchestrator.py`](src/orchestration/layer3_orchestrator.py)

It compared `attacker_src` (a raw address like `"10.0.2.10"`) against `affected_assets` (asset IDs like `"lab-server"`). Different namespaces — the condition was a coin that always landed tails. Layer 1 now resolves both ends, findings carry `attacker_asset_id`, and the comparison is asset-ID to asset-ID.

**3. Events vanished silently**

An address missing from the inventory ended the whole stage — no finding, no correlation, no audit record. Two of six stages disappeared, including the pivot onto a *second* life-critical device. Unknown devices now produce a placeholder asset at **Tier 2** (we can't prove an unidentified device is non-clinical) with **identity confidence 0.2**, which lowers response confidence rather than triggering aggressive action. `visibility_report()` surfaces what the inventory couldn't account for.

**4. The approval signature signed nothing**

`scope_hash` was the hardcoded constant `e3b0c442…b7852b855` — verified as `sha256("")`. Any action matched it. Now wired to `Layer5DecisionGate.compute_scope_hash()`, which hashes the real case, assets, actions and clinical impact.

### Wiring — four working components were never imported

**5. Layer 2 detector** — [`src/detection/layer2_detector.py`](src/detection/layer2_detector.py)

Scores were a literal array indexed by stage number; stage 1 always scored 0.60 regardless of content. Now learns a per-device baseline from 24h of normal traffic (333 events, 11 devices) and scores on five explainable components: event type, unknown peer, volume z-score, off-hours, clinical tier.

**6. Layer 4 enforcer** — was a hand-typed dict that ignored the proposal entirely.

**7. Layer 5 decision gate** — `main.py` had its own inline prompt. Wiring the real gate fixed #4 for free.

### Digital twin

**8–9. Inventory: 3 devices → 12**, across 6 zones, each with **both an IP and a name**. Every address the scenarios reference now resolves. This is the root fix for #3. Added: PACS server, lab analyzer, admin gateway, admin printer, radiology tech endpoint.

**10. Attacks are written as paths, not log entries**

```python
Stage("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT", "lateral_movement"),
```

A new scenario is three lines instead of fifty, and the chain structure (stage N's victim becomes stage N+1's attacker) is explicit — which is exactly what correlation looks for.

**11. `main.py` reads from the twin** — one source of truth, no more private dictionary.

**12. Normal traffic baseline** — Layer 2 detects *deviation from normal*; with no baseline there was nothing to deviate from, which is why scores had to be hardcoded in the first place. Tier 1 devices chatter around the clock (life support); office equipment goes quiet outside working hours.

---

## Five more defects found while fixing those

**13. `AuditEvent` was declared twice** in `src/schemas/contracts.py`. Python rebinds the name, so the second silently replaced the first — anything importing it got a model missing `layer`, `record_class` and `outcome`, the fields the Layer 6 chain requires.

**14. Correlation window used wall-clock, not event time.** Replaying history processes every stage in milliseconds, so the 15-minute window never expired and only *appeared* to work. A multi-day campaign would have collapsed into one case; a slow run would have split one campaign into several.

**15. Containment preserved the wrong protocol.** Every Tier 1/2 action preserved HL7 port 2575 — including on a PACS imaging server, which speaks DICOM. The block would have looked surgical and still taken imaging offline. Now each device's preserved flows are derived from the services it actually runs.

**16. Enforcement reported an arbitrary target.** `affected_assets[0]` comes from a set, so a campaign reaching intensive care could be reported against a Tier 3 printer. Now reports the most clinically critical asset.

**17. Detection scores saturated, erasing clinical tier.** Both an exploit against a printer and one against a patient monitor hit the 0.99 cap. The behavioural components are now capped at 0.84 so tier weight always moves the score — restoring exactly the distinction the system exists to make.

**18. Layer 2 baselines only learned outbound traffic.** Profiles were keyed by sender, so ordinary *received* traffic read as 502 standard deviations from a distribution never measured. Flows now train both endpoints.

**19. The peer check asked whether a device may talk to itself.** When the asset under assessment was the destination, the check compared `dst` against that same device's allowed peers — flagging every inbound flow as an unauthorised peer. It now checks the *counterpart*. This is what made the benign-burst false-positive test fail.

**20. Layer 5 used deprecated naive `datetime.utcnow()`**, which the Layer 6 audit contract rejects outright.

**21. `tests/test_layer6.py` imported `compliance.*`** but Layer 6 lives at `src/compliance/` on this branch, so the whole module failed to load.

---

## New files

| Path | What it is |
|---|---|
| [`digital_twin/hospital.py`](digital_twin/hospital.py) | 12 devices, 6 zones, tiers, peers, IPs, room layout |
| [`digital_twin/scenarios.py`](digital_twin/scenarios.py) | 4 campaigns as attack paths + normal traffic generator |
| [`visualiser/build.py`](visualiser/build.py) | Builds the self-contained topology HTML |
| [`visualiser/session.py`](visualiser/session.py) | Resident pipeline session for the live console |
| [`visualiser/server.py`](visualiser/server.py) | Stdlib HTTP server exposing the pipeline as JSON |
| [`visualiser/live.html`](visualiser/live.html) | Interactive attack console |
| [`tests/test_pipeline.py`](tests/test_pipeline.py) | 41 regression tests, one per defect |
| [`tests/test_session.py`](tests/test_session.py) | 22 tests for the live session |

---

## Test results

```
85 tests, 84 pass, 1 skipped          (41 pipeline + 22 session + 22 Layer 6)
4/4 campaigns run end to end
chain integrity: VERIFIED (56 records)
leak scan: clean
unresolved addresses: 0
```

The skip is a Layer 6 acceptance test that needs `findings.json`; this branch carries the older Layer 6 copy without the data-source locator.

---

## How to run it

```bash
python3 -m venv agentic_venv
agentic_venv/bin/pip install pydantic

PYTHONPATH=. agentic_venv/bin/python main.py                 # interactive
PYTHONPATH=. agentic_venv/bin/python main.py --approve       # auto-approve
PYTHONPATH=. agentic_venv/bin/python main.py --no-input      # auto-reject
PYTHONPATH=. agentic_venv/bin/python main.py --list          # list campaigns

agentic_venv/bin/python -m visualiser.build                  # static replay view
xdg-open artifacts/full_run/topology.html

PYTHONPATH=. agentic_venv/bin/python -m visualiser.server    # live attack console

PYTHONPATH=. agentic_venv/bin/python -m unittest discover -s tests -t .
```

**Campaigns:** `lateral_to_icu` (6 stages, reaches Tier 1), `ransomware_spread` (3), `exfiltration` (2), `benign_clinical_burst` (false-positive test — should raise **zero** findings).

---

## The live attack console

```bash
PYTHONPATH=. agentic_venv/bin/python -m visualiser.server
```

Opens `http://127.0.0.1:8000`. You are the attacker: pick a source device, a
target, and an attack type, then watch all seven layers respond with **real**
scores — the same Layer 0-5 code `main.py` runs, behind a small JSON API.

The session is stateful on purpose. Compromise the lab server, then attack the
ICU *from* it, and Layer 3 recognises the second attack as the next hop of the
same campaign rather than a fresh incident. That accumulation is the thing the
static replay cannot show.

| Endpoint | Does |
|---|---|
| `POST /api/attack` | runs one attack through Layers 0-5 |
| `POST /api/decision` | records a human approve/reject at Layer 5 |
| `POST /api/campaign` | replays a scripted campaign, stopping at the gate |
| `POST /api/reset` | clears the session and retrains the baseline |

Standard library only. Binds to localhost by default — it exposes an attack
simulator and a decision gate, and neither belongs on a shared interface.

**Worked example, live:**

```
office-ws  -> lab-server       MALWARE_STAGING   risk 0.89   Tier 2  -> held for approval
  approve                                                             -> APPLIED
lab-server -> icu-monitor-gw   EXPLOIT_ATTEMPT   risk 0.97   TIER 1  -> same case, 2 findings
                                                   chain: office-ws -> lab-server -> icu-monitor-gw
```

## The static topology view

A hospital floor of six zone rooms with devices inside, and the attack replaying across it.

**Rooms group by zone** because "the attack crossed from administration into intensive care" is the fact a viewer should grasp instantly. **The lines are network reachability, not walls** — `ehr-core` sits in one room and legitimately reaches the whole hospital; `guest-device` could be metres from the ICU and must never reach it. Drawing physical adjacency would show the wrong graph.

- **Grey lines** — permitted baseline links
- **Red curves** — attack traffic, numbered in order
- **Ring thickness/colour** — Tier 1 red and largest, Tier 2 amber, Tier 3 blue
- **Play / Step / scrubber** — replay the campaign
- **Click any device** — asset context: tier, vendor, software version, fallback mode, services, reachable peers, clinical constraints
- **Banner** — the Layer 5 decision and Layer 4 outcome

Self-contained HTML. No server, no build step, no dependencies.

---

## What's still open

1. **Reconcile the two Layer 6 copies.** `origin/Madhusudhan` has 18 modules including key management, retention/tombstone erasure and FIPS 204 ML-DSA signing. This branch has the older 13-module copy at `src/compliance/`.
2. **Three competing `ResponseProposal` definitions** still exist (`src/schemas/contracts.py`, `src/decision_gate/models.py`, and the gate's internal model).
3. **`artifacts/` is still tracked** on this branch — ~90 generated files that churn on every run.
4. **Rollback is implemented but never exercised** by `main.py`; auto-expiry isn't demonstrated.
5. **The live console holds one session per process** — fine for a demo, not for concurrent users.

---

## Note for review

The Layer 1 change alters which asset **every** finding is attributed to. Outputs in the earlier `concurrent_multi_device_attack_simulations` PDF will not reproduce: Tier 3 findings become Tier 1, and scenario 1 now demands human approval where it previously auto-approved.

**That is the fix, not a regression.**
