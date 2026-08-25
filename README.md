# ACCDS — Autonomous Clinical Cybersecurity Defense System

**Prepared by:** Manus AI
**Context:** A layered cybersecurity defense architecture designed to operate inside a digital twin of a hospital network.

---

## 1. Executive Overview

ACCDS is a cybersecurity defense system built to run inside a **digital twin of a hospital network** — a simulator representing departments, devices, users, data flows, and attack scenarios without requiring real MRI machines, patient monitors, or live hospital infrastructure.

**Core design principle:** ACCDS must protect clinical operations first. Every security action must be:
- **Proportional** to the threat
- **Reversible** where possible
- **Aware** of the clinical criticality of the affected asset

### Core Design Rules

| Design Rule | Meaning in Implementation |
|---|---|
| Observe before acting | Layer 0 collects data passively; enforcement is not mixed with collection |
| Know the asset before judging it | Detection results are enriched with device identity and clinical criticality |
| Detect behavior, not only signatures | The model learns expected communication patterns and flags deviations |
| Use agents for coordination, not uncontrolled autonomy | Agents propose and coordinate actions under explicit policies |
| Protect patient safety | Life-critical assets receive surgical blocking or human approval instead of blind isolation |
| Keep evidence | Every observation, decision, action, approval, and rollback is auditable |

---

## 2. System Boundary — The Digital Twin

The digital twin is the safe lab environment for development. It must model a hospital at the level needed for **cybersecurity decisions**, not full medical fidelity.

**Zones included:** Intensive care, radiology, laboratory, pharmacy, administration, guest/public access, and a security operations center.

**Attack scenarios generated:** Credential theft, ransomware propagation, port scanning, lateral movement, data exfiltration, denial-of-service, and misuse of unpatchable devices.

| Twin Object | Minimum Attributes | Why ACCDS Needs It |
|---|---|---|
| Simulated device | ID, type, vendor, software, IP, zone, clinical tier | Establishes identity and response constraints |
| Simulated user | Role, department, permissions, session history | Distinguishes expected access from abuse |
| Data flow | Source, destination, protocol, volume, time, purpose | Feeds behavior baselines and policy checks |
| Clinical service | Patient-care dependency, availability target, fallback mode | Prevents unsafe disruption |
| Attack scenario | Initial access, actions, indicators, expected impact | Enables repeatable evaluation/regression testing |

---

## 3. Layered Architecture at a Glance

The six-layer path is a **controlled feedback loop**, not a simple pipeline. Evidence moves upward (observation → decision); policies and approved controls move downward (decision → enforcement). The dashboard/audit layer feeds labels back to improve detection — without letting an agent silently rewrite safety rules.

| Layer | Name | Primary Objective | Main Output |
|---|---|---|---|
| 0 | Data Ingestion | Collect trustworthy telemetry without disrupting the twin | Normalized event stream |
| 1 | Asset Intelligence | Identify every asset and its clinical importance | Asset and criticality context |
| 2 | ML Behavioral Model | Detect deviations from expected behavior | Anomaly and risk findings |
| 3 | Multi-Agent Orchestration | Correlate findings and design a response plan | Explainable response proposal |
| 4 | Containment & Enforcement | Apply the safest effective technical control | Action result and rollback point |
| 5 | Decision Gate | Require human approval for high-risk actions | Approval, rejection, or escalation |
| 6 | Compliance & Privacy | Protect telemetry and preserve evidence | Redacted audit trail and reports |

A **Safety Control Plane** (patient-safety policy, fail-safe rollback, simulation-first testing) constrains Layers 3–5 throughout.

---

## 4. Layer-by-Layer Detail

### Layer 0 — Data Ingestion *("the eyes and ears")*

**Objective:** Collect network traffic metadata, system logs, identity events, simulated EHR messages, device status, and scenario signals — visibility without interference.

- **Receives:** Packets/flow records, logs, device messages, authentication events, process/service events, simulator time (via multiple adapters).
- **Must do:** Timestamp events, validate format, assign source ID, deduplicate, convert to a common schema. Preserve raw events for forensic replay while producing a normalized copy. Report *reduced visibility* if a source drops — never silently assume no activity.
- **Passes to Layer 1:** A normalized event with `event_id`, `timestamp`, `source`, `event_type`, `subject`, `src`, `dst`, `protocol`, `bytes`, `zone`, `scenario_id`, `raw_reference`. Must be append-only and traceable.
- **Acceptance test:** Replaying the same scenario twice must yield deterministic, correctly ordered events with no loss or duplication.

### Layer 1 — Asset Intelligence *("the master inventory")*

**Objective:** Convert observations into asset knowledge — discover devices, link observations to one identity, record vendor/software info, and assign a clinical criticality tier. Ensures an office laptop and a life-support simulator never get treated the same.

**Criticality Tiers:**

| Tier | Example in the Twin | Default Response Posture |
|---|---|---|
| 1 | Patient-monitor gateway, intensive-care controller | Surgical blocking; human approval for disruptive actions |
| 2 | Laboratory server, radiology workstation | Contain narrowly; approval depends on scope/confidence |
| 3 | Office endpoint, guest device | Rapid isolation normally permitted by policy |

- **Passes to Layer 2:** Asset context with `asset_id`, `asset_type`, `owner_zone`, `vendor`, `software_version`, `clinical_tier`, `known_constraints`, `allowed_peers`, `normal_services`, `fallback_mode`, `last_seen`, plus identity-match confidence. Low confidence must *lower* response aggressiveness, not raise it.
- **Acceptance test:** An inventory report must explain why every asset got its tier, and a tier change must change permitted response options.

### Layer 2 — ML Behavioral Model *("the behavioral brain")*

**Objective:** Learn normal behavior for devices, users, zones, and clinical services; detect anomalies such as unexpected scanning, unusual peers, abnormal data volume, credential misuse, or a diagnostic device acting like a discovery tool.

- Favor **transparent, explainable** features over black-box models — statistical thresholds, peer-group comparisons, and a lightweight anomaly detector as a baseline. Must support replay, versioning, and anomaly-vs-confirmed-attack distinction.
- **Receives:** Normalized events (Layer 0) enriched with asset context (Layer 1), historical/training data, scenario labels, analyst feedback.
- **Produces:** A finding with `finding_id`, `asset_id`, `behavior_window`, `anomaly_score`, `risk_score`, `indicators`, `baseline_version`, `confidence`, `related_events`, `recommended_observation_period`.
- **Passes to Layer 3:** The finding plus clinical tier, constraints, zone, suspected attack stage, confidence. **Layer 2 never issues enforcement commands directly** — it produces evidence, not orders.
- **Acceptance test:** Measure detection precision, false positives, latency, and performance *separately* per tier (1/2/3).

### Layer 3 — Multi-Agent Orchestration *("the AI team")*

**Objective:** Coordinate specialized, narrow, auditable agents (zone analyst, clinical safety agent, threat correlation agent, policy agent, response planner) that reason about different responsibilities.

- Agents exchange **structured messages**, not free text. The orchestrator maintains a case record, correlates findings, checks clinical constraints via the safety agent, and generates one response proposal with alternatives.
- Agents can *recommend* actions (e.g., a virtual shield), but only policy-controlled components convert a recommendation into an executable action.
- **Receives:** Findings (Layer 2), asset/clinical context (Layer 1), current policy, active scenarios, recent actions, and current safety mode (normal / heightened monitoring / emergency containment).
- **Passes to Layers 4 & 5:** A response proposal with `case_id`, `threat_summary`, `affected_assets`, `candidate_actions`, `clinical_impact`, `confidence`, `reason`, `approval_level`, `expiry_time`, `rollback_plan`. Must distinguish auto-executable actions from those needing the Decision Gate.
- **Acceptance test:** Given identical evidence and policy, the orchestrator must produce a deterministic proposal (or a clearly documented reason for escalation), and must **never** omit the rollback plan.

### Layer 4 — Containment & Enforcement *("the safe shield")*

**Objective:** Execute approved controls — stop malicious activity while preserving required clinical data flows. Supports at least two modes: coarse isolation (low-criticality assets) and surgical blocking (safety-sensitive assets).

- A surgical rule can block a malicious source/destination/port/protocol/session while allowing approved monitoring, control, and data-pipeline traffic to continue. In the twin, every action is simulated first, impact-evaluated, then applied.
- **Receives:** An approved or auto-approved low-risk action, plus target asset, exact scope, duration, priority, expiry, rollback instructions.
- **Passes onward:** An enforcement result with `action_id`, `status`, `applied_controls`, `blocked_flows`, `preserved_flows`, `start_time`, `expiry_time`, `verification`, `rollback_token` — sent to Layer 6 (audit) and back to Layer 3 (plan feedback).
- **Acceptance test:** Prove a Tier 1 surgical block stops malicious flow while preserving allowed clinical flows; verify automatic expiry and rollback.

### Layer 5 — Decision Gate *("the human override button")*

**Objective:** Prevent high-risk automation from becoming unsafe — a formal checkpoint for actions near Tier 1 assets, broad segmentation changes, uncertain identity matches, or high availability-impact actions.

- Dashboard shows evidence, affected asset, clinical tier, proposed action, expected impact, safe alternatives, confidence, and rollback plan. Reviewer can approve, reject, modify, or escalate.
- Approvals are **time-bound** and tied to a specific action hash — an old approval can't be reused for a changed action.
- **Receives:** Response proposal (Layer 3).
- **Passes onward:** A decision record with `decision_id`, `case_id`, `reviewer`, `decision`, `scope_hash`, `reason`, `timestamp`, `expiry`, `approved_action`. Rejection/timeout returns the case to safe monitoring or escalation — never a silent failure.
- **Acceptance test:** Simulate a critical-device incident; confirm no high-risk action executes without a valid approval on record.

### Layer 6 — Compliance & Privacy *("the secure diary and reporter")*

**Objective:** Protect sensitive patient information, record the complete chain of events, and generate incident reports. Privacy controls apply before telemetry reaches dashboards or external authorities.

- Raw evidence stays in a controlled, strict-access store; operational views use minimization and redaction.
- **Receives:** Normalized observations, asset context, findings, agent proposals, decision records, enforcement results, rollback events, analyst annotations.
- **Produces:** A tamper-evident audit trail, redacted operational events, incident timelines, evidence packages, and standardized reports — clearly separating observed facts, model inferences, human decisions, and actions taken. The reporting adapter is configurable so the simulator can demonstrate structure without contacting a real authority.
- **Acceptance test:** Generate a full incident timeline from one scenario; verify sensitive fields are redacted operationally while authorized forensic users can trace each record to its source.

---

## 5. Layer-to-Layer Contract Map

| From | To | Required Handoff | Must Never Be Omitted |
|---|---|---|---|
| Layer 0 | Layer 1 | Normalized observation event | Timestamp, source, subject, network context, raw reference |
| Layer 1 | Layer 2 | Asset context | Clinical tier, identity confidence, allowed peers, constraints |
| Layer 2 | Layer 3 | Detection finding | Evidence, score, confidence, baseline version, related events |
| Layer 3 | Layer 4 | Safe response proposal or approved action | Scope, reason, duration, preserved flows, rollback plan |
| Layer 3 | Layer 5 | High-risk approval request | Clinical impact, alternatives, confidence, action hash |
| Layer 4 | Layer 6 | Enforcement result | Applied controls, preserved flows, verification, rollback token |
| Layer 5 | Layer 4 | Decision record | Reviewer, decision, scope hash, expiry |
| All layers | Layer 6 | Audit event | Actor, timestamp, input/output reference, outcome |

> **Golden rule:** No layer should pass vague information to the next layer. Every handoff must state *what happened*, *which asset is affected*, *how confident the system is*, *what clinical constraints apply*, *what action is proposed*, and *how the action can be verified or undone*.

---

## 6. Implementation Roadmap (Vertical Slices)

| Phase | Deliverable | Exit Criteria |
|---|---|---|
| 0. Safety and scope | Threat model, clinical tiers, response policy, simulator boundary | Team can state what may be automated vs. requires approval |
| 1. Digital twin foundation | Zones, devices, users, flows, normal-operation generator | A repeatable hospital scenario runs start to finish |
| 2. Telemetry backbone | Layer 0 adapters, event schema, replay store | Events are timestamped, normalized, replayable, traceable |
| 3. Asset intelligence | Layer 1 inventory and tier assignment | Every asset has identity, owner, tier, constraints |
| 4. Baseline detection | Layer 2 features, baselines, anomaly findings | System detects seeded anomalies with measurable metrics |
| 5. Explainable orchestration | Layer 3 agents, case record, response proposals | Each proposal has evidence, safety impact, approval level, rollback |
| 6. Safe enforcement | Layer 4 isolation, surgical blocks, expiry, rollback | Attack traffic blocked while protected clinical flows remain available |
| 7. Human decision workflow | Layer 5 dashboard and approval records | High-risk actions pause until a valid human decision exists |
| 8. Privacy and reporting | Layer 6 redaction, audit trail, incident report generator | Full incident reconstructable without exposing unnecessary patient data |
| 9. Evaluation and hardening | Scenario library, regression tests, metrics, failure drills | Team can compare versions and demonstrate safe behavior under stress |

### Recommended First-Prototype Build Order

1. **Small twin:** 3 zones, 6–10 assets (1 Tier 1 device, 2 Tier 2 systems, 2 Tier 3 endpoints, 1 attacker-controlled host).
2. **Event schema + replay engine** before adding any ML — build a reliable debugging foundation first.
3. **One high-value scenario:** compromised office endpoint → lateral movement toward a Tier 1 device. Full path: observation → asset enrichment → anomaly finding → agent correlation → surgical-block proposal → decision gate review → enforcement → verification → audit.
4. Once that path works, add: ransomware propagation, credential misuse, data-exfiltration scenarios.
5. Prefer simple models and explicit policy rules first — add complexity only once every action in a recorded incident timeline can be explained.

---

## 7. Key Metrics and Demonstrations

| Category | Metric or Demonstration |
|---|---|
| Visibility | % of simulated events normalized and traceable to source |
| Asset knowledge | Inventory coverage and accuracy of clinical-tier assignment |
| Detection | Precision, recall, false-positive rate, detection latency by asset tier |
| Safety | % of protected clinical flows preserved during containment |
| Response | Time from finding → proposal → approval → enforcement → verification |
| Reversibility | Successful automatic expiry and rollback rate |
| Explainability | % of actions with evidence, reason, policy, and reviewer record |
| Privacy | % of operational records correctly redacted and audit completeness |

---

## 8. Suggested Project Structure

```
accds/
├── digital_twin/         # Hospital zones, devices, users, scenarios
├── ingestion/             # Layer 0 adapters and event normalization
├── asset_intelligence/    # Layer 1 inventory and criticality
├── detection/              # Layer 2 features, baselines, anomaly models
├── orchestration/          # Layer 3 agents, cases, response proposals
├── enforcement/            # Layer 4 virtual controls and rollback
├── decision_gate/          # Layer 5 approvals and dashboard APIs
├── compliance/             # Layer 6 redaction, audit, reporting
├── schemas/                 # Versioned contracts between layers
├── tests/                    # Unit, integration, safety, and scenario tests
└── docs/                      # Threat model, policies, runbooks, and diagrams
```

---

## 9. Final Mental Model

Think of ACCDS as a hospital security team with seven responsibilities:

- **Layer 0** watches.
- **Layer 1** identifies.
- **Layer 2** notices unusual behavior.
- **Layer 3** coordinates specialists.
- **Layer 4** applies the shield.
- **Layer 5** asks a human when the stakes are high.
- **Layer 6** keeps the secure diary and produces the report.

## Conclusion

ACCDS should be built as a **simulation-first, safety-aware, evidence-driven architecture**. The digital twin provides a controlled environment to test attacks, measure defenses, and prove clinical traffic remains available. Layered contracts keep responsibilities clear, while the decision gate and rollback mechanisms ensure autonomy never overrides patient safety.

**Success is not simply blocking an attack.** It is ACCDS being able to explain what it saw, identify what was at risk, choose the least disruptive effective response, obtain human approval when needed, verify the result, and preserve a trustworthy record of the entire event.
