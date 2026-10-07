# ACCDS incident report for case CASE-3b82cc12

- **Report ID:** RPT-CASE-3b82cc12
- **Case ID:** CASE-3b82cc12
- **Scenario:** port_scan_attack_01
- **Generated:** 2026-09-12T17:09:30.776514+00:00
- **View:** `operational`  (identifiers are pseudonymized)

## Integrity

Audit chain: **VERIFIED** - 22 records checked, chain intact.

Head hash: `9d8394b7e6aba92296f35ea336b346ab1b0c1f94a52c463ea4c28742f0cfe277`

## Summary

21 audit records span 2026-09-12T14:00:00+00:00 to 2026-09-12T17:04:16.747894+00:00.

| Layer | Records |
|---|---:|
| 0 Data Ingestion | 6 |
| 1 Asset Intelligence | 5 |
| 2 ML Behavioral Model | 3 |
| 3 Multi-Agent Orchestration | 2 |
| 4 Containment & Enforcement | 2 |
| 5 Decision Gate | 2 |
| 6 Compliance & Privacy | 1 |

## Observed facts

_Recorded observations. Not interpreted._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-09-12T14:00:00+00:00 | 0 | layer0.ingestion | success | subject~dc23d94e88b6 -> network~443695514664 via TCP (4096 bytes) in zone Intensive Care Unit |
| 2026-09-12T14:00:00+00:00 | 0 | layer0.ingestion | success | subject~dc23d94e88b6 -> network~443695514664 via TCP (4096 bytes) in zone Intensive Care Unit |
| 2026-09-12T14:00:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~a45d52d06645 identified as Patient Monitor Gateway in Intensive Care Unit, clinical tier 1, identity confidence 0.98 |
| 2026-09-12T14:00:00+00:00 | 0 | layer0.ingestion | success | subject~dc23d94e88b6 -> network~443695514664 via TCP (4096 bytes) in zone Intensive Care Unit |
| 2026-09-12T14:00:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~a45d52d06645 identified as Patient Monitor Gateway in Intensive Care Unit, clinical tier 1, identity confidence 0.98 |
| 2026-09-12T14:00:00+00:00 | 0 | layer0.ingestion | success | subject~dc23d94e88b6 -> network~443695514664 via TCP (4096 bytes) in zone Intensive Care Unit |
| 2026-09-12T14:00:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~a45d52d06645 identified as Patient Monitor Gateway in Intensive Care Unit, clinical tier 1, identity confidence 0.98 |
| 2026-09-12T14:00:00+00:00 | 0 | layer0.ingestion | success | subject~dc23d94e88b6 -> network~443695514664 via TCP (4096 bytes) in zone Intensive Care Unit |
| 2026-09-12T14:00:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~a45d52d06645 identified as Patient Monitor Gateway in Intensive Care Unit, clinical tier 1, identity confidence 0.98 |
| 2026-09-12T14:00:00+00:00 | 0 | layer0.ingestion | success | subject~dc23d94e88b6 -> network~443695514664 via TCP (4096 bytes) in zone Intensive Care Unit |
| 2026-09-12T14:00:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~a45d52d06645 identified as Patient Monitor Gateway in Intensive Care Unit, clinical tier ClinicalTier.TIER_1, identity confidence 0.98 |

## Model inferences

_Machine inference with a confidence score. Not confirmed fact._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-09-12T14:00:00+00:00 | 3 | layer3.orchestrator | escalated | Case CASE-4b353588 proposes [SURGICAL_BLOCK] at approval level REQUIRES_HUMAN_APPROVAL; CRITICAL: System is Tier 1 (Patient Monitor Gateway). Interventions must preserve critical flows. |
| 2026-09-12T14:00:00+00:00 | 3 | layer3.orchestrator | escalated | Case CASE-3b82cc12 proposes [SURGICAL_BLOCK] at approval level REQUIRES_HUMAN_APPROVAL; CRITICAL: System is Tier 1 (Patient Monitor Gateway). Interventions must preserve critical flows. |
| 2026-09-12T14:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-A14E9B57 on asset~a45d52d06645: anomaly 0.89, risk 0.92, indicators [PORT_SCAN_SWEEP, UNAUTHORIZED_PEER_COMMUNICATION, UNIFORM_PROBE_PAYLOAD_DETECTED] |
| 2026-09-12T14:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-A14E9B57 on asset~a45d52d06645: anomaly 0.89, risk 0.92, indicators [PORT_SCAN_SWEEP, UNAUTHORIZED_PEER_COMMUNICATION, UNIFORM_PROBE_PAYLOAD_DETECTED] |
| 2026-09-12T14:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-A14E9B57 on asset~a45d52d06645: anomaly 0.89, risk 0.92, indicators [PORT_SCAN_SWEEP, UNAUTHORIZED_PEER_COMMUNICATION, UNIFORM_PROBE_PAYLOAD_DETECTED] |

## Human decisions

_Decisions made by a named reviewer under a time-bound approval._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-09-12T16:13:55.929428+00:00 | 5 | layer5.reviewer:person~524480b21d87 | success | Reviewer person~524480b21d87 recorded APPROVED for case CASE-4b353588 (scope 4467f87c13b6ef0cbc26730a67dcf507d5f9a38a8bd927be7067ee2de7d7681c): Verified port scan attack on Tier 1 monitor. Surgical block approved. |
| 2026-09-12T16:13:55.929428+00:00 | 5 | layer5.reviewer:person~524480b21d87 | success | Reviewer person~524480b21d87 recorded APPROVED for case CASE-3b82cc12 (scope 4467f87c13b6ef0cbc26730a67dcf507d5f9a38a8bd927be7067ee2de7d7681c): Verified port scan attack on Tier 1 monitor. Surgical block approved. |

## Actions taken

_Controls applied, verified, expired or rolled back._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-09-12T16:13:55.929506+00:00 | 4 | layer4.enforcement | success | SURGICAL_BLOCK on asset~a45d52d06645: 1 flow(s) blocked, 1 preserved, status APPLIED |
| 2026-09-12T16:13:55.929506+00:00 | 4 | layer4.enforcement | success | SURGICAL_BLOCK on asset~a45d52d06645: 1 flow(s) blocked, 1 preserved, status APPLIED |
| 2026-09-12T17:04:16.747894+00:00 | 6 | analyst:soc_analyst | success | evidence.read.operational: incident review |

## Privacy controls

- Sensitive field instances handled: 129
- Fields pseudonymized: 85
- Fields dropped: 6
- Free-text substitutions: 33
- Leak scan: clean

---

Generated by ACCDS Layer 6 (Compliance & Privacy). This report is produced inside a hospital digital twin and was not transmitted to any external authority.
