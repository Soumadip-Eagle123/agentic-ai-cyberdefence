# ACCDS incident report for case CASE-CORR-8B9AAF

- **Report ID:** RPT-CASE-CORR-8B9AAF
- **Case ID:** CASE-CORR-8B9AAF
- **Scenario:** aiims_lateral_campaign
- **Generated:** 2026-10-07T13:20:42.050157+00:00
- **View:** `operational`  (identifiers are pseudonymized)

## Integrity

Audit chain: **VERIFIED** - 36 records checked, chain intact.

Head hash: `16b1e3b7f0ea52c87195568c9b5a3e04b8fa976ab0eb10e32497df6022503a2a`

## Summary

35 audit records span 2026-09-12T14:00:00+00:00 to 2026-10-07T13:20:42.032987+00:00.

| Layer | Records |
|---|---:|
| 0 Data Ingestion | 9 |
| 1 Asset Intelligence | 8 |
| 2 ML Behavioral Model | 6 |
| 3 Multi-Agent Orchestration | 5 |
| 4 Containment & Enforcement | 3 |
| 5 Decision Gate | 2 |
| 6 Compliance & Privacy | 2 |

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
| 2026-09-12T14:00:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~a45d52d06645 identified as Patient Monitor Gateway in Intensive Care Unit, clinical tier 1, identity confidence 0.98 |
| 2026-10-07T10:00:00+00:00 | 0 | layer0.ingestion | success | subject~0c7fb21f8b9d -> network~f97ad5785d85 via TCP (80 bytes) in zone administration |
| 2026-10-07T10:00:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~1a310edef656 identified as Reception Desk Endpoint in Administration, clinical tier ClinicalTier.TIER_3, identity confidence 0.99 |
| 2026-10-07T10:02:00+00:00 | 0 | layer0.ingestion | success | subject~0c7fb21f8b9d -> network~443695514664 via TCP (1200 bytes) in zone laboratory |
| 2026-10-07T10:02:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~1a310edef656 identified as Reception Desk Endpoint in Administration, clinical tier ClinicalTier.TIER_3, identity confidence 0.99 |
| 2026-10-07T10:05:00+00:00 | 0 | layer0.ingestion | success | subject~0c7fb21f8b9d -> network~ee6603e62360 via TCP (4096 bytes) in zone intensive_care |
| 2026-10-07T10:05:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~1a310edef656 identified as Reception Desk Endpoint in Administration, clinical tier ClinicalTier.TIER_3, identity confidence 0.99 |

## Model inferences

_Machine inference with a confidence score. Not confirmed fact._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-09-12T14:00:00+00:00 | 3 | layer3.orchestrator | escalated | Case CASE-4b353588 proposes [SURGICAL_BLOCK] at approval level REQUIRES_HUMAN_APPROVAL; CRITICAL: System is Tier 1 (Patient Monitor Gateway). Interventions must preserve critical flows. |
| 2026-09-12T14:00:00+00:00 | 3 | layer3.orchestrator | escalated | Case CASE-3b82cc12 proposes [SURGICAL_BLOCK] at approval level REQUIRES_HUMAN_APPROVAL; CRITICAL: System is Tier 1 (Patient Monitor Gateway). Interventions must preserve critical flows. |
| 2026-09-12T14:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-A14E9B57 on asset~a45d52d06645: anomaly 0.89, risk 0.92, indicators [PORT_SCAN_SWEEP, UNAUTHORIZED_PEER_COMMUNICATION, UNIFORM_PROBE_PAYLOAD_DETECTED] |
| 2026-09-12T14:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-A14E9B57 on asset~a45d52d06645: anomaly 0.89, risk 0.92, indicators [PORT_SCAN_SWEEP, UNAUTHORIZED_PEER_COMMUNICATION, UNIFORM_PROBE_PAYLOAD_DETECTED] |
| 2026-09-12T14:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-A14E9B57 on asset~a45d52d06645: anomaly 0.89, risk 0.92, indicators [PORT_SCAN_SWEEP, UNAUTHORIZED_PEER_COMMUNICATION, UNIFORM_PROBE_PAYLOAD_DETECTED] |
| 2026-10-07T10:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-001 on asset~1a310edef656: anomaly 0.65, risk 0.65, indicators [UNEXPECTED_SMB_TRAFFIC] |
| 2026-10-07T10:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-002 on asset~1a310edef656: anomaly 0.82, risk 0.82, indicators [PORT_SCAN_SWEEP, UNAUTHORIZED_PEER_CONNECT] |
| 2026-10-07T10:05:00+00:00 | 2 | layer2.model:v1.0.0 | success | Finding FIND-003 on asset~1a310edef656: anomaly 0.95, risk 0.95, indicators [EXPLOIT_ATTEMPT_SMB, CRITICAL_FLOW_INTERRUPTION_RISK] |
| 2026-10-07T13:20:42.031801+00:00 | 3 | layer3.orchestrator | success | Case CASE-CORR-8B9AAF proposes [COARSE_ISOLATION] at approval level AUTO_APPROVED; LOW: All affected assets are non-clinical Tier 3. Rapid isolation allowed. |
| 2026-10-07T13:20:42.032431+00:00 | 3 | layer3.orchestrator | success | Case CASE-CORR-8B9AAF proposes [COARSE_ISOLATION] at approval level AUTO_APPROVED; LOW: All affected assets are non-clinical Tier 3. Rapid isolation allowed. |
| 2026-10-07T13:20:42.032987+00:00 | 3 | layer3.orchestrator | success | Case CASE-CORR-8B9AAF proposes [COARSE_ISOLATION] at approval level AUTO_APPROVED; LOW: All affected assets are non-clinical Tier 3. Rapid isolation allowed. |

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
| 2026-09-12T17:09:30.773717+00:00 | 6 | analyst:soc_analyst | success | evidence.read.operational: incident review |
| 2026-10-07T10:06:05+00:00 | 4 | layer4.enforcement | success | COARSE_ISOLATION, SURGICAL_BLOCK on asset~1a310edef656: 1 flow(s) blocked, 1 preserved, status APPLIED |

## Privacy controls

- Sensitive field instances handled: 196
- Fields pseudonymized: 126
- Fields dropped: 9
- Free-text substitutions: 53
- Leak scan: clean

---

Generated by ACCDS Layer 6 (Compliance & Privacy). This report is produced inside a hospital digital twin and was not transmitted to any external authority.
