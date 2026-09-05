# ACCDS incident report for case CASE-a0c6049e

- **Report ID:** RPT-CASE-a0c6049e
- **Case ID:** CASE-a0c6049e
- **Scenario:** port_scan
- **Generated:** 2026-09-05T14:23:58.087469+00:00
- **View:** `operational`  (identifiers are pseudonymized)

## Integrity

Audit chain: **VERIFIED** - 29 records checked, chain intact.

Head hash: `d0114f0f90fee29f9f343cf9b1255c9aa724c4a2f15c89ba0bff2f995bb26a40`

## Summary

27 audit records span 2026-01-05T07:44:00+00:00 to 2026-09-05T14:28:58.063898+00:00.

| Layer | Records |
|---|---:|
| 0 Data Ingestion | 20 |
| 1 Asset Intelligence | 1 |
| 2 ML Behavioral Model | 1 |
| 3 Multi-Agent Orchestration | 1 |
| 4 Containment & Enforcement | 2 |
| 5 Decision Gate | 1 |
| 6 Compliance & Privacy | 1 |

## Observed facts

_Recorded observations. Not interpreted._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-01-05T07:44:00+00:00 | 1 | layer1.asset_intelligence | success | Asset asset~6ca5b1ee26c5 identified as office_endpoint in administration, clinical tier 3, identity confidence 1.0 |
| 2026-01-08T00:03:00+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~af36cd15472a via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:01+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~ddc2e66e50ef via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:02+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~9be5979f6ed5 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:03+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~8d373a24ac92 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:04+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~6b329d9d150f via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:05+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~8b38f64af999 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:06+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~9ce25e7c53be via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:07+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~c5a6a8e19b49 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:08+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~7f86aaefcaed via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:09+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~36e502b05f2e via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:10+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~421332abaa90 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:11+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~0b7358452d64 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:12+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~e38210d544a9 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:13+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~0083f2ad03e0 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:14+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~68e145e953e5 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:15+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~f40d6e24a1a2 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:16+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~00acdd9cfc57 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:17+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~c7c7e02cc968 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:18+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~42352cb1c1f9 via TCP (80 bytes) in zone administration |
| 2026-01-08T00:03:19+00:00 | 0 | layer0.ingestion | success | subject~5b742933679e -> network~9b1effdc8dae via TCP (80 bytes) in zone administration |

## Model inferences

_Machine inference with a confidence score. Not confirmed fact._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-01-08T01:00:00+00:00 | 2 | layer2.model:layer2-baseline-v1 | success | Finding finding-000366-asset~6ca5b1ee26c5-202601080000 on asset~6ca5b1ee26c5: anomaly 0.62, risk 0.569, indicators [new_peer, port_fanout, off_hours] |
| 2026-09-05T14:23:58.063674+00:00 | 3 | layer3.orchestrator | success | Case CASE-a0c6049e proposes [COARSE_ISOLATION, MONITOR_ONLY] at approval level AUTO_APPROVED; LOW: Tier 3 non-clinical endpoint. Rapid isolation permitted by policy. |

## Human decisions

_Decisions made by a named reviewer under a time-bound approval._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-09-05T14:23:58.063870+00:00 | 5 | layer5.reviewer:person~26756ab1746b | success | Reviewer person~26756ab1746b recorded APPROVED for case CASE-a0c6049e (scope 6344eed71f4790d1): Evidence supports containment; preserved flows verified against the care plan. |
| 2026-09-05T14:23:58.063929+00:00 | 6 | analyst:person~20ad4ba129f2 | success | Analyst person~20ad4ba129f2 noted: Confirmed true positive. Endpoint reimaged; no patient data was accessed. |

## Actions taken

_Controls applied, verified, expired or rolled back._

| Time | Layer | Actor | Outcome | Detail |
|---|---|---|---|---|
| 2026-09-05T14:23:58.063898+00:00 | 4 | layer4.enforcement | success | COARSE_ISOLATION on asset~6ca5b1ee26c5: 1 flow(s) blocked, 1 preserved, status VERIFIED |
| 2026-09-05T14:28:58.063898+00:00 | 4 | layer4.enforcement | rolled_back | Rollback RB-asset~6ca5b1ee26c5-b919ae on asset~6ca5b1ee26c5 (automatic_expiry) |

## Privacy controls

- Sensitive field instances handled: 195
- Fields pseudonymized: 139
- Fields dropped: 20
- Free-text substitutions: 35
- Leak scan: clean

---

Generated by ACCDS Layer 6 (Compliance & Privacy). This report is produced inside a hospital digital twin and was not transmitted to any external authority.
