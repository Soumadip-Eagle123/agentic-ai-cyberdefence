# ACCDS Simulation & Operational Defense Manual

An end‑to‑operational and architectural guide for the **Agentic Clinical Cybersecurity Defence System (ACCDS)** digital twin simulator. This document covers installation, core clinical safety principles, attack vectors and parameters, and instructions for running evaluations via both the Web Dashboard and the Terminal.

---

## 1. Quickstart: Installation & Running the System

### Prerequisites

* **Operating System**: Linux (Ubuntu/Debian recommended), macOS, or Windows WSL2
* **Python**: `3.11` or `3.12`
* **Package Manager**: Standard `pip` / `venv` or `uv`

### Installation Steps

1. **Clone and enter the repository:**
   ```bash
   git clone <repo-url>
   cd agentic-ai-cyberdefence
   ```

2. **Set up the virtual environment:**
   * Using standard Python:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   * Or using `uv`:
     ```bash
     uv venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   # Or: pip install pydantic pytest
   ```

4. **Ensure simulation directories exist:**
   ```bash
   mkdir -p artifacts/simulations
   chmod -R u+rwX artifacts
   ```

### Execution Modes

* **Mode A: Full Web Dashboard & Digital Twin Simulator**
  Starts the local HTTP API and UI server on port `8081`:
  ```bash
  python3 -m src.simulator.server
  ```
  Open your web browser and navigate to: **`http://127.0.0.1:8081`**

* **Mode B: Interactive Headless CLI Pipeline**
  Runs an end‑to‑end 6‑stage lateral campaign across Layers 0 to 6 with an interactive terminal approval prompt at Layer 5:
  ```bash
  python3 main.py
  ```

---

## 2. Core Safety Architecture & Mechanisms

### 2.1. Surgical Blocking: Machine Isolation vs. Patient Continuity

**Did the machine stay alive, or was it isolated from the attack?**

Both, at the exact same time. This capability defines the core clinical safety rule of ACCDS.

In enterprise IT security, compromised endpoints are subjected to **Coarse Isolation**—the network interface is severed completely. If coarse isolation is applied to an **ICU Controller** or **Bedside Patient Monitor**, nursing screens go black, alarm telemetry ceases, and the patient is placed in immediate physical danger.

ACCDS uses **Surgical Blocking** to filter specific network ports instead of disabling the interface:
```
[Attacker / Malware] ────── Port 445 (SMB) ─────► [ BLOCKED by Layer 4 ] ──X (Malware stopped)
                                                                                  │
                                                                           [ ICU‑CONTROLLER ]
                                                                                  │
[Patient Heart Monitor] ─── Port 2575 (HL7) ────► [ PERMITTED by Layer 4 ] ──────► (Telemetry live)
```
1. **It drops the attack vector (TCP Port 445 – SMB):** Windows File Sharing/SMB is the protocol exploited by ransomware (e.g., WannaCry) and lateral scanners to inject remote exploits. Layer 4 creates a surgical rule dropping all inbound traffic on Port 445.
2. **It keeps clinical channels open (TCP Port 2575 – HL7):** Bedside vital signs, pulse oximetry, and cardiac feeds transmit via the HL7 clinical protocol on Port 2575. Layer 4 explicitly whitelists Port 2575 bidirectionally.
3. **The Result:** The patient's heart monitor remains connected to clinicians, while unauthorized lateral packets are discarded at the ingress filter.

---

### 2.2. The Rollback Token & The 300‑Second Expiry Timer

* **The Rollback Token (`rollback_token`, e.g., `RB‑CAMPAIGN‑3B68E9`):**
  A cryptographic reference token registered in Layer 4's in‑memory firewall registry alongside every applied rule. If an operator clicks **Rollback** or issues an undo command, the executor queries this token to reverse that specific rule without altering other active network configurations.

* **The 300‑Second (5‑Minute) Timer:**
  A non‑negotiable fail‑safe timer. If a containment rule causes unintended latency or clinical degradation, it cannot remain active indefinitely. If the rule is not renewed within 300 seconds, Layer 4 automatically purges the rule and restores standard flow states.

---

### 2.3. The SHA‑256 Hash‑Chained Audit Ledger

Layer 6 constructs an immutable, tamper‑evident log modeled on blockchain hash chaining. Every event links cryptographically to the one preceding it:
```
┌─────────────────────────────────┐       ┌─────────────────────────────────┐       ┌─────────────────────────────────┐
│        Record #1 (Layer 0)      │       │        Record #2 (Layer 2)      │       │        Record #3 (Layer 5)      │
│  "Raw packet seen at 02:15 AM"  │       │   "ML detected Anomaly 0.58"    │       │ "Analyst approved surgical blk" │
│  Prev Hash: 0000000000000000    │       │  Prev Hash: a8f9… (Rec #1)    │       │  Prev Hash: b2c1… (Rec #2)    │
│  This Hash: a8f9…               ───────►│  This Hash: b2c1…               ───────►│  This Hash: cbd1… (Head Hash) │
└─────────────────────────────────┘       └─────────────────────────────────┘       └─────────────────────────────────┘
```
* **SHA‑256 Hashing:** Every record payload is converted to a canonical string and hashed into a 64‑character hexadecimal digest.
* **Cryptographic Chaining:** Record $N$ embeds the hash of Record $N‑1$.
* **Tamper Verification (`verify()`):** Modifying any field (such as changing an IP address or downgrading a risk score in storage) breaks the cryptographic link for every subsequent block. Running verification triggers an immediate **`TAMPER DETECTED`** flag and identifies the exact sequence number compromised.

---

## 3. Attack Simulation GUI: Scenarios, Nodes & Clinical Criticality

### 3.1. Preset Scenarios Dropdown

This menu injects pre‑configured cyber‑attack telemetry to test how the pipeline reacts.

| Scenario Parameter | What It Simulates | Effect on Layer 2 ML Model | Impact on Decision & Action (L3, L5, L4) |
|---|---|---|---|
| **`Custom attack`** | Lets you manually pick source, destination, vector, and byte payload. | Features depend entirely on your choices below (ports, peers, payload sizes). | Decision engine evaluates the risk based on the clinical tier of the target. |
| **`port scan`** | Rapid sequential connection probes across multiple ports in seconds. | Flags high `port_fanout` (e.g., $\ge 8$). Statistical score spikes; triggers indicator `PORT_SCAN_SWEEP`. | Assessed as reconnaissance. Prompts containment if aimed at clinical gear. |
| **`new_peer`** | A device connects to an IP it has never spoken to in historical training. | `new_peer_ratio` jumps to 1.0. Model flags sudden lateral expansion outside normal baseline. | Assessed as lateral movement/worm spreading. Triggers scoped blocks. |
| **`exfiltration`** | High‑volume outbound data flow (e.g., 250,000+ bytes) to external destinations. | `total_bytes` and `bytes_per_peer` deviate heavily from median baseline ($\text{MAD} \times 1.4826$). | Assessed as patient record theft/extortion. Layer 3 proposes an immediate egress block. |
| **`credential misuse`** | Multiple authentication failures followed by unauthorized access. | `failed_auth` counter $\ge 3$. Rule‑based multiplier boosts base anomaly score to $\ge 0.62$. | Assessed as brute‑force or stolen doctor credentials. Revokes session tokens. |
| **`off hours`** | Clinical record queries between 7:00 PM and 7:00 AM (e.g., 2:15 AM). | `off_hours_ratio` hits 1.0. Triggers `off_hours` deviation indicator. | If querying sensitive records off‑shift, flags suspicious insider activity. |
| **`diagnostic drift`** | A medical device (like an X‑ray workstation) starts sending discovery probes. | Deviates from peer‑group statistics (other X‑ray machines don't probe). | Triggers Layer 5 review to contain drift without interrupting active patient scans. |
| **`benign clinical burst`** | **Negative control:** Normal ICU surge (high vitals volume during patient trauma). | Bytes spike, but destination is an approved peer (`ehr‑core`). Anomaly score stays $< 0.55$. | NO containment triggered. Proves the ML doesn't false‑alarm during emergencies. |
| **`low confidence`** | Traffic from an unverified or spoofed MAC/IP address. | Layer 1 assigns low `identity_confidence` ($< 0.70$). Scales down overall risk score. | Forces conservative `MONITOR_ONLY`; avoids automated blocks on uncertain targets. |

### 3.2. Attacker Source Node & Target Node Dropdowns

These nodes define the origin and victim of the threat. Their **Clinical Tier** completely controls the severity and decision routing:

* **`office-ws` (Administration · Tier 3):**
  *Nature:* Non‑critical Windows desktop computer in billing or administration.
  *Effect on Pipeline:* If compromised, Layer 4 is allowed to execute **Coarse Isolation** (completely severed from the network) because no patient life depends on an office computer. Layer 5 auto‑approves this without waking up an analyst.

* **`lab‑server` (Laboratory · Tier 2):**
  *Nature:* Server running blood tests, pathology results, and diagnostic databases.
  *Effect on Pipeline:* Workflow‑critical. Cannot be pulled completely offline without halting laboratory operations. Layer 3 selects a **Scoped Block** (block outbound attack traffic, but keep diagnostic query ports like TCP 5432 or 443 open).

* **`radiology-ws` (Radiology · Tier 2):**
  *Nature:* Workstation viewing MRI, CT, and X‑ray imaging files.
  *Effect on Pipeline:* Workflow‑critical. When attacked, Layer 4 blocks attacker ports (SMB 445) but preserves **DICOM Port 104** so active patient imaging continues.

* **`ehr‑core` (Security Operations · Tier 2):**
  *Nature:* Central Electronic Health Records database repository.
  *Effect on Pipeline:* Contains all hospital patient records. High‑value target for exfiltration.

* **`icu‑monitor‑gw` (Intensive Care · Tier 1):**
  *Nature:* Gateway aggregating bedside patient heart monitors, pulse oximeters, and vitals.
  *Effect on Pipeline:* Life‑Critical. Total isolation is strictly forbidden. Any action forces `approval_level: REQUIRES_HUMAN_APPROVAL` (Layer 5) and allows **Surgical Block only** (preserving HL7 Port 2575).

* **`icu‑controller` (Intensive Care · Tier 1):**
  *Nature:* Critical care cabinet controlling ICU telemetry and operational parameters.
  *Effect on Pipeline:* Life‑Critical. Identical safety constraints as the monitor gateway.

---

## 4. Parameter Reference: ML Features, Vectors & Device Tiers

```
[1. Port Scan] ──────► [2. Lateral Movement] ──────► [3. Malware Staging] ──────► [4. Credential Dump] ──────► [5. Data Exfiltration]
(Reconnaissance)           (Subnet Pivot)                (Payload Drop)               (Account Theft)               (Data Exfiltration)
```

### 4.1. Attack Vectors (The Technical Methods)

| Attack Vector | Technical Mechanism | Layer 2 Feature Impact | Layer 3/4/5 Decision & Action |
|---|---|---|---|
| **`Port scan / discovery`** | Probes sequential TCP/UDP ports to map open network services. | Spikes `port_fanout` ($\ge 8$); flags rapid distinct destination connections. | Flags early reconnaissance. Drops discovery probes and sets target zone to `HEIGHTENED_MONITORING`. |
| **`Lateral movement`** | A compromised asset attempts an unauthorized connection across subnet boundaries (e.g., `office-ws` $\rightarrow$ `icu‑monitor‑gw`). | Violates Layer 1 `allowed_peers`; sets `new_peer_ratio = 1.0`. Emits `UNAUTHORIZED_PEER_COMMUNICATION`. | High risk. Proposes surgical containment if targeting clinical assets; routes to Layer 5 for human authorization. |
| **`Malware staging`** | Transfers executable binaries or ransomware encryptors via administrative services. | Spikes `total_bytes` and payload sizes over TCP Port 445 (SMB). | Classifies as an imminent ransomware outbreak. Proposes an emergency inbound block on Port 445. |
| **`Credential dump`** | Injects memory‑scraping routines (e.g., Mimikatz emulation) to harvest active security credentials. | Repeated authentication failures increment `failed_auth` ($\ge 3$); flags `AUTH_BURST`. | Assessed as active account takeover. Revokes identity tokens and severs the active session. |
| **`Data exfiltration`** | Aggregates and uploads patient medical records to external networks. | Significant outbound `total_bytes` anomaly toward unapproved peer entities. | Assessed as a potential HIPAA breach. Enforces egress containment while maintaining internal telemetry flows. |

### 4.2. Preset Scenarios (Automated Evaluation Profiles)

* **`off_hours`**: Telemetry generated between 19:00 and 07:00 (e.g., 02:15 AM).
  *ML Impact*: `off_hours_ratio` equals 1.0. Triggers `OFF_HOURS` deviation flags.

* **`diagnostic_drift`**: A diagnostic workstation emits anomalous, uniform 90‑byte sweeps toward unmapped endpoints.
  *ML Impact*: Deviates from peer‑group baseline statistics (other imaging consoles do not probe).

* **`benign_clinical_burst` (Negative Control)**: High‑volume vitals telemetry transmitted during patient trauma.
  *ML Impact*: Bytes spike, but destination is an approved peer (`ehr‑core`). Anomaly score remains **$< 0.55$**.
  *Outcome*: No firewall intervention occurs. Demonstrates that clinical surges do not generate false‑positive blocks.

* **`low_confidence`**: Telemetry emitted with unverified MAC/IP identity context.
  *ML Impact*: `identity_confidence` drops to 0.35, attenuating the computed risk score.
  *Outcome*: Enforces a conservative `MONITOR_ONLY` state to prevent premature automated containment on ambiguous targets.

### 4.3. Asset Criticality Tiers

* **Tier 1 (Life‑Critical): `icu‑monitor‑gw`, `icu‑controller`**
  *Clinical Profile*: Life‑support monitoring and intensive‑care cabinets.
  *Policy Rule*: Full network isolation is strictly prohibited. Only **Surgical Blocking** is allowed, bidirectional HL7 Port 2575 must remain preserved, and Layer 5 **Human Review is required** before enforcement.

* **Tier 2 (Workflow‑Critical): `lab‑server`, `radiology‑ws`, `ehr‑core`**
  *Clinical Profile*: Diagnostic processing, laboratory results, and centralized health records.
  *Policy Rule*: Requires **Scoped Blocking** to restrict lateral paths without halting operational imaging or database transactions.

* **Tier 3 (Non‑Clinical): `office‑ws`, `guest‑device`**
  *Clinical Profile*: Administrative, reception, and guest network endpoints.
  *Policy Rule*: Coarse Isolation is permitted by default. Layer 5 auto‑approves rapid containment to prevent lateral spread into clinical zones.

---

## 5. Testing Guide: How to Execute & Verify Attacks

```
[Layer 0: Ingest] ──► [Layer 1: Asset] ──► [Layer 2: ML] ──► [Layer 3: Orchestrate] ──► [Layer 5: Decision] ──► [Layer 4: Enforce] ──► [Layer 6: Audit]
```

### Approach A: Testing via the Web GUI

1. Open **`http://127.0.0.1:8081`** in your browser.
2. Click **`＋ Launch attack`** in the top control cluster.
3. Select an attack configuration:
   * **Preset:** Choose `port_scan`, `new_peer`, `exfiltration`, or `off_hours`.
   * **Custom:** Select `office-ws` as the **Attacker Source**, `icu‑monitor‑gw` as the **Target**, and `LATERAL_MOVEMENT` as the **Vector**.
4. To test multi‑hop tracking, select **Chained lateral movement**, pick `lab‑server` as a pivot, and click **Add hop +**.
5. Click **`▶ Execute attack`**.
6. Click **`Run pipeline`** in the top navigation bar.
7. **Handle Layer 5 Review:** Because a Tier 1 asset is targeted, the pipeline pauses at `L5`, turns amber, and opens the **Clinical Safety Checkpoint Modal**. Review the `scope_hash`, confirm the preserved HL7 flow on Port 2575, and click **`✓ Approve action`**.
8. **Verify Interception:**
   * The active attack wire on the map transitions to a dashed red link with an **`×`** containment marker.
   * The `icu‑monitor‑gw` status changes to **`SURGICAL BLOCK · HL7 ACTIVE`**.
   * Click **`L4`** in the stepper to inspect the applied rules.
   * Click **`Export .zip`** in Panel 06 to download the verified regulatory package.

### Approach B: Testing via the Operator Terminal (CLI)

1. On the dashboard, click **`›_ Open attack terminal`** to expand the built‑in console.
2. Inject a scenario via terminal syntax:
   ```bash
   # Launch a port scan sweep
   attack --type port_scan --src office-ws --dst radiology-ws

   # Launch a multi‑hop chained attack targeting the ICU
   attack --type custom_attack --src office-ws --dst icu-monitor-gw --chain office-ws,lab-server,icu-monitor-gw
   ```
3. Advance the execution pipeline:
   * To advance one layer at a time: Click **`STEP ↗`**.
   * To execute continuously: Click **`Run pipeline`**.
4. When prompted by the Layer 5 popup for Tier 1 targets, input your reviewer credentials and approve the scope.
5. Terminal output logs will confirm:
   ```text
   Layer 5 approved · soc‑analyst · scope sha256:11736b7f...
   Advanced to Layer 4 · Enforcement applied: surgical block on Port 445; Port 2575 preserved.
   Advanced to Layer 6 · Pipeline complete; 16 audit records verified.
   ```
