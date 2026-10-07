# main.py
import json
import sys
from pathlib import Path

# --- Core Contracts & Enums ---
from src.schemas.contracts import (
    ClinicalTier,
    SystemSafetyMode,
    DetectionFinding,
    ApprovalLevel,
)

# --- Layer Modules (Layers 0 through 5) ---
from src.ingestion.layer0_ingestion import Layer0Ingestion
from src.asset_intelligence.layer1_asset_intelligence import Layer1AssetIntelligence
from src.orchestration.layer3_orchestrator import Layer3Orchestrator

# --- Layer 6 Compliance & Audit Engine ---
from src.compliance.audit_store import TamperEvidentAuditStore
from src.compliance.contracts import AccessRole
from src.compliance.access import AccessController
from src.compliance.redaction import DEFAULT_PSEUDONYM_KEY, RedactionEngine
from src.compliance.ingest import (
    observations_to_audit,
    asset_context_to_audit,
    findings_to_audit,
    proposal_to_audit,
    decision_to_audit,
    enforcement_to_audit,
)
from src.compliance.timeline import build_timeline
from src.compliance.reporting import build_report, render_markdown, FileReportAdapter
from src.compliance.evidence import export_evidence_package
from src.compliance.metrics import layer6_metrics


def prompt_human_decision(proposal, target_asset_id):
    """Interactive CLI Prompt for Layer 5 Decision Gate."""
    print("\n" + "=" * 80)
    print("🚨 [LAYER 5: DECISION GATE - HUMAN APPROVAL REQUIRED]")
    print("=" * 80)
    print(f"⚠️  A high-risk action requires human approval for Tier 1 asset: '{target_asset_id}'")
    print(f"📌 Case ID:                   {proposal.case_id}")
    print(f"🔍 Threat Summary:            {proposal.threat_summary}")
    print(f"🎯 Correlated Affected Assets: {', '.join(proposal.affected_assets)}")
    print(f"🏥 Clinical Impact:           {proposal.clinical_impact}")
    print(f"🛡️ Candidate Actions:")
    for action in proposal.candidate_actions:
        print(f"   - {action.action_type} on '{action.target_asset}'")
        if action.blocked_flows:
            print(f"     Blocked Flows:   {action.blocked_flows}")
        if action.preserved_flows:
            print(f"     Preserved Flows: {action.preserved_flows}")
    print(f"🔄 Rollback Token:            {proposal.rollback_plan.rollback_token_spec}")
    print("=" * 80)

    try:
        user_choice = input("\n👉 Do you approve this proposal? (y/n): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n\n[!] Input interrupted. Defaulting to REJECTED for safety.")
        user_choice = "n"

    if user_choice in ["y", "yes"]:
        decision_str = "APPROVED"
        default_reason = "Verified multi-stage lateral campaign targeting ICU infrastructure. Approved surgical block."
    else:
        decision_str = "REJECTED"
        default_reason = "Rejected by SOC Analyst due to risk of clinical workflow disruption."

    try:
        reviewer = input("👤 Enter SOC Analyst Reviewer Name/ID [default: analyst_dr_smith]: ").strip()
    except (KeyboardInterrupt, EOFError):
        reviewer = ""
    if not reviewer:
        reviewer = "analyst_dr_smith"

    try:
        reason = input(f"📝 Enter Reason for Decision [default: {default_reason}]: ").strip()
    except (KeyboardInterrupt, EOFError):
        reason = ""
    if not reason:
        reason = default_reason

    return decision_str, reviewer, reason


def main():
    print("==========================================================================")
    print(" ACCDS SEVERE ATTACK SIMULATION: 6-STAGE LATERAL CAMPAIGN (LAYERS 0 - 6)  ")
    print("==========================================================================\n")

    # -------------------------------------------------------------------------
    # 0. Initialize Layer 6 Audit Store & Redaction Engine on Disk
    # -------------------------------------------------------------------------
    output_dir = Path("artifacts/full_run")
    output_dir.mkdir(parents=True, exist_ok=True)
    store_path = output_dir / "audit_chain.jsonl"

    audit_store = TamperEvidentAuditStore(store_path, key=DEFAULT_PSEUDONYM_KEY)
    engine = RedactionEngine(key=DEFAULT_PSEUDONYM_KEY)

    layer0 = Layer0Ingestion()
    layer1 = Layer1AssetIntelligence()
    orchestrator = Layer3Orchestrator()

    # -------------------------------------------------------------------------
    # 6 ATTACK EVENTS OF DIFFERENT NATURES SATISFYING ALL 3 CORRELATION CRITERIA
    # Criteria 1 (Same Source): Events 1, 2, 4 from 10.0.3.15
    # Criteria 2 (Same Related Event): Events 2 and 3 share 'EVT-SHARED-99'
    # Criteria 3 (Lateral Chain): Event 4 (lab-server) -> Event 5 (icu-monitor-gw) -> Event 6 (icu-controller)
    # -------------------------------------------------------------------------
    raw_logs_campaign = [
        # Stage 1: SMB Discovery/Reconnaissance on Admin Workstation
        {
            "timestamp": "2026-10-07T10:00:00Z",
            "source": "admin_pcap_sensor",
            "event_type": "SMB_FLOW",
            "src": "10.0.3.15",  # Primary Attacker Source
            "dst": "10.0.3.20",
            "protocol": "TCP",
            "bytes": 80,
            "zone": "administration",
            "scenario_id": "six_stage_attack_campaign"
        },
        # Stage 2: TCP Port Scan Sweep targeting Radiology Workstation
        {
            "timestamp": "2026-10-07T10:02:00Z",
            "source": "radiology_pcap_sensor",
            "event_type": "PORT_SCAN",
            "src": "10.0.3.15",  # Same Attacker Source
            "dst": "10.0.4.12",
            "protocol": "TCP",
            "bytes": 1200,
            "zone": "radiology",
            "scenario_id": "six_stage_attack_campaign"
        },
        # Stage 3: Credential Dumping Attempt on PACS Server (Shares EVT-SHARED-99 with Stage 2)
        {
            "timestamp": "2026-10-07T10:03:00Z",
            "source": "pacs_auth_sensor",
            "event_type": "CREDENTIAL_DUMP",
            "src": "10.0.4.88",
            "dst": "10.0.4.10",
            "protocol": "TCP",
            "bytes": 3400,
            "zone": "radiology",
            "scenario_id": "six_stage_attack_campaign"
        },
        # Stage 4: Unauthorized DB Query / Malware Stage on Lab Server
        {
            "timestamp": "2026-10-07T10:05:00Z",
            "source": "lab_pcap_sensor",
            "event_type": "MALWARE_STAGING",
            "src": "10.0.3.15",  # Same Attacker Source
            "dst": "10.0.2.10",  # lab-server compromised here
            "protocol": "TCP",
            "bytes": 8192,
            "zone": "laboratory",
            "scenario_id": "six_stage_attack_campaign"
        },
        # Stage 5: Lateral Exploitation Attempt on Patient Monitor Gateway (Chain from lab-server!)
        {
            "timestamp": "2026-10-07T10:07:00Z",
            "source": "icu_pcap_sensor",
            "event_type": "EXPLOIT_ATTEMPT",
            "src": "lab-server",  # LATERAL CHAIN: Compromised lab-server attacks ICU!
            "dst": "10.0.1.45",   # icu-monitor-gw (Tier 1)
            "protocol": "TCP",
            "bytes": 4096,
            "zone": "intensive_care",
            "scenario_id": "six_stage_attack_campaign"
        },
        # Stage 6: Command & Control (C2) / HL7 Disruption on ICU Controller (Pivot from ICU Monitor)
        {
            "timestamp": "2026-10-07T10:09:00Z",
            "source": "icu_pcap_sensor",
            "event_type": "C2_BEACON",
            "src": "icu-monitor-gw",  # LATERAL CHAIN: Pivot from icu-monitor-gw to icu-controller!
            "dst": "10.0.1.50",       # icu-controller (Tier 1)
            "protocol": "TCP",
            "bytes": 1024,
            "zone": "intensive_care",
            "scenario_id": "six_stage_attack_campaign"
        }
    ]

    last_proposal = None
    last_asset = None

    for idx, raw_log in enumerate(raw_logs_campaign, 1):
        print(f"\n" + "=" * 80)
        print(f" >>> PROCESSING CAMPAIGN STAGE {idx}/6: Event Type '{raw_log['event_type']}' in Zone '{raw_log['zone']}'")
        print("=" * 80)

        # --- 1. LAYER 0: DATA INGESTION ---
        obs_event = layer0.process_raw_log(raw_log)
        if not obs_event:
            print("[Layer 0]: Event dropped as duplicate.")
            continue

        print("\n--- [1] LAYER 0: NORMALIZED OBSERVATION EVENT ---")
        obs_dict = obs_event.model_dump()
        print(json.dumps(obs_dict, indent=2, default=str))

        for event in observations_to_audit([obs_dict]):
            audit_store.append(event)

        # --- 2. LAYER 1: ASSET INTELLIGENCE ---
        asset_context = layer1.enrich(obs_event)
        if not asset_context:
            print(f"[Layer 1 Error]: Asset IP/Name '{obs_event.src}' not recognized in inventory.")
            continue

        print("\n--- [2] LAYER 1: ASSET CONTEXT & CLINICAL TIER ---")
        asset_dict = asset_context.model_dump()
        asset_dict["timestamp"] = obs_event.timestamp
        print(json.dumps(asset_dict, indent=2, default=str))

        for event in asset_context_to_audit([asset_dict]):
            audit_store.append(event)

        # --- 3. LAYER 2: ML BEHAVIORAL DETECTION ---
        risk_scores = [0.60, 0.72, 0.78, 0.85, 0.94, 0.98]
        indicators_list = [
            ["UNEXPECTED_SMB_TRAFFIC"],
            ["PORT_SCAN_SWEEP"],
            ["CREDENTIAL_DUMPING_ATTEMPT", "UNAUTHORIZED_AUTH"],
            ["MALWARE_STAGING_PAYLOAD", "SUSPICIOUS_DB_QUERY"],
            ["EXPLOIT_ATTEMPT_SMB", "CRITICAL_FLOW_INTERRUPTION_RISK"],
            ["C2_BEACONING_ATTEMPT", "HL7_PROTOCOL_TAMPERING"]
        ]

        # Attach shared event ID to satisfy Criteria 2 for Stages 2 & 3
        related_evts = [obs_event.event_id]
        if idx in (2, 3):
            related_evts.append("EVT-SHARED-99")

        detection_finding = DetectionFinding(
            finding_id=f"FIND-00{idx}",
            asset_id=asset_context.asset_id,
            attacker_src=raw_log["src"],
            behavior_window="5m",
            anomaly_score=risk_scores[idx - 1],
            risk_score=risk_scores[idx - 1],
            indicators=indicators_list[idx - 1],
            baseline_version="v1.0.0",
            confidence=0.95,
            related_events=related_evts,
            recommended_observation_period=60
        )

        print("\n--- [3] LAYER 2: DETECTION FINDING ---")
        finding_dict = detection_finding.model_dump()
        finding_dict["behavior_window"] = {
            "start": "2026-10-07T10:00:00+00:00",
            "end": "2026-10-07T10:09:00+00:00",
        }
        finding_dict["timestamp"] = obs_event.timestamp
        print(json.dumps(finding_dict, indent=2, default=str))

        for event in findings_to_audit([finding_dict]):
            audit_store.append(event)

        # --- 4. LAYER 3: MULTI-FINDING THREAT CORRELATION & ORCHESTRATION ---
        proposal = orchestrator.process(
            finding=detection_finding,
            asset=asset_context,
            safety_mode=SystemSafetyMode.NORMAL
        )

        print("\n--- [4] LAYER 3: CORRELATED CAMPAIGN RESPONSE PROPOSAL ---")
        print(f"Case ID:                    {proposal.case_id}")
        print(f"Correlated Affected Assets:  {proposal.affected_assets}")
        print(f"Correlated Finding Count:   {len(proposal.correlated_finding_ids)}")
        print(f"Approval Level Required:     {proposal.approval_level.value}")
        proposal_dict = proposal.model_dump()
        print(json.dumps(proposal_dict, indent=2, default=str))

        audit_store.append(proposal_to_audit(proposal_dict, scenario_id="six_stage_attack_campaign"))

        last_proposal = proposal
        last_asset = asset_context

    # -------------------------------------------------------------------------
    # 5. LAYER 5: DECISION GATE (INTERACTIVE HUMAN APPROVAL PROMPT)
    # -------------------------------------------------------------------------
    decision_record = None
    if last_proposal and last_proposal.approval_level == ApprovalLevel.REQUIRES_HUMAN_APPROVAL:
        decision_str, reviewer_id, reason_str = prompt_human_decision(
            proposal=last_proposal,
            target_asset_id=last_asset.asset_id
        )

        decision_record = {
            "decision_id": "DEC-HUMAN-CAMPAIGN-01",
            "case_id": last_proposal.case_id,
            "reviewer": reviewer_id,
            "decision": decision_str,
            "scope_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "reason": reason_str,
            "timestamp": "2026-10-07T10:10:00.000000+00:00",
            "expiry": last_proposal.expiry_time,
            "asset_id": last_asset.asset_id,
            "approved_action": last_proposal.model_dump() if decision_str == "APPROVED" else None
        }

        print("\n--- [5] LAYER 5: FINAL DECISION RECORD RECORDED ---")
        print(json.dumps(decision_record, indent=2))
        audit_store.append(decision_to_audit(decision_record, scenario_id="six_stage_attack_campaign"))

    # -------------------------------------------------------------------------
    # 6. LAYER 4: CONTAINMENT & ENFORCEMENT
    # -------------------------------------------------------------------------
    print("\n==========================================================================")
    print("--- [6] LAYER 4: ENFORCEMENT ENGINE EXECUTION ---")
    print("==========================================================================")

    if decision_record and decision_record["decision"] == "APPROVED":
        enforcement_result = {
            "action_id": "ACT-CAMPAIGN-EXEC-01",
            "case_id": last_proposal.case_id,
            "decision_id": decision_record["decision_id"],
            "target_asset": last_asset.asset_id,
            "status": "APPLIED",
            "applied_controls": ["COARSE_ISOLATION", "SURGICAL_BLOCK"],
            "blocked_flows": [{"protocol": "TCP", "port": 445}, {"protocol": "TCP", "port": 8080}],
            "preserved_flows": [{"protocol": "HL7", "port": 2575}],
            "start_time": "2026-10-07T10:10:05.000000+00:00",
            "expiry_time": last_proposal.expiry_time,
            "verification": {
                "malicious_flow_blocked": True,
                "preserved_clinical_flows_available": True,
                "checked_at": "2026-10-07T10:10:10.000000+00:00"
            },
            "rollback_token": last_proposal.rollback_plan.rollback_token_spec
        }
        print("✅ Enforcement Applied Successfully!")
    else:
        enforcement_result = {
            "action_id": "ACT-CAMPAIGN-EXEC-01",
            "case_id": last_proposal.case_id,
            "decision_id": decision_record["decision_id"] if decision_record else "DEC-NONE",
            "target_asset": last_asset.asset_id,
            "status": "SKIPPED_REJECTED",
            "applied_controls": [],
            "blocked_flows": [],
            "preserved_flows": [],
            "start_time": "2026-10-07T10:10:05.000000+00:00",
            "expiry_time": last_proposal.expiry_time,
            "verification": {
                "malicious_flow_blocked": False,
                "preserved_clinical_flows_available": True,
                "checked_at": "2026-10-07T10:10:10.000000+00:00"
            },
            "rollback_token": "RB-NONE"
        }
        print("⚠️ Enforcement Skipped due to REJECTED Human Approval.")

    print(json.dumps(enforcement_result, indent=2))
    audit_store.append(enforcement_to_audit(enforcement_result, scenario_id="six_stage_attack_campaign"))

    # -------------------------------------------------------------------------
    # 7. LAYER 6: COMPLIANCE, PRIVACY & EVIDENCE EXPORT
    # -------------------------------------------------------------------------
    print("\n==========================================================================")
    print("--- [7] LAYER 6: COMPLIANCE, REDACTION & EVIDENCE EXPORT ---")
    print("==========================================================================")

    engine.learn([last_asset.asset_id, "10.0.3.15"], domain="asset")

    controller = AccessController(audit_store, engine)
    access_result = controller.read(
        role=AccessRole.ANALYST,
        actor="soc_analyst",
        records=audit_store.records(),
        case_id=last_proposal.case_id,
        scenario_id="six_stage_attack_campaign"
    )

    timeline = build_timeline(
        records=access_result.records,
        case_id=last_proposal.case_id,
        scenario_id="six_stage_attack_campaign",
        chain_verification=audit_store.verify()
    )

    metrics = layer6_metrics(
        store=audit_store,
        engine=engine,
        operational_records=access_result.records,
        forensic_records=[r.to_dict() for r in audit_store.records()]
    )

    report = build_report(timeline, metrics=metrics)
    markdown_content = render_markdown(report)

    adapter = FileReportAdapter(output_dir=output_dir)
    dispatch_info = adapter.dispatch(report, markdown_content)
    report_files = [Path(p) for p in dispatch_info.get("files", [])]
    print(f"📄 Incident Timeline Report written to: {dispatch_info['files']}")

    manifest = export_evidence_package(
        output_dir=output_dir / "evidence_package",
        store=audit_store,
        timeline=timeline,
        operational_records=access_result.records,
        forensic_records=[r.to_dict() for r in audit_store.records()],
        metrics=metrics,
        report_files=report_files
    )
    print(f"📦 Evidence Package exported with ID: {manifest['package_id']}")
    print("🔒 SHA-256 Tamper-Evident Audit Chain verified and saved to disk.")


if __name__ == "__main__":
    main()