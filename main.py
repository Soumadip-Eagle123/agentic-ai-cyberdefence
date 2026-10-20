"""ACCDS end-to-end simulation: Layers 0 through 6 over the hospital digital twin.

Run a multi-stage attack campaign against the simulated hospital and watch every
layer do its job: observe, identify, detect, correlate, ask a human when the
stakes are high, contain, and record.

    python main.py                                   # interactive
    python main.py --no-input                        # non-interactive, auto-reject
    python main.py --campaign ransomware_spread
    python main.py --approve                         # non-interactive, auto-approve
    python main.py --list                            # show available campaigns

Everything in this file is wiring. The hospital lives in ``digital_twin``, and
each layer lives in its own package under ``src/``.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from digital_twin import hospital, scenarios
from src.schemas.contracts import (
    ApprovalLevel,
    DecisionOutcome,
    SystemSafetyMode,
)

# --- Layers 0-5 ---
from src.ingestion.layer0_ingestion import Layer0Ingestion
from src.asset_intelligence.layer1_asset_intelligence import Layer1AssetIntelligence
from src.detection.layer2_detector import Layer2Detector
from src.orchestration.layer3_orchestrator import Layer3Orchestrator
from src.decision_gate.decision_logic import Layer5DecisionGate
from src.enforcement.layer4_executor import Layer4Executor

# --- Layer 6 compliance & audit ---
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

RULE = "=" * 78
THIN = "-" * 78


def banner(text: str) -> None:
    print(f"\n{RULE}\n {text}\n{RULE}")


# ---------------------------------------------------------------------------
# Layer 5 presentation
# ---------------------------------------------------------------------------
def show_approval_request(proposal, asset_id: str) -> None:
    """What the reviewer sees. The roadmap requires evidence, affected asset,
    clinical tier, proposed action, expected impact, alternatives, confidence
    and the rollback plan - all on one screen."""
    print(f"\n{RULE}")
    print(" [LAYER 5: DECISION GATE - HUMAN APPROVAL REQUIRED]")
    print(RULE)
    print(f" Tier 1 asset involved     : {asset_id}")
    print(f" Case ID                   : {proposal.case_id}")
    print(f" Threat summary            : {proposal.threat_summary}")
    print(f" Affected assets           : {', '.join(proposal.affected_assets)}")
    print(f" Clinical impact           : {proposal.clinical_impact}")
    print(f" Confidence                : {proposal.confidence}")

    if proposal.attack_chain:
        print("\n Attack path (how we got here):")
        for index, hop in enumerate(proposal.attack_chain, 1):
            flag = "  <-- LIFE-CRITICAL" if hop.get("victim_tier") == 1 else ""
            print(f"   {index}. {hop['attacker']} -> {hop['victim']} "
                  f"(tier {hop['victim_tier']}) {', '.join(hop['indicators'])}{flag}")

    print("\n Candidate actions:")
    for action in proposal.candidate_actions:
        print(f"   - {action.action_type} on '{action.target_asset}'")
        if action.blocked_flows:
            print(f"       blocked  : {action.blocked_flows}")
        if action.preserved_flows:
            print(f"       preserved: {action.preserved_flows}")
    print(f"\n Rollback token            : {proposal.rollback_plan.rollback_token_spec}")
    print(f" Auto-rollback after       : {proposal.rollback_plan.auto_rollback_seconds}s")
    print(RULE)


#: Commands an operator is likely to type at a shell while a prompt is waiting.
#: If one lands in the reviewer field, the prompt caught it by mistake.
_SHELL_WORDS = {
    "clear", "ls", "cd", "exit", "quit", "pwd", "git", "python", "python3",
    "cat", "vim", "nano", "code", "make", "pip", "sudo", "y", "n", "yes", "no",
}


def _looks_like_reviewer(name: str) -> bool:
    """A person's ID, not a stray terminal command."""
    if not name or len(name) > 64:
        return False
    if name.lower() in _SHELL_WORDS:
        return False
    return not any(token in name for token in ("/", "--", "=", " ", "|", ";", "$"))


def prompt_human_decision(proposal, asset_id: str, auto: Optional[str]):
    """Returns (DecisionOutcome, reviewer, reason)."""
    show_approval_request(proposal, asset_id)

    if auto == "approve":
        print("\n[non-interactive] auto-approving")
        return (DecisionOutcome.APPROVED, "automated_test_harness",
                "Non-interactive run: approved for pipeline verification.")
    if auto == "reject":
        print("\n[non-interactive] auto-rejecting")
        return (DecisionOutcome.REJECTED, "automated_test_harness",
                "Non-interactive run: rejected for pipeline verification.")

    # Re-ask rather than treating anything-that-isn't-y as a rejection. A typo
    # or a stray newline used to be recorded as a considered clinical decision,
    # and the next thing typed at the shell became the reviewer's name.
    approved = None
    while approved is None:
        try:
            choice = input("\n Do you approve this proposal? (y/n): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[!] Input interrupted. Recording REJECTED - no action will be taken.")
            approved = False
            break
        if choice in ("y", "yes"):
            approved = True
        elif choice in ("n", "no"):
            approved = False
        else:
            print("   Please answer 'y' or 'n'. This decision is recorded in the audit chain.")
    default_reason = (
        "Verified multi-stage lateral campaign reaching ICU infrastructure. "
        "Approved surgical block preserving HL7 vitals."
        if approved else
        "Rejected: risk of clinical workflow disruption outweighs the threat."
    )
    try:
        reviewer = input(" SOC analyst name/ID [analyst_dr_smith]: ").strip() or "analyst_dr_smith"
        reason = input(f" Reason [{default_reason[:40]}...]: ").strip() or default_reason
    except (KeyboardInterrupt, EOFError):
        reviewer, reason = "analyst_dr_smith", default_reason

    # A shell command captured as a reviewer name means the prompt swallowed
    # something the operator meant for their terminal. Refuse it rather than
    # writing nonsense into a clinical audit record.
    if not _looks_like_reviewer(reviewer):
        print(f"   ! '{reviewer}' does not look like a reviewer ID - using analyst_dr_smith")
        reviewer = "analyst_dr_smith"

    return (DecisionOutcome.APPROVED if approved else DecisionOutcome.REJECTED,
            reviewer, reason)


# ---------------------------------------------------------------------------
# Topology export, for the visualiser
# ---------------------------------------------------------------------------
def export_topology(path: Path, campaign, stage_records: List[Dict], proposals: List[Dict],
                    decision: Optional[Dict], enforcement: Optional[Dict]) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "campaign": {
            "scenario_id": campaign.scenario_id,
            "title": campaign.title,
            "description": campaign.description,
            "touches_tier1": campaign.touches_tier1,
            "zones_crossed": campaign.crosses_zones,
        },
        "zones": [
            {"name": z.name, "label": z.label, "rect": list(z.rect), "accent": z.accent}
            for z in hospital.all_zones()
        ],
        "devices": [
            {
                "asset_id": d.asset_id, "asset_type": d.asset_type, "zone": d.zone,
                "tier": d.tier, "ip": d.ip, "pos": list(d.pos),
                "peers": d.peers, "services": d.services, "vendor": d.vendor,
                "software_version": d.software_version,
                "fallback_mode": d.fallback_mode,
                "constraints": d.known_constraints,
            }
            for d in hospital.all_devices()
        ],
        "baseline_edges": [list(e) for e in hospital.baseline_edges()],
        "stages": stage_records,
        "proposals": proposals,
        "decision": decision,
        "enforcement": enforcement,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------
def run(campaign_name: str, output_dir: Path, auto: Optional[str],
        baseline_hours: int, quiet: bool) -> int:
    campaign = scenarios.get_campaign(campaign_name)

    banner(f"ACCDS SIMULATION: {campaign.title.upper()}")
    print(f" {campaign.description}")
    print(f" Stages: {len(campaign.stages)} | Zones crossed: {', '.join(campaign.crosses_zones)}"
          f" | Reaches Tier 1: {campaign.touches_tier1}")

    output_dir.mkdir(parents=True, exist_ok=True)
    audit_store = TamperEvidentAuditStore(output_dir / "audit_chain.jsonl",
                                          key=DEFAULT_PSEUDONYM_KEY)
    engine = RedactionEngine(key=DEFAULT_PSEUDONYM_KEY)

    layer0 = Layer0Ingestion()
    layer1 = Layer1AssetIntelligence()
    layer2 = Layer2Detector()
    layer3 = Layer3Orchestrator()
    layer5 = Layer5DecisionGate()
    layer4 = Layer4Executor()

    # --- Train Layer 2 on normal traffic ---------------------------------
    # Without a baseline there is nothing to deviate from, which is why the
    # scores in the original demo had to be hardcoded.
    banner("LAYER 2 BASELINE TRAINING (normal hospital traffic)")
    baseline = scenarios.generate_normal(hours=baseline_hours)
    learned = layer2.learn_from_events(baseline)
    print(f" Trained on {learned} normal events across {len(layer2.baselines)} devices"
          f" ({baseline_hours}h of hospital activity).")
    if not quiet:
        for asset_id, summary in list(layer2.baseline_summary().items())[:5]:
            print(f"   {asset_id:<18} events={summary['events_seen']:<4} "
                  f"peers={summary['known_peers']:<3} mean_bytes={summary['mean_bytes']}")

    # --- Replay the campaign ---------------------------------------------
    events = scenarios.generate_campaign(campaign)
    stage_records: List[Dict] = []
    proposals: List[Dict] = []
    last_proposal = None
    last_asset_id = None

    for event in events:
        raw_log = event.to_raw_log()
        banner(f"STAGE {event.stage_index}/{len(events)}: {event.event_type} in '{event.zone}'")

        # --- LAYER 0 ------------------------------------------------------
        obs = layer0.process_raw_log(raw_log)
        if not obs:
            print(" [Layer 0] duplicate event dropped")
            continue
        obs_dict = obs.model_dump()
        if not quiet:
            print(f"\n [0] OBSERVED   {obs.src} -> {obs.dst}  {obs.event_type}  "
                  f"{obs.bytes}B  ({obs.event_id})")
        for audit in observations_to_audit([obs_dict]):
            audit_store.append(audit)

        # --- LAYER 1 ------------------------------------------------------
        # Resolves the VICTIM (destination first) and the attacker's identity.
        # Never returns None, so a stage can no longer vanish.
        enrichment = layer1.enrich_full(obs)
        asset = enrichment.asset
        tier = int(asset.clinical_tier)
        flag = "  <-- LIFE-CRITICAL" if tier == 1 else ""
        print(f" [1] IDENTIFIED {asset.asset_id} ({asset.asset_type}) "
              f"zone={asset.owner_zone} TIER {tier}{flag}")
        if not enrichment.identity_known:
            print(f"     ! address '{obs.dst}' not in inventory - "
                  f"reduced visibility, identity confidence {asset.identity_confidence}")
        if enrichment.attacker_asset_id:
            print(f"     attacker resolved to: {enrichment.attacker_asset_id}")

        asset_dict = asset.model_dump()
        asset_dict["timestamp"] = obs.timestamp
        for audit in asset_context_to_audit([asset_dict]):
            audit_store.append(audit)

        # --- LAYER 2 ------------------------------------------------------
        finding = layer2.analyze_observation(
            asset_context=asset,
            event_id=obs.event_id,
            event_type=obs.event_type,
            src=obs.src,
            # The other end of the flow relative to the asset being scored.
            counterpart=(obs.src if enrichment.resolved_from == "dst" else obs.dst),
            byte_count=obs.bytes,
            timestamp=event.timestamp,
            attacker_asset_id=enrichment.attacker_asset_id,
        )
        if finding is None:
            print(f" [2] SCORED     below threshold ({layer2.threshold}) - no finding emitted")
            stage_records.append({
                "stage": event.stage_index, "src": obs.src, "dst": obs.dst,
                "asset_id": asset.asset_id, "tier": tier,
                "event_type": obs.event_type, "zone": obs.zone,
                "timestamp": obs.timestamp, "finding": None, "case_id": None,
                "attacker_asset_id": enrichment.attacker_asset_id,
            })
            continue

        print(f" [2] DETECTED   anomaly={finding.anomaly_score} risk={finding.risk_score} "
              f"confidence={finding.confidence}")
        print(f"     indicators: {', '.join(finding.indicators)}")
        for audit in findings_to_audit([finding.model_dump()]):
            audit_store.append(audit)

        # --- LAYER 3 ------------------------------------------------------
        proposal = layer3.process(finding=finding, asset=asset,
                                  safety_mode=SystemSafetyMode.NORMAL)
        correlated = len(proposal.correlated_finding_ids)
        print(f" [3] CORRELATED case={proposal.case_id} findings={correlated} "
              f"approval={proposal.approval_level.value}")
        if correlated > 1:
            path = " -> ".join(
                [str(proposal.attack_chain[0]['attacker'])]
                + [str(h['victim']) for h in proposal.attack_chain]
            )
            print(f"     chain: {path}")

        proposal_dict = proposal.model_dump()
        audit_store.append(proposal_to_audit(proposal_dict, scenario_id=campaign.scenario_id))
        proposals.append(proposal_dict)
        last_proposal, last_asset_id = proposal, asset.asset_id

        stage_records.append({
            "stage": event.stage_index, "src": obs.src, "dst": obs.dst,
            "asset_id": asset.asset_id, "tier": tier,
            "event_type": obs.event_type, "zone": obs.zone,
            "timestamp": obs.timestamp,
            "attacker_asset_id": enrichment.attacker_asset_id,
            "finding": {
                "finding_id": finding.finding_id,
                "anomaly_score": finding.anomaly_score,
                "risk_score": finding.risk_score,
                "indicators": finding.indicators,
                "confidence": finding.confidence,
            },
            "case_id": proposal.case_id,
            "approval_level": proposal.approval_level.value,
            "correlated_findings": correlated,
        })

    # --- Visibility report ------------------------------------------------
    visibility = layer1.visibility_report()
    banner("LAYER 1 VISIBILITY REPORT")
    print(f" Inventory size        : {visibility['inventory_size']} devices")
    print(f" Unresolved addresses  : {visibility['unresolved_count']}")
    print(f" Full visibility       : {visibility['fully_visible']}")
    if visibility["unresolved_addresses"]:
        for address, count in visibility["unresolved_addresses"].items():
            print(f"   ! {address} seen {count}x and not in inventory")

    if last_proposal is None:
        print("\n No findings were raised. Nothing to decide or enforce.")
        return 0

    # --- LAYER 5 ----------------------------------------------------------
    banner("LAYER 5: DECISION GATE")
    decision_record = layer5.evaluate_proposal(last_proposal)

    if decision_record is None:
        outcome, reviewer, reason = prompt_human_decision(last_proposal, last_asset_id, auto)
        decision_record = layer5.record_human_decision(
            case_id=last_proposal.case_id, reviewer_id=reviewer,
            decision=outcome, reason=reason,
        )
    else:
        print(f" AUTO-APPROVED by policy: {decision_record.reason}")

    decision_dict = decision_record.model_dump()
    print(f"\n decision   : {decision_record.decision.value}")
    print(f" reviewer   : {decision_record.reviewer}")
    print(f" scope_hash : {decision_record.scope_hash[:32]}...")
    print(f"              (bound to this exact action; an old approval cannot be reused)")
    audit_store.append(decision_to_audit(decision_dict, scenario_id=campaign.scenario_id))

    # --- LAYER 4 ----------------------------------------------------------
    banner("LAYER 4: CONTAINMENT & ENFORCEMENT")
    approved = decision_record.decision == DecisionOutcome.APPROVED
    enforcement = layer4.execute_proposal(last_proposal, force_execution=approved)
    enforcement_dict = enforcement.model_dump()
    enforcement_dict.setdefault("decision_id", decision_record.decision_id)

    print(f" status          : {enforcement.status.value}")
    print(f" target          : {enforcement.target_asset}")
    print(f" applied controls: {enforcement.applied_controls}")
    print(f" blocked flows   : {enforcement.blocked_flows}")
    print(f" preserved flows : {enforcement.preserved_flows}")
    print(f" verification    : {enforcement.verification}")
    print(f" rollback token  : {enforcement.rollback_token}")
    audit_store.append(enforcement_to_audit(enforcement_dict, scenario_id=campaign.scenario_id))

    # --- LAYER 6 ----------------------------------------------------------
    banner("LAYER 6: COMPLIANCE, REDACTION & EVIDENCE")
    controller = AccessController(audit_store, engine)
    engine.learn({d.asset_id for d in hospital.all_devices()}, domain="asset")
    engine.learn({d.ip for d in hospital.all_devices()}, domain="network")

    case_records = audit_store.for_case(last_proposal.case_id) or audit_store.records()
    forensic = controller.read(AccessRole.FORENSIC_INVESTIGATOR, "j.alvarez",
                               records=case_records, purpose="chain-of-custody review")
    operational = controller.read(AccessRole.ANALYST, "soc-shift-b",
                                  records=case_records, purpose="operational triage")

    timeline = build_timeline(operational.records, case_id=last_proposal.case_id,
                              scenario_id=campaign.scenario_id,
                              chain_verification=audit_store.verify())
    metrics = layer6_metrics(store=audit_store, engine=engine,
                             operational_records=operational.records,
                             forensic_records=forensic.records)
    report = build_report(timeline, metrics)
    adapter = FileReportAdapter(output_dir)
    dispatch = adapter.dispatch(report, render_markdown(report))

    manifest = export_evidence_package(
        output_dir / "evidence_package", store=audit_store, timeline=timeline,
        operational_records=operational.records, forensic_records=forensic.records,
        metrics=metrics,
        report_files=[Path(f) for f in dispatch.get("files", [])],
    )

    verification = audit_store.verify()
    print(f" audit records   : {len(audit_store)}")
    print(f" chain integrity : {'VERIFIED' if verification.ok else 'FAILED'} "
          f"({verification.records_checked} records)")
    print(f" leak scan       : {'clean' if metrics['privacy']['leak_scan']['clean'] else 'LEAKS'}")
    print(f" report          : {dispatch.get('files', ['-'])[0]}")
    print(f" evidence package: {manifest['package_id']}")

    # --- Topology export for the visualiser -------------------------------
    topology_path = output_dir / "topology.json"
    export_topology(topology_path, campaign, stage_records, proposals,
                    decision_dict, enforcement_dict)
    print(f" topology data   : {topology_path}")

    # --- Summary ----------------------------------------------------------
    banner("RUN SUMMARY")
    tier1_hit = [s for s in stage_records if s["tier"] == 1]
    detected = [s for s in stage_records if s.get("finding")]
    cases = {s["case_id"] for s in stage_records if s.get("case_id")}
    print(f" stages replayed      : {len(stage_records)}")
    print(f" findings raised      : {len(detected)}")
    print(f" correlated cases     : {len(cases)}  {sorted(cases)}")
    print(f" Tier 1 devices hit   : {len(tier1_hit)} "
          f"{sorted({s['asset_id'] for s in tier1_hit})}")
    print(f" human approval asked : {last_proposal.approval_level == ApprovalLevel.REQUIRES_HUMAN_APPROVAL}")
    print(f" enforcement outcome  : {enforcement.status.value}")
    print(f"\n Replay this run      :  python -m visualiser.build --data {topology_path}")
    print(f"                          then open {output_dir / 'topology.html'}")
    print(f" Launch attacks live  :  PYTHONPATH=. python -m visualiser.server")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ACCDS end-to-end hospital attack simulation")
    parser.add_argument("--campaign", default="lateral_to_icu",
                        help=f"one of: {', '.join(scenarios.campaign_names())}")
    parser.add_argument("--output", default="artifacts/full_run", type=Path)
    parser.add_argument("--baseline-hours", type=int, default=24,
                        help="hours of normal traffic to train Layer 2 on")
    parser.add_argument("--no-input", action="store_true",
                        help="non-interactive; auto-REJECT any approval request")
    parser.add_argument("--approve", action="store_true",
                        help="non-interactive; auto-APPROVE any approval request")
    parser.add_argument("--quiet", action="store_true", help="less verbose output")
    parser.add_argument("--list", action="store_true", help="list campaigns and exit")
    args = parser.parse_args()

    if args.list:
        print("Available campaigns:\n")
        for name in scenarios.campaign_names():
            campaign = scenarios.get_campaign(name)
            print(f"  {name:<24} {campaign.title}")
            print(f"  {'':<24} {len(campaign.stages)} stages, "
                  f"reaches Tier 1: {campaign.touches_tier1}\n")
        return 0

    auto = "approve" if args.approve else ("reject" if args.no_input else None)
    try:
        return run(args.campaign, args.output, auto, args.baseline_hours, args.quiet)
    except ValueError as error:
        print(f"error: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
