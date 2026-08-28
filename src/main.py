import json
from schemas.contracts import AssetContext, DetectionFinding, ClinicalTier, SystemSafetyMode
from orchestration.layer3_orchestrator import Layer3Orchestrator


def main():
    # 1. Mock Layer 1 Input (Asset Intelligence Context)
    tier1_asset = AssetContext(
        asset_id="DEV-ICU-MONITOR-01",
        asset_type="Patient Monitor Gateway",
        owner_zone="Intensive Care Unit",
        vendor="Philips",
        software_version="v4.2.1",
        clinical_tier=ClinicalTier.TIER_1,
        known_constraints=["Do not interrupt telemetry feed"],
        allowed_peers=["10.0.1.5", "10.0.1.6"],
        normal_services=["HL7_Vitals"],
        fallback_mode="LOCAL_STORAGE",
        identity_confidence=0.98
    )

    # 2. Mock Layer 2 Input (ML Finding)
    detection_finding = DetectionFinding(
        finding_id="FIND-2026-0882",
        asset_id="DEV-ICU-MONITOR-01",
        behavior_window="5m",
        anomaly_score=0.89,
        risk_score=0.92,
        indicators=["UNEXPECTED_SMB_TRAFFIC", "LATERAL_SCAN_PORT_445"],
        baseline_version="v1.0.4",
        confidence=0.95,
        related_events=["EVT-9901", "EVT-9902"],
        recommended_observation_period=60
    )

    # 3. Process through Layer 3 Orchestrator
    orchestrator = Layer3Orchestrator()
    proposal = orchestrator.process(
        finding=detection_finding,
        asset=tier1_asset,
        safety_mode=SystemSafetyMode.NORMAL
    )

    # Output structured proposal json
    print("=== Layer 3 Response Proposal Output ===")
    print(json.dumps(proposal.model_dump(), indent=2))


if __name__ == "__main__":
    main()