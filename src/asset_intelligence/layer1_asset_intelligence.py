from typing import Dict, Optional
from src.schemas.contracts import ObservationEvent, AssetContext, ClinicalTier

class Layer1AssetIntelligence:
    """Maps observation sources to physical assets, clinical tiers, and safety constraints."""

    def __init__(self):
        # Pre-seeded hospital device registry (simulated master inventory)
        self.asset_registry: Dict[str, AssetContext] = {
            "10.0.1.45": AssetContext(
                asset_id="DEV-ICU-MONITOR-01",
                asset_type="Patient Monitor Gateway",
                owner_zone="Intensive Care Unit",
                vendor="Philips",
                software_version="v4.2.1",
                clinical_tier=ClinicalTier.TIER_1,
                known_constraints=["Never isolate completely", "Preserve vital feeds"],
                allowed_peers=["10.0.1.5", "10.0.1.6"],
                normal_services=["HL7_Vitals"],
                fallback_mode="LOCAL_SD_CARD",
                identity_confidence=0.98
            ),
            "10.0.2.10": AssetContext(
                asset_id="DEV-RAD-XRAY-01",
                asset_type="Radiology Workstation",
                owner_zone="Radiology",
                vendor="Siemens",
                software_version="v2.1.0",
                clinical_tier=ClinicalTier.TIER_2,
                known_constraints=["Contain narrowly during workflows"],
                allowed_peers=["10.0.2.20"],
                normal_services=["DICOM_PACS"],
                fallback_mode="OFFLINE_CACHE",
                identity_confidence=0.95
            ),
            "10.0.3.15": AssetContext(
                asset_id="DEV-OFFICE-LAPTOP-04",
                asset_type="Reception Desk Endpoint",
                owner_zone="Administration",
                vendor="Dell",
                software_version="Windows 11",
                clinical_tier=ClinicalTier.TIER_3,
                known_constraints=["Non-clinical endpoint"],
                allowed_peers=["10.0.3.1"],
                normal_services=["HTTPS", "SMB"],
                fallback_mode="NONE",
                identity_confidence=0.99
            )
        }

    def enrich(self, event: ObservationEvent) -> Optional[AssetContext]:
        # Look up IP address in master inventory (checks source IP first, then destination IP)
        asset = self.asset_registry.get(event.src) or self.asset_registry.get(event.dst)
        return asset