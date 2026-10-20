from typing import Dict, Optional
from src.schemas.contracts import ObservationEvent, AssetContext, ClinicalTier
from src.simulator.catalog import DEVICES, DEVICE_BY_ID, DEVICE_BY_IP

class Layer1AssetIntelligence:
    """Maps observation sources to physical assets, clinical tiers, and safety constraints."""

    def __init__(self):
        # One canonical six-node inventory is shared with the dashboard. Values
        # remain a digital-twin catalogue; no network device is contacted.
        self.asset_registry: Dict[str, AssetContext] = {}
        for device in DEVICES:
            tier = ClinicalTier(device["tier"])
            peers = [DEVICE_BY_ID[peer]["ip"] for peer in device["peers"] if peer in DEVICE_BY_ID]
            services = [service.split(" · ")[0].replace(" ", "_").upper() for service in device["services"]]
            constraints = {
                1: ["Never isolate completely", "Preserve clinical telemetry"],
                2: ["Contain narrowly during active workflows"],
                3: ["Non-clinical endpoint; coarse isolation permitted"],
            }[device["tier"]]
            context = AssetContext(
                asset_id=device["id"],
                asset_type=device["type"],
                owner_zone=device["zone"],
                vendor="ACCDS Digital Twin",
                software_version="simulated-1.0",
                clinical_tier=tier,
                known_constraints=constraints,
                allowed_peers=peers,
                normal_services=services,
                fallback_mode="clinical-continuity" if tier == ClinicalTier.TIER_1 else "simulated",
                identity_confidence=0.99 if tier != ClinicalTier.TIER_1 else 0.98,
            )
            self.asset_registry[device["ip"]] = context
            self.asset_registry[device["id"]] = context

    def enrich(self, event: ObservationEvent, prefer_destination: bool = True) -> Optional[AssetContext]:
        """Resolve the asset being addressed, falling back to the source endpoint."""
        candidates = (event.dst, event.src) if prefer_destination else (event.src, event.dst)
        asset = next((self.asset_registry.get(value) for value in candidates if self.asset_registry.get(value)), None)
        return asset
