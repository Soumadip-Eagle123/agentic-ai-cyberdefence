"""Layer 1 - Asset Intelligence.

Turns an observation into knowledge about *which* device is involved and how
much patient care depends on it. Everything downstream hangs on getting this
right: the clinical tier decided here is what determines whether the system may
act on its own or must stop and ask a human.

Three corrections live in this module.

**The asset under attack is the destination.** The previous implementation
looked up ``event.src`` first, which in an attack is the *attacker*. An exploit
fired from a compromised laptop at the ICU patient monitor gateway resolved to
the laptop - Tier 3, non-clinical - so Layer 3 concluded "rapid isolation
allowed" and auto-approved containment against a life-critical device with no
human ever asked. Destination first, source as fallback, fixes it. The fallback
still matters: in a port sweep or an upload to the internet the destination is
not a hospital asset, and the device worth reporting is the sender.

**Both ends get resolved.** Correlating lateral movement means recognising that
the machine attacking the ICU is the lab server we watched get compromised a
minute ago. That comparison can only work if the attacker is expressed as an
asset id rather than a raw address, so ``enrich`` returns the attacker's
identity alongside the victim's.

**Unknown devices are reported, not dropped.** Previously an address missing
from the inventory ended the whole stage - no finding, no correlation, no audit
record. Two of six campaign stages disappeared that way, including an attacker
pivoting onto a second life-critical device. The roadmap is explicit that a gap
in visibility must be reported rather than passed off as an absence of activity,
so an unrecognised address now yields a placeholder asset with low identity
confidence, which lowers response confidence instead of triggering aggressive
action.
"""

from dataclasses import dataclass
from typing import Dict, Optional

from digital_twin import hospital
from src.schemas.contracts import AssetContext, ClinicalTier, ObservationEvent

#: Confidence assigned when an address is not in the inventory. Low on purpose:
#: the roadmap requires uncertain identity to reduce response confidence.
UNKNOWN_IDENTITY_CONFIDENCE = 0.2

#: Unknown devices are treated as Tier 2, not Tier 3. We cannot prove an
#: unidentified device is non-clinical, and guessing "harmless" is the dangerous
#: direction to be wrong in.
UNKNOWN_DEFAULT_TIER = ClinicalTier.TIER_2


@dataclass
class EnrichmentResult:
    """Both ends of an event, resolved.

    ``asset`` is the device at risk - the one tiering and response decisions are
    made about. ``attacker_asset_id`` is the other end when it is a device we
    know, which is what makes lateral-movement correlation possible.
    """

    asset: AssetContext
    attacker_asset_id: Optional[str] = None
    attacker_address: Optional[str] = None
    resolved_from: str = "dst"
    identity_known: bool = True

    @property
    def is_attacker_known_device(self) -> bool:
        return self.attacker_asset_id is not None


def _to_context(device: hospital.Device) -> AssetContext:
    return AssetContext(
        asset_id=device.asset_id,
        asset_type=device.asset_type,
        owner_zone=device.zone,
        vendor=device.vendor,
        software_version=device.software_version,
        clinical_tier=ClinicalTier(device.tier),
        known_constraints=device.known_constraints,
        allowed_peers=[
            (hospital.by_asset_id(p).ip if hospital.by_asset_id(p) else p)
            for p in device.peers
        ],
        normal_services=device.services,
        fallback_mode=device.fallback_mode,
        identity_confidence=0.98,
    )


def _unknown_context(address: str, zone: str) -> AssetContext:
    """A placeholder so an unrecognised device stays visible to the pipeline."""
    return AssetContext(
        asset_id=f"UNKNOWN-{address}",
        asset_type="Unidentified Device",
        owner_zone=zone or "unknown",
        vendor="Unknown",
        software_version="Unknown",
        clinical_tier=UNKNOWN_DEFAULT_TIER,
        known_constraints=["Identity unconfirmed - treat conservatively"],
        allowed_peers=[],
        normal_services=[],
        fallback_mode="UNKNOWN",
        identity_confidence=UNKNOWN_IDENTITY_CONFIDENCE,
    )


class Layer1AssetIntelligence:
    """Resolves observations against the hospital inventory."""

    def __init__(self) -> None:
        self.unresolved_addresses: Dict[str, int] = {}

    # -- main entry point --------------------------------------------------
    def enrich_full(self, event: ObservationEvent) -> EnrichmentResult:
        """Resolve both ends of an event. Never returns None."""
        victim = hospital.get(event.dst)
        attacker = hospital.get(event.src)

        if victim is not None:
            # Normal attack shape: a known device is being targeted.
            return EnrichmentResult(
                asset=_to_context(victim),
                attacker_asset_id=attacker.asset_id if attacker else None,
                attacker_address=event.src,
                resolved_from="dst",
                identity_known=True,
            )

        if attacker is not None:
            # The destination is not a hospital asset - a port sweep, or an
            # upload to the internet. The device worth reporting is the sender.
            return EnrichmentResult(
                asset=_to_context(attacker),
                attacker_asset_id=attacker.asset_id,
                attacker_address=event.src,
                resolved_from="src",
                identity_known=True,
            )

        # Neither end is known. Report reduced visibility rather than silence.
        self.unresolved_addresses[event.dst] = self.unresolved_addresses.get(event.dst, 0) + 1
        return EnrichmentResult(
            asset=_unknown_context(event.dst, event.zone),
            attacker_asset_id=None,
            attacker_address=event.src,
            resolved_from="unknown",
            identity_known=False,
        )

    # -- backwards-compatible shim ----------------------------------------
    def enrich(self, event: ObservationEvent) -> Optional[AssetContext]:
        """Victim asset context only.

        Kept so existing callers keep working. New code should prefer
        ``enrich_full``, which also returns the attacker's identity.
        """
        return self.enrich_full(event).asset

    # -- reporting ---------------------------------------------------------
    def visibility_report(self) -> Dict[str, object]:
        """What the inventory could not account for.

        A blind spot an attacker can aim for is worth surfacing explicitly.
        """
        return {
            "inventory_size": len(hospital.all_devices()),
            "unresolved_addresses": dict(self.unresolved_addresses),
            "unresolved_count": sum(self.unresolved_addresses.values()),
            "fully_visible": not self.unresolved_addresses,
        }
