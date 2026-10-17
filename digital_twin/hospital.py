"""The hospital digital twin: the single source of truth for what exists.

Every layer that needs to know "what is this device and how critical is it"
reads from here. Before this module, Layer 1 carried its own three-device
dictionary while the Layer 2 generator carried a different seven-device one,
and neither covered the addresses the attack scenarios actually used - which is
why two of the six campaign stages silently vanished.

A device has two kinds of identity:

* ``asset_id``  - the stable inventory name ("icu-monitor-gw")
* ``addresses`` - every network identifier it answers to (its IP, its hostname)

Keeping both matters. Telemetry arrives with IPs, humans and inventories speak
names, and lateral-movement correlation has to recognise that "10.0.2.10"
attacking the ICU *is* the lab server we watched get compromised a minute ago.

``zone_layout`` carries room rectangles and device positions for the topology
view. Those coordinates are presentation only: no layer makes a security
decision from them, because physical proximity is not network reachability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

#: Clinical tiers, straight from the roadmap.
#:   1 = life-critical, surgical blocking + human approval
#:   2 = workflow-critical, contain narrowly
#:   3 = non-clinical, rapid isolation permitted
TIER_1, TIER_2, TIER_3 = 1, 2, 3


@dataclass(frozen=True)
class Device:
    asset_id: str
    asset_type: str
    zone: str
    tier: int
    ip: str
    peers: List[str]
    services: List[str]
    vendor: str = "ACCDS-Sim"
    software_version: str = "1.0"
    fallback_mode: str = "degraded"
    hostnames: List[str] = field(default_factory=list)
    #: Position inside its zone room, as a fraction of the room (0-1).
    pos: Tuple[float, float] = (0.5, 0.5)

    @property
    def addresses(self) -> List[str]:
        """Every identifier this device answers to."""
        return [self.asset_id, self.ip, *self.hostnames]

    @property
    def known_constraints(self) -> List[str]:
        if self.tier == TIER_1:
            return ["Never isolate completely", "Preserve vital feeds"]
        if self.tier == TIER_2:
            return ["Contain narrowly during clinical workflows"]
        return ["Non-clinical endpoint"]

    @property
    def is_life_critical(self) -> bool:
        return self.tier == TIER_1


# ---------------------------------------------------------------------------
# The hospital
#
# Twelve devices across six zones. Every address referenced by the attack
# scenarios resolves to one of these, which is what stops events disappearing.
# ---------------------------------------------------------------------------
DEVICES: List[Device] = [
    # -- Intensive care: the devices the whole system exists to protect -----
    Device(
        asset_id="icu-monitor-gw", asset_type="Patient Monitor Gateway",
        zone="intensive_care", tier=TIER_1, ip="10.0.1.45",
        peers=["icu-controller", "ehr-core"],
        services=["HL7_Vitals", "monitoring"],
        vendor="Philips", software_version="v4.2.1",
        fallback_mode="LOCAL_SD_CARD", pos=(0.3, 0.45),
    ),
    Device(
        asset_id="icu-controller", asset_type="Intensive Care Controller",
        zone="intensive_care", tier=TIER_1, ip="10.0.1.50",
        peers=["icu-monitor-gw", "ehr-core"],
        services=["control", "clinical-data"],
        vendor="Draeger", software_version="v3.8.0",
        fallback_mode="MANUAL", pos=(0.7, 0.45),
    ),

    # -- Laboratory --------------------------------------------------------
    Device(
        asset_id="lab-server", asset_type="Laboratory Server",
        zone="laboratory", tier=TIER_2, ip="10.0.2.10",
        peers=["lab-analyzer", "ehr-core"],
        services=["lab-results", "database"],
        vendor="Roche", software_version="v5.1.2",
        fallback_mode="OFFLINE_CACHE", pos=(0.32, 0.45),
    ),
    Device(
        asset_id="lab-analyzer", asset_type="Laboratory Analyzer",
        zone="laboratory", tier=TIER_2, ip="10.0.2.20",
        peers=["lab-server"],
        services=["lab-results"],
        vendor="Roche", software_version="v2.4.0",
        fallback_mode="OFFLINE_CACHE", pos=(0.68, 0.45),
    ),

    # -- Radiology ---------------------------------------------------------
    Device(
        asset_id="pacs", asset_type="PACS Imaging Server",
        zone="radiology", tier=TIER_2, ip="10.0.4.10",
        peers=["radiology-ws", "rad-tech-ws", "ehr-core"],
        services=["DICOM_PACS", "imaging-store"],
        vendor="Siemens", software_version="v2.1.0",
        fallback_mode="OFFLINE_CACHE", pos=(0.26, 0.42),
    ),
    Device(
        asset_id="radiology-ws", asset_type="Radiology Workstation",
        zone="radiology", tier=TIER_2, ip="10.0.4.12",
        peers=["pacs", "ehr-core"],
        services=["DICOM_PACS", "clinical-data"],
        vendor="Siemens", software_version="v2.1.0",
        fallback_mode="OFFLINE_CACHE", pos=(0.55, 0.42),
    ),
    Device(
        asset_id="rad-tech-ws", asset_type="Radiology Technician Endpoint",
        zone="radiology", tier=TIER_3, ip="10.0.4.88",
        peers=["pacs"],
        services=["DICOM_PACS", "https"],
        vendor="Dell", software_version="Windows 11",
        fallback_mode="NONE", pos=(0.82, 0.42),
    ),

    # -- Security operations: where the clinical record server lives --------
    Device(
        asset_id="ehr-core", asset_type="Electronic Health Record Server",
        zone="security_operations", tier=TIER_2, ip="10.0.1.5",
        peers=["icu-monitor-gw", "icu-controller", "lab-server",
               "radiology-ws", "pacs", "office-ws"],
        services=["clinical-data", "database", "auth"],
        vendor="Epic", software_version="v9.3.1",
        fallback_mode="READ_ONLY_REPLICA", pos=(0.5, 0.45),
    ),

    # -- Administration: where the attacker gets in ------------------------
    Device(
        asset_id="office-ws", asset_type="Reception Desk Endpoint",
        zone="administration", tier=TIER_3, ip="10.0.3.15",
        peers=["ehr-core", "admin-gateway"],
        services=["HTTPS", "SMB"],
        vendor="Dell", software_version="Windows 11",
        fallback_mode="NONE", pos=(0.26, 0.45),
    ),
    Device(
        asset_id="admin-print", asset_type="Administration Printer",
        zone="administration", tier=TIER_3, ip="10.0.3.20",
        peers=["admin-gateway"],
        services=["SMB", "IPP"],
        vendor="HP", software_version="v1.9.0",
        fallback_mode="NONE", pos=(0.55, 0.45),
    ),
    Device(
        asset_id="admin-gateway", asset_type="Administration Gateway",
        zone="administration", tier=TIER_3, ip="10.0.3.1",
        peers=["office-ws", "admin-print", "ehr-core"],
        services=["routing", "dns"],
        vendor="Cisco", software_version="v15.2",
        fallback_mode="NONE", pos=(0.82, 0.45),
    ),

    # -- Guest network -----------------------------------------------------
    Device(
        asset_id="guest-device", asset_type="Guest Endpoint",
        zone="guest", tier=TIER_3, ip="10.0.5.33",
        peers=["public-dns"],
        services=["HTTPS", "dns"],
        vendor="Unknown", software_version="Unknown",
        fallback_mode="NONE", pos=(0.5, 0.45),
    ),
]


# ---------------------------------------------------------------------------
# Zone rooms, for the topology view only
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Zone:
    name: str
    label: str
    #: Room rectangle on a 1000x620 canvas.
    rect: Tuple[int, int, int, int]
    accent: str


ZONES: List[Zone] = [
    Zone("intensive_care", "Intensive Care", (40, 40, 300, 200), "#ef4444"),
    Zone("laboratory", "Laboratory", (380, 40, 270, 200), "#f59e0b"),
    Zone("radiology", "Radiology", (690, 40, 270, 200), "#8b5cf6"),
    Zone("security_operations", "Security Ops / EHR", (380, 290, 270, 170), "#06b6d4"),
    Zone("administration", "Administration", (40, 290, 300, 170), "#22c55e"),
    Zone("guest", "Guest Network", (690, 290, 270, 170), "#64748b"),
]


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------
_BY_ASSET_ID: Dict[str, Device] = {d.asset_id: d for d in DEVICES}

_BY_ADDRESS: Dict[str, Device] = {}
for _device in DEVICES:
    for _address in _device.addresses:
        _BY_ADDRESS[_address] = _device


def all_devices() -> List[Device]:
    return list(DEVICES)


def all_zones() -> List[Zone]:
    return list(ZONES)


def get(address: str) -> Optional[Device]:
    """Resolve any identifier - asset id, IP or hostname - to a device."""
    if not address:
        return None
    return _BY_ADDRESS.get(address)


def by_asset_id(asset_id: str) -> Optional[Device]:
    return _BY_ASSET_ID.get(asset_id)


def is_known(address: str) -> bool:
    return bool(address) and address in _BY_ADDRESS


def devices_in_zone(zone: str) -> List[Device]:
    return [d for d in DEVICES if d.zone == zone]


def tier_of(address: str) -> Optional[int]:
    device = get(address)
    return device.tier if device else None


def baseline_edges() -> List[Tuple[str, str]]:
    """Permitted peer links, deduplicated and undirected.

    This is the *reachability* graph - the thing the detector reasons about -
    and deliberately not a floor plan. ``ehr-core`` sits in one room and
    legitimately talks to the entire hospital; ``guest-device`` could be metres
    from the ICU and must never reach it.
    """
    seen = set()
    edges: List[Tuple[str, str]] = []
    for device in DEVICES:
        for peer in device.peers:
            if peer not in _BY_ASSET_ID:
                continue  # external peers like public-dns are not drawn
            key = tuple(sorted((device.asset_id, peer)))
            if key not in seen:
                seen.add(key)
                edges.append(key)
    return edges
