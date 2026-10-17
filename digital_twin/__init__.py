"""ACCDS hospital digital twin.

The safe laboratory the defence system is developed in: zones, devices, users,
flows and attack scenarios, modelled at the level cybersecurity decisions need
rather than as a physical replica.

Everything here is a data model. There is no 3D geometry, because no layer makes
a decision from physical space - they reason about identity, permission,
protocol, volume, time and clinical consequence.
"""

from .hospital import (
    DEVICES,
    TIER_1,
    TIER_2,
    TIER_3,
    ZONES,
    Device,
    Zone,
    all_devices,
    all_zones,
    baseline_edges,
    by_asset_id,
    devices_in_zone,
    get,
    is_known,
    tier_of,
)
from .scenarios import (
    CAMPAIGNS,
    Campaign,
    Stage,
    TwinEvent,
    campaign_names,
    generate_campaign,
    generate_normal,
    generate_with_baseline,
    get_campaign,
)

__all__ = [
    "CAMPAIGNS", "DEVICES", "TIER_1", "TIER_2", "TIER_3", "ZONES",
    "Campaign", "Device", "Stage", "TwinEvent", "Zone",
    "all_devices", "all_zones", "baseline_edges", "by_asset_id",
    "campaign_names", "devices_in_zone", "generate_campaign",
    "generate_normal", "generate_with_baseline", "get", "get_campaign",
    "is_known", "tier_of",
]
