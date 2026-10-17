"""Attack scenarios and normal traffic, generated from the hospital twin.

An attack is described as a **path**, not as a list of log entries:

    ("office-ws", "lab-server", "MALWARE_STAGING")

The generator turns that into timestamped telemetry. Two things follow from
writing attacks this way.

First, a new scenario is three lines instead of fifty, so the scenario library
can actually grow.

Second, and more importantly, the *chain* is explicit: stage N's destination
becomes stage N+1's source. That is the structure Layer 3's correlation engine
looks for when it decides whether separate findings are one campaign, and the
only way to produce it reliably is to generate it on purpose.

Normal traffic matters as much as the attacks. Layer 2 detects deviation from
normal, so with no baseline there is nothing to deviate from - which is exactly
why the scores in the original demo had to be hardcoded.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

from . import hospital
from .hospital import Device

CAMPAIGN_START = datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc)


@dataclass
class TwinEvent:
    """One piece of telemetry, as Layer 0 would receive it from a sensor."""

    timestamp: datetime
    source: str
    event_type: str
    src: str
    dst: str
    protocol: str
    bytes: int
    zone: str
    scenario_id: str
    #: Ground truth, for evaluation only. The detector never sees these.
    label: str = "normal"
    attack_stage: Optional[str] = None
    stage_index: Optional[int] = None

    def to_raw_log(self) -> Dict[str, object]:
        """The dict shape Layer 0's ``process_raw_log`` expects."""
        return {
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "source": self.source,
            "event_type": self.event_type,
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol,
            "bytes": self.bytes,
            "zone": self.zone,
            "scenario_id": self.scenario_id,
        }

    def to_dict(self) -> Dict[str, object]:
        return {
            **self.to_raw_log(),
            "label": self.label,
            "attack_stage": self.attack_stage,
            "stage_index": self.stage_index,
        }


@dataclass
class Stage:
    """One hop of an attack: who hits whom, and with what."""

    src: str
    dst: str
    event_type: str
    attack_stage: str
    bytes: int = 1024
    protocol: str = "TCP"
    note: str = ""


@dataclass
class Campaign:
    scenario_id: str
    title: str
    description: str
    stages: List[Stage]
    #: Minutes between consecutive stages.
    gap_minutes: int = 2

    @property
    def crosses_zones(self) -> List[str]:
        zones = []
        for stage in self.stages:
            device = hospital.get(stage.dst)
            if device and device.zone not in zones:
                zones.append(device.zone)
        return zones

    @property
    def touches_tier1(self) -> bool:
        return any(
            (d := hospital.get(s.dst)) is not None and d.is_life_critical
            for s in self.stages
        )


def _sensor_for(zone: str) -> str:
    return f"{zone.split('_')[0]}_pcap_sensor"


# ---------------------------------------------------------------------------
# The scenario library
# ---------------------------------------------------------------------------
#: The roadmap's flagship scenario: a compromised office endpoint works its way
#: toward a life-critical device, pivoting through each machine it takes.
LATERAL_TO_ICU = Campaign(
    scenario_id="lateral_to_icu",
    title="Compromised reception endpoint reaches the ICU",
    description=(
        "A reception desk workstation is compromised and sweeps the admin "
        "subnet, moves into the laboratory, stages malware on the lab server, "
        "then uses the lab server to exploit the ICU patient monitor gateway "
        "and finally pivots onto the ICU controller."
    ),
    stages=[
        Stage("office-ws", "admin-print", "SMB_FLOW", "discovery", 80,
              note="Reconnaissance on the admin subnet"),
        Stage("office-ws", "radiology-ws", "PORT_SCAN", "discovery", 1200,
              note="Port sweep crossing into radiology - workstation compromised"),
        Stage("radiology-ws", "pacs", "CREDENTIAL_DUMP", "credential_access", 3400,
              note="CHAIN: the compromised radiology workstation dumps credentials"),
        Stage("office-ws", "lab-server", "MALWARE_STAGING", "lateral_movement", 8192,
              note="Lab server compromised - becomes the next attacker"),
        Stage("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT", "lateral_movement", 4096,
              note="CHAIN: the compromised lab server attacks a Tier 1 device"),
        Stage("icu-monitor-gw", "icu-controller", "C2_BEACON", "command_and_control", 1024,
              note="CHAIN: pivot onto a second Tier 1 device"),
    ],
)

#: A shorter version of the same shape, for the no-human-approval walkthrough.
RANSOMWARE_SPREAD = Campaign(
    scenario_id="ransomware_spread",
    title="Ransomware propagation toward intensive care",
    description=(
        "A compromised office endpoint scans, spreads to the laboratory, and "
        "attempts to reach the ICU patient monitor gateway."
    ),
    stages=[
        Stage("office-ws", "admin-print", "SMB_FLOW", "discovery", 80),
        Stage("office-ws", "lab-server", "PORT_SCAN", "discovery", 1200),
        Stage("lab-server", "icu-monitor-gw", "EXPLOIT_ATTEMPT", "lateral_movement", 4096,
              note="CHAIN: lab server now attacking a Tier 1 device"),
    ],
)

#: Data leaving the hospital, with no lateral movement at all.
EXFILTRATION = Campaign(
    scenario_id="exfiltration",
    title="Bulk clinical data exfiltration",
    description="A compromised endpoint pulls records from the EHR and uploads them externally.",
    stages=[
        Stage("office-ws", "ehr-core", "BULK_QUERY", "collection", 120000),
        Stage("office-ws", "external-cloud", "DATA_UPLOAD", "exfiltration", 250000,
              note="Destination is outside the hospital inventory"),
    ],
)

#: Legitimate traffic that *looks* alarming. Tests for false positives.
BENIGN_BURST = Campaign(
    scenario_id="benign_clinical_burst",
    title="Legitimate clinical data burst",
    description=(
        "A large but entirely authorised transfer between the ICU gateway and "
        "the EHR server. Should NOT trigger containment."
    ),
    stages=[
        Stage("icu-monitor-gw", "ehr-core", "HL7_BULK", "none", 120000),
        Stage("icu-monitor-gw", "ehr-core", "HL7_BULK", "none", 118500),
    ],
)

CAMPAIGNS: Dict[str, Campaign] = {
    c.scenario_id: c for c in (LATERAL_TO_ICU, RANSOMWARE_SPREAD, EXFILTRATION, BENIGN_BURST)
}


def campaign_names() -> List[str]:
    return list(CAMPAIGNS)


def get_campaign(name: str) -> Campaign:
    try:
        return CAMPAIGNS[name]
    except KeyError:
        raise ValueError(
            f"unknown campaign '{name}'. Available: {', '.join(CAMPAIGNS)}"
        ) from None


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
def generate_campaign(
    campaign: Campaign | str,
    start: Optional[datetime] = None,
) -> List[TwinEvent]:
    """Turn an attack path into timestamped telemetry."""
    if isinstance(campaign, str):
        campaign = get_campaign(campaign)
    moment = start or CAMPAIGN_START

    events: List[TwinEvent] = []
    for index, stage in enumerate(campaign.stages):
        destination = hospital.get(stage.dst)
        # Zone is the victim's zone where known; otherwise the attacker's.
        source_device = hospital.get(stage.src)
        zone = (
            destination.zone if destination
            else (source_device.zone if source_device else "external")
        )
        label = "normal" if stage.attack_stage == "none" else "anomaly"
        events.append(
            TwinEvent(
                timestamp=moment + timedelta(minutes=index * campaign.gap_minutes),
                source=_sensor_for(zone),
                event_type=stage.event_type,
                src=stage.src,
                dst=stage.dst,
                protocol=stage.protocol,
                bytes=stage.bytes,
                zone=zone,
                scenario_id=campaign.scenario_id,
                label=label,
                attack_stage=None if stage.attack_stage == "none" else stage.attack_stage,
                stage_index=index + 1,
            )
        )
    return events


def generate_normal(
    hours: int = 24,
    seed: int = 7,
    start: Optional[datetime] = None,
) -> List[TwinEvent]:
    """Routine hospital traffic, so the detector has a baseline to learn.

    Life-critical devices chatter around the clock because they are life
    support. Office equipment goes quiet outside working hours. Volumes differ
    by tier, with jitter so the baseline is not suspiciously uniform. Every
    device only talks to peers it is permitted to talk to.
    """
    rng = random.Random(seed)
    begin = start or (CAMPAIGN_START - timedelta(hours=hours))
    events: List[TwinEvent] = []

    for hour in range(hours):
        moment = begin + timedelta(hours=hour)
        business_hours = 7 <= moment.hour <= 19
        for device in hospital.all_devices():
            if device.tier == hospital.TIER_1:
                rate = 2                      # never sleeps
            elif device.tier == hospital.TIER_2:
                rate = 2 if business_hours else 1
            else:
                rate = 1 if business_hours else 0   # office hours only

            internal_peers = [p for p in device.peers if hospital.by_asset_id(p)]
            if not internal_peers:
                continue

            for _ in range(rate):
                peer = rng.choice(internal_peers)
                base = {hospital.TIER_1: 900, hospital.TIER_2: 1800}.get(device.tier, 500)
                jitter = rng.randint(-base // 4, base // 4)
                events.append(
                    TwinEvent(
                        timestamp=moment + timedelta(minutes=rng.randint(0, 59)),
                        source=_sensor_for(device.zone),
                        event_type="NETWORK_FLOW",
                        src=device.asset_id,
                        dst=peer,
                        protocol="TCP",
                        bytes=max(50, base + jitter),
                        zone=device.zone,
                        scenario_id="normal",
                        label="normal",
                    )
                )
    return sorted(events, key=lambda e: e.timestamp)


def generate_with_baseline(
    campaign: Campaign | str,
    baseline_hours: int = 24,
    seed: int = 7,
) -> Tuple[List[TwinEvent], List[TwinEvent]]:
    """Baseline traffic plus an attack, as separate streams.

    The baseline trains the detector; the campaign is replayed afterwards.
    Keeping them apart is deliberate - training on the attack would teach the
    model that the attack is normal.
    """
    return generate_normal(hours=baseline_hours, seed=seed), generate_campaign(campaign)
