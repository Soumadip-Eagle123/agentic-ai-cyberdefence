from __future__ import annotations

import csv
import hashlib
import json
import random
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .schemas import EnrichedEvent


ASSETS = [
    {"asset_id": "icu-monitor-gw", "asset_type": "patient_monitor_gateway", "zone": "intensive_care", "tier": 1, "peers": ["icu-controller", "ehr-core"], "services": ["monitoring", "clinical-data"]},
    {"asset_id": "icu-controller", "asset_type": "intensive_care_controller", "zone": "intensive_care", "tier": 1, "peers": ["icu-monitor-gw", "ehr-core"], "services": ["control", "clinical-data"]},
    {"asset_id": "lab-server", "asset_type": "laboratory_server", "zone": "laboratory", "tier": 2, "peers": ["lab-analyzer", "ehr-core"], "services": ["lab-results", "database"]},
    {"asset_id": "radiology-ws", "asset_type": "radiology_workstation", "zone": "radiology", "tier": 2, "peers": ["pacs", "ehr-core"], "services": ["dicom", "clinical-data"]},
    {"asset_id": "office-ws", "asset_type": "office_endpoint", "zone": "administration", "tier": 3, "peers": ["ehr-core", "public-dns"], "services": ["https", "dns"]},
    {"asset_id": "guest-device", "asset_type": "guest_endpoint", "zone": "guest", "tier": 3, "peers": ["public-dns"], "services": ["https", "dns"]},
    {"asset_id": "ehr-core", "asset_type": "clinical_server", "zone": "security_operations", "tier": 2, "peers": ["icu-monitor-gw", "icu-controller", "lab-server", "radiology-ws", "office-ws"], "services": ["clinical-data", "database"]},
]


def asset_catalogue() -> Dict[str, dict]:
    return {asset["asset_id"]: asset for asset in ASSETS}


def _event(asset: dict, timestamp: datetime, index: int, *, dst: str, service: str, bytes_count: int, scenario_id: str = "normal", label: str = "normal", attack_stage: str | None = None, identity_confidence: float = 1.0, protocol: str = "TCP", event_type: str = "network_flow") -> EnrichedEvent:
    event = EnrichedEvent(
        event_id=f"{scenario_id}-{asset['asset_id']}-{index:06d}",
        timestamp=timestamp,
        event_type=event_type,
        subject=asset["asset_id"],
        src=asset["asset_id"],
        dst=dst,
        protocol=protocol,
        bytes=bytes_count,
        zone=asset["zone"],
        scenario_id=scenario_id,
        raw_reference=f"synthetic://{scenario_id}/{index}",
        asset_id=asset["asset_id"],
        asset_type=asset["asset_type"],
        owner_zone=asset["zone"],
        vendor="ACCDS-Sim",
        software_version="1.0",
        clinical_tier=asset["tier"],
        known_constraints=["preserve-clinical-flow"] if asset["tier"] == 1 else [],
        allowed_peers=asset["peers"],
        normal_services=asset["services"],
        fallback_mode="manual" if asset["tier"] == 1 else "degraded",
        identity_confidence=identity_confidence,
        label=label,
        attack_stage=attack_stage,
    )
    event.validate()
    return event


def generate_normal(days: int = 3, seed: int = 7, start: datetime | None = None) -> List[EnrichedEvent]:
    rng = random.Random(seed)
    start = start or datetime(2026, 1, 5, 0, 0, tzinfo=timezone.utc)
    events: List[EnrichedEvent] = []
    index = 0
    for hour in range(days * 24):
        current = start + timedelta(hours=hour)
        business = 7 <= current.hour <= 19
        for asset in ASSETS:
            rate = 2 if asset["tier"] == 1 else (1 if business or asset["tier"] == 2 else 0)
            for _ in range(rate):
                dst = rng.choice(asset["peers"])
                service = rng.choice(asset["services"])
                base = 900 if asset["tier"] == 1 else (1800 if asset["tier"] == 2 else 500)
                jitter = rng.randint(-base // 4, base // 4)
                events.append(_event(asset, current + timedelta(minutes=rng.randint(0, 59)), index, dst=dst, service=service, bytes_count=max(50, base + jitter), scenario_id="normal"))
                index += 1
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))


def inject_scenario(normal: List[EnrichedEvent], scenario: str, seed: int = 11) -> List[EnrichedEvent]:
    rng = random.Random(seed)
    events = list(normal)
    base_time = max(event.timestamp for event in normal) + timedelta(minutes=5)
    target = next(asset for asset in ASSETS if asset["asset_id"] == "office-ws")
    if scenario == "port_scan":
        for port in range(20):
            events.append(_event(target, base_time + timedelta(seconds=port), port, dst=f"port-{port}", service=f"port-{port}", bytes_count=80, scenario_id=scenario, label="anomaly", attack_stage="discovery", protocol="TCP"))
    elif scenario == "new_peer":
        clinical = next(asset for asset in ASSETS if asset["asset_id"] == "lab-server")
        for i in range(3):
            events.append(_event(clinical, base_time + timedelta(minutes=i), i, dst="icu-monitor-gw", service="lateral-movement", bytes_count=1200, scenario_id=scenario, label="anomaly", attack_stage="lateral_movement"))
    elif scenario == "exfiltration":
        for i in range(3):
            events.append(_event(target, base_time + timedelta(minutes=i), i, dst="external-cloud", service="bulk-upload", bytes_count=250000, scenario_id=scenario, label="anomaly", attack_stage="exfiltration"))
    elif scenario == "credential_misuse":
        for i in range(7):
            events.append(_event(target, base_time + timedelta(minutes=i), i, dst="ehr-core", service="auth", bytes_count=120, scenario_id=scenario, label="anomaly", attack_stage="credential_access", event_type="auth_failure" if i < 5 else "authentication", protocol="TLS"))
    elif scenario == "off_hours":
        late = base_time.replace(hour=2, minute=15)
        for i in range(3):
            events.append(_event(target, late + timedelta(minutes=i), i, dst="ehr-core", service="sensitive-records", bytes_count=3000, scenario_id=scenario, label="anomaly", attack_stage="credential_access"))
    elif scenario == "diagnostic_drift":
        diagnostic = next(asset for asset in ASSETS if asset["asset_id"] == "radiology-ws")
        for i in range(12):
            events.append(_event(diagnostic, base_time + timedelta(seconds=i), i, dst=f"unknown-{i}", service="discovery", bytes_count=90, scenario_id=scenario, label="anomaly", attack_stage="discovery"))
    elif scenario == "benign_clinical_burst":
        clinical = next(asset for asset in ASSETS if asset["asset_id"] == "icu-monitor-gw")
        for i in range(5):
            events.append(_event(clinical, base_time + timedelta(minutes=i), i, dst="ehr-core", service="clinical-data", bytes_count=120000 + rng.randint(0, 1000), scenario_id=scenario, label="normal", attack_stage=None))
    elif scenario == "low_confidence":
        events.append(_event(target, base_time, 0, dst="new-peer", service="unknown", bytes_count=1000, scenario_id=scenario, label="anomaly", attack_stage="discovery", identity_confidence=0.35))
    else:
        raise ValueError(f"unknown scenario: {scenario}")
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))


def save_events(events: Iterable[EnrichedEvent], path: str) -> None:
    records = [event.to_dict() for event in events]
    Path(path).write_text(json.dumps(records, indent=2), encoding="utf-8")


def load_events(path: str) -> List[EnrichedEvent]:
    path_obj = Path(path)
    if path_obj.suffix.lower() == ".csv":
        with path_obj.open(newline="", encoding="utf-8") as handle:
            records = list(csv.DictReader(handle))
        for record in records:
            for field in ("bytes", "clinical_tier"):
                record[field] = int(record[field])
            for field in ("identity_confidence",):
                record[field] = float(record[field])
            for field in ("known_constraints", "allowed_peers", "normal_services"):
                record[field] = json.loads(record[field]) if isinstance(record[field], str) else record[field]
    else:
        records = json.loads(path_obj.read_text(encoding="utf-8"))
    events = [EnrichedEvent.from_dict(record) for record in records]
    ids = [event.event_id for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event_id found")
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))


def fingerprint(events: Iterable[EnrichedEvent]) -> str:
    payload = json.dumps([event.to_dict() for event in events], sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()
