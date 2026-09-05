from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Tuple

from .schemas import EnrichedEvent

FEATURE_NAMES = [
    "event_count", "unique_peers", "port_fanout", "total_bytes", "bytes_per_peer",
    "failed_auth", "successful_auth", "off_hours_ratio", "new_peer_ratio",
    "new_service_ratio", "unapproved_peer_ratio", "protocol_diversity",
]


@dataclass
class FeatureWindow:
    asset_id: str
    start: datetime
    end: datetime
    values: Dict[str, float]
    event_ids: List[str]
    clinical_tier: int
    zone: str
    identity_confidence: float
    label: str
    attack_stage: str | None
    scenario_id: str


def _off_hours(timestamp: datetime) -> bool:
    return timestamp.hour < 7 or timestamp.hour > 19


def build_windows(events: Iterable[EnrichedEvent], window_minutes: int = 60) -> List[FeatureWindow]:
    grouped: Dict[Tuple[str, datetime], List[EnrichedEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
        start = event.timestamp.replace(minute=(event.timestamp.minute // window_minutes) * window_minutes, second=0, microsecond=0)
        grouped[(event.asset_id, start)].append(event)

    windows: List[FeatureWindow] = []
    for (asset_id, start), batch in sorted(grouped.items()):
        first = batch[0]
        peers = {event.dst for event in batch}
        services = {event.event_type for event in batch}
        ports = {event.dst for event in batch if event.protocol in {"TCP", "UDP"}}
        approved_peers = set(first.allowed_peers)
        normal_services = set(first.normal_services)
        total_bytes = sum(event.bytes for event in batch)
        failed_auth = sum(1 for event in batch if "fail" in event.event_type.lower())
        successful_auth = sum(1 for event in batch if event.event_type == "authentication")
        off_hours_ratio = sum(_off_hours(event.timestamp) for event in batch) / len(batch)
        values = {
            "event_count": float(len(batch)),
            "unique_peers": float(len(peers)),
            "port_fanout": float(len(ports)),
            "total_bytes": float(total_bytes),
            "bytes_per_peer": float(total_bytes / max(1, len(peers))),
            "failed_auth": float(failed_auth),
            "successful_auth": float(successful_auth),
            "off_hours_ratio": float(off_hours_ratio),
            "new_peer_ratio": float(len(peers - approved_peers) / max(1, len(peers))),
            "new_service_ratio": float(len(services - normal_services) / max(1, len(services))),
            "unapproved_peer_ratio": float(len(peers - approved_peers) / max(1, len(peers))),
            "protocol_diversity": float(len({event.protocol for event in batch})),
        }
        labels = [event.label for event in batch if event.label != "normal"]
        stages = [event.attack_stage for event in batch if event.attack_stage]
        scenario_ids = [event.scenario_id for event in batch if event.scenario_id != "normal"]
        windows.append(FeatureWindow(
            asset_id=asset_id,
            start=start,
            end=start + timedelta(minutes=window_minutes),
            values=values,
            event_ids=[event.event_id for event in batch],
            clinical_tier=first.clinical_tier,
            zone=first.zone,
            identity_confidence=min(event.identity_confidence for event in batch),
            label=labels[0] if labels else "normal",
            attack_stage=stages[0] if stages else None,
            scenario_id=scenario_ids[0] if scenario_ids else "normal",
        ))
    return windows
