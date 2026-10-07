import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from src.schemas.contracts import ObservationEvent

class Layer0Ingestion:
    """Passively ingests raw telemetry, normalizes formatting, and deduplicates events."""

    def __init__(self):
        self._seen_event_hashes = set()

    def process_raw_log(self, raw_data: Dict[str, Any]) -> Optional[ObservationEvent]:
        # Simple deduplication check based on key fields
        dedup_key = f"{raw_data.get('src')}-{raw_data.get('dst')}-{raw_data.get('timestamp')}-{raw_data.get('bytes')}"
        if dedup_key in self._seen_event_hashes:
            return None  # Drop duplicate event
        self._seen_event_hashes.add(dedup_key)

        # Normalize timestamp into standard ISO 8601 UTC format
        raw_ts = raw_data.get("timestamp", "")
        try:
            parsed_dt = datetime.fromisoformat(raw_ts)
        except (ValueError, TypeError):
            parsed_dt = datetime.now(timezone.utc)
        normalized_ts = parsed_dt.isoformat()

        event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"

        return ObservationEvent(
            event_id=event_id,
            timestamp=normalized_ts,
            source=raw_data.get("source", "digital_twin_sensor"),
            event_type=raw_data.get("event_type", "NETWORK_FLOW"),
            subject=raw_data.get("subject", raw_data.get("src", "unknown")),
            src=raw_data.get("src", "0.0.0.0"),
            dst=raw_data.get("dst", "0.0.0.0"),
            protocol=raw_data.get("protocol", "TCP").upper(),
            bytes=int(raw_data.get("bytes", 0)),
            zone=raw_data.get("zone", "General_Hospital"),
            scenario_id=raw_data.get("scenario_id", "baseline_normal"),
            raw_reference=f"/logs/raw/{raw_data.get('scenario_id', 'default')}/{event_id}.json"
        )