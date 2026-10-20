"""Canonical inventory and attack presets used by the dashboard and API."""

from __future__ import annotations

DEVICES = [
    {
        "id": "icu-monitor-gw",
        "name": "ICU Monitor Gateway",
        "type": "Patient monitor gateway",
        "zone": "Intensive Care",
        "zone_id": "intensive_care",
        "tier": 1,
        "ip": "10.0.1.45",
        "services": ["HL7 Vitals · 2575", "SMB · 445"],
        "peers": ["icu-controller", "ehr-core"],
        "icon": "monitor",
        "safety": "SURGICAL BLOCK ONLY",
    },
    {
        "id": "icu-controller",
        "name": "Critical Care Controller",
        "type": "ICU control cabinet",
        "zone": "Intensive Care",
        "zone_id": "intensive_care",
        "tier": 1,
        "ip": "10.0.1.50",
        "services": ["Patient telemetry", "SMB · 445"],
        "peers": ["icu-monitor-gw", "ehr-core"],
        "icon": "controller",
        "safety": "NO ISOLATION",
    },
    {
        "id": "lab-server",
        "name": "Laboratory Server",
        "type": "Laboratory database server",
        "zone": "Laboratory",
        "zone_id": "laboratory",
        "tier": 2,
        "ip": "10.0.2.10",
        "services": ["Database queries", "LIS results"],
        "peers": ["ehr-core", "icu-monitor-gw"],
        "icon": "server",
        "safety": "NARROW CONTAINMENT",
    },
    {
        "id": "radiology-ws",
        "name": "Radiology Workstation",
        "type": "DICOM workstation",
        "zone": "Radiology",
        "zone_id": "radiology",
        "tier": 2,
        "ip": "10.0.4.12",
        "services": ["DICOM · 104", "PACS imaging"],
        "peers": ["ehr-core", "lab-server"],
        "icon": "radiology",
        "safety": "WORKFLOW SENSITIVE",
    },
    {
        "id": "office-ws",
        "name": "Administration Endpoint",
        "type": "Office workstation",
        "zone": "Administration",
        "zone_id": "administration",
        "tier": 3,
        "ip": "10.0.3.15",
        "services": ["HTTPS", "DNS", "SMB"],
        "peers": ["ehr-core", "lab-server"],
        "icon": "desktop",
        "safety": "COARSE ISOLATION ALLOWED",
    },
    {
        "id": "ehr-core",
        "name": "EHR Core",
        "type": "Electronic health records database",
        "zone": "Security Operations",
        "zone_id": "security_operations",
        "tier": 2,
        "ip": "10.0.5.1",
        "services": ["Clinical records", "Database"],
        "peers": ["icu-monitor-gw", "icu-controller", "lab-server", "radiology-ws", "office-ws"],
        "icon": "database",
        "safety": "NARROW CONTAINMENT",
    },
]

DEVICE_BY_ID = {device["id"]: device for device in DEVICES}
DEVICE_BY_IP = {device["ip"]: device for device in DEVICES}

SCENARIOS = [
    "port_scan",
    "new_peer",
    "exfiltration",
    "credential_misuse",
    "off_hours",
    "diagnostic_drift",
    "benign_clinical_burst",
    "low_confidence",
]

PRESETS = {
    "port_scan": {"source": "office-ws", "target": "radiology-ws", "vector": "PORT_SCAN", "count": 12, "bytes": 80},
    "new_peer": {"source": "lab-server", "target": "icu-monitor-gw", "vector": "LATERAL_MOVEMENT", "count": 3, "bytes": 1200},
    "exfiltration": {"source": "office-ws", "target": "ehr-core", "vector": "EXFILTRATION", "count": 3, "bytes": 250000},
    "credential_misuse": {"source": "office-ws", "target": "ehr-core", "vector": "CREDENTIAL_DUMP", "count": 7, "bytes": 120},
    "off_hours": {"source": "office-ws", "target": "ehr-core", "vector": "OFF_HOURS_ACCESS", "count": 3, "bytes": 3000},
    "diagnostic_drift": {"source": "radiology-ws", "target": "ehr-core", "vector": "PORT_SCAN", "count": 12, "bytes": 90},
    "benign_clinical_burst": {"source": "icu-monitor-gw", "target": "ehr-core", "vector": "CLINICAL_BURST", "count": 5, "bytes": 900},
    "low_confidence": {"source": "office-ws", "target": "lab-server", "vector": "NEW_PEER", "count": 1, "bytes": 1000},
}

WIRES = [
    {"from": "icu-monitor-gw", "to": "icu-controller", "kind": "clinical", "label": "Telemetry · HL7 2575"},
    {"from": "icu-monitor-gw", "to": "ehr-core", "kind": "clinical", "label": "Vitals · HL7"},
    {"from": "lab-server", "to": "ehr-core", "kind": "clinical", "label": "Lab results"},
    {"from": "radiology-ws", "to": "ehr-core", "kind": "clinical", "label": "DICOM 104"},
    {"from": "office-ws", "to": "ehr-core", "kind": "normal", "label": "EHR access"},
    {"from": "office-ws", "to": "lab-server", "kind": "normal", "label": "LIS queries"},
    {"from": "lab-server", "to": "icu-monitor-gw", "kind": "normal", "label": "Possible pivot path"},
]
