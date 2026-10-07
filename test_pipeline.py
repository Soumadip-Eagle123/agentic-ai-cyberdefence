import json
from src.ingestion.layer0_ingestion import Layer0Ingestion
from src.asset_intelligence.layer1_asset_intelligence import Layer1AssetIntelligence

def main():
    print("=== Testing Layer 0 & Layer 1 Pipeline ===")

    # Simulated raw network logs (e.g. from the digital twin simulator)
    raw_logs = [
        {
            "timestamp": "2026-09-12T14:00:00Z",
            "source": "icu_pcap_sensor",
            "event_type": "SMB_FLOW",
            "src": "10.0.1.45",
            "dst": "10.0.2.10",
            "protocol": "tcp",
            "bytes": 4096,
            "zone": "Intensive Care Unit",
            "scenario_id": "port_scan_attack_01"
        },
        {
            # Duplicate log entry (should be dropped by Layer 0)
            "timestamp": "2026-09-12T14:00:00Z",
            "source": "icu_pcap_sensor",
            "event_type": "SMB_FLOW",
            "src": "10.0.1.45",
            "dst": "10.0.2.10",
            "protocol": "tcp",
            "bytes": 4096,
            "zone": "Intensive Care Unit",
            "scenario_id": "port_scan_attack_01"
        }
    ]

    layer0 = Layer0Ingestion()
    layer1 = Layer1AssetIntelligence()

    for idx, raw_log in enumerate(raw_logs, 1):
        print(f"\n--- Processing Raw Log #{idx} ---")
        
        # Layer 0: Ingestion & Normalization
        obs_event = layer0.process_raw_log(raw_log)
        if not obs_event:
            print("[Layer 0 Output]: Event dropped as duplicate!")
            continue

        print("[Layer 0 Output]: Normalized Event Created")
        print(json.dumps(obs_event.model_dump(), indent=2))

        # Layer 1: Asset Intelligence & Enrichment
        asset_context = layer1.enrich(obs_event)
        if asset_context:
            print("\n[Layer 1 Output]: Matched Asset Context")
            print(json.dumps(asset_context.model_dump(), indent=2))
        else:
            print("\n[Layer 1 Output]: Unknown asset IP.")

if __name__ == "__main__":
    main()