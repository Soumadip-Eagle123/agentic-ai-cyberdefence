# ACCDS Digital Twin Dashboard

The dashboard is a local simulator for the six-device hospital topology. It runs the repository's Layer 0 ingestion, Layer 1 asset inventory, Layer 2 behavioral model, Layer 3 orchestrator, Layer 5 decision gate, Layer 4 in-memory enforcement simulator, and Layer 6 audit and evidence pipeline.

Layer 5 appears before Layer 4 in the live stepper. A proposal that touches a Tier 1 asset pauses for a reviewer; the Layer 4 simulator does not apply a rule until that scope-bound approval is recorded. Tier 1 actions surgically block SMB/TCP 445 and preserve the HL7 feed on port 2575. Tier 2 actions use scoped rules for their workflow, and Tier 3 endpoints may be isolated in the digital twin.

## Start

From the repository root, run:

```bash
python -m src.simulator.server
```

Open <http://127.0.0.1:8081>. The server uses only the Python standard library beyond the project's existing Pydantic dependency. It serves the files in `web/` and binds to loopback by default. Pass `--port` to select another port.

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/catalog` | Device, wire, scenario, and safe layer-order metadata |
| `GET` | `/api/state` | Current simulation snapshot and contract-compatible layer fields |
| `GET` | `/api/stream` | Server-Sent Events stream of state snapshots |
| `POST` | `/api/attacks` | Inject a preset or custom simulated attack into Layer 0 |
| `POST` | `/api/step` | Advance one layer in the safe execution order |
| `POST` | `/api/run` | Advance until completion or a human approval pause |
| `POST` | `/api/decisions` | Record a scope-bound approval or rejection and resume |
| `POST` | `/api/rollback` | Cancel a pending action or roll back an applied simulated rule |
| `POST` | `/api/reset` | Clear the active in-memory run; evidence files remain available |
| `GET` | `/api/evidence.zip` | Download the operational Layer 6 evidence package |

Example attack request:

```json
{
  "scenario": "new_peer",
  "source": "lab-server",
  "target": "icu-monitor-gw",
  "vector": "LATERAL_MOVEMENT",
  "chain": ["lab-server", "icu-monitor-gw"]
}
```

The API response includes `scenario_id`, `current_layer`, and top-level `layer_0_event` through `layer_6_audit` fields where available, alongside grouped dashboard data. Runtime audit chains and evidence packages are written under `artifacts/simulations/<simulation-id>/`.

## Safety boundary

This is an offline digital-twin simulator. Layer 4 uses `Layer4Executor`'s in-memory active-rule registry; the server has no firewall, endpoint, hospital, or external service connector. Evidence export contains the operational/redacted report, integrity metrics, and manifest; it does not include the forensic-only record file.
