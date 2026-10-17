"""Local HTTP server for the interactive ACCDS view.

Runs the *real* pipeline behind a small JSON API, so clicking a device and
firing an attack produces genuine Layer 2 scores, genuine Layer 3 correlation
and a genuine Layer 5 decision, rather than a scripted animation.

Standard library only - no Flask, no build step, keeping the project's
zero-dependency promise. Binds to localhost by default: this exposes an attack
simulator and a decision gate, and neither belongs on a shared interface.

    python -m visualiser.server
    python -m visualiser.server --port 8080 --no-browser
"""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict

from .session import AttackSession

PAGE = Path(__file__).parent / "live.html"

#: One session per process. The pipeline is stateful by design - Layer 3 has to
#: remember open cases for a later attack to be recognised as the same campaign.
_session = AttackSession()
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "ACCDS/1.0"

    # -- plumbing ----------------------------------------------------------
    def _send(self, payload: Any, status: int = 200, content_type: str = "application/json") -> None:
        body = (json.dumps(payload, default=str).encode("utf-8")
                if content_type == "application/json" else payload)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.path.startswith("/api/"):
            print(f"  {self.command} {self.path}")

    # -- routes ------------------------------------------------------------
    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            if not PAGE.is_file():
                return self._send({"error": f"{PAGE} is missing"}, 500)
            return self._send(PAGE.read_bytes(), content_type="text/html; charset=utf-8")

        if self.path == "/api/hospital":
            with _lock:
                return self._send(_session.hospital_state())

        if self.path == "/api/state":
            with _lock:
                return self._send(_session.state())

        self._send({"error": "not found"}, 404)

    def do_POST(self) -> None:
        body = self._read_json()

        if self.path == "/api/attack":
            src, dst = body.get("src"), body.get("dst")
            event_type = body.get("event_type", "EXPLOIT_ATTEMPT")
            if not src or not dst:
                return self._send({"ok": False, "message": "src and dst are required"}, 400)
            if src == dst:
                return self._send({"ok": False, "message": "a device cannot attack itself"}, 400)
            with _lock:
                result = _session.launch(src, dst, event_type).to_dict()
                result["state"] = _session.state()
            return self._send(result)

        if self.path == "/api/decision":
            with _lock:
                outcome = _session.decide(
                    approve=bool(body.get("approve")),
                    reviewer=body.get("reviewer", ""),
                    reason=body.get("reason", ""),
                )
                outcome["state"] = _session.state()
            return self._send(outcome)

        if self.path == "/api/campaign":
            name = body.get("name", "lateral_to_icu")
            with _lock:
                try:
                    results = _session.run_campaign(name)
                except ValueError as error:
                    return self._send({"ok": False, "message": str(error)}, 400)
                return self._send({"ok": True, "results": results, "state": _session.state()})

        if self.path == "/api/reset":
            with _lock:
                _session.reset()
                return self._send({"ok": True, "state": _session.state()})

        self._send({"error": "not found"}, 404)


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive ACCDS hospital view")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1",
                        help="localhost by default; this exposes an attack simulator")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), partial(Handler))
    url = f"http://{args.host}:{args.port}/"

    state = _session.state()["baseline"]
    print(f"ACCDS interactive view on {url}")
    print(f"  hospital : {len(_session.hospital_state()['devices'])} devices, "
          f"{len(_session.hospital_state()['zones'])} zones")
    print(f"  baseline : {state['events']} normal events across {state['devices']} devices")
    print(f"  threshold: {state['threshold']}")
    print("\n  Click a device, pick a target, launch an attack.")
    print("  Ctrl+C to stop.\n")

    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
