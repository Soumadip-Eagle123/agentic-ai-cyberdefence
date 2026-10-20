"""Dependency-free HTTP and Server-Sent Events API for the local ACCDS dashboard."""

from __future__ import annotations

import argparse
import json
import mimetypes
from queue import Empty
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .service import SimulationError, SimulationService

WEB_ROOT = Path(__file__).resolve().parents[2] / "web"
SERVICE = SimulationService()


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ACCDS-Digital-Twin/1.0"

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")

    def _json(self, value: object, status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError as error:
            raise ValueError("Invalid Content-Length") from error
        if length < 0 or length > 1_000_000:
            raise ValueError("Request body exceeds the 1 MB limit")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Request body must be valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object")
        return value

    def _static(self, raw_path: str) -> None:
        relative = "index.html" if raw_path in {"", "/"} else raw_path.lstrip("/")
        target = (WEB_ROOT / relative).resolve()
        try:
            target.relative_to(WEB_ROOT.resolve())
        except ValueError:
            self._json({"error": "Not found"}, 404)
            return
        if not target.is_file():
            self._json({"error": "Not found"}, 404)
            return
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache" if target.suffix in {".html", ".js", ".css"} else "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def _stream(self) -> None:
        subscriber = SERVICE.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self.wfile.write(b"retry: 2000\n\n")
            self.wfile.flush()
            while True:
                try:
                    message = subscriber.get(timeout=15)
                    chunk = f"event: snapshot\ndata: {message}\n\n".encode("utf-8")
                except Empty:
                    chunk = b": keepalive\n\n"
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            SERVICE.unsubscribe(subscriber)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        if path == "/api/state":
            self._json(SERVICE.state())
        elif path == "/api/catalog":
            self._json(SERVICE.catalog())
        elif path in {"/api/stream", "/api/events"}:
            self._stream()
        elif path == "/api/evidence.zip":
            target = SERVICE.evidence_path()
            if target is None:
                self._json({"error": "Evidence is available after Layer 6 completes"}, 409)
                return
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        else:
            self._static(path)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = urlsplit(self.path).path
        try:
            body = self._body()
            if path == "/api/attacks":
                result = SERVICE.launch_attack(body)
            elif path == "/api/step":
                result = SERVICE.step()
            elif path == "/api/run":
                result = SERVICE.run_full()
            elif path == "/api/reset":
                result = SERVICE.reset()
            elif path == "/api/decisions":
                result = SERVICE.record_decision(body)
            elif path == "/api/rollback":
                result = SERVICE.trigger_rollback(body)
            else:
                self._json({"error": "Not found"}, 404)
                return
            self._json(result)
        except ValueError as error:
            self._json({"error": str(error)}, 400)
        except SimulationError as error:
            self._json({"error": str(error)}, 409)
        except Exception as error:  # the dashboard receives a compact error, server logs retain details
            print(f"API failure at {path}: {type(error).__name__}: {error}")
            self._json({"error": "The simulator could not complete this operation. See the server terminal for details."}, 500)

    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local ACCDS digital-twin dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: loopback only)")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    server = DashboardServer((args.host, args.port), DashboardHandler)
    print(f"ACCDS simulator dashboard: http://{args.host}:{args.port}")
    print("Simulation mode only: Layer 4 changes in-memory rules and never contacts network devices.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping ACCDS simulator dashboard.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
