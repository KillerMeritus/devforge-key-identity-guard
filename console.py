"""Serve the local operator console and its fixed synthetic scenarios."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from urllib.parse import urlsplit

from demo_cli import run


ORIGIN = "http://127.0.0.1:8080"
PAGE = Path(__file__).with_name("ui") / "mock.html"


class Console(BaseHTTPRequestHandler):
    def respond(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Host") != urlsplit(ORIGIN).netloc or self.path != "/":
            self.respond(404, b'{"error":"not_found"}')
            return
        self.respond(200, PAGE.read_bytes(), "text/html; charset=utf-8")

    def do_POST(self):
        phases = {"/run/pre": "pre", "/run/post": "post"}
        phase = phases.get(self.path)
        if (
            self.headers.get("Host") != urlsplit(ORIGIN).netloc
            or self.headers.get("Origin") != ORIGIN
            or self.headers.get("X-Recovery-Console") != "run"
            or self.headers.get("Content-Length") not in (None, "0")
            or phase is None
        ):
            self.respond(403, b'{"error":"forbidden"}')
            return
        try:
            result = run(phase)
        except (RuntimeError, OSError):
            self.respond(500, b'{"error":"Scenario failed. Run demo_cli.py for diagnostics."}')
            return
        self.respond(200, json.dumps(result).encode())


if __name__ == "__main__":
    print(f"Recovery Console: {ORIGIN}", flush=True)
    with HTTPServer(("127.0.0.1", 8080), Console) as server:
        server.serve_forever()
