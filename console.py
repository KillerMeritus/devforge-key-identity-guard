"""Serve the local operator console and its fixed synthetic scenarios."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

from demo_cli import run


ORIGIN = "http://127.0.0.1:8080"
UI = Path(__file__).with_name("ui")
STATIC = {
    "/": ("mock.html", "text/html; charset=utf-8"),
    "/console.css": ("console.css", "text/css; charset=utf-8"),
    "/console.js": ("console.js", "text/javascript; charset=utf-8"),
}
CSP = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"


class Console(BaseHTTPRequestHandler):
    def respond(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        asset = STATIC.get(self.path)
        if self.headers.get("Host") != urlsplit(ORIGIN).netloc or asset is None:
            self.respond(404, b'{"error":"not_found"}')
            return
        filename, content_type = asset
        self.respond(200, (UI / filename).read_bytes(), content_type)

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
        except (RuntimeError, OSError) as error:
            print(f"Recovery scenario {phase} failed ({type(error).__name__}).", file=sys.stderr)
            self.respond(500, b'{"error":"Scenario failed. Run demo_cli.py for diagnostics."}')
            return
        self.respond(200, json.dumps(result).encode())


def main():
    try:
        server = HTTPServer(("127.0.0.1", 8080), Console)
    except OSError as error:
        print(f"Cannot bind the Recovery Console to {ORIGIN}: {error.strerror}", file=sys.stderr)
        return 1
    with server:
        print(f"Recovery Console: {ORIGIN}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Recovery Console stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
