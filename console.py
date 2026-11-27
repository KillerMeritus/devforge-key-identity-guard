"""Serve the local operator console and its fixed synthetic scenarios."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

from demo_cli import ScenarioAssertion, run
from console_scenarios import LAB_SCENARIOS, assurance_lab, detector_replay, time_machine


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
        challenge = self.headers.get("X-Verification-Challenge")
        if challenge is not None and not re.fullmatch("[0-9a-f]{64}", challenge):
            self.respond(400, b'{"error":"invalid_challenge"}')
            return
        routes = {"/run/pre": lambda: run("pre", challenge_hex=challenge),
                  "/run/post": lambda: run("post", challenge_hex=challenge),
                  "/run/detection": detector_replay, "/run/archive": time_machine}
        lab = self.path.removeprefix("/run/lab/")
        if lab in LAB_SCENARIOS:
            routes[f"/run/lab/{lab}"] = lambda: assurance_lab(lab, challenge)
        scenario = routes.get(self.path)
        if (
            self.headers.get("Host") != urlsplit(ORIGIN).netloc
            or self.headers.get("Origin") != ORIGIN
            or self.headers.get("X-Recovery-Console") != "run"
            or self.headers.get("Content-Length") not in (None, "0")
            or scenario is None
        ):
            self.respond(403, b'{"error":"forbidden"}')
            return
        try:
            result = scenario()
        except ScenarioAssertion as error:
            self.respond(409, json.dumps({"error": str(error), "verification_failed": True}).encode())
            return
        except (RuntimeError, OSError, ValueError) as error:
            print(f"Console scenario {self.path} failed ({type(error).__name__}).", file=sys.stderr)
            self.respond(503, b'{"error":"Scenario unavailable. Check the console process log."}')
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
