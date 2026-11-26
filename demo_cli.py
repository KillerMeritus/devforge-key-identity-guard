"""Run a fresh, repeatable synthetic recovery incident."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hmac
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

from kig_core.attestation import verify_attestation
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness


BODY = "Synthetic design brief №1\nInternal demo only".encode()
WORKER = Path(__file__).with_name("node_server.py")
HTTP = build_opener(ProxyHandler({}))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def call(port, route, token="", fields=None):
    data = None if fields is None else json.dumps(fields).encode()
    request = Request(f"http://127.0.0.1:{port}/{route}", data=data, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
    })
    try:
        response = HTTP.open(request, timeout=8)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response), response.headers


def wait_for(predicate, description):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise RuntimeError(f"Timed out waiting for {description}")


def start(stack, state, node, log, port=None, checkpoint=None):
    if not port:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
    command = [sys.executable, str(WORKER), "--state", str(state), "--node", node,
               "--port", str(port)]
    if checkpoint:
        command.extend(["--test-stop-at", checkpoint])
    with log.open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)

    def stop():
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)

    stack.callback(stop)

    def ready():
        require(process.poll() is None, f"Node {node} exited: {log.read_text()[-800:]}")
        try:
            return call(port, "health")[1] == {"node": node}
        except (OSError, URLError):
            return False

    wait_for(ready, f"node {node}")
    return port, process


def run(phase):
    timeline = []

    def event(source, label, **fields):
        timeline.append(dict(source=source, label=label, **fields))

    with tempfile.TemporaryDirectory(prefix="track4-demo-") as path, ExitStack() as stack:
        state = Path(path)
        keys = [secrets.token_bytes(32) for _ in range(3)]
        signing_seeds = {node: secrets.token_bytes(32) for node in ("A", "B")}
        trusted_public_keys = {
            node: MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()
            for node, seed in signing_seeds.items()
        }
        key_files = dict(zip(("audit", "storage", "backup"), keys))
        key_files.update({f"attestation-{node}": seed for node, seed in signing_seeds.items()})
        for name, key in key_files.items():
            with open(os.open(state / f"{name}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
                handle.write(key)
        (state / "witness").mkdir(mode=0o700)
        witness = RevocationWitness(state / "witness" / "checkpoint.sqlite", keys[0])
        witness.provision()
        guard = Guard(state / "demo.sqlite", *keys, witness=witness)
        operator = guard.enroll("operator", "admin")
        laptop, teammate = guard.enroll("owner"), guard.enroll("teammate")
        guard.seed_file("brief", BODY, "owner", "teammate")
        guard.seed_file("notes", b"separate synthetic asset", "teammate")
        approval = guard.approve_rotation("operator", "brief", 1, time.time() + 120)
        log = state / "node-a.log"
        a, victim = start(stack, state, "A", log, checkpoint=phase)
        b, _ = start(stack, state, "B", state / "node-b.log")
        pool = stack.enter_context(ThreadPoolExecutor(max_workers=5))

        def execute(port, route, token, **fields):
            status, result, _ = call(port, route, token, fields)
            return status, result

        def read(port, token, version):
            return execute(port, "read", token, target="brief", version=version)

        def checked_read(port, token, version):
            status, result = read(port, token, version)
            require(status == 200 and base64.b64decode(result["body"]) == BODY, "file contents changed")
            return result

        checked_read(b, teammate, 1)
        client = MLKEM768PrivateKey.generate()
        challenge = "demo✓"
        public = base64.b64encode(client.public_key().public_bytes_raw()).decode()
        status, result = execute(a, "read", laptop, target="brief", version=1,
                                 public_key=public, challenge=challenge)
        require(status == 200, "protected read failed")
        shared = client.decapsulate(base64.b64decode(result["ciphertext"]))
        require(hmac.compare_digest(result["proof"],
                                    hmac.digest(shared, challenge.encode() + BODY, "sha256").hex()),
                "protected read proof failed")
        event("A", "Protected read verified", request_id=result["request_id"])
        target = guard.digest(laptop)
        require(execute(a, "revoke", "", target=target)[0] == 401, "anonymous revoke accepted")
        require(execute(a, "revoke", teammate, target=target)[0] == 403, "reader revoke accepted")
        require(execute(a, "rotate", teammate, target="brief", version=1, approval=approval)[0] == 403,
                "reader rotation accepted")
        status, result = execute(a, "revoke", operator, target=target)
        require(status == 200, "revocation failed")
        observed = result["commit_observed_ns"]
        event("A", "Device revoked", request_id=result["request_id"])

        def probe(port):
            status, result = read(port, laptop, 1)
            elapsed = (time.monotonic_ns() - observed) / 1_000_000
            require(status == 403 and result["reason"] == "revoked_device", "device was not revoked")
            return elapsed, result["request_id"]

        observations = {name: pool.submit(probe, port) for name, port in (("A", a), ("B", b))}
        peer = pool.submit(checked_read, b, teammate, 1)
        timings = {}
        for name, future in observations.items():
            timings[name], request_id = future.result()
            event(name, "Revoked device denied", request_id=request_id, elapsed_ms=round(timings[name], 2))
        peer.result()
        status, replacement = execute(b, "enroll", operator, target="owner")
        require(status == 200, "re-enrollment failed")
        checked_read(a, replacement["token"], 1)
        denied, mismatch = execute(b, "rotate", operator, target="notes", version=1, approval=approval)
        require(denied == 403 and mismatch["reason"] == "approval_target_mismatch", "approval mismatch missed")
        event("B", "Approval target mismatch", request_id=mismatch["request_id"])
        reconnect = pool.submit(execute, a, "rotate", operator, target="brief", version=1, approval=approval)
        wait_for(lambda: "CHECKPOINT prepared" in log.read_text(), "prepared ciphertext")

        def continuity(version, label):
            samples, request_ids = [], []
            for _ in range(5):
                started = time.monotonic_ns()
                peer_read = checked_read(b, teammate, version)
                request_ids.append(peer_read["request_id"])
                samples.append((time.monotonic_ns() - started) / 1_000_000)
            summary = dict(reads=len(samples), errors=0, max_latency_ms=round(max(samples), 2))
            event("B", label, request_id=request_ids[-1], request_ids=request_ids,
                  version=version, **summary)
            return summary

        continuity_results = {"prepared": continuity(1, "Teammate reads during rotation preparation")}
        require(not reconnect.done(), "rotation finished before the preparation probe")
        (state / "resume-rotation").touch()
        wait_for(lambda: f"CHECKPOINT {phase}" in log.read_text(), f"{phase}-commit checkpoint")
        if phase == "post":
            continuity_results["committed"] = continuity(2, "Teammate reads after commit before rotation reply")
            require(not reconnect.done(), "rotation replied before the post-commit probe")
        event("Harness", f"Reached {phase}-commit checkpoint")
        victim.kill()
        require(victim.wait(timeout=5) == -signal.SIGKILL, "expected SIGKILL termination")
        stopped = time.monotonic()
        event("Harness", "Node A killed")
        try:
            reconnect.result()
        except (OSError, URLError):
            pass
        else:
            raise RuntimeError("rotation unexpectedly acknowledged")
        a, _ = start(stack, state, "A", state / "node-a-restarted.log", port=a)
        expected = 1 if phase == "pre" else 2
        for name, port in (("A", a), ("B", b)):
            result = checked_read(port, teammate, expected)
            if name == "A":
                recovery_ms = (time.monotonic() - stopped) * 1000
            event(name, "Teammate read verified", request_id=result["request_id"], version=expected)
            denied, result = read(port, laptop, expected)
            require(denied == 403 and result["reason"] == "revoked_device", "revocation was lost")
            revoked_request_id = result["request_id"]
            event(name, "Revocation survived restart", request_id=revoked_request_id)
            if phase == "post":
                require(read(port, teammate, 1)[1]["reason"] == "wrong_version", "old version accepted")
            challenge = secrets.token_hex(32)
            route = f"evidence/{revoked_request_id}/attestation"
            require(call(port, route, teammate, {"challenge": challenge})[0] == 403,
                    "reader obtained a signed audit record")
            status, signed, _ = call(port, route, operator, {"challenge": challenge})
            require(status == 200 and verify_attestation(
                signed, trusted_public_keys[name], node=name, challenge=challenge,
                request_id=revoked_request_id
            ), "post-quantum attestation did not verify")
            require(signed["event"]["reason"] == "revoked_device", "signed wrong decision")
            event(name, "ML-DSA-65 revocation evidence verified", request_id=revoked_request_id)
        evidence = guard.evidence(operator)
        commits = [row for row in evidence if row["reason"] == "version_rotated"]
        require(len(commits) == (phase == "post"), "unexpected number of committed rotation events")
        if commits:
            event("Audit", "Rotation committed", request_id=commits[0]["request_id"], version=expected)
        backup = guard.backup("brief", expected)
        require(guard.verify_backup("brief", expected, backup, "A"), "intact backup rejected")
        damaged = backup[:-1] + bytes([backup[-1] ^ 1])
        require(not guard.verify_backup("brief", expected, damaged, "A"), "damaged backup accepted")
        checked_read(a, teammate, expected)
        event("Audit", "Damaged key backup rejected")
        status, response, headers = call(a, "message", operator, {})
        require(status == 501 and response == {"error": "messaging not supported in this track"},
                "unexpected messaging response")
        require(call(b, f"evidence/{headers['X-Request-ID']}", operator)[1]["proof"]
                == "audit_chain_verified", "message audit missing")
        require(call(b, f"evidence/{mismatch['request_id']}", teammate)[0] == 403, "audit disclosed")
        require(call(b, "config/clock-tolerance")[1] == {"tolerance_seconds": 5}, "bad clock config")
        return dict(checkpoint=phase, active_version=expected, timeline=timeline,
                    last_denial_ms=round(max(timings.values()), 2), recovery_ms=round(recovery_ms, 2),
                    evidence=guard.evidence(operator), proof_verified=True, audit_verified=True,
                    continuity=continuity_results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kill-at", choices=["pre", "post"], default="pre")
    parser.add_argument("--json", action="store_true")
    options = parser.parse_args()
    result = run(options.kill_at)
    if options.json:
        print(json.dumps(result))
    else:
        for row in result["timeline"]:
            detail = ""
            if "reads" in row:
                detail = f" · {row['reads']} verified, max {row['max_latency_ms']} ms"
            print(f"{row['source']:7} {row['label']}{detail}")
        print(f"PASS: recovered v{result['active_version']}; last denial {result['last_denial_ms']} ms; "
              f"recovery {result['recovery_ms']} ms")
