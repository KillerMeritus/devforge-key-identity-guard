# Architecture assurance handoff

The reviewed fallback is 127857d2d3682dbcea0e9d29c25fdf4753813897. This branch is a review candidate. Use baseline protected-file recovery for judging. The two workers run on one host.

## Request and recovery flows

- The root subprocess adapter is track4_service.py. The organizer supplies actor context. The separate HTTP demo uses bearer device credentials. Its test suite covers both contracts.
- node_server.py sends baseline requests to Guard in kig_core/guard.py. The worker checks the external mode binding and revocation witness, verifies the audit chain, resolves the credential and checks the applicable grant or approval. It records the decision inside the SQLite transaction. Both nodes share the working store.
- Rotation prepares authenticated ciphertext, then commits the version, ciphertext, approval consumption and audit entry together. Before commit, SQLite rollback retains v1. After commit, restart serves v2. The harness times the first verified read and tests revoked-device denial separately on both nodes.
- kig_core/witness.py stores a MAC-protected sequence and audit tag outside the working snapshot. A gap around checkpoint persistence can withhold service. An authenticated audit head says which decisions were recorded. A privileged SQLite writer can independently change authorization rows. The regression deletes a grant, checks the same history, then observes the new denial. Device, approval and asset deletion are independently checked too.
- Experimental worker_archive.py checks canonical state against retained evidence. Archive mode binds outside the database restore boundary. Verified post-commit recovery accepts a separately scoped authorization. Ambiguous pre-commit crash stays quarantined. Producer renewal remains deferred.

## Cryptography and the passport

AES-GCM binds file contents to the file and version. The organizer adapter uses ML-KEM-768 for its protected-read challenge. Worker evidence uses an independently provisioned ML-DSA-65 public key for each node. The worker returns the exact bytes it signed. Offline verification checks those bytes under the existing signature context, then binds the event to the verifier's expected node, request and challenge.

Run from the repository root after README setup. Choose your own 32-byte challenge (64 lowercase hex digits). Supply new directories. The harness provisions public keys separately before worker startup. Transfer these pins over a trusted path to an offline verifier. A key received only from the evidence sender cannot establish trust.

```sh
nonce=$(python -c 'import secrets; print(secrets.token_hex(32))')
python demo_cli.py --kill-at post --challenge "$nonce" --trust-dir ./judge-pins --passport-dir ./statements --json > run.json
rid=$(python -c 'import json; print(json.load(open("run.json"))["nodes"]["A"]["revoked_request_id"])')
python evidence_passport.py statements/A.json --key judge-pins/A.pub --node A --challenge "$nonce" --request-id "$rid"
```

The verifier returns exit 0 for VERIFIED and exit 1 for REJECTED. The demo signs revoked read decisions from both nodes. The event version is the version associated with that request. It does not attest the current database version. Worker keys, bearer tokens, plaintext and harness timings are outside the exported statement. A fresh challenge authenticates the signing interaction with a trusted worker. The event can be historical.

## Detector and console

kig_core/detector.py evaluates finite synthetic replay. Actor, session and correlation ID must match. Arrival lateness is five seconds. A separate 30-second corrected-time horizon limits association. This horizon is a local policy assumption. Lateral evidence requires two distinct service edges sharing a directed endpoint. Its classification is investigative. Corrected clocks carry ±125 ms per observation. A timing-only approval violation near the boundary is investigative. Absent or empty approval scope grants no service. Omitted or empty requested scope lists no additional requested services. Authorized reads still check the target service.

Finite replay excludes conflicting source IDs and deduplicates identical observations. Archived replay rejects conflicting input before claiming verified findings. Incremental ingest assumes identities have been checked upstream. There is no demonstrated live reconciliation or production accuracy estimate. Held-out results score anchor/rule pairs, not confidence calibration.

console.py serves the loopback console. A judge can enter a challenge and click a measured baseline invariant to inspect both node results or the verified audit. The passport is worker-signed. HTTP status, elapsed time and snapshot orchestration are harness observations. The trust-boundary panel identifies which component supplies each result. No live worker-audit monitor is included.

## Questions judges may ask

**Can an intact log prove that all authorization rows are genuine?** No. Direct database writers are trusted in baseline. The experimental archive provides an independent comparison for supported projections.

**Will a restored node always recover automatically?** Baseline transaction crashes have tested pre/post boundaries. Ambiguous archive outcomes deliberately withhold protected access.

**Can another verifier trust a passport from last week?** It can authenticate a historical statement using a previously trusted key and independently expected bindings. Current authorization requires a new state check.

**How representative are the detector numbers?** The cohorts are deterministic, labelled synthetic replays. A read one day later, a separate correlation ID, and two disconnected service edges each exposed an extra fallback correlation. These are regression cases, not field accuracy measurements.
