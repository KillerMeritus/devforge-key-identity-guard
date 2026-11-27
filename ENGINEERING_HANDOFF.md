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

The verifier returns exit 0 for STATEMENT AUTHENTICATED and exit 1 for REJECTED. Both nodes sign historical revoked-device denials and authorized teammate reads. The post-commit scenario also signs retired-version denials. The standalone verifier authenticates one statement. The demo harness independently compares the signed decision, reason and version to the expected scenario outcome. The event version is the version associated with that request. It does not attest the current database version. Worker keys, bearer tokens, plaintext and harness timings are outside the exported statement. A fresh challenge authenticates the signing interaction with a trusted worker. The event can be historical.

## Detector and console

kig_core/detector.py evaluates finite synthetic replay. Actor, session and correlation ID must match. Arrival lateness is five seconds. A separate 30-second corrected-time horizon limits association. This horizon is a local policy assumption. Lateral evidence requires two distinct service edges sharing a directed endpoint. Its classification is investigative. Corrected clocks carry ±125 ms per observation. A timing-only approval violation near the boundary is investigative. Absent or empty approval scope grants no service. Omitted or empty requested scope lists no additional requested services. Authorized reads still check the target service.

Finite replay excludes conflicting source IDs and deduplicates identical observations. Archived replay rejects conflicting input before claiming verified findings. Incremental ingest assumes identities have been checked upstream. There is no demonstrated live reconciliation or production accuracy estimate. Held-out results score anchor/rule pairs, not confidence calibration.

console.py serves the loopback console. A judge can enter a challenge and click a measured baseline invariant to inspect both node results or the verified audit. The passport is worker-signed. HTTP status, elapsed time and snapshot orchestration are harness observations. The trust-boundary panel identifies which component supplies each result.

## Questions judges may ask

**Can an intact log prove that all authorization rows are genuine?** No. Direct database writers are trusted in baseline. The experimental archive provides an independent comparison for supported projections.

**Will a restored node always recover automatically?** Baseline transaction crashes have tested pre/post boundaries. Ambiguous archive outcomes deliberately withhold protected access.

**Can another verifier trust a passport from last week?** It can authenticate a historical statement using a previously trusted key and independently expected bindings. Current authorization requires a new state check.

**How representative are the detector numbers?** The cohorts are deterministic, labelled synthetic replays. A read one day later, a separate correlation ID, and two disconnected service edges each exposed an extra fallback correlation. These are regression cases, not field accuracy measurements.

## Security Assurance Laboratory

Run `python console.py` and open `http://127.0.0.1:8080`. The scenario selector
runs eight allowlisted exercises against disposable local fixtures. The
approval and competing-rotation runs show the observed version before and
after on both workers, each rotation decision, and matching authenticated
audit records. Revocation, backup, and passport exercises use the existing
post-commit recovery harness. The scenario selector is separate from the
synthetic detector replay.

The passport exercise obtains each worker's signed revocation decision.
The verifier uses the node public key provisioned by the local harness
before worker startup. The interface exposes the challenge, request ID, node,
public key, and signed bytes. A controlled copy changes the signed request
version while preserving the signature, and the same verifier must reject
that copy. The public key in this local view comes from the harness, so
external verification still requires independently provisioned trust.
Authentication applies to historical statements. The measured security
invariants also depend on harness assertions and observations.

The Evidence Explorer includes authenticated worker audit history from a
completed recovery run. A separate monitor observes only the controlled recovery and approval runs. The
archive quarantine and historical receipt workflow remains experimental.

## Historical claims and live audit

The passport exercise now evaluates three fixed historical claims on both
workers: revoked-device denial, authorized teammate read, and retired-version
denial. Its policy expectations come from fixture setup and observed HTTP
request IDs, with challenges chosen before signing and node public keys
provisioned before worker startup. The signed event binds the credential or
actor, target asset, read action, authorization decision, reason and requested
version. The retired-version claim uses the independently expected retired
version. These claims concern the signed requests, not the current database,
the age of its state, or whether a process actually terminated.

For an offline check, provision `A.pub`, `B.pub` and the expectations through
your trusted channel. The JSON has `actor` and/or `credential_ref` (required for revoked-device denial), `asset`,
`version`, and `nodes.A` and `nodes.B` with `challenge` and `request_id`.
The existing demo export writes the three `*.expected.json` files into
`--trust-dir` alongside its separately provisioned public keys. A real verifier
must establish those values independently of the signed envelopes.

```sh
python security_claims.py --expected judge-pins/revoked-device.expected.json \
  --key-a judge-pins/A.pub --key-b judge-pins/B.pub revoked-device \
  statements/A.json statements/B.json
```

Exit codes 0, 1 and 2 mean VERIFIED, FAILED and INSUFFICIENT EVIDENCE.
The selector also shows the existing individual signature authentication result.

The Operational Audit Monitor reads authenticated audit snapshots with the
existing operator authorization while disposable recovery and approval runs
are in progress. It streams findings, matching HTTP denial-without-body
containment evidence, and the separately scripted operator revocation.
Related denials are linked only within the same fixture, credential and
asset, within five seconds by audit time. Links are for investigation. The
observer performs no administrative actions. Audit unavailability and
integrity failures are surfaced without creating worker event identities.
The monitor labels a denial as a retired-version read only when an earlier
authenticated rotation record for the same asset established a newer
version. Its finding includes that rotation record's identity. Other
version denials keep a generic label. Organizer synthetic detector replay
remains separate.

Each fixture is limited to 40 polls, 256 audit records, and a 250 ms
database deadline per poll. Scheduled scenario checkpoints trigger reads,
with 25 ms retry spacing if a watched denial is missing. An exhausted budget
produces a monitor status event if a required request remains unobserved or
a later checkpoint must be skipped. The report lists any unobserved request
IDs, preserves authenticated findings and finishes as UNAVAILABLE when
coverage is incomplete. A successful final poll may complete its checkpoint.
Poll gap includes
scenario work between checkpoints. Verification time includes authorization,
witness checks and authenticated audit reads. Audit-to-observation time uses
same-host wall-clock timestamps and includes scenario scheduling. The
observation-to-alert measurement uses a monotonic clock and measures local
classification through creation of the finding, before browser delivery.

## Verified encrypted asset recovery

In archive mode, an operator can export a transaction-consistent working
snapshot and later restore it against the current independent evidence store.

```sh
python archive_ops.py --state /path/to/state export /private/path/current.sqlite
python archive_ops.py --state /path/to/state restore /private/path/current.sqlite
```

Export checks the independent archive, working audit and commit markers,
current credential/grant/approval/asset projections, and the authenticated
ciphertext of each asset. It publishes a private SQLite file without
overwriting an existing destination. Asset bytes stay encrypted. The
snapshot contains sensitive working metadata, so restrict its storage
and transport. Keys and the independent archive stay separate and must
survive recovery.

Restore accepts the same retained checkpoint only. A later recorded
operation can make a backup stale even if the encrypted bytes are
unchanged. Restore refuses unresolved pending operations and stale
snapshots. For a missing working database, stop both workers and ensure
SQLite sidecars from the missing database are absent before restoring.
Keep the working state directory, keys, revocation witness and archive.
This procedure recovers the complete encrypted working store. Baseline
continues to trust direct database writers. Archive mode provides the
independent current-state and rollback checks.
