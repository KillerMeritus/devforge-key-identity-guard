# Recovery Console · DevForge Track 4

A synthetic secure-file workflow that demonstrates device revocation across
two local workers and key rotation recovery across a real process kill.

## Setup

Use Linux and Python 3.12. Create a virtual environment and install the
pinned dependencies. For offline setup, stage compatible wheels first,
then use pip with `--no-index --find-links /path/to/wheelhouse`.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git ../Track-4-Toolkit
python ../Track-4-Toolkit/validate.py --entry ./track4_service.py
python -m unittest discover -s tests -v
```

The toolkit used during development was commit `8901dfb`. Keep it separate
from the submission. The judge import path uses Python's standard library
and the organizer's `pqcrypto`. FastAPI, Uvicorn, and cryptography are
demo dependencies. The judge gets its own writable state directory and
does not import the HTTP server. Its audit lookup covers ordinary reads
keyed by the organizer's request ID. The demo worker separately records
protected-read decisions in its authenticated audit chain.

## Stages and human checks

| Stage | Command | What to look for |
|---|---|---|
| 1. Organizer adapter | `python ../Track-4-Toolkit/validate.py --entry track4_service.py` followed by `python -m unittest discover -s tests -p test_adapter.py -v` | The public checker ends in “Local scenario passed”. The independent client verifies the protected-read proof, and revoked and malformed requests disclose no proof or content. |
| 2. Two-node identity | `python demo_cli.py --kill-at pre` | Each node reports an explicit revoked-device denial while the teammate's file still verifies. The harness also checks that a regular device cannot revoke or rotate and the owner can use a new credential. |
| 3. Rotation and recovery | Run `python demo_cli.py --kill-at pre` and `python demo_cli.py --kill-at post` | Pre-commit recovers v1. Post-commit recovers v2 and shows a durable rotation event. Both runs show five successful Node B reads during preparation, reject a damaged key backup, and preserve revocation. Post-commit also shows five v2 reads before the rotation reply. |
| 4. Audit and detection | `python detection_cli.py --practice ../Track-4-Toolkit/practice` and the full unit suite | The practice log should flag the unexpected role change, its subsequent access, and the report worker's cross-service path. Approved changes and isolated routine denials are quiet. The tests verify exact expiry, uncertainty, audit row edits, and tail deletion with the head intact. |
| 5. Operator console | `python console.py`, then open `http://127.0.0.1:8080` | Predict v1 for “Before commit” and v2 for “After commit”. Run each choice and open an event. Node outcomes and evidence come from the real harness. Try an incorrect prediction and confirm the UI still shows the observed version. |
| 6. Release | Repeat from a fresh Git checkout | Save command output, add the final two-page brief and a recorded demo link, then confirm public repository and video access before submission. |

Use `python demo_cli.py --kill-at post --json` to export redacted evidence.
The console displays the timeline after the run completes. The service
processes use ephemeral ports to avoid collisions across fresh runs.

## Design and evidence limits

- The organizer's actor-level API and the demo's device-level API share
  SQLite transaction helpers. The judge uses the caller identity supplied
  by its sandbox. The demo derives roles from randomly provisioned bearer
  credentials. Operator evidence is role-restricted.
- The demo has two independently running processes on one host with one
  SQLite authority. Report measured time from when the server observes
  the revocation commit to each node's first explicit denial. The probes
  are local and launched in parallel after the revoke response. These
  measurements do not establish distributed replication or host failover.
- A read authorized before a transaction commits may finish with that
  snapshot. Key rotation updates ciphertext, version, approval consumption,
  and audit evidence in one transaction. An authenticated version mismatch
  rejects new requests after cutover. The harness pauses before the write
  transaction and after commit to prove availability at those boundaries.
  Reads also append audit rows, so SQLite can serialize them behind a
  writer during the commit transaction.
- Key backups are encrypted and verified against the active asset and
  version. The demo uses a generated damaged fixture, because the toolkit
  checkout has no `practice/bad_backup.bin`. Backup verification does not
  implement whole-store restore or replace live keys.
- The audit chain with authenticated head detects edits or tail deletion
  when the head survives. The external revocation checkpoint covers stale
  file snapshots as described below.
- The detector evaluates one event at a time within a finite replay. It
  emits confirmed approval and correlation findings once their evidence
  arrives. A generic access-review fallback waits for replay closure so
  a delayed role-change event can provide a more specific explanation.
  Each corrected timestamp has a ±125 ms uncertainty range. When ranges overlap,
  the detector records uncertainty and avoids claiming the change
  preceded the read. Events outside the five-second timestamp-to-receipt tolerance
  cannot supply path or causal evidence.
- The mixed replay scores event ID and rule pairs. Latency starts at
  receipt of the last required evidence item and ends at local detector
  emission. Use `python detection_cli.py --real-time` to preserve fixture
  receipt intervals. The benchmark covers four measured rules, excludes
  the close-of-input fallback, and does not include a live collector,
  external delivery, or production-scale state retention.
- ML-KEM protects the organizer interoperability exchange. File data in
  the demo is encrypted at rest. Messaging is deliberately unsupported and
  an authenticated request to `POST /message` produces an audited 501.
- Test with synthetic data and trusted local processes only. The project
  does not establish production security, offline host recovery, or
  messaging features such as forward secrecy.

## Post-quantum audit verification

The local demo provisions a separate ML-DSA-65 signing seed for each
worker and pins each public key to its node at setup. After recovery the
client requests a fresh challenge-bound signature from each node on its
own recorded revocation denial. The attestation route requires an active
operator and an intact audit chain. A request to sign a different node's
record returns HTTP 409. The verifier checks the expected node, pinned key,
challenge, and request ID before reporting success.

The demo uses separate signing keys on a shared host, with both seed files
in the private demo state directory. It does not demonstrate process-level
key isolation. ML-KEM-768 handles the
organizer's separate protected-read exchange.

## Revocation survives old snapshots

The demo provisions an authenticated checkpoint store in a separate SQLite
file, outside the file database's restore boundary. It advances the
checkpoint to the revocation's audit sequence and tag before acknowledging
a revoke. In each worker, protected operations require that record to be
present in their current database view. Missing, tampered, or mismatched
checkpoints prevent file reads and signed evidence. HTTP 503 means the
node cannot serve that state. It is distinct from an explicit revocation
denial on a healthy node.

Run `python -m unittest discover -s tests -p test_rollback.py -v` to restore
a pre-revocation backup with the witness preserved and exercise both HTTP
workers. The test restores the current database afterward, then confirms
the teammate can read and the revoked laptop cannot.

The witness is kept on the demo host. The guarantee covers snapshots older
than the latest checkpointed revocation when the witness survives.
Rollback of the witness itself, rotation-only rollback after that
revocation, and automatic reconciliation are outside this milestone. An
interrupted revocation can leave the checkpoint ahead of the file store.
In that case the workers withhold protected operations pending trusted
recovery.

## Archive-enabled worker integration

The two HTTP workers support an opt-in archive mode. In that mode, protected
reads and fresh evidence require verified current rows and a durable archive
confirmation. Revocation, rotation, and enrolment require an `Idempotency-Key`
header. Reuse the original key when retrying the same request. A successful
enrolment retry returns the device reference without redisclosing its token.

Provision a stopped, known-good demo state once, then start both workers on
the same directory. The investigator credential path must be a new file kept
outside the working database's restore boundary.

```sh
python archive_ops.py --state "$state" provision "$investigator_credential_file"
python node_server.py --archive --state "$state" --node A --port 8081
python node_server.py --archive --state "$state" --node B --port 8082
```

Keep `archive.required` and the archive directory outside any restore of
`demo.sqlite`. Both workers must use `--archive` for that state directory.
An existing archive directory also binds the mode for fixtures provisioned
before the marker was introduced. Run the baseline from a separately
provisioned directory with its own working database and witness.

`GET /historical/{producer}/{event_id}` accepts the independently scoped
investigator bearer credential and returns the original canonical archive event
and its receipts. The endpoint remains available during working-store
quarantine when the archive and investigator grant verify.

From the trusted offline environment, inspect the pending receipt and authorize
recovery only after the coordinator verifies the corresponding committed rows
and transaction marker. Provide the separately authorized actor with the
credential file through the trusted operator channel.

```sh
python archive_ops.py --state "$state" status
python archive_ops.py --state "$state" authorize-recovery "$pending_tag" "$recovery_actor" "$recovery_credential_file"
python archive_ops.py --state "$state" recover "$pending_tag" "$recovery_credential_file"
python archive_ops.py --state "$state" restore "$verified_snapshot"
```

The recovery and restore commands verify under the same lock used by the
workers. A live worker can record `ABORTED` when SQLite rolls back its open
transaction and the preceding application state verifies. If a killed worker
left a pending receipt without positive evidence of commit or rollback, both
workers return HTTP 503 for protected operations. Retain the stores for
investigation. The experimental mode currently has no reconciliation path
for that ambiguous case.

Producer credentials expire one hour after archive provisioning by default.
Worker restarts use the original expiry. Scoped recovery can finalize a
verified commit after producer expiry. Returning an expired producer to
service requires credential renewal, which is outside this prototype.

Run the independent reviewer and smoke checks from the repository root.
The console smoke script uses Playwright and its installed Chromium by
default. Use `--chromium PATH` to select an existing executable.

```sh
PYTHONPATH=. python tests/reviewer_worker_core.py
PYTHONPATH=. python scripts/smoke_archive_ops.py
python scripts/smoke_console.py
```

## Submission status

Source, reproducible demo, validator results, and threat-model metadata
are included. The public GitHub release, final brief, and externally
viewable five-minute recording need the team's release step.
