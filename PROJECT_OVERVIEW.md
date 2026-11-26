# Recovery Console

Recovery Console is a two-worker secure-file prototype for
[DevForge Track 4](https://github.com/KillerMeritus/devforge-key-identity-guard).
A judge can revoke a synthetic device, interrupt a real key rotation on either
side of commit, and inspect which file version and authorization decisions
survive. The same harness powers the browser and terminal demo.

## Architecture

| Component | Role |
|---|---|
| Organizer adapter | One stdin/stdout request per invocation. The organizer supplies the actor identity. SQLite in writable temporary state preserves setup, decisions, and revocations. |
| Baseline workers | Two authenticated loopback processes share one SQLite file authority. Device tokens are stored as digests. AES-GCM protects file contents. Rotation updates ciphertext, active version, approval consumption, and audit event in one transaction. |
| Independent revocation witness | A separately retained checkpoint rejects snapshots that predate the latest recorded revocation when the witness survives. |
| Evidence | Canonical audit records and an authenticated head protect event order. The verifier checks the pinned worker key, fresh challenge, node, and request ID for ML-DSA-65 attestations. The organizer protected-read adapter supports ML-KEM-768 interoperability. |
| Detector | A deterministic finite replay evaluates approval scope, privilege changes, service paths, and clock uncertainty. Contested IDs are excluded from causal evidence. |
| Experimental archive | A separate SQLite evidence store retains detector replay inputs and confirmations. The isolated Time Machine shows stale-state quarantine, independently authorized historical retrieval, and verified current-snapshot recovery. |

## Release boundary

The baseline protected-file workflow is the primary release. The workers
share a host and a database. Local process interruption does not demonstrate
host failover or distributed replication. The immediate version cutoff is
logical. Previously derivable keys and already disclosed plaintext may remain
recoverable under their original trust assumptions.

Archive mode remains experimental. Ambiguous pre-commit crashes quarantine
protected operations. Live producer renewal, portable historical signatures,
and live detector ingestion are deferred. The messaging endpoint is an
unsupported stub and provides no messaging protections.

See [objective coverage](OBJECTIVE_COVERAGE.md), [metrics](METRICS.md), and
[verification evidence](EVIDENCE.md).
