# Evidence map

| Track goal | Reproduction |
|---|---|
| Key rotation | Post-commit CLI run and racing-rotation test. Inspect five verified reads on Node B during preparation, five at v2 before the rotation response, and both workers rejecting v1 after commit. |
| Revocation across nodes | Either CLI run. Inspect per-node and last-node denial timings. |
| Interrupted rotation | Run both checkpoint flags. Inspect active version, successful read, and revocation evidence. |
| Backup integrity | Either CLI run verifies the intact backup and rejects a deliberately altered encrypted backup. |
| Log integrity | Run the audit test, then inspect linked request evidence in the console. The rollback test verifies that an external checkpoint blocks a pre-revocation database restore. |
| Routine and suspicious activity | Run the practice detector and mixed benchmark. Use `--real-time` for uncompressed receipt spacing and local emission latency. |
| Lateral movement | Practice fixture shows the report worker's related out-of-policy service edges. |
| Clock differences | Practice replay includes source offset and out-of-order arrival. The detector test covers uncertain order and exact approval expiry. |
| Replay and recipient binding, forward secrecy, delivery under loss and resumption | Messaging is unsupported in the file-service prototype. An authenticated call returns 501 and is audited. |

## Incremental detector verification

- Organizer toolkit revision `8901dfb`. All five labelled alert anchors matched across the 22 practice events in both original and reversed input order.
- Uncompressed synthetic replay. 120 events, 60 expected alerts across four rules, all 60 matched and zero false positives. The measured median was 0.086 ms and p95 was 1.51 ms for this run.
- These timings start at receipt of the last required event in the local process. They exclude external transport and the generic fallback that waits for input closure.

## Post-quantum verification and access control

Both crash scenarios request a signed revocation denial with a fresh
challenge from each node and verify it against that node's pinned ML-DSA-65 key.
The route test checks denied access for anonymous, reader, and revoked
operator credentials, rejects signing from a corrupt audit chain, and
checks verification failures for changed evidence, a wrong key, a wrong
request ID, a different challenge, or an incorrect node. It also verifies
that Node B refuses to sign a record originating from Node A.

## Rollback protection

Run `python -m unittest discover -s tests -p test_rollback.py -v`. It
restores an old file database using SQLite's backup API while the witness
survives. Node A and Node B withhold reads and signed evidence. Restoring
the current database allows the teammate to read and leaves the laptop
revoked. Separate cases cover a missing or altered witness, and failure
after the witness commits but before the file database commits.

## Archive acceptance gate

Run the opt-in baseline fixture from the repository root:

```sh
TRACK4_ARCHIVE_ACCEPTANCE=1 python -m unittest discover -s tests -p test_rollback.py -k post_revocation_restore -v
```

On the runtime at `ca94e31`, both nodes returned HTTP 200 for the
authorized read and the fresh attestation after a restore that retained
the revocation but lost a later unauthorized rotation attempt. The
fixture expected HTTP 503 in all four cases. The current-state restore
checks passed inside the same run. Archived historical retrieval is a
separate pending assertion to add once investigator access exists.

## Isolated archive increment

| Command from the repository root | Observed result |
|---|---|
| `python -m unittest discover -s tests -p test_archive.py -v` | 8 passed. Covers canonical bytes and rejecting extra fields, scoped/expired/revoked credentials, exclusive provisioning, pinned identity, chain corruption and missing state, duplicate and conflicting retries, terminal state binding, bounded capacity, a real process kill, and two real writer races. |
| `python -m unittest discover -s tests -v` | 22 passed and 1 skipped. The skipped archive-enabled rollback fixture remains a release blocker for the archive. The 14 existing baseline tests passed, including both process-kill scenarios. |
| `python <toolkit>/validate.py --entry track4_service.py` | Toolkit `8901dfb` reported 22 PASS lines and “Local scenario passed.” |
| Local Playwright/Chromium smoke harness | Both baseline console scenarios passed. Pre-commit recovered v1, post-commit recovered v2, and evidence remained inspectable. |

The archive module uses an explicitly provisioned local SQLite store and
independent receipt/grant keys. It authenticates a predecessor-linked
history, binds terminal receipts to their pending intent and expected
pre-state, and returns retained canonical bytes to an independently scoped
investigator. Its append API reserves capacity for a terminal receipt.
Investigator grants in this increment are provisioned fixtures, including
expired and revoked states.

There are no worker, adapter, CLI, or dashboard changes. A trusted
test producer supplies the outcome binding. The archive alone cannot attest
what a working SQLite transaction committed. Worker-side queries of actual
persisted rows, cross-store coordination and recovery, live investigator grant
administration, and producer-specific event projections remain pending.
The authenticated head detects missing records if the newer head survives.
Restoring the entire archive and its head to a consistent older copy remains
outside the isolated guarantee. A pending operation stays pending after a
process kill. It is never automatically aborted because a marker is absent.

## Isolated archive review fixes

- Producer grants bind node, subsystem, and allowed event kinds. The archive
  derives receipt metadata from that grant. The separate application actor
  is still an assertion by the producer until workers derive it from verified
  credentials.
- Event schema v2 records the authorization decision. A terminal receipt
  records transaction outcome and delivery status separately. Retrieval
  exposes lifecycle and whether a mutation was confirmed. Pending and
  aborted events remain retrievable as attempts.
- Receipts bind versioned, sorted affected-state projections. Authorized
  rotations must cover the asset and approval. Initial projections are
  authenticated. New intents for known entities must match their latest
  retained projection. Workers still have to verify actual persisted rows
  and commit markers before finalization. No worker integration is enabled.
- The archive reports used and remaining record capacity and whether it
  can accept an intent. At capacity, finalization and authorized historical
  retrieval still work under the tested conditions. The 1,024-record limit
  permits up to 512 operations at two records per operation. No pruning.

| Command | Observed result |
|---|---|
| `python -m unittest discover -s tests -p test_archive.py -v` | 12 passed. New checks cover producer identity, authenticated initial projections, complete rotation projections, and pending/aborted historical status. |
| `python -m unittest discover -s tests -v` | 26 passed, 1 skipped. The archive-enabled rollback gate is still pending. |
| `python <toolkit>/validate.py --entry track4_service.py` | 22 PASS lines. |

Run `PYTHONPATH=. python scripts/benchmark_archive.py` for the local capacity
benchmark. Each level takes 12 samples per operation and five samples of an
append plus finalize under a 50 ms competing SQLite writer lock. Sizes are
on-disk SQLite sizes at the start of each level. Samples recorded zero
verification failures. Timings are local and do not include worker I/O.

| Start fill | Records | SQLite bytes | Verify P50/P95 ms | Append P50/P95 ms | Finalize P50/P95 ms | Contended P50/P95 ms |
|---|---:|---:|---:|---:|---:|---:|
| 0% | 0 | 24576 | 0.073 / 0.225 | 0.325 / 0.545 | 0.338 / 1.238 | 54.899 / 55.273 |
| 25% | 256 | 237568 | 3.700 / 3.950 | 4.111 / 6.564 | 4.056 / 4.223 | 62.539 / 69.247 |
| 50% | 512 | 446464 | 7.320 / 9.421 | 7.704 / 11.629 | 7.702 / 8.922 | 71.096 / 73.717 |
| ~90% | 920 | 778240 | 13.100 / 13.369 | 13.552 / 15.880 | 13.429 / 14.229 | 81.892 / 86.304 |

Remaining release gates include event-specific producer schemas and detector
source provenance, cross-process worker enforcement and row verification,
historical access during quarantine, and live investigator grant lifecycle.
The isolated schema change applies to freshly provisioned fixtures. There
is no archive migration or full-archive rollback guarantee in this revision.
