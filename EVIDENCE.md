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
