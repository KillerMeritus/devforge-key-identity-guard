# Evidence map

| Track goal | Reproduction |
|---|---|
| Key rotation | Post-commit CLI run and racing-rotation test. Inspect five verified reads on Node B during preparation, five at v2 before the rotation response, and both workers rejecting v1 after commit. |
| Revocation across nodes | Either CLI run. Inspect per-node and last-node denial timings. |
| Interrupted rotation | Run both checkpoint flags. Inspect active version, successful read, and revocation evidence. |
| Backup integrity | Either CLI run verifies the intact backup and rejects a deliberately altered encrypted backup. |
| Log integrity | Run the audit test, then inspect linked request evidence in the console. Full database restore is outside the audit claim. |
| Routine and suspicious activity | Run the practice detector and mixed benchmark. Use `--real-time` for uncompressed receipt spacing and local emission latency. |
| Lateral movement | Practice fixture shows the report worker's related out-of-policy service edges. |
| Clock differences | Practice replay includes source offset and out-of-order arrival. The detector test covers uncertain order and exact approval expiry. |
| Replay and recipient binding, forward secrecy, delivery under loss and resumption | Messaging is unsupported in the file-service prototype. An authenticated call returns 501 and is audited. |

## Incremental detector verification

- Organizer toolkit revision `8901dfb`. All five labelled alert anchors matched across the 22 practice events in both original and reversed input order.
- Uncompressed synthetic replay. 120 events, 60 expected alerts across four rules, all 60 matched and zero false positives. The measured median was 0.086 ms and p95 was 1.51 ms for this run.
- These timings start at receipt of the last required event in the local process. They exclude external transport and the generic fallback that waits for input closure.
