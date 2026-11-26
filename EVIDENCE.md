# Evidence map

| Track goal | Reproduction |
|---|---|
| Key rotation | Post-commit CLI run and racing-rotation test. Inspect five verified reads on Node B during preparation, five at v2 before the rotation response, and both workers rejecting v1 after commit. |
| Revocation across nodes | Either CLI run. Inspect per-node and last-node denial timings. |
| Interrupted rotation | Run both checkpoint flags. Inspect active version, successful read, and revocation evidence. |
| Backup integrity | Either CLI run verifies the intact backup and rejects a deliberately altered encrypted backup. |
| Log integrity | Run the audit test, then inspect linked request evidence in the console. Full database restore is outside the audit claim. |
| Routine and suspicious activity | Run the practice detector and mixed benchmark. Use `--real-time` for actual receipt spacing and batch-delay evidence. |
| Lateral movement | Practice fixture shows the report worker's related out-of-policy service edges. |
| Clock differences | Practice replay includes source offset and out-of-order arrival. The detector test covers uncertain order and exact approval expiry. |
| Replay and recipient binding, forward secrecy, delivery under loss and resumption | Messaging is unsupported in the file-service prototype. An authenticated call returns 501 and is audited. |
