# Official objective coverage

The objectives follow the organizer's Track 4 brief. The executed commands
and exact checkout are recorded in the release evidence manifest.
[Project repository](https://github.com/KillerMeritus/devforge-key-identity-guard)

| Official objective | Status | Implementation and executed evidence | Observed result and limitation |
|---|---|---|---|
| Key rotation | Baseline verified | [guard.py](kig_core/guard.py), [demo_cli.py](demo_cli.py), [security matrix](tests/test_security_matrix.py), [demo tests](tests/test_demo.py) | Valid approval consumed once. Wrong actor, target, version, or expired approval rejected. 40/40 v1 reads during preparation and 20/20 v2 reads after commit. 8/8 immediate post-cutover v1 probes rejected. Zero configured grace. Local continuity at the tested boundaries. |
| Revocation across nodes | Baseline verified | [witness.py](kig_core/witness.py), [demo_cli.py](demo_cli.py), [rollback tests](tests/test_rollback.py) | Initial and post-restart 16/16 explicit revocation denials each. Post-restart teammate 16/16. Fresh enrolment works in the real demo. Same-host timing, with no distributed propagation claim. |
| Crash recovery | Baseline verified | [demo_cli.py](demo_cli.py), [demo tests](tests/test_demo.py), [reviewer](tests/reviewer_worker_core.py) | Real SIGKILL before commit recovered v1 and after commit recovered v2. Revocation survived. Experimental ambiguous pre-commit outcomes remain quarantined. |
| Backup integrity | Baseline verified | [guard.py](kig_core/guard.py), [demo_cli.py](demo_cli.py), both baseline crash CLI invocations | Harness accepts intact backup and rejects a damaged one. No automatic live restore from that blob. |
| Log integrity | Baseline verified | [guard.py](kig_core/guard.py), [node_server.py](node_server.py), [security matrix](tests/test_security_matrix.py), [route tests](tests/test_node_routes.py) | Synthetic input with CR/LF, tab, escape, and spoofed fields created one authenticated denial with an opaque target. Invalid inputs and audit or ciphertext tampering disclose no protected content. Detects tampering when trusted keys and checkpoint/head survive. |
| Routine and suspicious activity | Verified on held-out replay | [detector.py](kig_core/detector.py), [held-out labels](tests/fixtures/detector-heldout.json), [evaluation](scripts/evaluate_detector.py) | 7 TP, 0 FP, 0 FN, F1 1.000 and 0 false alerts per 1,000 benign events on this fixture. The separate 1,284-input cohort with 1,176 benign IDs matched all 72 labels and emitted zero false alerts. See metrics for latency and synthetic scope. |
| Lateral movement | Verified on held-out replay | [detector.py](kig_core/detector.py), [held-out regression](tests/test_detector_heldout.py), [archive replay tests](tests/test_detector_archive.py) | Both anchored findings on related unexpected edges matched labels. Unrelated or repeated edges stayed quiet. Findings carry actor, edges, source IDs, rule, explanation and uncertainty. Path signals require investigation. |
| Clock differences | Verified on held-out replay | [detector.py](kig_core/detector.py), [held-out regression](tests/test_detector_heldout.py) | Out-of-order evidence correlated when corrected times establish order. Overlap and late evidence produce notes. Fixed ±125 ms uncertainty, five-second lateness and fixture offset ranges are in metrics. |
| Replay and recipient binding | Unsupported | [node_server.py](node_server.py), [messaging regression](tests/test_node_routes.py) | Audited HTTP 501 in baseline. No encrypted message recipient or message replay claim. |
| Forward secrecy | Unsupported | [judge.py](kig_core/judge.py), [adapter tests](tests/test_adapter.py) | ML-KEM protected-read proof passed. No forward-secrecy claim for completed sessions. |
| Delivery under loss or reordering | Unsupported | [node_server.py](node_server.py), [messaging regression](tests/test_node_routes.py) | No messaging delivery protocol. Detector replay ordering concerns observations only. |
| Session resumption | Unsupported | [node_server.py](node_server.py), [messaging regression](tests/test_node_routes.py) | No resumable messaging session or session-to-peer binding feature. |

The organizer adapter checks are mapped individually in [Adapter contract coverage](HIDDEN_ASSESSMENT.md).

## Architecture assurance branch

| Objective | Branch evidence | Boundary |
|---|---|---|
| Persisted-state integrity | tests/test_security_matrix.py deletes grant, credential, approval and asset rows independently of audit history | Baseline trusts direct database writers. Experimental archive compares supported current projections. |
| Causal detection | tests/test_architecture.py exercises independent flows, day-separated events, disconnected edges and approval boundaries | 30-second event-time policy. Finite synthetic replay. |
| Verifiable decisions | evidence_passport.py, tests/test_architecture.py and the Chromium challenge scenario | Original signed bytes, pinned node key, verifier challenge and request binding. Historical worker decisions for revocation, teammate reads and post-commit retired-version denial. Process termination and timings are harness observations. |

## Judge-facing execution

The local Security Assurance Lab exposes baseline revocation, approval expiry
and consumption, competing rotations, both process-kill boundaries, backup
verification, and historical worker-statement authentication. Stale-state
quarantine uses the experimental archive. The Chromium smoke test executes
all eight choices, repeats the approval fixture with fresh request identities,
and checks actual modified-copy rejection. Its simulated HTTP error responses
exercise interface presentation. The detector remains a separate synthetic replay.

Historical policy appraisal requires independent identity, asset, version,
request, challenge and key expectations. It evaluates all three supported
claims with both workers' signed statements. Live monitoring observes actual
authenticated baseline audit records during the controlled fixtures, separately
from synthetic detector inputs. Containment is confirmed only when the
matching HTTP denial withheld protected content.

## Deep assurance review candidate

Archive-mode current-state checks were exercised for credential, grant,
approval, and ciphertext changes with the original audit history retained.
The recovery regression covers offline archive export, refusal of stale
rotation snapshots, quarantine on both workers after working-state rollback,
and restore into a missing database. The HTTP worker reference matrix
derives decisions from fixture policy rather than database rows. Direct
Python lab checks cover repeated approvals, competing rotations, damaged
backup rejection and Evidence Passport negative verification.

Archive verification is bounded to the configured record capacity. See
the review evidence benchmark for measured costs up to 920 records.
Baseline retains its documented direct-database-writer trust assumption.
