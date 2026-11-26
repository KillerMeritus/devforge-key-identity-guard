# Measured rubric evidence

[Original project repository](https://github.com/KillerMeritus/devforge-key-identity-guard)

## Reproduce

```sh
toolkit_dir="$PWD/../Track-4-Toolkit"
PYTHONPATH=. python scripts/measure_rubric.py --practice "$toolkit_dir/practice" --runs 4 --probes 40
PYTHONPATH=. python scripts/evaluate_detector.py --baseline 4f75ed2
```

Observations use Linux 6.18.57, x86_64, Python 3.12.14,
and loopback workers on one host with 9 visible CPUs.
The harness uses temporary SQLite fixtures and local monotonic clocks. Values
below describe these test runs. The release manifest identifies the exact
checkout and includes the raw observations alongside the verification logs.

## Key lifecycle and revocation

**Configured old-version grace window is 0 ms.** Authorization checks the
active committed version. A request already authorized on an earlier snapshot
can finish under that snapshot. Previously derivable keys are not
cryptographically destroyed by the cutoff.

The cutoff origin is the worker's monotonic timestamp at its post-commit
checkpoint, measured immediately after the transaction exits. Each value ends
at the first scheduled old-version probe's HTTP response. The harness polls
for the checkpoint before dispatch, so this measures observed enforcement with
probe scheduling and loopback round-trip included.

| After-commit run | Node A v1 rejection (ms) | Node B v1 rejection (ms) | HTTP 403 wrong-version probes |
|---|---:|---:|---:|
| 1 | 17.34 | 16.65 | 2/2 |
| 2 | 20.53 | 18.75 | 2/2 |
| 3 | 17.28 | 15.71 | 2/2 |
| 4 | 17.93 | 17.14 | 2/2 |

There were **8/8** explicit v1 rejections at the observed cutoff and **8/8**
additional v1 rejections after restart in committed runs. Authorized Node B
reads succeeded **40/40** on v1 during preparation, then **20/20** on v2
after commit while the rotation reply was paused. These are scheduled probes
across the demonstrated boundaries.

For revocation, time starts at the revoke worker's observed post-commit
timestamp and ends at each node's first explicit revoked-device response.
The two probes are dispatched in parallel after the revoke reply. Last-node
delay is the larger observed value. Recovery time starts when SIGKILL has
been confirmed and ends at the first verified teammate read on restarted A.

| Run | A revocation (ms) | B revocation (ms) | Last node (ms) | Recovery (ms) | Observed version |
|---|---:|---:|---:|---:|---|
| Before commit 1 | 2.68 | 3.67 | 3.67 | 296.41 | v1 |
| Before commit 2 | 1.79 | 3.60 | 3.60 | 252.81 | v1 |
| Before commit 3 | 2.10 | 3.58 | 3.58 | 231.77 | v1 |
| Before commit 4 | 2.26 | 6.28 | 6.28 | 211.63 | v1 |
| After commit 1 | 1.91 | 3.49 | 3.49 | 211.44 | v2 |
| After commit 2 | 2.09 | 4.74 | 4.74 | 211.68 | v2 |
| After commit 3 | 1.93 | 3.42 | 3.42 | 230.87 | v2 |
| After commit 4 | 2.26 | 3.32 | 3.32 | 233.11 | v2 |

The eight runs produced **16/16** initial explicit revocation denials and
**16/16** more after Node A restarted, including responses from the surviving
Node B. The authorized teammate had **16/16** successful post-restart node
probes. HTTP 503 responses are excluded from explicit revocation counts.
Median recovery was **242.29 ms** before commit
and **221.28 ms** after commit.

## Held-out detection

Same fixed labels before and after changes. There are 24 arriving inputs,
22 unique IDs, 14 explicitly labelled benign IDs, 7 expected alert keys,
and 1 contested ID. An exact duplicate and an inconsistent duplicate account
for the two additional arrivals. Labels were authored from synthetic scenario
intent independently of emitted rules.

| Revision | TP | FP | FN | Precision | Recall | F1 | False alerts / 1,000 benign | Alert median ms | Alert p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 7 | 2 | 0 | 0.778 | 1.000 | 0.875 | 142.86 | 0.0058 | 0.0096 |
| Candidate | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.00 | 0.0075 | 0.0127 |

False alerts per 1,000 benign = 1,000 × false alerts ÷ labelled benign event
count. A zero denominator is reported as undefined. Precision, recall, and
F1 use unique anchor/rule pairs. The prior detector took the first payload
for a contested ID and generated two false findings. The candidate excludes
contested IDs before finite evaluation and reports the conflict. Both rows use
seven matched latency samples, measured inside the detector from arrival of
the last supporting input to alert emission. Fixture replay is immediate and
latencies omit network, archive writes, and external dispatch.

Source offset correction subtracts the supplied offset from event time.
Tested offsets were −900 to +1,500 ms. Receipt minus corrected event time
ranged from 50 to 6,000 ms. Processing uses ±125 ms uncertainty per event,
a 250 ms overlap boundary for two observations, and an absolute five-second
lateness limit for path and causal evidence. The 6,000 ms sample produced
a late observation note. Related out-of-order evidence can correlate when
corrected times establish sufficient separation.

## Performance and overhead

The HTTP fixture uses an authorized 1,024-byte file, one reader and serial
requests to Node A. Each mode starts from a fresh fixture. The p95 uses
the nearest-rank observation. Local verification time is a separate
measurement from the end-to-end HTTP read difference.

| Measurement | Samples | Median (ms) | p95 (ms) | Boundary |
|---|---:|---:|---:|---|
| Baseline HTTP read | 40 | 1.1168 | 1.4534 | Loopback request to response body. |
| Archive HTTP read | 40 | 8.6116 | 13.2659 | Same HTTP read, including archive verification and durable writes. |
| Archive verification pass | 40 | 3.1986 | 3.5548 | Local authenticated receipt chain and working-state verification at 80 receipt rows. Excludes HTTP and appending. |
| Detector only | 4 | 0.0794 | 0.1391 | Local finite evaluation of the same 22 organizer practice inputs. |
| Archived detector replay | 4 | 24.8160 | 24.9627 | Same input, including durable sources, alert writes and verification reads. Excludes provisioning. |
| Verified experimental snapshot restore | 4 | 59.0450 | 59.9300 | Restore call through teammate and revoked-device checks on both workers. |

The median archived replay difference was **24.7367 ms**
for 22 inputs and five confirmed findings. One replay's source ingestion
median was 0.630 ms with p95
0.993 ms. This is bounded offline
replay, with no live worker ingestion.

A genuinely ambiguous archive crash remains quarantined, so there is no
recovery-availability sample for that state. Archive results are experimental.

## Expanded deterministic detector evaluation

The 24-input held-out file is unchanged. A separate scenario-authored
generator uses 12 cohorts with varying identities, service edges and approval
targets. It labels routine noise, approved access, scoped violations,
out-of-order pairs, clock overlaps and contested identities independently
of the detector. The expanded replay includes **1,284 inputs**, **1,176
labelled benign IDs**, and **12 contested IDs**.

```sh
PYTHONPATH=. python scripts/evaluate_detector.py --expanded --baseline 4f75ed2
```

| Revision | TP | FP | FN | F1 | False alerts / 1,000 benign | Matched alert latency median / p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Detector at 4f75ed2 | 72 | 24 | 0 | 0.857 | 20.41 | 0.0024 / 0.0058 |
| Reviewed detector at baf8eae and final candidate | 72 | 0 | 0 | 1.000 | 0.00 | 0.0028 / 0.0079 |

Each latency row has 72 matched samples. This is local finite replay and
excludes networking, archive writes and live collection. These synthetic
scenarios do not establish production accuracy. The evidence package
contains the original measurement and a clean-checkout rerun.

Finite replay examines the complete batch before emitting findings, so
conflicting payloads under one ID are quarantined as evidence in either
arrival order. Uncontested findings are still evaluated. The experimental
archive replay rejects a conflicting input before confirmation. Live alert
reconciliation for conflicts that arrive after an alert has already been
published remains outside the implemented scope.
