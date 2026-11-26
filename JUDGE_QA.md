# Judge technical Q&A

**What is the differentiator?** The same real two-worker harness drives the
CLI and UI. A judge can predict the surviving key version, see both node
decisions, open their audit evidence, and reproduce the result.

**What commits together?** The baseline rotation transaction updates the
encrypted asset, active version, approval consumption, and audit entry.
Preparation uses a separate read phase. Post-cutover authorization rejects v1
with a configured zero grace window.

**How do you measure revocation?** From the server's observed post-commit
monotonic timestamp to each node's first explicit revoked-device response.
The last-node value is the larger of the two. An unavailable response is
never counted as a revoked-device denial.

**What does post-quantum crypto prove here?** An authorized client verifies an
ML-KEM-768 protected-read proof. For local audit attestations it validates an
ML-DSA-65 signature against the expected node key, request and fresh
challenge. These capabilities do not imply a messaging or forward-secrecy
protocol.

**Why does a pending archive operation cause quarantine?** A retained intent,
a missing marker, and a snapshot cannot establish whether the working
transaction committed and was later rolled back. The operator can recover
a verified commit with scoped authority. Ambiguous operations withhold
protected availability.

**Can the log be forged by user-supplied metadata?** The application derives
actor, node, decision, and reason. It emits canonical structured records
and uses opaque references for untrusted targets. The audit chain verifies
event content and order before baseline reads and evidence exports. This
assumes a surviving trusted audit key, head and witness boundary.

**How does the detector avoid overclaiming?** Direct approval violations have
policy evidence. Related unusual lateral edges are marked for investigation.
Overlapping corrected-time ranges produce an uncertainty note. A contested
source ID cannot supply causal evidence in finite replay.

**What does the score mean?** The fixed held-out synthetic fixture measures
known event/rule pairs. It has 24 inputs, 22 unique IDs and 14 labelled benign
events. The numbers in [METRICS.md](METRICS.md) characterize this fixture and
local processing boundaries.

**What is out of scope?** Production distribution, host failover, coordinated
backup rollbacks, old derivable key destruction, archive producer renewal,
portable historical attestations, live detector collection, and messaging.

[Original project repository](https://github.com/KillerMeritus/devforge-key-identity-guard)
