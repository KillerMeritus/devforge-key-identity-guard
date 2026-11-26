# The Recovery Console · PRD v2

**Product requirements document · DevForge Track 4 · Trust, but verify**  
**Status** Proposed for implementation · **Delivery budget** 10 hours plus up to 2 hours of contingency  
**Target repository** `KillerMeritus/devforge-key-identity-guard`

## Revision and implementation status

This PRD supersedes the prior planning draft. The implementation baseline is
`48256c8`. Existing tests prove that both local workers reject a file database
snapshot taken before the latest externally checkpointed revocation, provided
that checkpoint survives. Independent retention of subsequent evidence is
**planned**. Sections 8–11 govern the new phase and its release gates.

The original plan treated audit integrity and revocation recovery as separate
requirements. FR‑07 asked whether a surviving log could be verified. The
restore test asked whether a revoked device could regain access. Neither asked
whether an incident investigator could retrieve an event generated after the
latest revocation. That left the audit rows and their current head inside the
same restore boundary. Every new recovery test must now identify which state
rolls back, which evidence survives, what the service refuses, and what recovery
can safely restore.

## 1. Product decision

Build a two-node secure file service and an operator console that can show what survived an interrupted key rotation. The judge revokes a test laptop, interrupts rotation at a defined transaction boundary, and inspects the recovered service. Both nodes must still deny the revoked device. An authorized teammate must still be able to read the committed file. The console links the observed outcome to requests, key versions, and audit evidence.

A device‑revocation flag handles the basic permission change. The product addresses the harder question of whether the permission change remains effective when keys rotate, requests overlap, and one process dies. The same workflow gives the operator a way to distinguish routine administration from an unexpected change and investigate an unusual service path.

### Users and jobs

| User | Job | Success |
|---|---|---|
| File owner | Read a protected synthetic file and regain access after losing a device | A replacement credential works. The old credential stays revoked. |
| Authorized teammate | Keep working while a separate device loses access or file encryption rotates | Reads remain available through healthy nodes and return the committed file contents. |
| Security operator | Revoke a device, approve changes, and investigate an alert | Every material decision has a precise reason and supporting evidence. |
| Judge | Reproduce an access decision and a recovery outcome | Can choose a crash boundary or approval variant, observe real results, and rerun the case from a clean checkout. |

### Scope

- **P0, release scope** Organizer adapter, two independently running local nodes, device enrolment and revocation, file‑key rotation, both process‑kill cases, damaged‑key‑backup rejection, verifiable audit, contextual detection, repeatable CLI demonstration, and submission evidence.
- **P1, demo scope** Single‑screen browser console and one judge‑controlled scenario. Use the CLI if browser work threatens the release gate.
- **P0, independent evidence milestone** Retain security audit events outside
  the protected database's restore boundary and verify independent freshness.
  This is a gate for the retention claim. The existing file-service baseline
  remains usable for judging if the new phase fails its release gate.
- **P2, optional** Approval comparison and clock-uncertainty replay.
- **Messaging scope** End‑to‑end messaging, recipient binding, message replay controls, forward secrecy, loss/reordering delivery, and session resumption are **unimplemented** for this track. We will expose a **no‑op messaging endpoint** (`POST /message`) that returns a documented *“unsupported”* error and logs the request (see FR‑13). Record the file-only scope in the submission. The stub does not establish messaging coverage.

## 2. Product behavior and acceptance

| ID | Priority | Requirement | Acceptance evidence |
|---|---|---|---|
| FR-01 | P0 | Initialize the organizer sandbox through the documented adapter. Enforce ownership and disabled‑actor state, durably revoke an actor, and retrieve a read decision by request ID. | Public validator passes from a fresh directory. Separate subprocesses return an exact Unicode and multiline body, deny wrong owners and disabled or revoked actors, and return the requested audit decision. |
| FR-02 | P0 | Perform organizer protected reads after authorization. Decode the standard Base64 raw ML‑KEM‑768 public key, verify the decoded length and challenge type, encapsulate, and emit the contract proof. | An independent client decapsulates the ciphertext and verifies lowercase hex HMAC‑SHA‑256 over UTF‑8 `challenge + stored_body`. Changing either input invalidates the proof. Denials disclose no body, ciphertext, or proof. Malformed fields yield a controlled response. |
| FR-03 | P0 | An authenticated operator revokes an individual demo device. A verified owner can be re‑enrolled through a trusted operator workflow. | A and B independently deny the old credential. The teammate remains authorized and a fresh credential works for the owner. Missing credentials, regular devices, and revoked operator credentials cannot administer access. |
| FR-04 | P0 | Rotate a file encryption key with a matching, unexpired, single‑use approval. Prepare new ciphertext while the current version serves reads. Atomically switch the active version. | New ciphertext verifies under the new key. Both nodes reject new requests presenting the prior version after commit. Two rotations staged against the same active version produce one committed change. An approval whose scope or expiry changes before commitment is rechecked. |
| FR-05 | P0 | Recover after a real process kill before or after the rotation commit. An already‑authorized read may finish with the snapshot it captured. | Before commit, recover the original version and no successful rotation audit event. After commit, recover the new version and one successful event even if the caller got no reply. In both cases the revoked device stays denied and the exact committed file remains readable. |
| FR-06 | P0 | Verify authenticated, encrypted key backups before accepting their key material. Bind backup metadata to its asset and version and enforce eligibility against current trusted state. | Intact eligible backup opens. A damaged backup, wrong wrapping key, or mismatched asset/version produces a recorded failure and leaves usable state intact. Backup restoration alone never changes device revocation state. Generate the corrupted-backup fixture locally. The public validator does not exercise this case. |
| FR-07 | P0 | Produce structured, tamper‑evident audit records. Actor, role, action, and node come from trusted execution context. | Multiline input stays in one record. Verification detects row modification and trailing‑row deletion with the newer authenticated head intact. The demo explains the limit for a full rollback of the audit database and head together. |
| FR-08 | P0 | Distinguish approved administration from suspicious change and flag unexpected service edges for valid identities. | A correctly scoped action during approval validity stays quiet. A missing, expired, or mismatched approval and a configured unexpected edge produce explainable results. Alerts identify actor, services, rule, anchor event, and supporting IDs. |
| FR-09 | P0 | Handle bounded clock uncertainty and out‑of‑order delivery. Preserve source timestamps, receipt timestamps, and original evidence. | A replay within the declared lateness bound (**±5 seconds**) produces the expected findings. Overlapping corrected time intervals yield order‑uncertain where ordering matters. An event exactly at approval expiry is outside the window. |
| FR-10 | P0 | Run the canonical demo and evidence capture from a fresh fixture using one documented entry point. | A fresh run seeds synthetic identities, proves access, revokes, rotates, kills and restarts a process, and reports evidence. Harness failures produce a distinct error and preserve useful diagnostics. |
| FR-11 | P1 | Present the scenario in an offline, single‑screen operator console with an evidence drawer. | The console (static HTML mockup `ui/mock.html`) and CLI reflect the same real backend outcomes. Status is clear without color alone. A node timeout appears as unavailable and never as a security denial. |
| FR-12 | P1 | Let the judge predict whether the old or new version survives a selected crash boundary. | The console asks for a prediction, runs the real scenario through the harness, and reveals the observed version, teammate read, revoked‑device denial, and linked evidence. A failed run surfaces the failed assertion. |
| FR-13 | P1 | Expose a no‑op messaging endpoint (`POST /message`) that returns a documented *“unsupported”* error and logs the request. | The endpoint is reachable, returns HTTP 501 with JSON `{"error":"messaging not supported in this track"}` and creates an audit entry. The evidence sheet notes this as the handling of the messaging scope. |

## 3. Technical design and boundaries

### Components

| Component | Implementation decision |
|---|---|
| Judge entry point | Root `track4_service.py`. Python 3.12, stdlib, and organizer‑provided `pqcrypto==0.4.0` on this import path. One input JSON object through EOF, one output JSON object, and sanitized diagnostics on stderr. |
| Shared core | `kig_core/` holds shared SQLite helpers, access rules, structured audit, and detection. Boundary‑specific code handles judge actor IDs and authenticated demo device credentials. |
| Demo backend | Two independent FastAPI/Uvicorn processes on loopback, separately probed, sharing one SQLite authority. Demo‑only vetted AEAD dependency lives outside the judge import path. |
| Operator UI | Plain HTML/CSS/JS static mockup (`ui/mock.html`). A full React scaffold is optional and will only be added if time permits. |
| Demo harness | `demo_cli.py` starts and supervises the named demo processes, owns synthetic fixtures and failure checkpoints, and returns test and timeline evidence. It now supports `--kill-at pre|post` to send `SIGKILL` at the pre‑commit or post‑commit checkpoint (see AT‑01). |
| Storage | Separate judge and demo state directories. Use temporary writable state for the judge and keep ciphertext inside SQLite for the demo. Initialize WAL at database setup, use explicit transactions, set connection‑level durability, timeout, and foreign‑key settings, and keep writes short. |
| Evidence export | New endpoint `GET /evidence/{request_id}` returns a **JSON** object matching the audit schema (actor, action, node, timestamps, decision, proof). |
| Config | New endpoint `GET /config/clock-tolerance` returns the numeric bound (`{"tolerance_seconds":5}`). |
| Alert SLA | The detector must emit alerts with a **median latency ≤ 250 ms** and **95‑th percentile ≤ 500 ms**. Measured in the benchmark harness and reported in the evidence sheet. |

### Interface and state contracts

| Judge operation | Inputs and outcome |
|---|---|
| `setup` | Consume `owners`, `contents`, `disabled`, and synthetic `key_material` as documented. Return `{"ready":true}` after state is durable. |
| `read` | Accept `actor`, `asset`, `request_id`. Return `decision` and the exact `body` on allow. On deny, emit only the denial fields permitted by the contract. |
| `revoke` | Accept `actor` and persist actor‑level revocation before returning a JSON object. |
| `audit` | Accept `request_id` and return the corresponding `request_id` and `decision` for the read. |
| `protected_read` | Accept `actor`, `asset`, `challenge`, and `public_key`. On success return `ciphertext` and `proof`. Keep the shared secret internal. |
| `POST /message` | Returns HTTP 501 `{"error":"messaging not supported in this track"}` and logs the attempt. |
| `GET /evidence/{request_id}` | Returns structured JSON audit evidence (see FR‑07). |
| `GET /config/clock-tolerance` | Returns `{"tolerance_seconds":5}`. |

Store identities and grants, device credential digests and revocation status, current asset version and ciphertext, approvals, audit rows, and an authenticated audit head. Provision independent random secrets in private state outside SQLite. Existing state with unavailable key material requires a controlled failure. Keep raw bearer tokens out of logs, URLs, and persistent browser storage. Enforce operator role server‑side. Use **401** for missing or invalid authentication and **403** for authenticated callers who lack permission. Treat contention, malformed requests, and node unavailability as separate outcomes.

### Rotation, cutoffs, and recovery

1. Capture the expected file version and ciphertext. Prepare authenticated ciphertext for the next version **outside** the write transaction.
2. Start the commit transaction. Re‑check authenticated operator authority, exact approval scope and expiry, and expected version. Atomically persist the new ciphertext/key state, active version, approval consumption, and audit event/head.
3. Expose two checkpoints to the local test harness. The pre‑commit checkpoint is **after transactional writes, before COMMIT**. The post‑commit checkpoint is **after COMMIT, before response**. Send `SIGKILL` to the actual process and verify its termination (via `--kill-at pre|post`).
4. After restart, probe both nodes and inspect the durable event. If a rotation reply was lost, confirm the outcome using the current version and audit before retrying. A stale expected version cannot silently rotate twice.
5. A request whose authorization snapshot is taken after commit must use the current version. A read already authorized may finish with its captured ciphertext. Apply the same snapshot semantics explicitly to revocation. Data already returned to a client can remain on that device.

### Detection and evidence

Use trusted approvals separate from request‑supplied evidence. Match subject, action, scope, and `valid_from <= event_time < valid_until`. Evaluate service paths against configured role and service context. Keep detection labels out of the rules.

For ordering, correct reported source time by the known offset, represent remaining uncertainty as a **time range**, and buffer up to the documented arrival‑lateness limit (**±5 s**). Record delayed arrivals separately from clock uncertainty. Include rule ID, identity, services, evidence IDs, anchor ID, timing confidence, and reason in each alert. Suppress claims that require a particular event order when the order remains ambiguous.

### Threat model and claim limits

- **Protected assets** Synthetic file bytes, file keys, device and operator credentials, approvals, audit records, and backups.
- **Sandbox threats** A lost or revoked device, an ordinary user attempting an admin action, an interrupted process, corrupted key backup material, altered audit rows, stale versions, and misleading timestamps.
- **Trust assumptions** The host, trusted operator provisioning, and private key storage remain trusted. The test fixture uses fictional identities. Secrets and file content stay out of operator evidence unless a synthetic file read is explicitly shown.
- **Limits** Shared SQLite is one local authority and one failure domain. Process‑kill tests provide process‑crash evidence. Host loss, full datastore rollback, and production high availability require separate designs and tests. The protected‑read proof demonstrates organizer interoperability. The audit verifies records against the available trusted head.

## 4. Operator experience

**Visual direction** Use a graphite incident console with a bright transaction marker, distinct node lanes, and short outcome labels. Reserve amber for staged work, red for an explicit denial, green for a verified result, and neutral gray for unavailable or pending. Pair each color with text. Keep the interruption and recovery visible on one screen.

| Region | Behavior |
|---|---|
| Status strip | Show Node A, Node B, current file key version, and last observed decision for each node. Show when a result came from a prior run. |
| Incident timeline | Synchronize A, B, and durable audit lanes. Show revoke, rotation staged, process killed, restart, and verified outcome. Mark harness observations and durable audit events with their source. A pre‑commit crash can appear on the timeline even though its staged audit row rolled back. |
| Prediction control | Select before or after commit, predict the surviving version, and run against fresh synthetic state. Prevent accidental double starts. Show predicted and observed values with the underlying checks. |
| Evidence drawer | Show source, request ID, actor, device, node, active or requested version, outcome, reason, and linked audit verification. Redact secrets and file contents. Report explicit unavailability and timeouts. |
| Terminal fallback | Run the same harness and assertions. Print version, tests, denial timing, and evidence IDs in the same sequence. |

### Five‑minute demonstration

1. **0:00–0:45 · Baseline.** Both test users read the file. Show independent ML‑KEM proof verification.
2. **0:45–1:30 · Revoke.** Revoke the laptop. Show explicit denials on A and B, the last‑node measurement, and successful teammate access.
3. **1:30–3:15 · Interrupt.** Let the judge select a crash boundary. Kill at the checkpoint, recover, and reveal the version alongside the teammate read and old‑device denial. Show the opposite checkpoint as a prepared run or an integration‑test result.
4. **3:15–4:30 · Investigate.** Compare a scoped approval with a mismatch and inspect one unexpected service‑path alert. If the UI is unavailable, show the underlying results in the CLI.
5. **4:30–5:00 · Verify.** Open the audit evidence and show the reproducible checks. State the shared‑authority topology and recovery boundary.

## 5. Measurement and release verification

| Measure | Method |
|---|---|
| Last‑node revocation enforcement | Run concurrent probes using a shared monotonic clock on the demo host. Report time from observed revoke commit to first explicit revoked‑device denial per node and the maximum across A and B. Publish probe cadence and count timeouts separately. This is a detection bound under the measured local topology. |
| Read continuity | Probe an authorized teammate during revocation and normal rotation. Record successes, explicit denials, and transport or lock errors. During a crash, distinguish the killed process from the surviving node. |
| Recovery time | Measure from confirmed process termination to the first successful probe of the restarted process against the expected version. Publish the checkpoints and observed versions. |
| Detector quality | Run organizer practice logs for functional checks. Use a separate labelled synthetic set with counts and provenance. Match alerts one‑to‑one by documented anchor and rule. Report precision, recall, F1, and false alerts per 1,000 benign events. |
| Alert latency | In a timed replay, report **median latency ≤ 250 ms** and **95‑th percentile ≤ 500 ms** from the receipt of the last required evidence event to matching alert emission. Preserve the supported timing window and sample count. |

### Release gate

- Public toolkit validator and independent protected‑read proof test pass.
- Integration tests cover wrong ownership, credential/role boundaries, re‑enrolment, both nodes, exact approval expiry, racing rotations, both real crash checkpoints, damaged backup handling, and audit edits or truncation.
- Clean checkout runs in the documented offline runtime with a read‑only source tree and writable temporary state. Judge and demo environments remain isolated.
- Each claim in the evidence sheet maps to a reproducible command, test result, or stated limitation. No known release‑blocking defects remain.
- Public repository, dependency list, and setup README are ready. The PDF is at most two pages, includes a one‑page threat model and the public link to the five‑minute recording, and the link opens signed out. Verify the exact submission revision.

## 6. Solo delivery plan

| Time | Deliverable and stop condition |
|---|---|
| 0:00–2:00 | Inspect existing code, wire adapter, run the public validator, and pass the independent KEM proof check. Preserve a known‑good revision. |
| 2:00–3:30 | Run A and B separately. Finish authenticated access, operator controls, revocation probes, and re‑enrolment. Start the terminal runbook. |
| 3:30–5:45 | Finish transactional rotation, real crash harness (`demo_cli.py --kill-at pre|post`), both recovery tests, and authenticated backup rejection. |
| 5:45–7:15 | Finish audit verification and contextual detection. Run timing, boundary, and synthetic benchmark cases. |
| 7:15–8:15 | Build the evidence timeline and prediction control if the core is green. Exercise the terminal fallback on fresh state. |
| 8:15–10:00 | Freeze features. Run the clean verification. Produce and verify the required documentation, PDF, recording, and release revision. |
| 10:00–12:00 | Fix release failures and rehearse. Add one optional capability only if the release remains green. Re‑run verification and refresh any affected recording. |

Give Codex one milestone at a time with scope, acceptance tests, exact commands, and observed results. Reserve the final 105 minutes for verification and submission. Cut optional clock controls and browser polish first. Keep both real crash cases and the terminal demo.

## 7. Differentiators and open decisions

| Idea | User value | Cut line |
|---|---|---|
| **Predict the recovery** | The judge chooses a failure boundary and checks their prediction against a real process run. | First browser interaction after the terminal crash harness is green. |
| **Change one field** | A judge changes the approval target and sees the exact mismatch and linked audit record. | Add when scope matching and the evidence drawer already work. |
| **Clock uncertainty scrubber** | An operator sees why a service path can become ambiguous without rewriting the original events. | Add after timing bounds and stable evidence IDs are available. |
| **Restore a valid pre‑revocation snapshot (baseline tested)** | A recovered file store cannot restore access to a revoked credential if a newer trusted revocation authority survives. | Keep this regression gate. Test restored old state and missing external authority. Withhold protected reads when current revocation state cannot be verified. |

### Open questions for organizers

- **Scoring impact of file‑only scope** – Will the absence of full end‑to‑end messaging reduce the maximum points for the “Core Challenge Objectives” section? We will report the status via FR‑13.
- **Topology credit** – Does running two independent processes over a shared SQLite authority count as a multi‑node topology for the “revocation across nodes” metric?
- **Protected‑read local execution** – Can the protected‑read proof be executed locally in the validator, or must it be run against a remote organizer service?

## 8. Hackathon rules and release boundaries

| Rule source | Requirement |
|---|---|
| Track 4 problem statement, ground rules | Only the assigned sandbox, mock services, synthetic data, and test identities. No testing against other teams or out-of-scope systems. No denial-of-service against shared services. All fault injection in this PRD uses private fixtures. |
| Submission integrity | Keep secrets out of the repository and the evidence bundle. No AI/ML components in the submission, custom cryptographic primitives presented as secure, or unattributed copying. Use vetted libraries for standardized primitives. |
| Original work | Use the repository created during the hackathon. Credit third-party code and dependencies. Build the core prototype and controls during the event. |
| Adapter v1 | Keep the existing root adapter and its five operations. Fresh process per request, UTF-8 JSON over stdin/stdout, sanitized stderr, writable temporary state, and no network or package installation at judge runtime. Test the published Linux/Python 3.12 baseline. |
| Deliverables | Working prototype, public repository at submission with reproducible setup and documented dependencies, and a brief of at most two pages including a one-page threat model and publicly accessible five-minute demo recording link. |
| Claim boundaries | Public toolkit results establish public checks. PQ evidence and private fixture recovery have their own tests. Hidden grading, production-grade isolation, and file-only scoring across messaging goals remain unverified. |

The retention feature belongs to the **local demo**. It must run offline with
a local mock archive. Cloud services, public collectors, and external endpoints
are outside the delivery plan. Preserve the existing CLI and judge contract.
Use ML-KEM-768 for the judge proof and ML-DSA-65 for per-node evidence
verification. Keep separate pinned key identities and operator checks. A valid
signature authenticates the signed record and its context. Freshness comes
from the independently retained position.

## 9. Independent evidence requirements

**Protected state.** Separate the restorable working database from an audit
archive with its own state and credentials. The archive retains the complete
redacted event and latest verified sequence and digest. The restore operation
has access to the working database only. Normal nodes may submit events
through the archive interface. Investigators may retrieve retained records
through a separately authorized path. The application API offers no edit,
delete, or reset operation. The demo models a separate restore boundary on
one host. Operating-system administrators and simultaneous rollback of both
stores remain outside this guarantee.

| ID | Required behavior | Evidence for sign-off |
|---|---|---|
| FR‑14 | Retain each scoped security event durably outside the working database. Include authenticated access decisions and denials, enrolment, revocation, approval consumption, rotation, evidence-access actions, and detector alerts included in the demo. Use an explicit schema to exclude credentials, key material, and plaintext. | Retrieve the original event by request or event ID after local restore. Verify both positive evidence and redaction. Pre-authentication malformed requests, health probes, and process stdout are outside retained event scope. |
| FR‑15 | Bind the retained position to a provisioned store identity, monotonic sequence, and authenticated digest. Detect stale, conflicting, missing, or unverifiable archive state. | A restore after revocation but before a later suspicious event leaves the laptop revoked and both nodes return unavailable for protected operations. The archive independently returns the later event. |
| FR‑16 | Define durability at acknowledgement. Protected reads must withhold content if their required evidence cannot be retained. Critical mutations require a durable receipt before success. Use a stable operation ID across retries and prevent conflicting duplicates. | Inject lost replies and failures at each write boundary. A retry produces the same logical record or an explicit conflict. A crash cannot create a false completed outcome. |
| FR‑17 | Distinguish incomplete operations from committed outcomes across the two stores. Track PENDING, CONFIRMED, ABORTED, and UNRESOLVED states. Reconciliation must compare trusted records and the working transaction state before restoring access. | Interrupt before archive write, after pending receipt, after working commit, and after archive confirmation but before reply. No ambiguous state authorizes protected access. |
| FR‑18 | Gate evidence access and signing by active authorization and state verification. Preserve node identity, signed payload, and request binding. Provide a deliberately scoped investigator path for retained historical evidence while the working store is blocked. | Unprivileged and revoked identities cannot query or sign. Stale working state cannot mint accepted fresh evidence. Authorized investigators can retrieve the retained original and verify provenance. |
| FR‑19 | Show three distinct outcomes in CLI and console: explicit policy denial, audit state unavailable, and verified historical evidence. | Reproduce the user's case with evidence IDs and distinguish unavailable from no suspicious activity. |
| FR‑20 | Keep a release evidence manifest keyed by exact Git SHA and tool version. Capture public validator, local tests, both browser scenarios, synthetic replay, and the restore scenario. | A second person can rerun each command and locate the relevant trace. Store a compact redacted milestone report. Operational audit persistence and test-output retention have separate purposes. |

### Migration and cutoff

Provision the archive explicitly from a known-good demo fixture. If adopting
existing verified state, record the authenticated starting position and mark
prior history as pre-retention. Workers must never auto-create an empty
archive on startup when retained state is missing. An archive key or identity
change requires an authorized transition with a preserved prior verification
key and a documented recovery test. Evidence must identify when the retention
guarantee starts.

### Ordering and recovery design constraints

- Keep the existing revocation witness while developing and testing the audit
  archive. State transitions across independent stores require a documented
  protocol. Do not describe them as a single SQLite transaction.
- Preferred protocol for the first prototype: serialize security-relevant
  operations per working store, retain a pending record before the working
  transaction commits, then finalize with an append-only confirmation.
  Bind both records to a stable operation ID and authenticated working-store
  position. Protected operations require a consistent confirmed position.
  Test concurrency, a lost acknowledgement, and each interruption boundary
  before treating this protocol as implemented.
- Recovery must never infer success solely from a pending receipt or
  reconstruct missing access-control changes from unverified logs. An
  unresolved mismatch withholds protected operations. Preserve the archive
  for investigation and recover from a trusted consistent snapshot or a
  documented reconciliation procedure. An early prototype may require
  manual reconciliation and must say so.
- Local role authentication depends on the working store. During stale-state
  recovery, authenticate investigation separately against an authority
  outside that restore. A stale working-store administrator role cannot
  grant access to retained evidence.
- Bound queue and retention in the demo. Archive unavailability or capacity
  exhaustion is explicit. Losing both stores, losing the archive trust root,
  and compromising the shared host remain explicit limits. Previously
  disclosed plaintext cannot be recalled. Backup confidentiality requires
  decryption keys outside the restored database and protected separately.

## 10. Failure-oriented acceptance matrix

All new rows are pending until executed against the exact release revision.
Existing feature regressions remain mandatory.

| Scenario | Expected outcome |
|---|---|
| Normal access, rotation, and revocation with archive healthy | Authorized teammate reads. Revoke only the target credential. Emit recoverable evidence and valid per-node signatures. |
| Restore before revocation | Both nodes withhold protected operations. The revoked credential stays denied after a trusted current restore. |
| Restore after revocation, before later suspicious event | Both nodes report stale or unverifiable audit state. Investigator retrieves the later original with its ID, provenance, and rule context. |
| Truncated tail; deleted or edited middle event; changed head; valid-looking conflicting history | Detect the missing or inconsistent position. Block fresh signatures based on stale state. Preserve independently retained evidence. |
| Missing archive, timeout, invalid receipt, or archive at capacity | No protected content or successful critical acknowledgement. Distinguish unavailable from revoked. Restore availability only after verification. |
| Process interruption at each write boundary | Each operation is classified as PENDING, CONFIRMED, ABORTED, or UNRESOLVED using the recovery table in Section 12. No false success. Repeated requests do not advance the sequence twice or mutate state twice. |
| Concurrent writers and out-of-order retries | One canonical history, authenticated predecessor linkage, no substituted event or cross-node signature, and controlled contention handling. |
| Archive edit/delete attempted through application-facing API | Denied. Read-only investigator credential cannot append. Revoked application operator cannot use stale claims to retrieve evidence. |
| Restore both stores, invalid trust root, or shared-host compromise | Demonstrate or document the resulting limit. Make no claims of independent physical storage or immutable retention against host administrators. |
| Wrong node/key, wrong request, stale challenge, or changed signed record | Verification fails. A healthy counterpart and existing organizer proof still work. |
| Missing archive during startup or mismatched store identity | Fail closed without creating an empty replacement. Explicit initialization works only for a fresh fixture or verified migration. |
| Role changes and evidence redaction | Verify the investigator grant at access time. The archive retains request metadata, with no plaintext payload, tokens, private keys, or raw diagnostics. |
| Boundary and load checks | Repeat deterministic negative cases and measure local P50/P95 latency at a declared test scale. Report added archive cost and unavailable outcomes separately. |

## 11. Implementation and change control

1. **Protocol and fixture first.** Write the exact after-revocation restore
   test and define the archive API, trust roots, permissions, and failure
   outcomes. Confirm the existing validator and suites still pass.
2. **Retention and enforcement.** Implement the mock append-only archive,
   idempotent receipts, and verification against both stores. Add crash,
   retry, concurrent-writer, and unavailable cases before enabling the
   behavior for the demo. Keep the adapter path isolated.
3. **Investigation and PQV.** Wire retrieval and node-bound verification.
   Demonstrate recovery, explicit unavailable states, and signed historical
   evidence. Verify that no secrets appear in the release evidence.
4. **Release review.** Re-run public toolkit, local suite, both browser
   scenarios, and clean offline setup. Push tested, independently revertible
   commits directly to `main`. Update the milestone manifest and submission
   status after observing results, then review public repository access and
   the final brief/video. Keep any unmet claim explicitly pending.

For each future milestone, write down the protected asset, who can mutate
it, what can be lost or restored, where trust survives, what happens on
failure, and which test would falsify the claim. Review the scenario matrix
before updating `main`. If verification time is short, ship the proven
baseline and mark independent retention incomplete.

## 12. Conditional approval gate — Proof-Carrying Recovery

**Planning status:** these requirements govern archive implementation. The
review came from static inspection. Keep the current runtime as the fallback
until the new gates pass on an exact candidate SHA.

### Operation states and recovery

The archive stores immutable records. `UNRESOLVED` is a recovery verdict,
not a replacement for a durable record.

| State | Required evidence | Deterministic recovery |
|---|---|---|
| PENDING | Authenticated intent durably appended. No terminal receipt exists. | Check the working transaction marker in verified current state. Confirm only when the marker matches the intent and committed change. Abort only on positive evidence that the transaction did not commit. Absence in a restored or unverified database is insufficient. Otherwise classify UNRESOLVED. |
| CONFIRMED | Archive terminal receipt and working marker agree on the operation, outcome, and committed state binding. | Return the recorded non-sensitive outcome under fresh authorization. A missing or mismatched working marker after restore is UNRESOLVED for service availability. Keep the durable receipt. |
| ABORTED | Terminal archive receipt records a verified noncommit, including a controlled rollback or a verified transaction/fencing record. | Never apply this operation again under the same ID. A newly authorized retry of the intent needs a new ID. A conflicting commit marker is UNRESOLVED. |
| UNRESOLVED | Store unavailable, unverifiable, stale, or conflicting, or insufficient proof of commit/noncommit. | Withhold protected data and success acknowledgements. Preserve both histories. Permit authorized historical investigation independently. Reconcile against a trusted snapshot or independently verified commit/abort evidence. No automatic reset. |

Allowed archive transitions are new → PENDING → one terminal state. Duplicate
terminal writes with identical authenticated intent and outcome are no-ops.
Unknown IDs and late delivery cannot supersede terminal records. The first
prototype may resolve interrupted operations manually. Acceptance covers all
crash boundaries, uncertain commit, lost terminal reply, conflict, and
recovery with both stores available.

### Canonical event and receipt contracts

Use a versioned, allowlisted schema. Define event identity as a provisioned
producer identity plus producer event ID. Every envelope carries schema
version, store and producer IDs, event/operation/request IDs, authenticated
principal reference where known, node, event kind, result, receipt timestamp,
and sufficient correlation metadata. Define kind-specific fields and stable
reason codes. Canonical bytes use UTF-8 and a project profile of deterministic
JSON serialization with fixed schema keys, sorted object keys, compact
encoding, and integers for time and sequence. Reject duplicate keys, unknown
fields in signed payloads, floats, invalid UTF-8 and unbounded values. Publish
golden canonical byte fixtures. RFC 8785 is a reference, and compatibility
requires its own tests before claiming it.

| Producer | Required retained events and bindings |
|---|---|
| Authorization and protected reads | Authorized and denied file/evidence decisions, asset and version, authenticated actor/device class, and reason. Record delivery acknowledgement separately when known. A decision to allow is not proof the recipient received bytes. |
| Identity and policy administration | Enrolment, revocation, role and policy changes, approvals issued/denied/consumed, scope and policy version. Include approved target, action, and non-secret before/after references. |
| Key and backup lifecycle | Rotation intent/outcome, version transitions, backup verification and restore decisions, sign-key provisioning/retirement, trust-root transitions. |
| Evidence and archive operations | Investigator grants and denials, evidence retrieval/signing, initialization, checkpoint progress, conflicts, archive failures, and reconciliation outcomes. Protect against recursive logging by emitting archive bookkeeping through its own control log. |
| Detector | Retain accepted redacted source envelopes independently of derived alerts. Alerts bind rule and rule version, source IDs, approval reference, corrected timing intervals, and interpretation. Retain conflict/late/invalid dispositions where safe. |

Never store tokens, private keys, plaintext protected data, raw request bodies,
or unbounded diagnostics. Use a non-secret, schema-typed redacted state
projection. For mutations, bind the terminal receipt to the store, operation
ID, authenticated caller scope, intent digest, schema version, predecessor,
outcome, and **affected entity ID plus expected and resulting versions and
state digests**. Examples include credential revocation status, role/grant
version, approval consumption, and encrypted file/key version. Write a commit
marker containing that binding in the same SQLite transaction as the mutation.
Verify it against the confirmed receipt. Preserve this marker across normal
retries. Audit position alone does not prove a working-state change.

### Local archive interface for the first implementation

| Operation | Input and outcome |
|---|---|
| Read verified position | A configured store identity and pinned archive verifier. Return the authenticated confirmed position and any outstanding intent. Unknown or inconsistent history is unavailable. |
| Append intent | Authenticated producer, scoped operation ID, canonical intent, expected predecessor, and deadline. Return a durable authenticated pending receipt only after append. An exact duplicate receives its existing receipt. A mismatched duplicate or predecessor receives conflict. |
| Finalize intent | Reference the exact pending receipt and provide an authenticated outcome binding. A confirm requires independently checked persisted state and commit marker at the worker boundary. An abort requires verified noncommit evidence. Return the existing terminal receipt for an exact retry. |
| Retrieve retained event | A currently authorized archive investigator, scope, and event ID. Return the original canonical bytes and retained provenance. Working-store state is not an authentication input. |

These are internal local interfaces, with a separate investigator entry
point to be implemented after worker enforcement. The organizer adapter
and baseline CLI do not depend on them. Add the investigator assertion to
the opt-in rollback fixture before the gate can be called passing. The
first fixture exercises stale reads and fresh attestations and records
their baseline failure in `EVIDENCE.md`.

### Verify persisted state before accepting a receipt

A verified receipt and matching SQLite marker establish which change was
intended. They do not prove the database currently contains that change.
For each affected entity, compare the receipt’s expected projection with
a fresh query of the actual rows in one protected SQLite snapshot. Bind
the projection kind and version to the digest. Confirm the pre-state
against the verified preceding position and the post-state against the
committed transaction. When later mutations supersede an old receipt,
verify the latest confirmed projection for each affected entity and
follow the authenticated predecessor links for history. Never compare an
obsolete post-state directly to a legitimately updated entity. Missing,
additional, or mismatched rows in the defined projection are unverifiable.

| Mutation | Canonical non-secret working-state projection |
|---|---|
| Enrol or revoke a device | Device reference, actor reference, role, enabled/revoked state, credential generation, and any predecessor/replacement reference. Verify the actual credential row and the persisted relationship. Exclude bearer secrets. |
| Change roles or grants | Actor reference, policy version, and complete sorted affected role/grant set with action, scope, and validity. Verify row deletion explicitly as absence within verified state. |
| Issue or consume approval | Approval reference, subject, target, exact scope, file version, validity, and issuance/consumption state. A consumed approval is absent from the live approval table and bound to its verified operation marker. |
| Rotate or restore file state | Asset reference, active version, key identifier, digest of persisted authenticated ciphertext, and approval reference/consumption when applicable. Verify the active row and corresponding approval state without exporting content or keys. |
| Change trust or investigator grants | These changes belong to the independently authorized archive store. Verify persisted store identity, key identifier/epoch, and scoped grant status/expiry there. Working-store data cannot change these grants. |

A negative integration test must preserve the genuine receipt and marker,
change the actual projected rows in a private fixture, and verify that the
worker withholds protected operations. A marker is never an authorization
source. Protected reads evaluate current credential, grant, and asset state.

### Cross-process serialization

Use a stable, provisioned POSIX advisory lock file for each store pair.
Both workers and the trusted offline restore tool must acquire the same
lock. The current owner is the process holding the open lock descriptor.
Never delete or replace the lock file to clear contention. Take the process
lock first, then the working SQLite transaction, then archive I/O. Archive
handlers must not acquire the working lock or call back into a worker.
Hold the lock through the final durable receipt and the working-state
verification that gates the response. Use a five-second acquisition deadline
in the demo, with SQLite and archive I/O bounded by the remaining deadline.
On timeout return unavailable with no protected content or success result.

OS process exit releases the lock, but release of a lock is never proof
of a commit or abort. The next owner verifies both stores and resolves
the recorded state before serving. A successful local rollback observed
under the live lock can justify ABORTED. A process kill with missing
working evidence is UNRESOLVED unless a separate trusted noncommit proof
exists. In particular, an authenticated old snapshot can look identical
to a pre-commit crash. Do not infer ABORTED from a missing marker there.

Keep the existing crash workflow independently runnable. Prepare new
ciphertext outside the process lock, recheck the version after acquiring
it, and release it after the confirmed receipt and before the post-commit
test pause. Preserve and measure Node B reads during preparation and after
the confirmed commit before reply. Reads may wait during the brief write
section. Archive-enabled crash recovery remains a release gate. If the
prototype cannot distinguish verified noncommit from unknown state and
meet its required recovery outcomes, keep it disabled for release.

### Historical evidence and fresh attestations

A retained signature can verify historical origin and content. Display its
original signing context, event ID, and retained sequence. It does not
establish present freshness or grant access. An investigator may obtain this
historical evidence while workers are unavailable only through the archive
authority’s separately provisioned, current scoped credential. The stale
working database cannot authorize that request. A fresh current-state
attestation requires a new challenge, a pinned node key, active current
authorization, and verified working/archive state. A receipt mismatch,
missing archive, or UNRESOLVED operation blocks fresh successful signing.

### Retries, ordering, and access

- Scope idempotency keys to authenticated principal, endpoint, and operation
  kind. Bind that key to canonical intent. Same key and different intent
  returns conflict without effects. A retry always rechecks current
  authorization. Protected reads never replay cached plaintext or revive an
  old proof. Evaluate a fresh request and challenge against current policy,
  with an independently auditable new attempt.
- Enrolment retries cannot replay or recover a bearer secret. After a lost
  response, disclose only the enrolment reference and state to the authorized
  operator. To issue a replacement, first revoke the credential whose
  delivery is uncertain via a new authorized operation. Test retries by
  another identity and revocation during retries.
- Deduplicate source IDs only when canonical bytes match. A differing
  payload for the same producer/event ID creates a conflict record and
  cannot replace source evidence or participate in automatic correlation.
  Approval must match subject, action, resource/scope, version and valid
  interval. Missing or ambiguous scope cannot authorize a protected change.
- Retain source event and receipt time separately, plus corrected time and
  uncertainty. Use bounded correlation keyed by actor/session/flow. Demo
  defaults are 30 seconds of corrected event-time span and the existing
  5-second arrival tolerance. Set explicit capacity and expiry limits; report
  late and overflow outcomes. If corrected intervals overlap, record order
  uncertain and omit any causal claim. Revalidate detector accuracy and
  latency before retaining earlier performance claims.
- Separate investigator identities from working-store operators. Provision
  through the archive authority, grant read scope and expiry, verify grants
  on every request, and support revocation/rotation within that authority.
  Reject missing authority and revoked, expired or cross-scope credentials.
  Log investigator actions independently, without granting append/delete.
- The current file-key version policy is **logical retirement**. Old material
  may remain in backups or be derivable from a retained root key. Claim
  cryptographic destruction only if a separate design proves all relevant
  material and recoverable copies are unavailable. This phase makes no
  destruction claim.

### Invariant traceability and time budget

Code paths below are planned integration points. Add exact code and test
links as each change lands.

| Invariant | Planned code boundary | Acceptance test |
|---|---|---|
| IR‑1 No stale protected access | Worker guard and archive position verifier | Restore between revocation and a later event; both nodes refuse and investigator retrieves the event. |
| IR‑2 A receipt proves the intended state change | Guard transaction marker and archive finalization | A valid receipt for the wrong target, version, or state digest fails. A genuine marker and receipt with changed persisted rows also fail. Process kills cover each boundary. |
| IR‑3 Retries do not disclose secrets or repeat mutations | Worker auth, idempotency state, issuance | Lost reply, revoked caller, divergent intent, and no read or enrolment secret replay. |
| IR‑4 Retained history resolves provenance | Canonical event writer, detector ingestion, node attestation | Duplicate/conflicting IDs, bounded and ambiguous timing, source retrieval, wrong signing key and replayed challenge. |
| IR‑5 Investigation is independently authorized | Archive investigator interface | Fresh, expired, revoked, and scoped credentials against stale working state. |
| IR‑6 Baseline remains runnable | Judge adapter and demo harness | Public validator, local suite, pre/post crash UI runs and offline clean setup. |

Timebox the design and test contract to the first 45 minutes available. Reserve
**at least the original 105 minutes** for release verification, documentation,
and rehearsal before committing to archive work. Use only remaining time for
a narrow local prototype, with a stop/go checkpoint after the protocol and
fixture pass. Defer the security-invariant dashboard until archived evidence
and receipt verification are demonstrably correct. Keep the existing
evidence UI as the fallback. Ship the verified baseline if the new milestone
cannot meet its gates.

For every increment record the commit SHA, commands and observed results,
remaining risks, and PRD deviations. A dashboard may display measured
invariant states as passed, failed, pending, or unavailable. It must never
infer a pass from a missing run. Keep the archive local/offline and outside
the organizer adapter contract.

## 13. Sources

- [Track 4 Toolkit and public validator](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit)
- [Organizer adapter v1](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit/blob/main/docs/adapter-v1.md)
- [Toolkit practice logs and labels](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit/tree/main/practice)
- Team input · `Pasted text(2).txt`, The Recovery Console build plan
- New UI mockup `ui/mock.html`
- [SQLite Online Backup API](https://sqlite.org/backup.html)
- [NIST SP 800-53 Rev. 5](https://doi.org/10.6028/NIST.SP.800-53r5), AU-5 and AU-9 as design references, with no compliance claim
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) for primitive roles

- [RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [Making retries safe with idempotent APIs](https://aws.amazon.com/builders-library/making-retries-safe-with-idempotent-APIs/)
