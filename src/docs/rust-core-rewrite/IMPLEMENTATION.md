# Rust implementation status · 2026-10-24

Owner-authorized goal is active. The plan at a21ea75 remains the scope baseline; WORK-ITEMS/ACCEPTANCE are obligations, not execution receipts. All source work uses the existing staging checkout, no new worktree. Integration SHA and evidence hashes are recorded outside source after commits.

| Area | Implemented / locally checked | Still required |
| --- | --- | --- |
| R00 contracts | Public schemas reviewed at Gateway wrapper, semantic v1, synthetic exact bytes | Further wire edge vectors; signed package details at R24 |
| R01 feasibility | Local Rust1.94.1; actual TLS/WSS/MCP/Node22 crypto and HTTP official-client development slices | Native target toolchains/builds, complete dynamic public MCP surface |
| R02 platform | Real Linux/macOS/Windows peer/session facts, isolated Linux IPC | Full native IPC mutual authentication/session binding; persistent principal decision |
| R03 oracles | Independent nonce/process/HTTP observers and receipt integrity tooling | Native GUI observer, Mac/Windows observers, frozen full performance budget |
| R04 workspace | Four crates, pinned lock, real help/version/build-info, strict lint | Foundation gate passed at 4a78e91; later adapter changes require their own integration gate |
| R05 contracts/crypto | IDs/capability/session/error/operation DTOs, ordered legacy codecs; RSA-PSS/OAEP/HMAC/Ed25519 interoperated with Node22 | Full Gateway/Host composition; DTOs do not authenticate callers |
| R06 storage | Linux protected raw reads/locks plus bounded immutable enrollment material/intent/prepared/commit journal, exact-chain reconciliation and durable fixed-size clock floor | New checkpoint verification is recorded externally; native Mac/Windows secure store, durable abort/allocation, retention, migration and original owner coordination remain required |
| R07 operations | Reserved-only dispatch; owner incarnation; immutable payload; bounded accounting; explicit unknown/cancel/liveness/drain and maintenance fence; nonauthor scenario review | Move-only start/action permits connect the same owned executor through Host and negotiated WSS; Core-attested physical retention with actual quiescence is now implemented; persistent collection scheduling, durable restart recovery and full remote owner issuance still required |
| R08 IPC | Linux private UDS/kernel peer read scope, bounded frames/stdio, deadline and no-replay fixture journeys | Management mutation, Desktop authentication, Mac/Windows, actual Core/GUI binding |
| R09 Exec | Real owned Codex PTY/Unicode/exit/drain/cancel, Core-bound continuations and physical retirement; original native UUID/writeId/raw-page translation is now implemented | Final legacy CLI journey evidence, native Windows/macOS release and durable restart recovery still required |
| R10 Host | One owned Codex executor, Core admission, supervised start/read/targeted actions, canonical shared-budget bootstrap, strict TLS/WSS explicit generation negotiation; real local action effects and duplicate negatives | Gateway-issued owner coordination, persistent collection scheduling/durable audit, reconnect policy, legacy frontend and native platform lifecycle |
| R11 SDK/HTTP | Official SDK five-version/38-tool surface, Hyper loopback listener, authenticated session ownership, bounded bodies/queues, synchronous close fence and observed owned backend cleanup | Concrete native backend/remote registry, TLS listener composition, real account, POST cancellation under body/connection pressure and SDK detached-task observability limits |
| R12 enrollment | Rust Core target-bound approval, same-credential confirmation/CAS/revoke, signed strictTLS journal service, same-authority paired Host WSS and real MCP-to-Codex owner isolation/physical cleanup checkpoint | Defaults/ingress, original credential/pair migration, transport epoch/dropresponse faults, multiple Desktop connections and cross-platform recovery remain required |
| R13 legacy CLI | Explicit `host run --legacy-gateway`, read-only doctor/status, original publisher/raw-manifest exact member closure and native file pin; same-budget WSS-before-executor bootstrap and Host-owned cleanup | Immutable old Gateway44cf147 + same Rust release CLI passed standard-CA/leaf real pipe/PTY/stdin/cross-owner/no-replay/disconnect/SIGTERM scenes; original-default-style self-signed TLS admission FAILED separately. Synthetic profiles do not prove onboarding, original pair or service/App cutover |

| R14 sessions | Bounded Core registry, fresh incarnation IDs, provider-specific facts, selection/expiry/revocation contracts; runtime Host admission-lock composition is under verification | Authenticated native association, actual Desktop dispatch, durable revocation, real platform lifecycle acceptance |
| R15 Linux discovery | Typed kernel-authenticated system-login1 candidate probe and independent loginctl development evidence; Unknown association only | Worker isolation/candidate CLI and property consistency fixes under verification; watcher, native agent/compositor binding, Window/Capture/Input and real lifecycle acceptance |

No Rust candidate has been packaged, signed, installed or accepted on the three platforms. Existing signed packages and original device identities/pairing/permissions have not been modified. Historical JS test counts are not Rust completion evidence. Stable remains NO-GO.

Evidence tiers remain distinct: codec/fixture checks; real external executor interoperability; development vertical slice; exact final candidate native acceptance. Root integration commits alone cannot promote one tier into another.

The R09 native batch found actual Codex RPC head-of-line queueing: a later start acknowledgement may time out after a bounded long read even though the native start eventually runs. Its first failed sample lacked a saved operation identity; later reproduction has its own exact operation/UUID/independent one-effect reconciliation. The latter does not relabel the former. Subsequent Host scheduling must retain Unknown and never replay to obtain a quicker answer.

Legacy Gateway raw frames carry process UUID/writeId but no per-chat owner, grant or Host-issued operation token. The final Host must not invent those assurances. R10/R13 must preserve native raw cursor/base64/id semantics through one executor, explicitly negotiate stronger v2, and represent unknown outcomes without converting them to a definite-rejection error understood by old clients.

M4 HTTP review fixed a late backend-admission versus shutdown race with one shared registration/fence lock order; closure must never overwrite a late task set and claim it joined. The official SDK does not expose joins for all detached outer tasks; reports retain `sdk_detached_tasks_joined: None`. Bodyless GET/DELETE now bypass slow POST readers and control reservations are no longer double-taken. POST cancellation still shares bounded body/connection admissions; the narrower 256KiB development response ceiling remains explicit. This is not a final production Gateway. Each checkpoint full quality result binds its exact SHA outside source.

M5 physical retention (ADR-003) automatically tracks every dispatched Core record. Known action audit transfers immediately, uncertain actions require exact ended/drained resource and real Tokio execution quiescence; metadata cannot be reaped before provider release. A new actual Linux Host/Codex scenario crossed 256 acknowledged actions, preserved one ambiguous input and writeId with 258 independently read effects, then proved resource-limit1 reuse. A subsequent strict pre-I/O refusal retention correction has its own focused counterexample; final combined-source quality remains a separate checkpoint receipt. No periodic persistent collector, durable restart recovery or final release claim follows from this in-memory slice.


Enrollment recovery (ADR-004) is an incremental Core/store checkpoint, not completed enrollment service or migration. Production starts Recovering; existing native namespace/floor are required and no legacy profile is treated as empty. Verified original history, unique commit chain, exact material references and a durable clock high-water mark precede Core readiness. One unresolved original intent remains fenced and Unknown. Recovered transport uncertainty is distinct from later uncertain connections; startup closure cannot erase later uncertainty. Actual journal re-sync and protected-file tests are distinct from pure Core replay tests. The public boot diagnostics explicitly report `network_ready: false` until typed-profile crypto and actual transport/service composition exist. No root CLI business command, installed JS runtime, identity or signed artifact has been switched by this checkpoint.


Signed enrollment service (ADR-005) now composes Core, owned single-writer journal, AWS-LC proofs, original-token idempotent confirmation, self API and strict Hyper/TLS admission. New independent tests and failure receipts are external. Expired pending collection is itself a durable Core mutation; observed material uncertainty becomes sticky admission failure. Public blocking-job reconciliation cannot claim quiescence while the listener remains active. This service is not yet the complete CLI/Gateway/Host distribution: the existing inspection-only BootstrapDiagnostics continues to report network_ready=false; it must not be interpreted as a global capability result for another composed object.


Legacy foreground (ADR-006) is an explicit compatibility slice. `foreground/profile.rs`
reads original deployment/state, publisher pin, raw signed manifest, active release,
RSA identity, host credential and CA binding. Mutable `host.exec.binary` never selects
native code. `store/payload.rs` streams exact closure hashes and retains the original
ELF descriptor through native cleanup; no arbitrary `--codex-bin`/token override exists
in the product CLI. macOS/Windows protected filesystem launch remains unsupported in
this slice; synthetic Linux bootstrap is not a platform migration.

`host/bootstrap::ExecHostReservation` reserves RPC/protocol/WSS from one byte source
before strict WSS admission, and moves that reservation into the one native executor.
`host/legacy::LegacyExecSession` translates original UUID/writeId/raw cursor frames
through the same Core permits. Old frames cannot provide v3 per-chat grants; a lost
start/ACK remains Unknown, never an invented definite RPC rejection. One session and
executor survive network loss; explicit Host stop joins their actual cleanup.

Foreground refuses known original owner/health resources, and refuses `service.json`
without an actual OS stopped-service observer. Its Rust execution lease protects Rust
workers only; it is not proof that an old JS/App/service owner was stopped. Public
`host_run` is a waiter for an owned Tokio worker: waiter drop signals the official
CancellationToken drop guard and does not drop the worker's lease or native child.
Cleanup tracks original operation exit evidence independently from executor exit,
I/O joins and supervised jobs. An original Unknown cannot disappear through a later
empty inventory. Native API-waiter-drop fault injection is still NOT TESTED.


The be6b585 product checkpoint has actual isolated old-Gateway receipts: standard
CA/leaf A/B journeys passed with original signed payload bytes and independent file
and kernel process observers. Both ended with no owned process residual/fallback
kill. Original Gateway MCP DELETE retains Exec as an explicitly observed legacy
limitation; its SIGTERM, then explicit Rust Host SIGTERM, exercised actual cleanup.
The network-loss case SIGKILLed the owned Gateway and retained the same native
executor/one-effect command until Host stop. Its original-default-style self-signed
TLS fixture failed admission before any native executor start and remains FAIL.
Release-mode full 507MB closure verification completed around 0.55s/Host connected
around 0.65s in these fixtures; debug profiling's 12.39s was mainly SHA CPU. These
observations are not a final platform startup SLA or a fix to historical Windows
login recovery. The same product SHA also compiled natively offline on pho x64;
native tests/App/signing/TCC/account acceptance were not run.


Session authority and the necessary SDK allocation isolation boundary are described
in [ADR-007](ADR-007-SESSION-FACTS.md). These changes are not automatically covered by
the earlier 35a9fe3 gate or Mac compile. The original self-signed TLS failure is now
precisely classified by the unchanged verifier as `tls_certificate_ca_used_as_leaf`;
that diagnosis does not fix original Gateway compatibility. The historical self
API401 statement was not supported by the located original receipt: that request
sent no authorization and returned404. Originalrc12 lacked the self controller;
original-pair authenticated self/CAS remains NOT_TESTED, not a diagnosed bad key
or clock. No trust anchor, device credential, original
signed artifact or installed runtime was replaced to obtain a successful result.


Browser's initial real Linux headless Host batch passed with independent HTTP and
kernel cgroup/PID observers after correcting Chromium's Unix socket path limit.
The954becb frozen full local developer gate and same-SHA Mac x64 compile passed;
the Mac result is compile only. Original failed attempts remain FAIL.

The subsequent Browser increment reuses all24 original frozen tool schemas through
mature offline-only jsonschema validation. Core owns bounded opaque reference scope;
the thin worker supplies native epochs and checks expected epoch immediately before
one upstream call. Snapshot mode none and one in-flight request are safety invariants,
not proof of an atomic navigation lock; see [ADR-010](ADR-010-BROWSER-REFERENCES.md).
Focused pure-Core/provider cases and the actual Linux Host reference batch passed:
first direct Snapshot, wrong-owner/raw/stale refusal, independent input/click nonce,
autonomous navigation, tab changes and same-profile reopen invalidation. Two original
cgroups and all25 sampled PID/birth identities were independently observed gone.
The complete frozen integration gate is recorded separately for the resulting SHA.
This does not accept every tool's behavior: file transfer, login continuity, headed
ownership, public paired routing, native Mac/Windows lifecycle and signed candidates
remain required. No installed runtime has been switched.


R20 management intent and R15 Linux event watch now have an incremental checkpoint;
see [ADR-011](ADR-011-MANAGEMENT-INSPECTION-SESSION-WATCH.md). Core owns explicit roles
and deterministic review dependencies; the shared Runtime/CLI raw reader preserves
both original hashes, unknown fields/large integers, awaiting approval, App login
false and unresolved ownership. Missing manager/run/autostart is Unspecified, never
an installation/start default. Known-field inspection is not complete legacy schema,
credential or execute authority. No management write transaction has been added.

Linux watch runs official zbus subscriptions/reconciliation only in the owned
memory-limited same-image child. Parent sequence/stream identity/child birth and
full-source fence are implemented. Four actual owned fault scenes passed after
fixing idle pipe closure detection; eight sampled original process identities
were independently gone. Full regression evidence is recorded separately for the
frozen resulting SHA. No real lock/logout/compositor change or authenticated Agent,
HostRegistry/Cua, native Mac/Windows, migration, package or account claim follows.


## R21 shared-writer / durable-Prepared increment (2026-10-24)

The configuration owner now shares one move-owned writer with singleton typed enrollment/management handles. Management fences the existing full enrollment service gate before preparation; caller loss cannot release the actual blocking-job slot or implicitly resume admission. Both fixed namespaces participate in root pinning and the shared budget, including standalone management. Management persistence stores exact approved raw materials and durable Prepared only. Core owns the checked C07 phase protocol; observed Prepared bytes are not a new durability receipt.

Related actual owned-file/service-gate cases and an independent five-scene process-exit/reopen batch passed at the recorded exact source inputs. These do not complete R21: no canonical apply/commit/recovery, native reader barrier or legacy handoff is implemented yet. Nonempty management journals remain fenced across reopen until that reconciliation exists. See [ADR-012](ADR-012-SHARED-CONFIGURATION-WRITER-PREPARATION.md); current frozen-gate/integration evidence remains in the external Owner Control Report. No Rust package/install/deployment or latest-platform acceptance is inferred.

A subsequent liveness correction publishes monotonic owner poison/fence facts without taking the filesystem mutex on async enrollment/Host response checks. The real current-thread service/held-owner-lock case and the affected shared-writer plus process-exit/reopen batches passed at their exact inputs. Actual filesystem decisions remain under the single guarded writer; these published rejection bits cannot authorize apply or release maintenance. Mac native compile evidence at5fbb909 predates this correction and is not inherited by the newer source.
