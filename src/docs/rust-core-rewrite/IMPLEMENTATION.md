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
| R13 legacy CLI | Explicit `host run --legacy-gateway`, read-only doctor/status, original publisher/raw-manifest exact member closure and native file pin; same-budget WSS-before-executor bootstrap and Host-owned cleanup | Actual immutable old Gateway journey, original certificate compatibility and startup timing have distinct external receipts; synthetic profiles do not prove onboarding, original pair or service/App cutover |

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
