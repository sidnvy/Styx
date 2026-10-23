# Rust implementation status · 2026-10-24

Owner-authorized goal is active. The plan at a21ea75 remains the scope baseline; WORK-ITEMS/ACCEPTANCE are obligations, not execution receipts. All source work uses the existing staging checkout, no new worktree. Integration SHA and evidence hashes are recorded outside source after commits.

| Area | Implemented / locally checked | Still required |
| --- | --- | --- |
| R00 contracts | Public schemas reviewed at Gateway wrapper, semantic v1, synthetic exact bytes | Further wire edge vectors; signed package details at R24 |
| R01 feasibility | Local Rust1.94.1; actual TLS/MCP/Node22 crypto spikes | Native target toolchains/builds, complete dynamic public MCP surface |
| R02 platform | Real Linux/macOS/Windows peer/session facts, isolated Linux IPC | Full native IPC mutual authentication/session binding; persistent principal decision |
| R03 oracles | Independent nonce/process/HTTP observers and receipt integrity tooling | Native GUI observer, Mac/Windows observers, frozen full performance budget |
| R04 workspace | Four crates, pinned lock, real help/version/build-info, strict lint | Foundation gate passed at 4a78e91; later adapter changes require their own integration gate |
| R05 contracts/crypto | IDs/capability/session/error/operation DTOs, ordered legacy codecs; RSA-PSS/OAEP/HMAC/Ed25519 interoperated with Node22 | Full Gateway/Host composition; DTOs do not authenticate callers |
| R06 storage | Linux private raw read/version/hash, preservation manifest, distinct writer/execution locks | Mac/Windows secure store, durable transactions/journal, old owner coordination; no live migration |
| R07 operations | Reserved-only dispatch; owner incarnation; immutable payload; bounded accounting; explicit unknown/cancel/liveness/drain and maintenance fence; nonauthor scenario review | Move-only start permit now connects real executor; continuation permits, scheduling fairness and full Host coordinator still required |
| R08 IPC | Linux private UDS/kernel peer read scope, bounded frames/stdio, deadline and no-replay fixture journeys | Management mutation, Desktop authentication, Mac/Windows, actual Core/GUI binding |
| R09 Exec | Real owned Codex PTY/Unicode/exit/drain/cancel; Unknown start reconciled by independent effect, no replay; normal retirement | Host/Gateway binding, continuation admission/audit, legacy wire translation, native Windows/macOS |
| R11 SDK | Actual official SDK negotiation of five legacy versions and 38 source-derived public tools; bearer admission and typed session factory | HTTP/TLS listener, session ownership/close semantics, WSS relay, actual backend grants/routes |

No Rust candidate has been packaged, signed, installed or accepted on the three platforms. Existing signed packages and original device identities/pairing/permissions have not been modified. Historical JS test counts are not Rust completion evidence. Stable remains NO-GO.

Evidence tiers remain distinct: codec/fixture checks; real external executor interoperability; development vertical slice; exact final candidate native acceptance. Root integration commits alone cannot promote one tier into another.

The R09 native batch found actual Codex RPC head-of-line queueing: a later start acknowledgement may time out after a bounded long read even though the native start eventually runs. Its first failed sample lacked a saved operation identity; later reproduction has its own exact operation/UUID/independent one-effect reconciliation. The latter does not relabel the former. Subsequent Host scheduling must retain Unknown and never replay to obtain a quicker answer.

Legacy Gateway raw frames carry process UUID/writeId but no per-chat owner, grant or Host-issued operation token. The final Host must not invent those assurances. R10/R13 must preserve native raw cursor/base64/id semantics through one executor, explicitly negotiate stronger v2, and represent unknown outcomes without converting them to a definite-rejection error understood by old clients.
