# Rust implementation status · 2026-10-24

Owner-authorized goal is active. The plan at a21ea75 remains the scope baseline; WORK-ITEMS/ACCEPTANCE are obligations, not execution receipts. All source work uses the existing staging checkout, no new worktree. Integration SHA and evidence hashes are recorded outside source after commits.

| Area | Implemented / locally checked | Still required |
| --- | --- | --- |
| R00 contracts | Public schemas reviewed at Gateway wrapper, semantic v1, synthetic exact bytes | Further wire edge vectors; signed package details at R24 |
| R01 feasibility | Local Rust1.94.1; actual TLS/MCP/Node22 crypto spikes | Native target toolchains/builds, complete dynamic public MCP surface |
| R02 platform | Real Linux/macOS/Windows peer/session facts, isolated Linux IPC | Full native IPC mutual authentication/session binding; persistent principal decision |
| R03 oracles | Independent nonce/process/HTTP observers and receipt integrity tooling | Native GUI observer, Mac/Windows observers, frozen full performance budget |
| R04 workspace | Four crates, pinned lock, real help/version/build-info, strict lint | Continuous gate and source SHA integration |
| R05 contracts/crypto | IDs/capability/session/error/operation DTOs, ordered legacy codecs; RSA-PSS/OAEP/HMAC/Ed25519 interoperated with Node22 | Full Gateway/Host composition; DTOs do not authenticate callers |
| R06 storage | Linux private raw read/version/hash, preservation manifest, distinct writer/execution locks | Mac/Windows secure store, durable transactions/journal, old owner coordination; no live migration |
| R07 operations | Reserved-only dispatch; owner incarnation; immutable payload; bounded accounting; explicit unknown/cancel/liveness/drain and maintenance fence; nonauthor scenario review | Provider ports/scheduling fairness and full runtime coordinator; no native-effect acceptance yet |
| R09 Exec | Implementation in progress over real Codex, no JS fallback | Actual owner-bound Host route, all process/PTY/cancel/cleanup scenarios |

No Rust candidate has been packaged, signed, installed or accepted on the three platforms. Existing signed packages and original device identities/pairing/permissions have not been modified. Historical JS test counts are not Rust completion evidence. Stable remains NO-GO.

Evidence tiers remain distinct: codec/fixture checks; real external executor interoperability; development vertical slice; exact final candidate native acceptance. Root integration commits alone cannot promote one tier into another.
