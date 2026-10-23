# ADR-004 · Enrollment authority and durable recovery

Status: implementation checkpoint; not a completed R06/R12 release gate.

Core owns invitation consumption, pending requests, exact approval targets, capability generations, credential references, revocation tombstones and per-frame admission. Runtime owns protected material bytes, RSA/PSS/OAEP/HMAC verification, actual transport facts, exclusive writer ownership and durable filesystem evidence. An ordinary MCP owner is not an enrollment administrator. Serialized records, content references and file existence are not authentication proofs.

Use the existing pinned Serde, AWS-LC, nix and OS filesystem APIs. This journal is the enrollment domain's bounded original-byte/commit record, not a new general database, crypto protocol or second configuration authority. It does not replace the versioned legacy migration/activation contract. SQLite or another mature storage engine remains an implementation option if later transactional requirements justify it; language choice does not establish correctness or performance.

## Write boundary

1. Crypto verifies canonical legacy signing bytes and the actual listener leaf/origin. Core binds approval to the complete pending request/device/SPKI/profile tuple.
2. Core allocates a transaction and capability generation, validates the mutation and fences the affected device before asynchronous I/O.
3. Runtime stores content-addressed materials with explicit Profile, Token and Sealed roles. Token reference hash equals the actual credential hash. Never generate a second credential to recover a lost acknowledgement.
4. Runtime preserves the **original** intent bytes and writes a matching prepared record. The immutable committed record, after file and directory synchronization, is the publication boundary. Exact existing records may be re-synchronized; differing bytes or forks are refused.
5. Only actual verified durability permits Core publication. Ordinary I/O error or absence of a commit record is not proof of nonexecution or nonwrite. A prepared-only intent remains Unknown.

The Linux implementation borrows the configuration writer exclusively and uses descriptor-relative, no-follow, current-user private directories/files, exact inode observations, bounded reads and rename-no-replace. Other targets explicitly return Unsupported until native secure primitives are implemented. Historical immutable credential bytes remain private journal material after revoke; their existence cannot authorize a device because Core's committed revoked/tombstone state wins. Retention/compaction and native migration remain required work, not an implicit sweep.

## Restart boundary

Production Core construction starts Recovering. Normal authentication, claim, approval targeting, connections and mutations remain closed until trusted boot has classified the whole namespace. The runtime must reject ambiguous, unsafe, unreadable, over-budget or unclassified orphan entries, not interpret them as an empty installation.

Replay verifies original-byte digests, complete material references, unique transaction identity, commit hash chain and consecutive committed revisions. Transaction sequence must increase but may have gaps; historical Gateway epoch need not equal the new process's epoch. Core revalidates each historical mutation against its historical prior state and prepared timestamp before applying it. Current expiry or current transport state must not rewrite historical evidence.

A single verified unresolved intent restores its original bytes and affected-device fence without applying the mutation or inventing a missing commit. Re-synchronizing this original record is not authorization to commit it. Already validated staged settlement must remain possible when the recovered durable clock floor is newer than its original timestamp; settlement never lowers that floor.

A fixed-size durable clock floor is advanced before TTL-bearing operations, including rejected joins and read-only claim observations. Existing journal without a proven floor is blocked; `None` is not zero. Real wall clock below the recovered floor is blocked. File synchronization/process-crash tests do not prove power-loss behavior or defeat a malicious whole-storage rollback. Fresh-root creation and original-profile migration require separate bootstrap evidence.

Approved devices replay into **RecoveredUnknown** lanes. They do not become Offline because no in-memory socket exists. A trusted original-transport quiescence fact can reconcile each startup lane once, bound to the current process brand and complete credential/capability identity. Later uncertain connections use a different Unknown state, so an unused startup proof cannot clear new uncertainty. Gateway socket closure is never native Host process exit or permission to replay an operation.

## Explicit limits and acceptance

- Exact-token claim/confirmation, public HTTP auth/status compatibility, real signed joins and self-device CAS still need integrated runtime/network evidence.
- The current one-connection-per-device/lane model is the Exec development slice; legacy multiple Computer connections require a bounded aggregate before Desktop completion.
- There is no durable abort/allocator record yet. Any intent/prepared entry without a commit is preserved Unknown. A purely in-memory, truly pre-write aborted allocation cannot be reconstructed from disk; a new epoch prevents transaction-ID reuse but is not evidence that the old sequence high-water mark was restored.
- Profile semantic schema and initial key-to-ciphertext binding must be verified by the trusted crypto adapter, beyond content hashes. A Gateway with only the public key cannot decrypt a sealed credential to invent a fresh OAEP proof.
- Required evidence includes real private-file reopen, process exits at write/sync/rename boundaries, fork/alias/mode/hash negative controls, recovery before admission, stale closure rejection and exact original-credential continuation. Mock/Core-only passes cannot close native platform or original-pair acceptance.
- No Rust package, deployment, original-profile migration, three-platform acceptance or Stable release follows from this checkpoint.
