# ADR-012 · Shared configuration writer and durable management preparation

2026-10-24. Accepted incremental implementation of frozen C07; the full R21 transaction, native reader barrier and same-identity cutover remain incomplete.

## Problem and retained boundaries

`EnrollmentService` stages Core intent before its filesystem closure. Sharing a filesystem mutex alone cannot prevent management from interleaving between staging and durable publish. The old `OwnedEnrollmentJournal` also moved the only configuration writer into itself; independently claiming another writer for management would conflict rather than compose.

Keep Core pure, serialization in `styx-contracts::management`, OS/filesystem work in Runtime. No dependency versions, process topology, service identity or trust model changed. Enrollment and management retain distinct journal schemas; enrollment's committed approval record is not repurposed as a management transaction.

## Implemented

- `store/configuration.rs::OwnedConfigurationRoot` moves the existing private root and configuration guard exactly once into one shared mutex-protected owner. Clones share that owner; they never clone a writer FD or create another recovered enrollment ledger. Each namespace handle can be minted once.
- Bootstrap pins BOTH fixed existing journal namespaces, including when management runs without an enrollment handle. Namespace replacement, a newly appearing unpinned namespace, unsafe files and unknown I/O observations poison all handles. Ordinary closure errors cannot skip post-checks. Per-namespace bounds and the common 64 MiB journal cap remain distinct; preparation checks aggregate growth before its first write.
- `SharedEnrollment::begin_configuration_maintenance` uses the existing complete service-method gate, then the configuration owner. Its bounded blocking job retains the existing slot after waiter loss. No service/store locks remain held while a returned maintenance handle is used. Lock order is service gate -> configuration owner; store callbacks must never reenter the service or the same owner.
- `EnrollmentService::ordinary_admission` fences new enrollment/preflight, new Host admission, profile discovery and current-profile checks. Existing connection settlement remains a separate Core port. This is configuration maintenance, NOT Host execution maintenance or physical job settlement. `authorize_host_frame` retains healthy/lease checks for existing connections; it does not claim that all native work has stopped.
- Hot health/admission checks publish only monotonic poison/fence rejection facts through standard Acquire/Release atomics. They never take the filesystem mutex from async Host response/lease paths. Actual filesystem and transaction decisions retain the same locked owner and full checks. A small unwind guard publishes poison if a store closure fails to complete; it never restores authority. This fixes the real path where an async lease check could synchronously wait behind management fsync/inventory work.
- An opaque maintenance handle binds the same owner and transaction ID. Drop does not resume admission. There is deliberately no public boolean-based resume method.
- `store/secure_journal.rs` extracts the existing descriptor-relative private-file/immutable append primitives; original enrollment public paths and wire schema remain compatible.
- `store/management.rs::OwnedManagementJournal` opens only an existing pinned namespace. Preparation checks exact deployment and canonical-before bytes before any write, stores exact intent/before/approved-target bytes, then a durable Prepared record. It reobserves canonical-before after persistence; a conflicting post-write observation is Unknown, not a pre-write refusal.
- Idempotent preparation re-syncs the exact original four entries and directory; presence alone does not return a fresh durable receipt. `ObservedPrepared` explicitly represents only observed bytes, distinct from `PreparedPersistence`.
- Existing nonempty management bytes fence ordinary admission on owner reopen, including intent-only and unknown orphan files. Observation retains all inventory; it never fills a missing Prepared, deletes remnants, changes canonical state, generates a new transaction, or clears the fence.
- `styx-core::management::transaction` validates Planned -> Prepared -> Applied -> Verified -> Committed facts and original transaction/deployment/before/target/journal-chain bindings. Recoverable/Unknown retain the last durable boundary and uncertainty history. These pure facts are not filesystem or caller authority.

## Actual verification at this checkpoint

Related local compilation/linting and actual owned filesystem/service-gate cases have passed. An additional actual lock-contention case holds the owner mutex in a real thread while a current-thread Tokio service reads an empty profile set; the service must complete before the holder is sent its release signal. It does not invent a Host connection lease or claim actual native response settlement. Independent subprocess verification used the exact related-batch test binary for five fresh-root scenes: normal preparation, exit after intent write, exit after target rename, exit after Prepared rename, and complete preparation with lost reply. A new process observed the original bytes, exact journal bindings and retained fence after each scene; no canonical replacement occurred. Evidence lives outside the checkout in `r21-transactions/related-2-hot-check` and `r21-transactions/oracle/actual-prepare-2-hot-check`; the earlier receipts remain preserved.

The service-gate case holds a real complete service closure, not an actual invite at an internal stage breakpoint. The empty fixture does not supply a real Host lease; actual connection-ended settlement during maintenance is NOT TESTED. Acquiring all job permits proves the critical blocking work completed and released its slot; it does not claim a dropped JoinHandle was joined. Process exit tests do not prove sudden power-loss durability.

The standalone management budget regression fills an existing unclaimed enrollment namespace and verifies preparation refuses before creating any management journal file. A separate owned negative control changes canonical bytes after durable preparation and verifies shared sticky Unknown without overwriting that foreign change.

The frozen complete gate and integration SHA must be read from the current Owner Control Report; focused evidence is not automatically a full release gate.

## Explicitly incomplete / next implementation

1. A versioned native canonical state reader and compatibility barrier, complete validation and authorized bootstrap/handoff proof. The legacy read-only projection is NOT apply authority. Opening a private root or taking the Rust flock does not establish that a legacy JS owner stopped.
2. Canonical conditional replacement, actual Applied/Verified/Committed persistence, same-transaction recovery/reply-loss query, verified abort/fence release and rollback rules. There is no `apply` CLI or production configuration mutation in this slice.
3. Resumable Host execution maintenance, physical operation/provider settlement and the distinct owner-release/activation protocol. Do not call shutdown as a maintenance shortcut.
4. macOS/Windows private-store adapters, native manager/UI/bootstrap integration, same-identity migration, package/sign/deployment and real account acceptance.

A future rename-based conditional replacement is serialized only against cooperating exclusive writers. A prior hash/inode check followed by rename is not an atomic compare-and-swap against a same-UID uncooperative writer; do not advertise it as such. Neither root privilege nor deleting an old lock is a handoff proof.

## Official semantics used

- [Tokio spawn_blocking](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html): stopping the waiter does not stop started blocking work; keep admission permits with actual work. The implementation still uses the already pinned Tokio 1.52.3; no upgrade was made. The web reference currently renders a newer version, so pinned-source semantics and scenario evidence remain authoritative.
- [Rust Mutex](https://doc.rust-lang.org/std/sync/struct.Mutex.html): shared ownership uses ordinary RAII guards. Poison is advisory; no unsafe memory soundness or authentication claim relies on it, and this module never clears poison.
- [Linux rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html): atomic name replacement and NOREPLACE do not supply an expected-content compare operation. Existing journal append keeps its NOREPLACE and file/directory sync protocol.
