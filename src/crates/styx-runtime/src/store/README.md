# R06 store slice

Implemented surface (not full R06 completion):

- `PrivateRoot::open`: existing current-user private Linux directory, pinned dirfd and identity; all absolute ancestor symlinks rejected. Never creates/chmods the legacy root.
- `read_raw`: regular, single-link, current-user private file; relative traversal, symlinks and unsafe intermediate directories rejected. Explicit byte budget; descriptor and name identities/size/mtime/ctime rechecked before return. Raw bytes and SHA256 remain authoritative.
- `read_json`: caller selects `schema` or `version` and supported integers. Duplicate/missing/noninteger/unsupported versions and trailing/invalid JSON rejected. Unknown fields are skipped without converting their numbers; no `Value` roundtrip or original rewrite. Typed config/policy validation belongs to a later importer and is not implied by a valid version.
- `preservation_manifest`: caller lists explicit role/path inputs. Two-pass observations, hashes, version, root/file identity; no private content in manifest/Debug. This is explicitly `per_file_stable_not_transactional`, not a coherent multi-file snapshot. Coordinate writers/legacy transactions before cutover; this function grants no migration authority.
- `try_configuration_writer` and `try_execution_lease`: explicit creation of distinct 0600 lock resources. Rust `File::try_lock` (Linux nonblocking kernel flock), separate opaque guard types, boot UUID + PID start ticks + `getrandom::fill` 128-bit generation. No PID-based stale takeover, lockfile unlink, owner metadata rewrite, or inherited lock across exec. Validate guards before operations; root/lock replacement fails closed.
- `ProcessIdentity`: Linux kernel boot UUID + `/proc/<pid>/stat` birth ticks, not wall-clock boot time or PID existence. Missing/inaccessible identity cannot be promoted to current.

Guard creation mutates only its new ownership-namespace file. Read-only import does not create these files. Locks protect cooperating instances using this resource: they do not discover or supersede existing legacy locks, prove no live tasks, resolve journals, or isolate malicious code already controlling the same OS account. The current slice does not persist the in-memory lease identity/journal, implement atomic file writes/flush, transaction recovery or reader barriers. Do not use it for live migration yet.

macOS and Windows secure store/lock/process implementations return `Unsupported`; there is no canonicalize/read fallback with weaker checks. Native ACL/reparse protection, kernel birth identity and durable ownership records remain required platform work.

Tests use only synthetic private temporary roots and explicitly owned children. They cover raw-byte/big-integer retention, secret-redacted diagnostics, digest/manifest observations, unsafe paths/aliases/modes, budgets/wrong objects, root/lock replacement, distinct locks, independent-process exclusion and release, and forged birth identity. The ignored child entry is invoked by the parent oracle with a specific fixture root; it is not a skipped product gate.


Dependency tightening: `nix` 0.31.3 fs/user safe `openat` returns `OwnedFd`, consumed by `File::from`, and `geteuid` supplies the effective user. O_NOFOLLOW/O_CLOEXEC remain explicit on every relative open. `File::try_lock` replaces direct flock; Linux behavior was checked against official Rust 1.94.1 source, then verified by the existing independent-process oracle. No handwritten unsafe block or unsafe lint allowance remains in store. `getrandom::fill` replaces the local syscall/EINTR loop and fails closed on entropy errors. Other platform operations remain Unsupported.
