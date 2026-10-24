# ADR 027: original credential locator retirement within the original journal

Status: implementation and actual-scene verification in progress. This does not
complete C07, activate a native runtime or authorize ordinary dispatch.

The already joined original Linux service proof is rechecked before and after
retirement. One synchronous multi-thread-runtime `block_in_place` span retains
that proof, signed candidate, original writer and maintenance. A different manager
owner/invocation or remaining original process/cgroup refuses the transition;
a post-effect ambiguity is Unknown and invalidates the in-process binding.
No name-based StopUnit, automatic effect retry or token restoration is added.

The existing ManagementV1 journal gains a versioned credential sub-stage at the
same transaction ID/sequence/high-water. It is not a DesiredStateCommit: canonical
state remains the original raw bytes. Intent binds configuration/Host roots,
original token metadata and private digest, selected preservation digest, original
service descriptor, verified native candidate and publisher. Intent and Prepared
are durable before a descriptor-relative `RENAME_NOREPLACE` moves the original
`device/host.token` to the fixed transaction-derived private name in that SAME
directory. Original UID/mode/nlink/inode/raw bytes/mtime are retained; rename ctime
is separately captured. The file and parent directory are synced, then the original
journal records Retired. This remains pending, never Committed or admission-ready.

Legacy roots without a management namespace can create only this one fixed 0700
namespace under the original maintenance/writer. Creation is exclusive; an
untracked existing name is not adopted. Exactly one logical journal handle remains
retained for that owner lifetime, including failure. Queries resync and compare
the original chain through that handle rather than attempting a second claim.
Unknown/partial records and guard names are retained. Resync never performs the
rename, synthesizes a missing phase, restores a token or establishes quiescence.

The original fence changes preservation validation for ONLY the authenticated
retired-token entry: original name absent, fixed destination with original inode
and raw bytes, held descriptor and original private device directory. Every other
selected identity/config/publisher file remains under its existing exact check.
The selected set is not the complete C07 preservation inventory.

Important consumer boundary: original Host direct/stdin/launcher entries read the
old token locator; existing connections may already cache it. A co-located old
Gateway catalog can reference the SAME file, and the present Rust compatibility
reader also fixes/revalidates that original name. Retirement therefore cannot be
followed by restoring/copying that name, retaining an untracked cached bearer, or
pretending the existing loader can validate a new Host. A dedicated migration
reader must consume the same opaque original transaction/inode binding for Host
AND affected Gateway consumers. Nonempty legacy catalog import, current revocation
and desired disabled state, native application/verification/commit, restart
reconciliation and eligible rollback remain required work under C07. No fresh-root
provenance is forged, and no old catalog snapshot is promoted to current grants.

Cooperative boundary: before/after manager samples are not an atomic lock against
arbitrary same-UID systemctl/standalone processes. Authorized ordinary entries must
honor maintenance; all known old credential-caching scopes must settle before final
native admission. Credential absence alone is never treated as that evidence.

Verification: same-journal real private-file interrupted/preflight aggregates are
separate from the owned original-service physical-stop/retirement and independent
old direct/stdin/stable-entry refusal scene. Neither substitutes for native paired
validation, complete original deployment migration or actual platform acceptance.

Maintenance reader increment: only an in-process `Arc<RetiredLegacyCredential>`
can mint `RetiredCredentialReadBinding`; it keeps the original writer, service
proof, journal and verified candidate alive. Reads freshly verify that SAME
physical invocation is settled and resync the original retirement before/after.
Both configuration and Host kernel roots must match; only the fixed retired
original token descriptor/name is accepted. Wrong roots fail, never select other
credentials. `validation_profile` retains original identity, configuration, CA,
publisher and old active inventory while deriving workers from the retained native
candidate. Its opaque wrapper has no conversion to an ordinary startup profile,
execution lease or Core grant. Ordinary loaders and previously loaded profiles
still refuse the retired original locator. This does not implement final native
state loading or Gateway authentication.

Historical enrollment preflight is separate: the protected original maintenance
borrow retains exact registry/catalog/token bindings, current capability generation,
default selection and revocation tombstones. A summary explicitly says no native
import or original-Gateway settlement. Old records lack original join/CAS signature
history; revoked devices often legitimately lack token files. Do not fabricate
JoinFacts, credentials, fresh pairing or initial-request grants to fit native
recovery. The trusted historical baseline, no-credential revoked identity port,
affected Gateway credential reader and final publication remain missing. Static
catalog entries and unfinished invitations/claims remain explicit preparation
blockers, not silently discarded historical facts.

The retired-reader isolated-service scene uses the existing explicitly synthetic
old-format bootstrap. Its source reader, file effects and original service process
are real; its `host.prepare/pair/doctor` succeeded records do not attest execution
of those onboarding workflows. Report this narrow scope even if the reader scene
passes. Real completed original onboarding and migrated paired execution remain
separate acceptance requirements.
