# ADR 028 · Original enrollment history, without invented pairing proof

The original protected Gateway registry can contain a current capability grant
and opaque generation with no original join/CAS signature history. Revocation may
legitimately remove the token file. Replaying native Join/Approve would invent
proof, credentials or an initial-request restriction that no longer represents
the authorized current grant. Frozen Device and public MCP contracts stay intact.

Add a private versioned historical baseline in the EXISTING EnrollmentV1 journal:
fixed immutable intent/prepared/committed files, original exact bytes/digests,
original source and enrollment kernel roots, C07 transaction, source-file bindings,
current approved Devices, independent no-credential revoked identities, original
default and material refs. Raw newline-bearing token and normalized bearer retain
separate typed Token hashes/materials; raw files stay unchanged. Real profile/RSA
validation uses existing VerifiedProfile, never a new crypto implementation.

Only the branded trusted Core recovery control can attest a verified committed
baseline, and only a pristine recovering ledger can consume it. Full pure link,
capacity, identity/fingerprint and material validation precedes mutation. Baseline
is revision/sequence 1 and original receipt head; subsequent native records use
that predecessor. Tombstones participate in normal AND replay rejoin/capacity
checks. Default is original active selection and normal/replayed revoke clears it.
Transport lanes start RecoveredUnknown; disk recovery never infers offline.

Persistence is under the original move-owned writer and opaque active maintenance
of the fixed enrollment root. The original top-level source-maintenance borrow
and snapshot remain retained. These two existing kernel roots have their own
single writers; no global cross-root atomicity or legacy Gateway quiescence is
claimed. Whole-bundle file/count/byte preflight includes the clock and both
namespaces' shared budget. Existing native records, orphan materials, pending or
partial baseline cannot be merged/overwritten, silently completed or retried into
success. Resync only the exact original existing chain. Caller retains original
resources on error; no drop/boolean reopens a fence.

CRITICAL: enrollment-domain committed baseline is candidate history while C07 is
pending, not completed migration. EnrollmentService unconditionally refuses
ordinary HTTP/Host/Exec admission with migration_commit_required when recovered
history exists. There is no public clear/force flag. Final admission needs the
original complete C07 commit/transport settlement capability, not yet implemented.
Source snapshots are rechecked outside the enrollment-owner mutex and must be
revalidated again at final C07 settlement/publication. Any stale source must not
become a current grant by replay. Original Gateway settlement, affected credential
reader, complete native state application, migration commit/restart/eligible
rollback and real three-platform acceptance remain required.

Current original preflight still explicitly blocks unfinished invitations/claims
and unsupported static catalog cases rather than discarding them. That is an
unfinished migration input requirement, not a reduced final compatibility promise.
This increment does not reopen public tool scope, add dependencies or redesign UI.

Verification separates pure Core contracts, actual journal failure/interrupted
file effects, synthetic profile boot-chain codec tests, and protected original
registry/RSA projection with a real independent-process reopen. The last retains
positive fixture bytes for an independent post-test oracle. It proves file and
recovery behavior plus publication refusal; it does not prove old onboarding,
original Gateway shutdown, remote authentication, C07 commit, activation or release.
