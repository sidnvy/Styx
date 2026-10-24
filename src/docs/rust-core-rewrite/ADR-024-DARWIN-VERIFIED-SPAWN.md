# ADR-024 · Darwin retained-image spawn barrier

2026-10-24. Incremental Mac Host Exec port. This decision introduces no new
management authority, helper service, public MCP tool, or GUI dependency.

## Decision and reason

Keep the shared Codex RPC, Host bootstrap, Core authorization and operation ledger.
Only the native image launch adapter differs. Linux retains its original kernel-FD
launch. Darwin's actual retained-FD launch spike failed before a child existed
(EBADF/EACCES); silently falling back to an ordinary pathname would lose the image
binding. Use Darwin posix_spawn START_SUSPENDED, validate the created direct child
against the retained approved image, then SIGCONT before starting any Codex RPC.

Payload inventory retains original root/file descriptions, full SHA256, current UID,
ACL/privacy, file identity and exact signed closure. Static native CDHash is an
additional image binding, not publisher trust. The original external publisher pin
and signature remain mandatory; neither an ad-hoc signature nor a public key
bundled alongside an image supplies product trust. Admit only native thin Mach-O
executables for the current architecture; unsupported formats are explicit refusals.

The paused direct child is bound by original kernel boot/PID birth, static and dynamic
code-signature CDHash, exact path and revalidated retained image before resuming.
Verification failure retains the original child and requests termination, then the
same parent waits. No unverified child is allowed to initialize the Exec protocol.
This is a cooperating owned-parent boundary, not a defense against arbitrary hostile
same-UID debuggers or external SIGCONT. No universal same-UID isolation claim is made.

## Libraries and lifecycle ownership

Use pinned nix safe spawn/wait/signal wrappers, standard-library owned pipes and
official Security Framework wrappers. A scoped FFI call provides the official SDK
addchdir action missing from pinned nix; the wrapper relies on that pinned crate's
repr(transparent) initialized object, not a copied OS structure. CLOEXEC_DEFAULT
restricts this child's inherited descriptors. This does not assert global atomic
pipe inheritance across unrelated process launchers.

One supervisor retains the original image and owns waitpid. Signal and reap share
one facts lock; after a known reap the PID is never signaled again. Canceling a
waiter retains its JoinHandle. Drop requests termination and does not manufacture
an actual-wait receipt. Business descendants remain under the existing Host cleanup
contract; observing direct-child exit does not settle every operation or descendant.
The enclosing foreground job retains configuration/execution ownership through
initialization and cleanup. Raw generic Mac Codex spawn stays refused: only the
protected paired-profile path can pass the retained image to this adapter.

## Verification boundary

Evidence is recorded outside source under r06-macos-payload. The native inventory,
ACL/alias/replacement/bounds and static CDHash aggregate has passed on pho with
synthetic private data. Its first test-principal failure remains recorded. No native
runtime was launched by that aggregate.

The grouped suspended-spawn acceptance must independently show: no effect before
resume; wrong CDHash yields zero effects; correct resume yields exactly one fixture
effect; cancellation retains original ownership; actual wait and original birth
absence. A copied, freshly owned Rust test executable may be ad-hoc signed solely
for this fixture. It does not change any existing signed App/worker or grant TCC.
The native grouped batch passed on pho: recovery-before-resume and wrong-CDHash
effects were zero; correct resume produced exactly one effect; actual wait, retained
cancelled waiter, supervisor join and independent original-birth absence passed.
Evidence: `r14-cli/macos-suspended-spawn/actual-1/summary.json`, SHA256
`f3aa8cd53107ec8545c9d80f0f5917357ff63683efe789325afe744750d36cde`.
That snapshot is explicitly base5140ad4 plus 19 recorded WIP files; the later
profile platform correction is covered separately, never retroactively inherited.

Then run ordinary Linux Gateway + Mac Host strict TLS Exec/PTY using the same
protected synthetic identity across restart, original native Codex bytes, real nonce
effects and exact child cleanup. Native compile and fixture launch do not establish
that result. Mac App/TCC continuity, same-identity migration, persistent lifecycle,
original-publisher packages, Windows execution and final acceptance remain open.
