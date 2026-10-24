# ADR-026 · Original Linux service selection and physical settlement

2026-10-25. R26 prerequisite, not an installed-runtime migration, activation,
commit, rollback or proof that every old connector is quiescent.

## Responsibilities

Keep the existing configuration owner, maintenance transaction and legacy writer
fence. Its default path still requires service.json absence. An explicit protected
material branch accepts an opaque LegacyServiceDescriptor, captured only from the
same private Host root/fixed filename. It continuously rechecks original raw bytes
and file observations, counts them in the existing material/file budgets, and
refuses cross-root or same-byte replacement. This is material provenance, not a
signed service proof or permission to control a process. No boolean can bypass
service presence and no descriptor DTO creates authority.

The separate Linux manager derives real service authority from the original
protected deployment/publisher pin, active signed release and full retained
inventory. Stable Node and launch/installer/private-storage copies must exactly
match the original signed members. No unsigned Node fallback. It validates the
original user unit, effective policy/argv, authenticated user manager/unique owner,
InvocationID, original kernel process birth, actual loaded Node image SHA and
held cgroup descriptors. Native transient-unit policy and naming are unchanged.
The two selections meet only when configuration root and original descriptor
Host-root/raw/stat provenance match under the same continuous writer fence.

## Stop ownership

Use the already locked rustix 1.1.5 process feature for owned pidfd_open and
pidfd_send_signal. This adds one Linux direct dependency but changes no package
version. Prefer these safe mature wrappers to a new syscall/unsafe implementation.
See the pinned upstream docs for [pidfd_open](https://docs.rs/rustix/1.1.5/rustix/process/fn.pidfd_open.html)
and [pidfd_send_signal](https://docs.rs/rustix/1.1.5/rustix/process/fn.pidfd_send_signal.html).

A manager name or PID alone cannot select the stop target. Revalidate the entire
original scope, open/revalidate its pidfd, then send at most one TERM to that
original process. Do not StopUnit by name or adopt a later Invocation. Settlement
requires original birth absence, original cgroup empty/removed and consistent
manager exit facts. Node wrapper exit0 alone does not prove descendant cleanup.
A caller timeout, cancellation or dropped waiter is not a successful stop. The
single owned job retains its scope/fence through Unknown; confirmed results also
require explicit consumption and task joining. No blind signal retry or detached
success receipt. Any unresolved retained resource is reported as such.

## Next handoff boundary

Even exact physical settlement does not retire an enabled legacy unit, an old
bootstrap or direct connect.mjs. R26 still needs journaled old activation and
credential-locator retirement, preserved original material, reader barrier,
validated native activation under maintenance, commit/recovery and eligible
rollback. Do not fabricate legacy succeeded steps or create fresh device trust.
Existing standalone/cached-credential scopes must be accounted for before any
final handoff. An unrelated side unit must remain untouched.

## Acceptance

The filesystem batch checks default refusal, real legacy exclusive-writer
refusal, cross-Host descriptor substitution and original-file replacement. It is
not service settlement. The separate owned-unit batch must use unchanged original
signed Node/bootstrap in fresh private profiles; reject wrong image/invocation or
unit changes before control; settle only the exact selected original scope while
an independently owned side unit lives; retain Unknown/fence on faults. Capture,
unit control, actual cleanup, activation/migration and final platform acceptance
are recorded separately. Source parsing or mocks never establish native PASS.

The composition keeps the short ownership-changing file/fsync section on its
original stack via bounded Tokio block_in_place, then synchronously registers
the owned capture job before another await. It checks MultiThread runtime
before mutation and returns Unsupported otherwise; no current-thread panic.
This hands unrelated tasks to other workers and does not claim cancellable OS
filesystem calls. Read/hash work stays in the existing bounded blocking pool.
See [pinned Tokio behavior](https://docs.rs/tokio/1.52.3/tokio/task/fn.block_in_place.html).
