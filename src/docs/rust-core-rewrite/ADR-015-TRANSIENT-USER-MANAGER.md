# ADR-015 · Current-user transient Host manager

2026-10-24. R22 implementation subset. No persistent installation, logout/boot
claim, new account, autostart, linger or original service mutation.

## Responsibility and handoff

Use mature native systemd user-manager tools to launch the SAME ordinary Rust
paired Host. Core/Host still owns grants, operations, executor supervision and
safe shutdown. The native manager owns the service process lifetime after explicit
successful handoff; the launcher can exit while the Host remains. Dropping a
returned observation does not stop a handed-off service. No second executor,
policy ledger or canonical desired state is added.

Successful process launch is distinct from Host connection or tool readiness.
Use Type=exec and verify actual process image/argv, profile root, unit invocation
and cgroup. Report `process_started_host_readiness_not_observed`, then actual
acceptance must prove readiness through real paired Exec/PTY effects. The manager
is current UID, with a fixed native user bus/runtime locator and no inherited
graphical environment used as authority.

## Explicit interface

`host start --transient --state-dir ABS --json` returns public bounded UnitRefDto
observation data. Caller may retain that exact output in a private owner file.
`host status --transient --state-dir ABS [--owner-file ABS] --json` only observes;
without a file it lists strictly scoped native units, including inspection after
lost start reply. Listing neither adopts a unit nor invents the original result.
`host stop --transient --state-dir ABS --owner-file ABS
--expected-invocation ID --json` requires current scope and exact invocation.
The file/DTO itself grants no authority: runtime reobserves all native facts.
No arbitrary unit, PID, executable, bus address or raw credentials are CLI inputs.

Startup cancellation must keep the same owned future alive through reconciliation
or cleanup of its original chosen unit. Never retry unknown startup by allocating
a new unit. On successful explicit native-manager handoff, launcher exit is
intentional. No hidden auto-restart is introduced.

## Shutdown and limits

Restart=no, KillMode=mixed, SendSIGKILL=no and TimeoutStopSec=infinity preserve the
Host's ordinary TERM cleanup; timeout is Unknown, never clean stop. Observe exact
unit/invocation, original process birth, cgroup and actual clean exit. Own utility timeout uses bounded TERM grace then exact-child KILL/wait; it never
kills the Host or service cgroup. An unconfirmed utility retains its child and
capacity in an owned reaper. Startup's missing-unit cleanup additionally waits
for that original utility to be reaped, so it cannot abandon a possible late
StartTransientUnit submission. Such unresolved startup remains owned rather than
claiming deadline completion or clean cancellation.

Native manager acknowledgement alone does not establish resource drain. systemd StopUnit
has no InvocationID atomic CAS: random scoped unit identity plus before/after
checks protects cooperating ownership, not a hostile same-UID replacement race.
Use existing mature native unit-reference pinning if needed to retain exit facts
through transient unit garbage collection; never fabricate clean status after GC.

This is an explicit runtime action against a protected transitional profile, not
a native desired-state transaction, old owner cutover, persistent service mode or
final signed runtime package. Original identities/pairing/publisher/TCC and
installed services remain untouched. Desktop Agent association remains separate.

## Acceptance and references

Actual ordinary CLI launch exits while paired Exec/PTY continues; same-scope
second owner refuses; query does not start; foreign/wrong invocation stop refuses;
exact Stop has independent process/cgroup/cleanup evidence and does not revive.
Original bytes and every owned unit/process outcome must be recorded. Synthetic
fixture import remains separate from fresh product onboarding.

Primary semantics: [systemd-run](https://freedesktop.org/software/systemd/man/latest/systemd-run.html),
[systemd.service](https://freedesktop.org/software/systemd/man/latest/systemd.service.html),
[systemd.kill](https://www.freedesktop.org/software/systemd/man/252/systemd.kill.html).
Installed version/man and actual user-manager observations govern the local run;
latest online documentation is not proof that an installed feature exists.
