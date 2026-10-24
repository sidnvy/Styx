# ADR-007 · Host-owned session facts and isolated Linux discovery

Status: incremental implementation decision, not R14/R15 completion or native acceptance.

The existing Host admission mutex owns the operation ledger, Exec policy and the
bounded Core session registry. `HostAuthority` is the mutation port; ordinary
Host handles can inspect facts. No separate session policy service or second
operation ledger is introduced. Core registration remains an attestation port
for a trusted native adapter, not a parser for remote statements of authority.
Linux OS candidates with unknown agent/compositor association are never registered.

Each registry construction consumes fresh OS entropy, even for the same public
HostGeneration. Session generations and observation identifiers include that
incarnation; reusing counters after a reconstruction cannot make old bindings
valid. Provider timestamps come from the trusted Host monotonic clock. Read and
selection views reject expired observations. A healthy independent provider can
remain useful when another is unavailable. Full lifecycle changes invalidate
session/provider resources; targeted provider changes do not grant unrelated
capabilities.

Revoked identities are bounded process-local tombstones. Ordinary rediscovery,
alias IDs, state changes and forgetting cannot reactivate them. Only terminated
entries can be forgotten. Durable revocation across a Host restart and explicit
reauthorization are still required; this in-memory implementation is not their
substitute. Registry limits are 32 sessions, 16 providers per session, 256 retained
events and 1MiB logical metadata. They do not describe OS process RSS or Host queued
I/O. Cursor loss requires a new snapshot. No live entry is silently evicted.

Exec remains independent of desktop availability. The Codex coordinator refuses
non-Exec/session-bearing contexts and desktop policy projections; it does not use
session registration as Gateway approval. Future desktop dispatch must combine a
fresh session projection and real configured/grant/local-policy facts under the
same admission lock. A projection copied across an await is not a dispatch permit.
Windows sessions remain unsupported until actual SID/token observation is wired;
that condition does not disable Exec. Linux/macOS UID bootstrap does not prove
login/compositor/native-agent association or OS desktop authorization.

Linux candidate discovery uses the mature zbus typed system-login1 API. Only the
fixed kernel-authenticated system bus and a root-owned unique login1 service are
accepted. Environment variables, caller socket paths and caller UIDs do not select
the authority. Candidate facts are rechecked for changes and expose Unknown agent
and compositor association. They are observations, never a Ready desktop.

Independent review found that zbus validates its standard maximum message size
before allocating, but that maximum is 128MiB. Post-decoding Styx field/fact limits
cannot be described as preallocation limits. The pinned SDK has no lower public
receive-size configuration. Reimplementing D-Bus framing or patching the local SDK
would violate the mature-protocol implementation policy.

Consequently the CLI/Host discovery entry uses one owned worker process, with
address-space/data/CPU/descriptor limits applied before Tokio initialization.
The parent pins its actual Linux executable image through an open /proc descriptor,
uses a fixed argument with no UID/socket override, admits only one worker, and
bounds stdout before decoding it. A clean environment carries only a fixed,
non-secret original-parent PID/birth stamp; the worker checks it before and after
installing the safe Linux parent-death signal, so adoption by another process is
not accepted as the original parent. Core dumps are disabled for the worker. Cancellation/timeout/oversize initiates kill and
actual wait; holding a process handle or sending a signal is not a reap receipt.
The permit and image pin remain owned until physical cleanup. The child has no
management mutation or desktop authorization authority. This process boundary
isolates a real SDK allocation/fault boundary; it is not a new daemon or service.

Graceful supervision requires its owning Tokio runtime to remain alive. Forced
runtime/process destruction is not a successful cleanup receipt; a future Host
watcher must also participate in total Host shutdown supervision.

The worker's 512MiB address-space and 96MiB data limits are separate from the
parent's 64KiB output bound. Neither is called a 64KiB wire/RSS limit. An allocation
failure must fail discovery without terminating the parent. Unknown cleanup must
remain explicit, with no replacement worker admitted before real reap. The socket
close result is not a claim that all detached SDK tasks have joined; process exit
provides the worker isolation boundary.

`doctor --desktop-sessions` is read-only OS candidate diagnostics and requires no
profile. It is mutually exclusive with profile diagnostics, and never attaches,
registers, changes grants, starts a desktop, or injects display variables into Exec.
The fixed internal worker mode is not an authorization boundary: invoking it can
only inspect the invoking user's OS facts under tighter process limits.

Still required: event delivery and <=2s bounded reconciliation, actual authenticated
session-agent IPC, login/display/compositor association, platform provider mapping,
dispatch-time generation/permission checks, durable revocation, and real native
lock/logout/compositor/revocation/multiple-session acceptance. Mock and process-local
contract evidence cannot close these native requirements.
