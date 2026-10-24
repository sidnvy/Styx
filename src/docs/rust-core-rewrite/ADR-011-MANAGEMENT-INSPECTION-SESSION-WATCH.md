# ADR-011 · Management intent inspection and isolated Linux session watch

Status: implemented development checkpoint. Focused Core/contract, actual Linux
protected-file import, independent actual CLI role/read-only batch and four owned
watcher fault scenes passed. A complete frozen integration gate is a separate
receipt. This is not completed R20/R21, authorized Desktop, migration or release.

## Management authority

Core management/deployment.rs owns role derivation and explicit component intent;
management/plan.rs produces deterministic dependencies without authorizing them.
Manager, desired run and service autostart each have Unspecified. An unspecified
component emits only original-binding/ownership review, never installation,
start, stop, re-pair or enable. A joined Host produces no local Gateway, ingress,
plugin or tunnel. Stopped intent produces no runtime/identity preparation or
start, and places persistence before stop. App login preferences are separate.
No plan or observed service success grants execution authority.

Runtime management::inspect_deployment and CLI plan share one protected reader.
It retains both original RawFile values and hashes, including whitespace, unknown
fields and integers beyond IEEE754/u128. Serde skips unknown values rather than
round-tripping through Value/f64. Mode, schemas and exact state.configSha256 are
checked. Known recorded steps preserve awaiting_approval; running is projected as
uncertain with replay_authorized=false. At most64 steps/id128 are retained, keeping
prefix dependencies/output bounded. Two reader permits stay inside the blocking
closure until actual read work ends, even if a waiter drops.

This is deliberately labeled a known-field projection, not full legacy config,
signed-payload, credential, active-owner or migration validation. Unknown metadata
is never executable. A future apply MUST NOT reuse this reader/step success as
credential or execution authority. It needs the C07 single writer, native owner
quiescence and durable transaction port. The raw files are reobserved before return;
that detects per-file change, not an atomic snapshot against legacy JS. Existing
advance/background/capability/foreground guards are reported, never removed or
stolen. The Rust flock does not automatically exclude a legacy advance.lock.
No configuration, grant, identity, pairing or service mutation is implemented by
this entry point. Generic transaction/update/recovery/rollback remain required.

## Linux facts and stream ownership

The private platform/linux/watch module uses official zbus streams. It subscribes
to logind unique-owner signals and bus ownership changes before collecting the
initial double-sampled snapshot. Signals invalidate old login-instance keys before
reconciliation; locking and unlocking both invalidate. Thirty-second bounded
reconciliation complements events, with100ms coalescing and1.8s collection deadlines.
Login-owner change, stream EOF, errors and overflow fence the entire source.
Candidates keep Unknown Agent/compositor association. No HostAuthority registration,
Desktop attach, Window/Capture/Input or Cua dispatch is added.

The public session_probe/watch parent launches the pinned same image in its existing
constrained child boundary. It uses actual UID/fixed system bus, fresh parent-minted
stream instance and exact child process birth. Eight64KiB events, strict sequence,
unique-owner and complete candidate validation prevent silent replacement without
invalidation. Any terminal report/worker EOF fences the caller's old association;
a missing final event never becomes proof of delivery. Waiter drop cancels the owned
job, which retains image pin/slot/Child until actual wait. No worker auto-restart.
The current cumulative CPU2/3s child limit is a bounded diagnostic slice, not proof
of unlimited persistent monitoring. Persistent service/Host composition still needs
its own budget/lifecycle and real logout/compositor proof. The diagnostic budget is
not advertised as a reservation in the Host's shared queued-byte allocator.

## Output failure discovered by real scenarios

The new CLI doctor --desktop-sessions --watch uses a distinct Linux stdout open-file
description and official Tokio AsyncFd. It never changes the shell-shared flags;
O_NOCTTY prevents acquiring a controlling terminal. Every frame is bounded to64KiB
and a write waiter has250ms. ERROR readiness detects an idle pipe reader disappearing,
without waiting for the next logind event or reading terminal keyboard input.
Partial/cancelled frames cannot be continued with another JSON frame. On output
failure the CLI first cancels/reaps its watcher, then finishes output resources and
returns curated output_unavailable. Regular files use official Tokio file I/O:
flush/finish await submitted work, without claiming hard cancellation or fsync
durability. Append/current offset are preserved in the independent description.
Unpollable/unsupported stdout types are refused before starting a watcher.

Independent native batch2 passed normal CLI cancellation, consumer close after a
verified worker start, exact pidfd worker SIGKILL and a prefilled unread pipe.
The last completed around0.29s; all8 sampled original CLI/worker birth identities
were gone. First batch's consumer-close failure is retained: normal cancellation
passed, but idle output closure was detected only on a later write. It was fixed
with ERROR readiness, not a relaxed deadline. Sampling is not enumeration of every
possible short-lived task. Regular-file pending-I/O faults, real lock/logout,
HostRegistry/Agent authentication, compositor/Cua and Mac/Windows are NOT TESTED.

## Dependency and verification boundary

No registry package/version/checksum changed. CLI reuses pinned nix on Linux and
enables existing Tokio fs. The workspace lock lists the new direct CLI dependency.
Original compile/lint/locked-preflight failures remain external. Independent CLI
Plan read-only negatives preserve original raw bytes, explicit App login false,
Unspecified manager/run, opaque legacy lock and awaiting approval. No UI API parity,
write/commit/reply-loss recovery, signed candidate or installed runtime is accepted.
