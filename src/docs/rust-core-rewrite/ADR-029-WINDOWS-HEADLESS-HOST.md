# ADR-029 · Windows protected headless Host

2026-10-25. Incremental Windows x64 execution port. This does not add a
management authority, desktop dependency, public MCP tool or persistent service.

## Boundary

Keep the shared Host TLS/WSS connection, Codex stdio RPC, Core owner/grant/operation
ledger and explicit cleanup. The Windows adapter supplies protected filesystem
observations, distinct configuration/execution leases and native child ownership.
Use the already locked official `windows-sys` 0.61.2 binding, standard-library owned
handles, locks and pipes, and Tokio's existing Windows pipe adapter. No new crypto,
wire protocol, executor, command interpreter or global developer environment.

The initial protected profile reader consumes original schema1 signed worker
bytes and the original identity, token, CA and publisher pin. Windows fixed worker
paths end in `.exe`; neither a mutable executable locator nor an Authenticode
claim substitutes for publisher signature and whole signed-closure verification.
The Rust Host runs independently of Node management code. Original JS Core is an
explicit test-only enrollment oracle until Windows native management migration is
implemented. Windows writable journals, native migration and Gateway execution
remain unsupported by this decision; read/lease support never authorizes them.

## Filesystem and local identity

Only local drive-absolute paths are accepted. Reject traversal, UNC/device paths,
reparse points, alternate streams, aliased regular files and ambiguous DOS names.
Retain directory ancestors without delete sharing and regular inputs without
write/delete sharing. Revalidate handle identity, raw hashes, bounds and DACLs;
this is a cooperating current-user boundary, not isolation against a fully
compromised account or administrator. Current-user ownership is required; effective
allow ACEs are restricted to that user, SYSTEM and Administrators. Existing ACLs
are inspected and never repaired silently. Explicit new lease files have private
DACLs; the two kernel lock resources remain independent.

Windows process identity uses PID, kernel creation FILETIME and token SID. Original
process handles, not a later PID lookup, own execution and wait. These observations
are not a cross-boot Windows persistent claim/migration protocol.

## Native execution and recovery

Create an unnamed, non-inherited, kill-on-close Job without breakaway permission.
Create the native process suspended with `PROC_THREAD_ATTRIBUTE_JOB_LIST` and an
explicit standard-handle list. Creation-time Job membership avoids the user-space
create/assign crash interval. Keep the original primary-thread handle, process
handle, image pin and I/O reservation. Verify the exact loaded image file identity,
full digest, kernel birth/SID and Job membership before one resume. Failure owns and
settles the original child; it never falls back to an ordinary pathname spawn.

Only the native adapter uses narrowly scoped OS FFI. The fixed exec-server command
uses a separately specified application path; business commands continue through
upstream Codex. Worker environment is explicit: original CODEX_HOME plus bounded
OS/token-derived Windows/user directories and system search paths. SSH's inherited
PATH or arbitrary host.json environment keys do not become trusted configuration.

Root process wait, Job ActiveProcesses zero, RPC drain and Host job joins are
separate facts. Drop or a termination acknowledgement is not cleanup success.
Cancellation retains the original ownership and reservation while cleanup runs.
Unknown outcomes remain unknown and input/start operations are never replayed.
Gateway transport loss does not respawn the native executor or change its owner.

## Acceptance and limitations

Evidence belongs under `r35-windows-headless`; source design does not establish a
PASS. Required native checks include DACL/reparse/alias/stream/bounds refusals,
independent kernel lock exclusion, birth mismatch, PE pinning, suspended verification,
actual process wait and empty Job. The cross-machine journey must run the ordinary
Rust CLI, original native Codex and real TLS/WSS/MCP, inspect an independent nonce
effect, reject a foreign owner and settle the original process tree.

An isolated original-Core Windows fixture may archive only its own never-installed
service descriptor after original-step and task/process reconciliation. Preserve
its exact bytes and identity in evidence. This is explicit fixture preparation,
not production migration or normal complete onboarding. Existing installed service
ownership records remain intact and cause ordinary Host admission to refuse.

An owned SSH reverse loopback tunnel can provide initial cross-machine transport
without expanding the current Gateway listener contract. Such evidence is not a
claim of direct LAN ingress, Windows service restart/login recovery, desktop access,
full three-platform packaging, production identity migration or account acceptance.
