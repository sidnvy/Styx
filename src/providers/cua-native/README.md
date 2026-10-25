# Pinned native Cua once-write adapter

This is a bounded patch to mature Cua Driver 0.36.0, not a replacement desktop
engine. The upstream commit, original Git blobs and byte hashes, patched hashes,
archive hash, lock hash, toolchain and release command are fixed in source.json.
Use a separate build directory. Verify every original file hash, apply the patch
with zero fuzz at the upstream repository root, then verify every final hash.
Build in libs/cua-driver/rust using the locked features/arguments in source.json.
Never alter an installed or previously signed worker release in place.

The standard native tools remain available. Two private AX tools and a connection-bound native drain control
are added; the Styx public 38-tool/Computer10 schema is unchanged. On Linux, runtime accepts
the exact original 64-tool catalog for reads and requires the exact 66-tool
catalog for this once-write path. macOS and Windows validate the exact frozen
ten-tool projection plus the private pair when present; a partial pair is rejected. A new independently signed worker closure is
required before deployment. Source/build success alone is not GUI acceptance.

The Linux private route retains the original transport, full native snapshot
target, AT-SPI connection and unique owner, process birth, exact frame/window
and object path. Its token is consumed before awaiting one SetTextContents call. There is
no ordinal rewalk, Insert/Value/activation fallback or automatic write retry.
ACK means effect unverified; false/error/lost reply after possible send stays
Unknown. Core remains the only owner, grant and operation authority.

The original event loop carries a checked healthy epoch into original cached
snapshot elements. Observed structure/Defunct events invalidate it; subscription
failure, stream error/EOF or overflow permanently fence private writes in that
child. This does not guarantee every app emits every event or an atomic remote
object generation. Unsupported/cross-process targets fail closed. See ADR-031
for the runtime admission, absolute deadline and post-acquisition recheck.

Actual build, signing, native effect and platform results live in immutable
execution receipts; this directory makes no acceptance or deployment claim.

## macOS integration status

The pinned patch also contains the macOS counterpart of the same two private
AX schemas. It retains the original AX objects, window/process identity and
observed invalidation; it consumes the acquired target before one native setter.
It adds no public Computer tools and does not replace the signed App-owned
embedded Cua permission principal. Runtime Host/Gateway composition is integrated,
but complete native builds and installed platform effects remain unverified.

The private Mac session report is schema 2. It retains separately typed per-row
and root lock observations. A unique matching native UID/audit row with explicit
unlocked state remains supported even with other nonmatching rows. A missing
per-row bit is accepted only as a separately labelled kernel-console-security
candidate: exactly one console row, root IOConsoleLocked=false, completed active
login, canonical console UUID and no nonzero lock timestamp. Malformed, locked,
transitioning or ambiguous observations refuse. Requiring root=false narrows the
old per-row path when that root fact is absent; this awaits native qualification.

Native snapshots retain the original root and IOResources ports, registry IDs
and observed four-byte IOConsoleUsersSeed. Changed or unavailable source facts
invalidate the original target. Runtime carries this stamp in its existing
source identity, so changes fence the source and invalidate the Core session's
old targets. Neither equal reads nor the seed provide an atomic action fence or
prove that every unobserved transition can be detected.

A read-only pho observation found an active console with a missing per-row bit;
that alone does not qualify the candidate. Required real-device verification is
lock/unlock with an unconsumed old target, fresh-target recovery, permission
loss, and rejection during transitions. The native session module has passed a
Darwin-target typecheck, and pure registry-policy fixtures pass. The full native
AX/platform build, GUI effects and this lock qualification remain NOT RUN.

The original proxy control connection can request native transport drain. Its
terminal admission fence waits for the original blocking work and retained
session-cleanup task. Timeout or lost reply remains unknown. macOS overlay
cleanup acknowledges removal consumption and the AppKit layer update, not
physical display presentation. No business operation is automatically retried.

The transport change has passed a real Linux Unix-socket/SDK failure scenario.
The complete macOS AX/session/overlay closure has NOT been compiled or accepted
on a Mac. Linux evidence cannot satisfy that gate. A new signed worker and native
permission, target-invalidation, effect and cleanup scenarios are required.

The existing same-UID UDS protocol also has a read-only, strict-schema private
observation method for the original embedded daemon. It reports actual process
and parent births, native UID/audit/console identity, TCC probes and separately
typed per-session/global lock facts. Descriptor booleans grant no authority.
The daemon retains its original bounded reader task through connection loss and
joins it during shutdown before SDK teardown. These observations do not create
a Core session or grant. The Rust Host consumer requires the matched schema-2
worker and preserves the labelled observation boundary; lock evidence is never
a substitute for TCC, device capability approval or Core authorization.

## Windows integration status

The patch includes retained UIA objects on an original MTA thread, strict raw-tree
traversal, token/session/desktop binding, and single-consumption ValuePattern
writes to eligible Edit controls. Failed or lost setter replies remain Unknown;
there is no keyboard, focus, or alternate setter fallback. Raw traversal requires
S_OK; another HRESULT cannot prove complete enumeration or ancestry.

Snapshot retirement invalidates and takes references under the slot lock, then
releases and joins them outside that lock. Private tool synchronous stages run on
the blocking pool. The original MTA join can still wait on COM: a capture timeout
is not a cleanup receipt. The direct worker's original Job remains the physical
shutdown boundary; an async waiter disappearing does not prove cancellation.

Windows runtime wiring is integrated, but private once-write admission remains
disabled pending native build and effect verification. A Linux build of the
combined sources does not compile the Windows platform module or prove UIA.
