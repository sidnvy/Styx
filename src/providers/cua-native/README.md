# Pinned native Cua once-write adapter

This is a bounded patch to mature Cua Driver 0.36.0, not a replacement desktop
engine. The upstream commit, original Git blobs and byte hashes, patched hashes,
archive hash, lock hash, toolchain and release command are fixed in source.json.
Use a separate build directory. Verify every original file hash, apply the patch
with zero fuzz at the upstream repository root, then verify every final hash.
Build in libs/cua-driver/rust using the locked features/arguments in source.json.
Never alter an installed or previously signed worker release in place.

The standard native tools remain available. Two private AX tools and a connection-bound native drain control
are added; the Styx public 38-tool/Computer10 schema is unchanged. Runtime accepts
the exact original 64-tool catalog for reads and requires the exact 66-tool
catalog for this once-write path. A new independently signed worker closure is
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
embedded Cua permission principal. Runtime Host integration is still incomplete.

The private Mac session reader requires a unique matching native UID/audit
session, on-console/login state, and an explicit unlocked boolean from Apple's
private IOConsoleUsers schema. Missing or malformed facts fail closed. This is
an observation, not an atomic lock/action fence; availability on a real unlocked
Mac must be measured before accepting the adapter. A read-only check on pho
(macOS 26.6.2) found an active completed console session with no per-session
lock field. This version therefore refuses that observation as Unknown; the
Mac positive path is not yet usable or accepted. The separately observed root
IOConsoleLocked=false is not silently substituted for the missing field.

The original proxy control connection can request native transport drain. Its
terminal admission fence waits for the original blocking work and retained
session-cleanup task. Timeout or lost reply remains unknown. macOS overlay
cleanup acknowledges removal consumption and the AppKit layer update, not
physical display presentation. No business operation is automatically retried.

The transport change has passed a real Linux Unix-socket/SDK failure scenario.
The added macOS AX/session/overlay code has NOT been compiled or accepted on a
Mac. Linux evidence cannot satisfy that gate. A new signed worker and native
permission, target-invalidation, effect and cleanup scenarios are required.

The existing same-UID UDS protocol also has a read-only, strict-schema private
observation method for the original embedded daemon. It reports actual process
and parent births, native UID/audit/console identity, TCC probes and separately
typed per-session/global lock facts. Descriptor booleans grant no authority.
The daemon retains its original bounded reader task through connection loss and
joins it during shutdown before SDK teardown. These observations do not create
a Core session or grant, and do not resolve the missing lock-field limitation.
The Rust Host connection consumer is still an external integration draft.
