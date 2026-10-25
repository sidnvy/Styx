# Pinned native Cua once-write adapter

This is a bounded patch to mature Cua Driver 0.36.0, not a replacement desktop
engine. The upstream commit, original Git blobs and byte hashes, patched hashes,
archive hash, lock hash, toolchain and release command are fixed in source.json.
Use a separate build directory. Verify every original file hash, apply the patch
with zero fuzz at the upstream repository root, then verify every final hash.
Build in libs/cua-driver/rust using the locked features/arguments in source.json.
Never alter an installed or previously signed worker release in place.

The standard native tools remain available. Only two private owned-stdio tools
are added; the Styx public 38-tool/Computer10 schema is unchanged. Runtime accepts
the exact original 64-tool catalog for reads and requires the exact 66-tool
catalog for this once-write path. A new independently signed worker closure is
required before deployment. Source/build success alone is not GUI acceptance.

The private route retains the original transport, full native snapshot target,
AT-SPI connection and unique owner, process birth, exact frame/window and object
path. Its token is consumed before awaiting one SetTextContents call. There is
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
