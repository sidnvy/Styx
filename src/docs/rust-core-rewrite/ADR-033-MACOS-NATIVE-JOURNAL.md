# ADR-033: Darwin persistence under the existing native Core authority

Status: implementation in progress; actual capability probe passed, native
contract/Host/runtime acceptance remains unproven until exact-source execution.

## Decision and compatibility

Reuse the original C07 coordinator, canonical parser, shared configuration owner,
C08 Mach-O verifier and native join protocol. macOS receives its own tagged
NativeRootIdentity::Macos {device,inode,uid}; do not encode Darwin objects as
Linux identities. The wire Host platform is still `darwin`. These are observed
DATA identities, not writer, grant, migration or execution capabilities.

This is an additive platform identity variant, with the same marker/state schemas
and unchanged existing Linux/Windows encoding. An older reader that does not
recognize `macos` must reject it; no alias/fallback is permitted. Existing installed
profiles, publisher pins, device keys and App/TCC ownership are not rewritten.
The slice creates/reopens only explicitly fresh native profiles. Legacy cutover,
credential retirement and migration scanners remain Linux-only; unrecognized
families stay retained orphans and prevent native completion/recovery proof.

## OS adapter boundary

Reuse mature nix/std/libc APIs and existing Darwin no-follow FD traversal, owner,
mode, empty-ACL, single-link, file-ID and original process/writer checks. Exclusive
fresh/fixed creation never adopts an existing name or repairs ACLs. Namespace
read/scan/publication remains bounded under original root/writer/namespace pins.
Immutable publication uses Darwin renameatx_np(RENAME_EXCL) through one small ABI
shim; cooperative conditional replacement uses renameat after exact expected
canonical bytes/observation checks. It is not hostile-same-user kernel CAS.

Regular file and affected directory barriers use actual fsync followed by
F_FULLFSYNC, with no silent downgrade. The owned pho capability probe
`r41-macos-native/fsync-probe-1/receipt.json` (SHA256
0f0c7c5580da8389b2cc54ff148a4b55ee44af2e982efd48173fdf1eaa7df919)
observed both operations succeed on one regular file and two fresh directories,
with unchanged dev/inode/UID/private mode/empty ACL. All original FDs closed and
SSH actually exited0. This demonstrates API support on that tested filesystem,
not physical power-loss correctness or broad filesystem compatibility. Failure
on another filesystem remains Unknown rather than synthesized durability.

Apple documents the stronger drive-cache flush contract:
https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html
https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html

## Verification boundaries

The native owned-FS batch must exercise actual fresh/no-replace/conflict/orphan,
clock replacement, private/ACL/alias refusal and same-object resync. The shared
Windows/macOS C07 aggregate must exercise exact commit/reopen, foreign/stale
intent refusal and two actual child exits followed by original-chain recovery.
Reusing one common coordinator test avoids divergent platform recovery specs.

Those store results do not prove request/approval/claim/self or ordinary Host/Exec
startup, which require a matched signed runtime candidate. Nor do they prove
App/TCC, existing-identity migration, Browser/Computer readiness, login/quit/boot,
rollback, ARM64 physical behavior, package signing, installation or deployment.
