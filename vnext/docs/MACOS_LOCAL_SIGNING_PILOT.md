# Local development signing pilot

This pilot uses the existing Apple Development certificate for a local owned
Styx app. It does not establish Developer ID distribution or notarization.
Native compilation and plist validation passed. The first signing operation on
the nested Cua binary returned `errSecInternalComponent`. No signing retry,
keychain unlock, ACL change, key export, app launch, or TCC request followed.
The initial builder also exposed a `/tmp` canonical-path entry bug: it exited
zero without building. Commit259448f fixes that separately and retains the
initial failure in the evidence receipt.

The prepared app is retained in the private marked scratch directory
`/private/tmp/styx-local-dev-20261019-0743bc4c` on piermini. From that Mac user's
interactive Terminal, review the staged helper and execute:

```sh
/opt/homebrew/bin/node /private/tmp/styx-local-dev-20261019-0743bc4c/vnext/host/finish-macos-local-signing.mjs /private/tmp/styx-local-dev-20261019-0743bc4c/build-config.json
```

The OS may request approval to use the existing private key. The script does
not approve that prompt or modify keychain settings. It signs the nested driver
and app, then verifies deep/strict signatures and the certificate OU team
`MGPKJXPZX4`. The `7MPHNTHAJT` suffix in the certificate's display name is not
its team OU. Only successful verification produces the private external receipt
`Styx.app.local-signing.json`. A failure stops immediately; inspect the OS error
without blindly retrying. Local signing does not prove TCC permissions or GUI
acceptance. Those remain separate gates after signature verification.

The staged helper SHA256 is
`0971f11b4e080c4ed7a3ca7207dde5bc59a30db5461286e5d4beafc3778094d1`.
The scratch directory is mode0700; config and ownership marker are mode0600.
No existing personal app, service, or permission was modified.

Separate native Exec acceptance passed on macOS using the official checksum-pinned
Codex0.163.0 arm64 archive and Node25.6.1. The isolated adapter exercised pipe
stdout/stderr and exit7, PTY stdin/readback, exact `unknown_session` cross-owner
refusal, confirmed cleanup followed by OS PID absence, and fresh transport
reconnection. Its private execution home was removed. The sanitized receipt is
`evidence/macos-native-exec-20261019.json`. This proves the direct native adapter,
not the signed app, HTTP gateway, TCC or GUI. Only public runtime/source material
and the signing-ready owned app remain in the marked scratch directory.
