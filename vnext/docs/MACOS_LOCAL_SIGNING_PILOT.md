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

A user retry from an SSH terminal returned the same signing error. Read-only
follow-up found an existing `pier` UID501 Aqua console login and the normal
`login.keychain-db` default user keychain. The public code-signing certificate
chain verified successfully, using local certificates and offline cached
revocation information, through WWDRG3 to Apple Root CA. Its validity covers
the test date. This rules out a missing local intermediate or expired leaf in
that evaluation; it does not establish fresh online revocation status.

In SSH, reading keychain settings returned `User interaction is not allowed.`
That is evidence that this session cannot interact with the keychain, rather
than proof that the keychain is locked or that a particular private-key ACL
is wrong. No private key was inspected or used by these diagnostic commands.
The next meaningful attempt requires physical Mac desktop access or Screen
Sharing into the existing `pier` graphical session: open Terminal **on that Mac
desktop**, then run the command above. A terminal connected by SSH is still the
same remote security context. The user handles any OS key-use approval dialog.
If the graphical attempt also fails without a dialog, stop and inspect the
login keychain's visible state and this certificate's associated private-key
Access Control in Keychain Access; do not blindly retry or automatically
change permissions. This pilot does not require a new certificate or paid
membership to diagnose the existing local key.
