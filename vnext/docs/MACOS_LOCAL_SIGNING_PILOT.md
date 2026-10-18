# Local development signing pilot

Current result: `/Applications/Styx.app` signature/identity, LaunchServices,
normal/crash cleanup, both user-granted permissions and owned-window local GUI
acceptance PASS. Screenshot, AX observation, observed click, independent readback
and fixture cleanup passed. Gateway integration and external distribution remain
separate gates. Historical signing commands below are not current instructions.

## Historical signing attempts

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

## Successful graphical signing and corrected final verification

The user subsequently signed Cua and Styx successfully in the Mac graphical
session. The final verifier exposed a separate product bug: `codesign -R`
treats a plain argument as a requirement filename. Both development and
Developer ID plans now prefix inline expressions with `=`. Verification-only
completion performed deep/strict checks and the exact Apple anchor, app bundle
identifier, and OU requirement successfully, without re-signing or using keys.
The original blocked attempts above remain historical evidence.

The actual signed app then launched through LaunchServices. Cua's read-only
health check attributed it to parent application `app.styx.host`, matching the
owned app PID. Permission inspection, with prompting and capture probes disabled,
reported the host's Accessibility and Screen Recording grants both false.
Native GUI acceptance is therefore BLOCKED on human grants for this signed app.
No screenshot, AX operation, permission request, or automatic grant occurred.
Normal owned app termination removed its descriptor and socket. The evidence
is `evidence/macos-signed-app-20261019.json`. External Developer ID distribution
and notarization remain NOT RUN for this local Apple Development artifact.

A native macOS regression now ad-hoc signs an isolated copy of `/usr/bin/true`,
accepts its correct inline identifier requirement, and rejects a wrong one.
This uses no private key. Native packaging tests:8PASS,1platformskip. The first
run's matcher expected different rejection wording; the actual OS correctly
rejected the wrong requirement and the diagnostic matcher was corrected.

A further bounded signed-app lifecycle check killed only the verified owned
Styx PID with SIGKILL. Its exact Cua child exited via parent-liveness EOF and
removed the socket. LaunchServices then started a fresh app/daemon generation;
normal termination again removed descriptor/socket. All three observations
passed (`evidence/macos-signed-app-crash-20261019.json`). No GUI action or
interrupted-action replay was tested.

## Stable local installation

After the user reported difficulty selecting the temporary app in Privacy &
Security, the existing signed app was installed to `/Applications/Styx.app`.
The destination was absent and writable; exclusive directory creation prevented
an overwrite. The exact owned temporary app was gracefully stopped first.
All7bundle files were identical after `ditto`; deep/strict and exact
Apple-anchor/app-identifier/team-OU checks passed without re-signing. LaunchServices
started the installed app and Cua health confirmed its exact installed parent
application. Prompt-disabled permission readback still reported both grants
false. This establishes a stable selection path; it does not prove the temporary
path was the cause of the user's selection issue.

The installed app is intentionally retained and running for the user. Select
`/Applications/Styx.app` in Finder or Privacy & Security. It is a menu-bar app:
click the text **Styx** in the top-right macOS menu bar, then **Request macOS
permissions…** to initiate the local OS flow. Permission requests and grant
changes remain the user's actions. No private key, signature or TCC setting was
changed during installation. Evidence: `evidence/macos-stable-install-20261019.json`.

## Owned GUI acceptance preparation

After the user's grant changes, Screen Recording readback became true but
Accessibility remained false, including after one exact installed-app graceful
restart. GUI acceptance was not started. No window was captured or acted on.

`host/macos/OwnedGuiFixture.swift` is a separate test-only AppKit window with a
unique title/PID, one button, private independent JSON readback and35second
expiration. It compiled natively with warnings-as-errors. It is never bundled
into the product and uses no signing identity. The opt-in
`host/macos/owned-gui-acceptance.py` checks actual host grants before launching
it, scopes every window query/capture/action to its exact PID/title, and removes
its private screenshot/readback and fixture process in cleanup. It uses the
installed app's existing embedded Cua socket, not a separate Cua daemon; it does
not claim Gateway or end-to-end native Exec integration. It uses the pinned
CLI's inspected `describe` schemas and a fixed per-run session for snapshot
tokens. Actual GUI results remain NOT RUN until both host grants read back true.

The prepared native binary and script are in the private marked scratch. When
both grants are ready, the explicit opt-in command on piermini is:

```sh
STYX_MAC_OWNED_GUI=1 /usr/bin/python3 /private/tmp/styx-local-dev-20261019-0743bc4c/owned-gui-acceptance.py /private/tmp/styx-local-dev-20261019-0743bc4c
```

A fresh permission readback at02:44:22 after the user's02:43:57 app restart still
showed AXfalse/ScreenRecordingtrue. Narrow read-only `com.apple.TCC` logs for
`app.styx.host` identify the actual blocker: **Failed to match existing code
requirement … service kTCCServiceAccessibility**. The logged existing requirement
was a CDHash `553904db1f5ee2a15a3864641253d6d8f902aa01`; the installed signed
app's CDHash is `2907afe8b13cba6363b38d39b74dbec941fe22f6`, with an Apple
Development designated requirement. The old hash's origin was not established.
Both responsible app and child were attributed to the installed app and UID501.
The appropriate human repair is to remove the existing Styx row from
Accessibility using its minus button, then add `/Applications/Styx.app`, enable
that fresh row, and quit/reopen Styx. Screen Recording already passes and need
not be changed. No TCC database access, reset, permission mutation or GUI fixture
launch was performed. Exact diagnostic evidence is retained in
`evidence/macos-accessibility-requirement-mismatch-20261019.json`.

## Actual owned-window GUI PASS

After the user removed the stale Accessibility entry, re-added the installed
app and restarted it, the actual app owner29842/Cua29844 reported both grants
true. Bounded GUI acceptance then passed through the installed Styx embedded
Cua socket: screenshot840×384, six AX elements, an observed exact-button token
click, fixture exit0 and independent private JSON readback. Capture/click were
277ms after fixture setup, with the fixture still alive. The fixture, private
screenshot and independent readback were cleaned; only a screenshot hash is
retained. The installed app remains running for the user. This is native local
embedded GUI evidence; Gateway/Exec integration and distribution notarization
are separate gates.

Initial fresh-fixture attempts failed honestly: screenshot and AX observation
passed, but action returned `tool_invocation_failed` with
`AXUIElementPerformAction(AXPress) returned -25204`. The first harness did not
retain the exact error; later instrumentation captured it. Changing to the
official persistent MCP SDK alone did not resolve it, disproving transport as
an established fix. The fixture's button handler immediately terminated its
own AX responder. Deferring termination one second after the independent write
allowed the AX call to finish; a new fixture then passed. The fixture also uses
a single exclusive write option instead of the ambiguous atomic/no-overwrite
combination. Every prior fixture was cleaned before a distinct fresh test; no
uncertain action was replayed. Product app code, signatures and TCC settings
were not changed. Exact PASS and initial failure evidence are retained in
`evidence/macos-owned-gui-20261019.json` and
`evidence/macos-owned-gui-initial-failures-20261019.json`.
