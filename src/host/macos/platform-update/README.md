# macOS platform update prototype

This directory is an isolated Sparkle feasibility probe, not a product updater. No Styx Core, Host, existing App, TCC permission, service, certificate trust, or production signing key is changed.

## Native result, 2026-10-22

On PilotMac (macOS 26.6, arm64), the official Sparkle 2.10.0 framework performed a real update from fixture App version 1 to version 2. Styx Computer Use clicked Sparkle's standard **Install Update** and **Install and Relaunch** controls. The old App's `applicationShouldTerminate` returned `terminateLater`; its asynchronous MainActor check replied successfully. Sparkle replaced the App and launched version 2 at the same path. The old PID was 66198; the new PID was 67021. Independent lifecycle JSON, installed Info.plist, strict code-signature verification, and a fresh native screenshot/AX read agreed.

`acceptance-20261022.json` records the exact observations. The probe App and its loopback server were stopped afterward. Production Styx stayed on rc5, with its App/Core PIDs unchanged and all 23 preserved identity/credential hashes matching.

The fixture uses ad-hoc App signatures and an Ed25519 archive key generated **only in a private test file**. It does not use Keychain. This tests the real Sparkle download/verification/install/relaunch mechanism, not Developer ID/notarization, public HTTPS distribution, or Styx Host migration.

## Reproduce without touching production

1. Download the official `Sparkle-2.10.0.tar.xz` release. Expected SHA256: `c2bf58aa8387266ac179357b1415d6f2635f044da8be41042af32425dae6da0c`.
2. Create a new private directory under `/private/tmp/styx-sparkle-…`, extract the archive there, and copy `Probe.swift`, `FixtureKey.swift`, and `build-probe.py` there. Do not reuse a previous `probe` directory.
3. Run `python3 build-probe.py /private/tmp/styx-sparkle-YOUR-RUN`. It compiles two tiny App bundles, signs the archive with an isolated fixture seed, invokes official `generate_appcast`, and starts a feed server bound only to loopback. The private key sits outside the served directory. `probe/build-receipt.json` records the server PID and paths.
4. Open the exact `probe/installed/StyxSparkleProbe.app`, observe version 1, click Check for Updates, Install Update, then Install and Relaunch. Observe version 2 independently. Read `probe/observations/events.jsonl` and verify the installed bundle with `codesign --verify --deep --strict`.
5. Run `swift finish-probe.swift FULL-PATH-TO-PROBE-EXECUTABLE` to request normal fixture exit. Confirm its PID has gone. Stop only the server PID whose command still names this run's feed directory. Keep the receipt; never publish the fixture private key.

The loopback HTTP exception is fixture-only. Shipping feeds must use HTTPS. No framework binaries or generated keys are committed here.

## Minimal product connection proposed

**Platform owner:** retain a single `SPUStandardUpdaterController`; use its standard UI and menu action. Sparkle owns archive download, archive validation, App replacement and relaunch. Remove the custom `.app` replacement workflow rather than wrapping it in another updater. The existing `StyxUpdater` is only a possible temporary Host transaction runner; it must not compete with Sparkle for App replacement.

**Quit boundary:** use the existing `NSApplicationDelegate.applicationShouldTerminate` as the common gate for ordinary Quit and Sparkle-triggered termination. Its async `prepareToQuit` calls the authenticated `/api/app/quit`, which already performs `prepareDeploymentWorkAdmission` / `commitDeploymentWorkAdmission` and App login-recovery suspension. Return `terminateLater`, then reply true only after the existing lifecycle response proves success. Work still running or unknown means reply false and visible retry feedback. Do not call `NSApp.terminate` synchronously inside the MainActor update Task; let Sparkle request termination. Commit 6b4cf96 provides the existing explicit-quit scheduling fix.

`SPUUpdaterDelegate.updater(_:shouldPostponeRelaunchForUpdate:untilInvokingBlock:)` can delay installation while doing preparatory work, but is **not the sole work guard**: its documented coverage excludes some update paths. `willInstallUpdate` is an observation callback, not an async migration transaction hook. Release any acquired fence when an update is cancelled or aborted. Do not use an install callback to kill running tasks.

**Host boundary:** Sparkle cannot migrate `deployment.json`, Host active pointers, publisher pins, identities, or pairing. Existing usable APIs are `inspectHostPayloadCandidate`, `readHostPayloadHandoff`, `prepareHostPayloadHandoff`, `executeHostPayloadHandoff`, migration plan/apply/rollback, and Core `advance(..., 'host.doctor')`. Existing native absence, signature continuity, immutable candidate binding, admission, byte-preservation and rollback checks stay in force.

**Missing narrow product connection:** before `server.mjs` calls `resumeNativeStartup` / starts any foreground Host on the first launch of an updated App, inspect the installed signed bundle versus the deployed Host. A matching bundle continues normally. An admitted mismatch must automatically run the existing handoff/doctor flow under the already accepted application update, without a second user-facing “sync Host” button. Current native absence correctly refuses a running registered App, so the minimal reuse requires an automatic early-start handoff: stage the verified transaction runner before starting Host, normally exit this bootstrap App/Core, execute the offline migration, run doctor, then reopen. This may involve an internal second launch, but remains one user update operation. It is not implemented or accepted by this probe. A startup-only Core interface must expose reconciling/ready/recovery-required and must not auto-retry a partial journal or claim ready from version equality. Failure must return to the existing explicit retry/cancel/rollback UI, without re-pairing or resetting settings.

The startup policy must cover both Sparkle updates and a user manually replacing the signed App. Gate it on the registered canonical path, stable signing certificate and verified bundled artifacts, never on an arbitrary download path or untrusted version string. Root owns this shared Core integration; this directory adds no alternate role/configuration store.

**Build identity:** current rc5/rc7 product Apps both expose `CFBundleVersion=0.3.0`, preventing Sparkle from distinguishing those builds. Add an explicit monotonically increasing release build number to the Mac builder (for example `1008`), retain `CFBundleShortVersionString=0.3.0`, and retain the full Host release semver separately. One CI release allocates one build number; rebuilds must not silently publish different bytes under it. Generate the appcast from the actual signed App metadata. Do not derive ordering from ad-hoc prerelease parsing or compare only marketing versions.

## Preconditions before production integration

- Decide and provision a persistent **Sparkle archive signing key**; the fixture key is never promoted. Keep it distinct from the Host publisher key.
- Configure a maintained HTTPS appcast/archive location and release retention policy.
- Use Developer ID/notarization for public distribution. Current local development signing is only local acceptance evidence. Follow Sparkle's library-validation and nested-helper signing requirements; do not weaken production entitlements to make a probe pass.
- Run the combined real Styx update → guarded quit → automatic Host reconcile → doctor → reopen flow. This isolated result does not pass that product acceptance gate.

Official references: [Sparkle setup, archive signing and build versions](https://sparkle-project.org/documentation/), [programmatic standard updater](https://sparkle-project.org/documentation/programmatic-setup/), [updater delegate hooks and limitations](https://sparkle-project.org/documentation/api-reference/Protocols/SPUUpdaterDelegate.html), [official 2.10.0 release](https://github.com/sparkle-project/Sparkle/releases/tag/2.10.0).
