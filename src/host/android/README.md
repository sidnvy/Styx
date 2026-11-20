# Native Android Host

This is the independent Android Styx Host, not the ADB instrumentation controller.
The app runs the shared Rust enrollment and Host protocol through JNI. Kotlin owns
Android service lifetime, protected credential storage and Accessibility APIs.
There is no Android HTTP server, Exec service, Browser runtime, Root or ADB runtime dependency.

## Development build

Use the existing Android SDK (API 36), NDK 29.0.14206865, JDK 21 and Rust
`aarch64-linux-android` target. From the repository root on the Linux workstation:

```bash
ANDROID_HOME=/home/sid/remote-mic-arch/android-sdk \
JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
src/host/android/build.sh
```

The script reuses the repository Cargo target and Gradle cache. Its debug APK is
copied to `~/Developer/Artifacts/Styx/android-host/styx-android-debug.apk`.
This is a development/acceptance APK, not a published Styx release.
For Kotlin-only checks, use `gradlew -p src/host/android --offline :app:compileDebugKotlin`.
APK assembly requires the actual Rust `libstyx_android.so`; it never bundles a stub.
Override `STYX_ANDROID_NATIVE_LIB` when invoking Gradle directly with an existing native build.

## On the phone

Install the APK, enter the existing Gateway address, invitation short code and
phone label, then pair. Start Host runs a visible foreground service, including
while Android control permission is disabled. Enable **Styx Android control** in
system Accessibility settings to allow screen reading and actions. Grant the
notification permission to make the running Host notification visible.
**Stop Host** and the notification's **Stop** action stop the same native Host.
Closing the Activity leaves the foreground Host service running.

After Gateway revocation, use **Forget pairing** in the App, confirm locally,
then pair with a new invitation. Forgetting stops the Host and removes only this
App's protected enrollment; Android permissions and Host settings remain in place.
The old Gateway device record must be revoked separately if it is still active.

An encrypted opaque enrollment blob is stored under the app's no-backup directory.
Its AES-GCM key remains in AndroidKeyStore. No credentials are returned by NativeHost
status or written to logs. The pairing Activity blocks screenshots and recent-apps
previews, and password node text is omitted from Android observations.

## Platform contract

`com.styx.host.NativeHost` exposes static JNI `pair`, `start`, `stop`, `forget` and `status`.
`AndroidPlatform` provides `loadCredentials`, `storeCredentials` and
`execute(method, paramsJson)`. Rust supplies the internal `__caller_id` from its
existing caller authority; Android does not accept a separate caller session or
perform authentication.

The three public tool methods are `android_observe`, `android_act` and
`android_run_steps`. Each Core caller has one current observation, replaced by
that caller's next observation. The current observation retains node paths,
semantic fields and immutable Android node-identity copies. An action resolves
and refreshes the current node, checks its source identity and semantic fields,
and permits a bounds-only relayout. Replaced nodes and changed target content
are rejected. Another caller's observation does not invalidate these references.
Explicit `release_caller` and Host `clear` callbacks discard references.

Observations return the active app's accessible tree and optional scaled JPEG
screenshot (1280 pixels maximum dimension by default). `truncated` identifies a
tree that reached the requested `max_nodes`. Screen coordinates always use the
native `display.width`/`height`, not the returned JPEG dimensions. Android's secure
screens and lock screen remain protected. A screenshot failure is returned as
`screenshot_error`; the successful tree can still be used.

Node actions use Accessibility `performAction`, Unicode text uses `ACTION_SET_TEXT`,
and explicit coordinate actions use `dispatchGesture`. There are no implicit
clipboard, coordinate or shell fallbacks. Batches stop at the first failed step
and report completed steps. `observe_after` returns a fresh tree, without an image.
Cancellation clears the relevant observations so remaining steps cannot execute;
a gesture already dispatched may finish, be cancelled by Android, or have an
unknown outcome. No unknown action is replayed.

## Verification boundaries

Kotlin compilation and manifest merging verify source wiring only. JNI loading,
actual Gateway pairing, Accessibility grant, locked-screen refusal, background
connection, revocation and measured operation latency require a physical-device
acceptance run. They must be reported separately from compilation and APK creation.

## Android platform acceptance

The test APK contains its own synthetic fixture Activity. It exercises the actual
Accessibility adapter and emits only aggregate results and timings. Install the
Host normally, enable its Accessibility service, keep the phone unlocked, and pause
any other automation that changes the foreground app during this run.

Set `STYX_ANDROID_DEVICE` to the explicitly selected authorized device. After the
normal native build, build and install the separate test APK:

```bash
src/host/android/gradlew -p src/host/android --offline :app:assembleDebugAndroidTest
adb -s "$STYX_ANDROID_DEVICE" install -r -t --dont-kill \
  src/host/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s "$STYX_ANDROID_DEVICE" shell am instrument --no-restart -w -r \
  com.styx.host.test/com.styx.host.test.PlatformAcceptanceInstrumentation
```

Use `--no-restart`: ordinary instrumentation force-stops its target App, which also
owns the AccessibilityService being tested. The runner preserves Accessibility
services with `FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES` and checks live readiness
before opening the fixture. A failed readiness check is not a platform-action pass.
A successful platform run still does not establish Gateway pairing or independent
operation after ADB disconnect.


For a one-time development pairing through the real App UI, the same test runner
accepts `-e mode pair_ui`. Supply a JSON object with `gateway_url`, `short_code`
and optional `device_label` through stdin to a mode-0600 file at
`/data/user/0/com.styx.host/no_backup/styx-pairing-input.json` using the debug App's
normal `run-as` access. Keep the JSON out of command arguments, logs and test
extras. The runner reads and immediately deletes the file, fills MainActivity's
three fields and clicks **Pair phone** once. It returns only public Host status
and error codes; `pair_result` confirms enrollment separately from connection
status. It never retries pairing. Invoke this mode with `am instrument
--no-restart -w -r -e mode pair_ui` and the runner component above. It does not
change production code or replace the App's pairing and credential-storage path.

The explicit `-e mode forget_ui` acceptance action opens the real App's **Forget
pairing** confirmation and presses **Forget** once. Run it only when local reset
is intended, using the same `--no-restart` runner invocation. It verifies that the
credential file is absent, public status has no environment identity, and the
Accessibility connection is preserved; it never reads credentials or deletes
files itself.

For normal Host lifecycle acceptance, use `-e mode host_ui -e action start` or
`-e mode host_ui -e action stop` with the same `--no-restart` invocation. Each
clicks the corresponding real App button once, waits for its public terminal
state and reports sanitized status and readiness. `-e action status` performs
only those public reads. None of these actions reads or resets credentials.
The synthetic fixture keeps its own visible window awake for MCP acceptance;
leaving or closing the fixture restores normal screen-timeout behavior.

For real Keyguard acceptance, use `-e mode keyguard -e action status` with the same
`--no-restart` runner. It reads Android's public Keyguard, device-security and
interactive state without opening an Activity. `-e action lock` requests the
normal Accessibility `GLOBAL_ACTION_LOCK_SCREEN` once, then observes Keyguard
for up to five seconds. It never changes lock settings, supplies a credential,
or retries the action. Keep the normal device access route available for the
owner to unlock when authentication is configured.

A successful request is separate from a real lock: require `lock_accepted: true`
and `after.is_keyguard_locked: true` before testing native-tool refusals. Screen
off with Keyguard still false is not a locked-screen pass. On a device whose
current settings do not produce Keyguard, record that coverage limitation and
restore the ordinary awake state without changing the user's security setup.
