# Native Android Host

This is the independent Android Styx Host, not the ADB instrumentation controller.
The app runs the shared Rust enrollment and Host protocol through JNI. Kotlin owns
Android service lifetime, protected credential storage and Accessibility APIs.
There is no Android HTTP server, Exec service, Browser runtime, Root or ADB runtime dependency.

## Multi-display control

`android_list_displays` returns the physical and accessible virtual displays,
with `display_id`, dimensions, and application windows. Pass the returned
`display_id` to `android_observe` to read that screen (including optional
screenshot), then use its `observation_id` with `android_act` or
`android_run_steps`. Actions may also specify `display_id`; if supplied it must
match the observation. A caller can retain a fresh observation per display,
without invalidating the others. Omitting `display_id` continues to target 0.

Node actions and touch gestures are routed to the observed display. Global
navigation (`back`, `home`, `recents`) remains limited to display 0 because
Android's accessibility global-action API has no display selector. A missing
virtual display invalidates its observation. Screenshots use the platform
Accessibility screenshot API, and can return `screenshot_error` if Android
blocks capture. Virtual displays are provisioned externally (for example by
scrcpy); the app itself requires no ADB or Root permission.

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

For a development APK update, first press **Stop Host** and wait for `state: stopped`
with `transport_drain: complete`, then replace the APK, reopen the App and press
**Start Host**. The existing pairing and Android permissions remain in place.
`stopped` describes the local Host; `unknown` or `unsupported` transport drain is
not proof that Gateway completed the old caller cleanup. Installing over a running
App terminates its process without this exchange. Existing callers then remain
bound to that old Host generation; a fresh authenticated MCP session can observe
the new Host, while old observations and unknown actions must never be replayed.

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

## Release APK producer

`src/ci/release-android.py` uses the same SDK, NDK, JDK, Cargo target and Gradle
cache as the development build. It builds the real Rust JNI library with Cargo's
release profile and assembles a non-debuggable arm64 APK. The version name comes
from the root `Cargo.toml`; `--build-number` supplies Android's increasing
`versionCode` (the existing release source job already produces this number).
The Gradle inputs are `STYX_ANDROID_VERSION_NAME` and
`STYX_ANDROID_VERSION_CODE`. The ordinary debug build keeps its development
suffix and still uses Android's debug identity.

For an unsigned packaging check on the workstation:

```bash
ANDROID_HOME=/home/sid/remote-mic-arch/android-sdk \
JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
python3 -I -B src/ci/release-android.py --offline --unsigned \
  --build-number 1174 \
  --output /home/sid/Developer/Artifacts/Styx/android-host/release-check
```

The output name ends in `-android-arm64-unsigned.apk`. Its receipt identifies the
source revision, dirty-source status, versionCode, actual JNI library and APK
hashes, and `signing: UNSIGNED`. This checks packaging; it is not a published
or installable release and does not establish device acceptance.

A signed build omits `--unsigned` and requires these environment inputs on the
existing signing machine:

- `STYX_ANDROID_KEYSTORE`: path to the established Android release keystore.
- `STYX_ANDROID_KEYSTORE_PASSWORD`: that keystore's password.
- `STYX_ANDROID_KEY_ALIAS`: the established release key alias.
- `STYX_ANDROID_KEY_PASSWORD`: the key password.

The producer neither creates nor transfers a private key and does not update
GitHub secrets. It verifies the signed APK, records the public certificate
fingerprint and rejects the Android debug identity for publication. Passwords
are environment inputs, not command arguments or receipt fields.

**Current publication gap:** the existing phone build uses the local Android
debug certificate; a formal Android release signing identity and its CI signing
access have not been configured. The four existing desktop/Gateway assets remain
the current official release set. This producer does not publish a parallel APK
release or silently replace that set.

When that signing access is ready, integrate this producer into the existing
`styx-release.yml` after its source/quality jobs. Use the same source revision,
version and build number, existing Android toolchain versions, and shared
Cargo/Gradle caches. Upload the signed `Styx-<version>-android-arm64.apk` to an
`assets-android` artifact, include that job in the final publish dependencies,
and add the APK to the existing exact checksum asset list in
`release-ci.py`. Only then include Android in the same immutable GitHub Release.
No second workflow or distribution channel is needed.

If the formal release uses a different certificate from the development build,
Android will not accept it as an ordinary in-place update over that debug APK.
Decide the development-to-release migration before installing the first signed
release, preserving the existing phone pairing until that transition is explicit.
