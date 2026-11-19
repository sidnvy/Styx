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

An encrypted opaque enrollment blob is stored under the app's no-backup directory.
Its AES-GCM key remains in AndroidKeyStore. No credentials are returned by NativeHost
status or written to logs. The pairing Activity blocks screenshots and recent-apps
previews, and password node text is omitted from Android observations.

## Platform contract

`com.styx.host.NativeHost` exposes static JNI `pair`, `start`, `stop` and `status`.
`AndroidPlatform` provides `loadCredentials`, `storeCredentials` and
`execute(method, paramsJson)`. Rust supplies the internal `__caller_id` from its
existing caller authority; Android does not accept a separate caller session or
perform authentication.

The three public tool methods are `android_observe`, `android_act` and
`android_run_steps`. Each Core caller has one current observation, replaced by
that caller's next observation. Only lightweight node paths and observed identity
are retained; an action refreshes the current Android node and rejects changed
targets. Another caller's observation does not invalidate these references.
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
