#!/usr/bin/env bash
set -euo pipefail
android_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$android_dir/../../.." && pwd)"
variant="${1:-debug}"
case "$variant" in
  debug) gradle_task=assembleDebug ;;
  release)
    gradle_task=assembleRelease
    : "${STYX_ANDROID_VERSION_NAME:?Set the release version name}"
    : "${STYX_ANDROID_VERSION_CODE:?Set the increasing release version code}"
    ;;
  *) printf 'usage: %s [debug|release]\n' "$0" >&2; exit 2 ;;
esac
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
: "${ANDROID_HOME:?Set ANDROID_HOME to the existing Android SDK}"
ndk_dir="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/29.0.14206865}"
ndk_bin="$ndk_dir/toolchains/llvm/prebuilt/${ANDROID_NDK_HOST_TAG:-linux-x86_64}/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android30-clang"
export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
export AR_aarch64_linux_android="$ndk_bin/llvm-ar"
cargo_args=(build --locked -p styx-android --target aarch64-linux-android)
gradle_args=(-p "$android_dir")
if [[ "${STYX_ANDROID_OFFLINE:-1}" == 1 ]]; then
  cargo_args+=(--offline)
  gradle_args+=(--offline)
fi
if [[ "$variant" == release ]]; then cargo_args+=(--release); fi
cd -- "$repo_dir"
python3 -I -B src/ci/dev-env.py cargo "${cargo_args[@]}"
export STYX_ANDROID_NATIVE_LIB="$repo_dir/target/aarch64-linux-android/$variant/libstyx_android.so"
"$android_dir/gradlew" "${gradle_args[@]}" ":app:$gradle_task"
suffix="$variant"
if [[ "$variant" == release && -z "${STYX_ANDROID_KEYSTORE:-}" ]]; then suffix=release-unsigned; fi
artifact_dir="${STYX_ARTIFACT_ROOT:-$HOME/Developer/Artifacts/Styx}/android-host"
mkdir -p -- "$artifact_dir"
cp -- "$android_dir/app/build/outputs/apk/$variant/app-$suffix.apk" "$artifact_dir/styx-android-$suffix.apk"
sha256sum "$artifact_dir/styx-android-$suffix.apk"
