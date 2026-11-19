#!/usr/bin/env bash
set -euo pipefail
android_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$android_dir/../../.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
: "${ANDROID_HOME:?Set ANDROID_HOME to the existing Android SDK}"
ndk_dir="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/29.0.14206865}"
ndk_bin="$ndk_dir/toolchains/llvm/prebuilt/${ANDROID_NDK_HOST_TAG:-linux-x86_64}/bin"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android30-clang"
export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
export AR_aarch64_linux_android="$ndk_bin/llvm-ar"
cd -- "$repo_dir"
python3 -I -B src/ci/dev-env.py cargo build --locked --offline -p styx-android --target aarch64-linux-android
export STYX_ANDROID_NATIVE_LIB="$repo_dir/target/aarch64-linux-android/debug/libstyx_android.so"
"$android_dir/gradlew" -p "$android_dir" --offline :app:assembleDebug
artifact_dir="${STYX_ARTIFACT_ROOT:-$HOME/Developer/Artifacts/Styx}/android-host"
mkdir -p -- "$artifact_dir"
cp -- "$android_dir/app/build/outputs/apk/debug/app-debug.apk" "$artifact_dir/styx-android-debug.apk"
sha256sum "$artifact_dir/styx-android-debug.apk"
