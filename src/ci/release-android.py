#!/usr/bin/env python3
"""Build the native Android APK with the existing SDK, NDK and project caches.

The tag workflow owns release eligibility/publication. --unsigned is a packaging
check, never an installable release substitute. Signing keys are supplied by the
signing machine; this producer neither creates nor copies a private key.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ANDROID = ROOT / "src/host/android"
SIGNING_VARIABLES = (
    "STYX_ANDROID_KEYSTORE",
    "STYX_ANDROID_KEYSTORE_PASSWORD",
    "STYX_ANDROID_KEY_ALIAS",
    "STYX_ANDROID_KEY_PASSWORD",
)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-number", type=int, required=True,
                        help="Increasing Android versionCode, normally the release source job's build_number")
    parser.add_argument("--unsigned", action="store_true",
                        help="Build and verify an unsigned APK for packaging checks only")
    parser.add_argument("--offline", action="store_true",
                        help="Reuse the existing Cargo/Gradle dependency caches without downloads")
    args = parser.parse_args()
    if not 1 <= args.build_number <= 2100000000:
        parser.error("--build-number must be in Android's versionCode range")
    env = os.environ.copy()
    if args.unsigned:
        for name in SIGNING_VARIABLES:
            env.pop(name, None)
    else:
        missing = [name for name in SIGNING_VARIABLES if not env.get(name)]
        if missing:
            parser.error("Android release signing is not configured: " + ", ".join(missing))
        if not Path(env["STYX_ANDROID_KEYSTORE"]).is_file():
            parser.error("STYX_ANDROID_KEYSTORE must name the existing signing-machine keystore")
    sdk = env.get("ANDROID_HOME") or env.get("ANDROID_SDK_ROOT")
    if not sdk:
        parser.error("Set ANDROID_HOME to the existing Android SDK")
    build_tools = Path(sdk) / "build-tools/36.0.0"
    for name in ("aapt2", "apksigner"):
        if not (build_tools / name).is_file():
            parser.error("Android SDK Build Tools 36.0.0 are required")
    if env.get("JAVA_HOME"):
        env["PATH"] = str(Path(env["JAVA_HOME"]) / "bin") + os.pathsep + env.get("PATH", "")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    env.update(STYX_ANDROID_VERSION_NAME=version,
               STYX_ANDROID_VERSION_CODE=str(args.build_number),
               STYX_ANDROID_OFFLINE="1" if args.offline else "0")
    subprocess.run(["bash", str(ANDROID / "build.sh"), "release"], cwd=ROOT, env=env, check=True)
    suffix = "-unsigned" if args.unsigned else ""
    apk = ANDROID / f"app/build/outputs/apk/release/app-release{suffix}.apk"
    badging = subprocess.check_output([str(build_tools / "aapt2"), "dump", "badging", str(apk)],
                                     env=env, text=True)
    if (not re.search(r"^package: name='com\.styx\.host' versionCode='" + str(args.build_number)
                      + r"' versionName='" + re.escape(version) + r"'", badging)
            or "application-debuggable" in badging):
        raise SystemExit("APK package/version/debuggability does not match the release inputs")
    with zipfile.ZipFile(apk) as archive:
        if "lib/arm64-v8a/libstyx_android.so" not in archive.namelist():
            raise SystemExit("APK is missing its actual arm64 Rust JNI library")
    verification = subprocess.run([str(build_tools / "apksigner"), "verify", "--print-certs", str(apk)],
                                  env=env, text=True, capture_output=True)
    if args.unsigned:
        if verification.returncode == 0:
            raise SystemExit("--unsigned unexpectedly produced a signed APK")
        signer = None
    else:
        if verification.returncode != 0:
            raise SystemExit("APK signature verification failed")
        if "CN=Android Debug" in verification.stdout:
            raise SystemExit("The Android debug identity cannot sign a published release")
        match = re.search(r"Signer #1 certificate SHA-256 digest: ([0-9a-f]+)", verification.stdout)
        if not match:
            raise SystemExit("APK signer certificate fingerprint is missing")
        signer = match.group(1)
    args.output.mkdir(parents=True, exist_ok=True)
    artifact = args.output / f"Styx-{version}-android-arm64{suffix}.apk"
    shutil.copyfile(apk, artifact)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    receipt = dict(platform="android", abi="arm64-v8a", version=version,
                   version_code=args.build_number, source_revision=revision, source_dirty=dirty,
                   native_profile="release",
                   native_library_sha256=digest(ROOT / "target/aarch64-linux-android/release/libstyx_android.so"),
                   artifact=artifact.name, sha256=digest(artifact),
                   signing="UNSIGNED" if args.unsigned else "VERIFIED",
                   signer_certificate_sha256=signer)
    (args.output / "android-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
