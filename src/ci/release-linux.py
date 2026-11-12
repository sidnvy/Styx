#!/usr/bin/env python3
"""CI adapter for the existing native binary producer and Linux runtime sealer.

Build uses the native host's pinned Rust toolchain and existing Cargo cache.
Package can seal binaries produced on other runners; it does not execute them.
Original producer receipts and signed worker releases remain mandatory inputs.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin",
           "x86_64-apple-darwin", "x86_64-pc-windows-msvc")


def available_jobs():
    """Respect an explicit override, otherwise use the runner's allocated CPUs."""
    override = os.environ.get("CARGO_BUILD_JOBS")
    if override is not None:
        return positive_jobs(override)
    count = os.cpu_count() or 1
    if hasattr(os, "sched_getaffinity"):
        count = min(count, len(os.sched_getaffinity(0)))
    quota = Path("/sys/fs/cgroup/cpu.max")
    if quota.is_file():
        value, period = quota.read_text().split()
        if value != "max":
            count = min(count, max(1, (int(value) + int(period) - 1) // int(period)))
    return min(count, 256)


def positive_jobs(value):
    number = int(value)
    if not 1 <= number <= 256:
        raise argparse.ArgumentTypeError("jobs must be in 1..256")
    return number


def existing_path(value):
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise argparse.ArgumentTypeError("an existing canonical absolute path is required")
    return path


def output_path(value):
    path = Path(value)
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise argparse.ArgumentTypeError("a fresh absolute output path is required")
    if path.is_relative_to(ROOT):
        raise argparse.ArgumentTypeError("release output must stay outside the source checkout")
    return path


def run(arguments):
    subprocess.run([str(value) for value in arguments], cwd=ROOT, check=True)


def build(args):
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "amd64"):
        raise ValueError("Linux x86_64 runner required for the Linux binary build")
    jobs = args.jobs if args.jobs is not None else available_jobs()
    print(json.dumps({"stage": "native-build", "jobs": jobs,
                      "target_dir": str(args.target_dir), "profile": "release",
                      "target": "x86_64-unknown-linux-gnu"}), flush=True)
    command = [sys.executable, "-I", "-B", ROOT / "src/tools/release/build-native-binary.py",
               "--source-revision", args.source_revision, "--gate-receipt", args.gate_receipt,
               "--target-dir", args.target_dir, "--output", args.output, "--jobs", jobs]
    if args.reuse_workspace_cache:
        command.append("--reuse-workspace-cache")
    run(command)


def package(args):
    if sys.platform != "linux":
        raise ValueError("the existing runtime sealer requires a Linux signing job")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        raise ValueError("full source revision required")
    if args.flavor == "host" and not (args.worker_release and args.worker_publisher_file):
        raise ValueError("Host packages require the original signed worker release and publisher")
    if args.asset and args.publisher_private_key is None:
        raise ValueError("unsigned signing preparation cannot create a release asset")
    command = [sys.executable, "-I", "-B", ROOT / "src/tools/release/build-native-runtime.py",
               "--source-revision", args.source_revision, "--target", args.target,
               "--version", args.version, "--binary", args.binary,
               "--build-receipt", args.build_receipt, "--output", args.output,
               "--expected-publisher", args.expected_publisher, "--relocated-binary",
               "--tunnel-client", args.tunnel_client,
               "--tunnel-client-sha256", args.tunnel_client_sha256,
               "--tunnel-client-license", args.tunnel_client_license,
               "--tunnel-client-notice", args.tunnel_client_notice]
    if args.publisher_private_key:
        command += ["--publisher-private-key", args.publisher_private_key]
    else:
        command += ["--prepare-signing", "--publisher-file", args.publisher_file]
    if args.flavor == "host":
        command += ["--worker-release", args.worker_release,
                    "--worker-publisher-file", args.worker_publisher_file]
        kinds = ["codex_exec", "browser_node22"]
        # macOS Cua is retained in the signed App, not a standalone worker closure.
        if not args.target.endswith("apple-darwin"):
            kinds.append("cua_native")
        for kind in kinds:
            command += ["--worker-kind", kind]
    run(command)
    if args.asset:
        shutil.copyfile(args.output / "native-runtime-candidate.tar.gz", args.asset)
        args.asset.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    native = commands.add_parser("build", help="build on the Linux native runner")
    native.add_argument("--source-revision", required=True)
    native.add_argument("--gate-receipt", required=True, type=existing_path)
    native.add_argument("--target-dir", required=True, type=existing_path)
    native.add_argument("--output", required=True, type=output_path)
    native.add_argument("--jobs", type=positive_jobs)
    native.add_argument("--reuse-workspace-cache", action="store_true",
                        help="reuse a validated native Git checkout's workspace cache")
    native.set_defaults(action=build)
    sealed = commands.add_parser("package", help="seal original native outputs on Linux")
    sealed.add_argument("--source-revision", required=True)
    sealed.add_argument("--target", choices=TARGETS, default=TARGETS[0])
    sealed.add_argument("--version", required=True)
    sealed.add_argument("--flavor", choices=("host", "gateway"), default="host")
    sealed.add_argument("--binary", required=True, type=existing_path)
    sealed.add_argument("--build-receipt", required=True, type=existing_path)
    sealed.add_argument("--output", required=True, type=output_path)
    sealed.add_argument("--expected-publisher", required=True)
    signing = sealed.add_mutually_exclusive_group(required=True)
    signing.add_argument("--publisher-private-key", type=existing_path)
    signing.add_argument("--publisher-file", type=existing_path,
                         help="prepare an unsigned manifest for external signing")
    sealed.add_argument("--worker-release", type=existing_path)
    sealed.add_argument("--worker-publisher-file", type=existing_path)
    sealed.add_argument("--tunnel-client", required=True, type=existing_path)
    sealed.add_argument("--tunnel-client-sha256", required=True)
    sealed.add_argument("--tunnel-client-license", required=True, type=existing_path)
    sealed.add_argument("--tunnel-client-notice", required=True, type=existing_path)
    sealed.add_argument("--asset", type=output_path,
                        help="copy the signed archive to its final external asset filename")
    sealed.set_defaults(action=package)
    args = parser.parse_args()
    os.umask(0o077)
    args.action(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        # Producer logs are public build diagnostics; never print signing key bytes.
        print(f"release adapter failed: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1)
