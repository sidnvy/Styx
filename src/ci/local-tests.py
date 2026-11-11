#!/usr/bin/env python3
"""Small, explicit local test entry point; no device or release acceptance."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = (
    "providers::cua::public_contract::tests::branch_only_tool_projection_preserves_bound_targets_and_environment",
    "providers::cua::public_contract::tests::complete_branch_declarations_keep_the_existing_schema_admission",
    "management::native_join_http::transport_tests::local_rejection_admits_fixed_authenticated_request_over_tls",
    "management::native_join_http::transport_tests::local_rejection_does_not_admit_anonymous_or_generic_admin_requests",
)
HUB_RECOVERY = (
    "management::setup_pending_restart_reference_tests::hub_pending_across_foreground_restart_is_refused_without_approval_or_claim",
    "management::setup_pending_restart_reference_tests::hub_explicit_retire_preserves_gateway_then_pairs_new_identity_in_same_root",
    "enrollment::retirement::tests::linux::signed_reader7_expired_pending_only_advances_durable_floor",
)


def packages():
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
    return {tomllib.loads((ROOT / member / "Cargo.toml").read_text())["package"]["name"]
            for member in workspace["workspace"]["members"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="print commands only; does not claim a test pass")
    subs = parser.add_subparsers(dest="profile", required=True)
    unit = subs.add_parser("unit", help="ordinary non-ignored Rust tests in explicit packages")
    unit.add_argument("--package", action="append", required=True)
    subs.add_parser("contracts", help="fast schema and local native-client admission regressions")
    integration = subs.add_parser("integration", help="pass explicit arguments to the existing full quality gate")
    integration.add_argument("quality_args", nargs=argparse.REMAINDER)
    recovery = subs.add_parser("hub-recovery", help="explicit signed-payload Hub recovery references; no device acceptance")
    recovery.add_argument("--cli", type=Path, required=True)
    recovery.add_argument("--payload", type=Path, required=True)
    recovery.add_argument("--publisher", type=Path, required=True)
    recovery.add_argument("--publisher-pin", required=True)
    args = parser.parse_args()
    if args.profile == "unit":
        unknown = set(args.package) - packages()
        if unknown:
            parser.error("unknown workspace package(s): " + ", ".join(sorted(unknown)))
        commands = [["cargo", "test", "--locked", "--offline", "-p", package, "--", "--test-threads=1"]
                    for package in dict.fromkeys(args.package)]
    elif args.profile == "contracts":
        commands = [["cargo", "test", "--locked", "--offline", "-p", "styx-runtime", case,
                     "--", "--exact", "--test-threads=1"] for case in CONTRACTS]
        print("Scope: schema projection/equivalence and local rejection admission; no device acceptance. "
              "Full TLS enrollment rejection is an ignored fixture-dependent integration scenario.", flush=True)
    elif args.profile == "hub-recovery":
        if not sys.platform.startswith("linux"):
            parser.error("hub-recovery references require Linux")
        for path, directory in ((args.cli, False), (args.payload, True), (args.publisher, False)):
            if not path.is_absolute() or not (path.is_dir() if directory else path.is_file()):
                parser.error("hub-recovery requires existing absolute CLI, payload and public publisher paths")
        if not re.fullmatch(r"[a-f0-9]{64}", args.publisher_pin):
            parser.error("publisher-pin must be an externally trusted lowercase SHA256 pin")
        commands = [["cargo", "test", "--locked", "--offline", "-p", "styx-runtime", "--lib", case,
                     "--", "--ignored", "--exact", "--test-threads=1", "--nocapture"] for case in HUB_RECOVERY]
        print("Scope: isolated loopback, real signed reader7 inputs and synthetic identities; "
              "no Tunnel, service, account or native device acceptance. Build the current CLI explicitly first.", flush=True)
    else:
        forwarded = args.quality_args
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        if not any(x == "--evidence" and i + 1 < len(forwarded) and not forwarded[i + 1].startswith("--")
                   or x.startswith("--evidence=") and len(x) > len("--evidence=")
                   for i, x in enumerate(forwarded)):
            parser.error("integration requires explicit --evidence and quality inputs; see rust-quality.py --help")
        commands = [[sys.executable, "-I", "-B", str(ROOT / "src/ci/rust-quality.py"), *forwarded]]
        print("Scope: existing full local quality gate; package, deployment and native acceptance are not claimed.", flush=True)
    import shlex
    if args.dry_run:
        for command in commands:
            print(shlex.join(command))
        print("NOT RUN (dry-run)")
        return 0
    env = os.environ.copy()
    if args.profile == "hub-recovery":
        env.update(STYX_SETUP_TEST_CLI=str(args.cli), STYX_SETUP_TEST_PAYLOAD=str(args.payload),
                   STYX_SETUP_TEST_PUBLISHER=str(args.publisher), STYX_SETUP_TEST_PIN=args.publisher_pin)
    if sys.platform.startswith("linux"):
        env.setdefault("CARGO_BUILD_JOBS", "8")
    if args.profile != "integration":
        pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        for tool in ("cargo", "rustc"):
            result = subprocess.run([tool, "--version"], cwd=ROOT, env=env, text=True,
                                    encoding="utf-8", errors="replace", capture_output=True)
            if result.returncode or not re.match(r"^" + tool + r" " + re.escape(pin) + r"(?:\s|$)", result.stdout):
                print(f"FAIL: {tool} must match pinned {pin}", file=sys.stderr)
                return 1
    for command in commands:
        print("+ " + shlex.join(command), flush=True)
        result = subprocess.run(command, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace",
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout, end="", flush=True)
        if result.returncode:
            print(f"FAIL: command exited {result.returncode}", file=sys.stderr)
            return 1
        if args.profile != "integration":
            passed = sum(int(n) for n in re.findall(r"^test result: ok\. (\d+) passed;", result.stdout, re.MULTILINE))
            if not passed:
                print("FAIL: no tests passed; ignored or filtered-out tests are not a pass", file=sys.stderr)
                return 1
    print("PASS: selected local checks only", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as exc:
        print(f"FAIL: unable to run required command: {exc}", file=sys.stderr)
        sys.exit(1)
