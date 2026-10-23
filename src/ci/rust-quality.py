#!/usr/bin/env python3
"""Local Rust foundation gate. Orchestrates Cargo; never claims final/native release.

No product configuration is opened. Logs are private raw command output, so test
code must obey the product's secret-safe diagnostics contract. Summaries print
only check names/status, never captured raw stdout, environment or config values.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import tomllib
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
POLICY = Path(__file__).with_name("rust-dependency-policy.json")
CRYPTO_TEST = "crypto::tests::legacy_node22_bidirectional_crypto_batch"
CODEX_TEST = "providers::codex::tests::real_codex_native_stdio_complete_scenario_batch"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def private_new_dir(path):
    if not path.is_absolute() or path.resolve() != path or path.is_relative_to(ROOT) or path.exists() or path.is_symlink():
        raise ValueError("fresh_absolute_directory_required")
    path.mkdir(parents=True, mode=0o700)
    if path.resolve() != path:
        raise ValueError("directory_alias_rejected")
    return path


def source_inputs(root):
    files = [root / "Cargo.toml", root / "Cargo.lock", root / "rust-toolchain.toml", POLICY, Path(__file__).resolve()]
    for base in (root / "src/crates", root / "src/acceptance/oracles"):
        files += [p for p in base.rglob("*") if p.is_file() and p.suffix in {".rs", ".toml", ".py", ".json", ".mjs"}]
    files += [root / "src/shared/enrollment-protocol.mjs", *[root / "src/docs/rust-core-rewrite" / name for name in ("LEGACY-WIRE-VECTORS-V1.json", "CONTRACT-V1.json", "FEATURE-INVENTORY-V1.json", "PUBLIC-MCP-V1.json")]]
    return {str(p.relative_to(root)): sha(p) for p in sorted(set(files))}


def metadata_errors(metadata, policy, root):
    errors = []
    ids = set(metadata["workspace_members"])
    packages = {p["name"]: p for p in metadata["packages"] if p["id"] in ids}
    if set(packages) != set(policy["members"]):
        errors.append("workspace_member_set_changed")
    for name, package in packages.items():
        if name not in policy["members"]:
            continue
        rule = policy["members"][name]
        allowed = set(rule["workspace_allowed"]) | set(rule["external_allowed"])
        for dep in package["dependencies"]:
            if dep["name"] not in allowed:
                errors.append(f"{name}:unreviewed_dependency:{dep['name']}")
            if dep["name"] in packages:
                if dep["name"] not in rule["workspace_allowed"]:
                    errors.append(f"{name}:outward_workspace_dependency:{dep['name']}")
                elif Path(dep.get("path", "")).resolve() != Path(packages[dep["name"]]["manifest_path"]).parent.resolve():
                    errors.append(f"{name}:workspace_dependency_path_mismatch")
            elif dep.get("path") or dep.get("source", "").startswith("git+"):
                errors.append(f"{name}:unreviewed_external_source:{dep['name']}")
    # Metadata catches declared deps; this catches obvious std IO/native imports.
    # It is deliberately identified as a lexical lint, never a compiler proof.
    core = root / "src/crates/styx-core/src"
    forbidden = policy["pure_core_forbidden_paths"]
    for path in core.rglob("*.rs"):
        text = path.read_text()
        # Ignore comments/strings for this narrow lint to avoid error-message false positives.
        code = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"', '', text, flags=re.S)
        for item in forbidden:
            if re.search(r"\b" + re.escape(item).replace("::", r"\s*::\s*") + r"\b", code):
                errors.append(f"core_forbidden_path:{path.relative_to(root)}:{item}")
        if re.search(r"std\s*::\s*\{[^;]*\b(fs|net|os|process)\b", code):
            errors.append(f"core_grouped_std_io_import:{path.relative_to(root)}")
    return errors


class Gate:
    def __init__(self, directory, target):
        self.directory, self.target = directory, target
        self.checks = []
        allowed = {"PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME", "LD_LIBRARY_PATH", "LIBRARY_PATH", "LANG", "LC_ALL", "TERM"}
        self.env = {k: v for k, v in os.environ.items() if k in allowed}
        self.env.update(CARGO_TARGET_DIR=str(target), CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never", PYTHONDONTWRITEBYTECODE="1", GIT_OPTIONAL_LOCKS="0")

    def save(self):
        data = {"schema": 1, "kind": "rust_foundation_development_quality", "scope": "local_current_platform_only", "status": "RUNNING", "checks": self.checks, "native_platform_acceptance": "NOT_RUN", "package": "NOT_BUILT", "deployment": "NOT_RUN"}
        path = self.directory / "progress.json"
        path.write_text(json.dumps(data, indent=2) + "\n")

    def run(self, name, command, *, timeout=900, extra_env=None):
        entry = {"name": name, "command": command, "cwd": str(ROOT), "started_at": now()}
        started = time.monotonic()
        logs = {}
        with (self.directory / (name + ".stdout.log")).open("xb") as stdout, (self.directory / (name + ".stderr.log")).open("xb") as stderr:
            os.chmod(stdout.name, 0o600); os.chmod(stderr.name, 0o600)
            env = self.env | (extra_env or {})
            proc = None
            try:
                proc = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=os.name == "posix")
                entry["exit_code"] = proc.wait(timeout)
                entry["status"] = "PASS" if entry["exit_code"] == 0 else "FAIL"
            except subprocess.TimeoutExpired:
                entry.update(status="FAIL", reason="command_timeout", exit_code=None)
                if os.name == "posix" and proc:
                    try:
                        if os.getpgid(proc.pid) == proc.pid:
                            os.killpg(proc.pid, signal.SIGKILL)
                            entry["owned_process_group"] = "termination_requested_and_leader_reaped"
                        else:
                            entry["descendant_cleanup"] = "UNCONFIRMED"
                    except ProcessLookupError:
                        entry["descendant_cleanup"] = "UNCONFIRMED"
                    proc.wait()
                elif proc:
                    proc.kill(); proc.wait()
                    entry["descendant_cleanup"] = "UNCONFIRMED"
            except OSError as error:
                entry.update(status="FAIL", reason=type(error).__name__, exit_code=None)
        for stream in ("stdout", "stderr"):
            path = self.directory / (name + "." + stream + ".log")
            logs[stream] = {"path": path.name, "sha256": sha(path), "bytes": path.stat().st_size}
        entry.update(elapsed_seconds=time.monotonic() - started, completed_at=now(), logs=logs)
        self.checks.append(entry)
        self.save()
        print(json.dumps({"check": name, "status": entry["status"]}), flush=True)
        return entry

    def read(self, name, stream="stdout"):
        path = self.directory / (name + "." + stream + ".log")
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("analysis_log_too_large")
        return path.read_text(errors="replace")

    def semantic(self, entry, errors):
        if errors:
            entry["status"] = "FAIL"
            entry["semantic_errors"] = errors
            self.save()


def execute(args):
    evidence = private_new_dir(Path(args.evidence))
    target = Path(args.target_dir) if args.target_dir else evidence / "target"
    if not target.is_absolute() or target.resolve() != target.absolute() or target == ROOT or target.is_relative_to(ROOT):
        raise ValueError("external_absolute_target_required")
    target.mkdir(parents=True, exist_ok=True)
    policy = json.loads(POLICY.read_text())
    gate = Gate(evidence, target)
    receipt = {"schema": 1, "kind": "rust_foundation_development_quality", "started_at": now(), "status": "RUNNING", "root": str(ROOT), "target_dir": str(target), "checks": gate.checks, "native_platform_acceptance": "NOT_RUN", "package": "NOT_BUILT", "deployment": "NOT_RUN", "final_release_gate": False}
    initial = None
    try:
        initial = source_inputs(ROOT)
        receipt["inputs"] = initial
        head = gate.run("git-head", ["git", "rev-parse", "HEAD"], timeout=30)
        dirty = gate.run("git-status", ["git", "status", "--porcelain=v1", "--untracked-files=normal"], timeout=30)
        if head["status"] == "PASS":
            receipt["source_revision"] = gate.read("git-head").strip()
            gate.semantic(head, [] if re.fullmatch(r"[a-f0-9]{40}", receipt["source_revision"]) else ["git_revision_shape"])
        if dirty["status"] == "PASS":
            receipt["dirty_status"] = gate.read("git-status")
        pin = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        tc = gate.run("rustc-version", ["rustc", "--version"], timeout=30)
        cg = gate.run("cargo-version", ["cargo", "--version"], timeout=30)
        gate.semantic(tc, [] if pin == policy["toolchain"] and re.match(r"^rustc 1\.94\.1\s", gate.read("rustc-version")) else ["exact_rustc_and_toolchain_pin_required"])
        gate.semantic(cg, [] if re.match(r"^cargo 1\.94\.1\s", gate.read("cargo-version")) else ["exact_cargo_required"])
        if tc["status"] != "PASS" or cg["status"] != "PASS":
            raise ValueError("toolchain_precondition_failed")
        md = gate.run("dependency-metadata", ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked", "--offline"], timeout=60)
        if md["status"] == "PASS":
            gate.semantic(md, metadata_errors(json.loads(gate.read("dependency-metadata")), policy, ROOT))
        gate.run("format", ["cargo", "fmt", "--all", "--", "--check"], timeout=120)
        gate.run("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--offline", "--", "-D", "warnings"])
        tests = gate.run("workspace-tests", ["cargo", "test", "--workspace", "--locked", "--offline"])
        if tests["status"] == "PASS":
            ignored = sorted(set(re.findall(r"test ([\w:]+) \.\.\. ignored", gate.read("workspace-tests"))))
            receipt["ignored_tests"] = [{"test": name, **policy["known_ignored"].get(name, {"kind": "UNREVIEWED"})} for name in ignored]
            gate.semantic(tests, ["unreviewed_ignored_test:" + name for name in ignored if name not in policy["known_ignored"]])
        receipt["legacy_node22_interop"] = "NOT_RUN_explicit_node22_not_supplied"
        if args.node22:
            node = Path(args.node22)
            if not node.is_absolute() or not node.is_file() or not os.access(node, os.X_OK):
                raise ValueError("explicit_absolute_executable_node22_required")
            nv = gate.run("node22-version", [str(node), "--version"], timeout=30)
            gate.semantic(nv, [] if re.fullmatch(r"v22\.\d+\.\d+\s*", gate.read("node22-version")) else ["node22_major_required"])
            receipt["node22_input"] = {"path": str(node), "sha256": sha(node)}
            if nv["status"] == "PASS":
                crypto = gate.run("node22-crypto", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", CRYPTO_TEST, "--", "--ignored", "--exact"], extra_env={"STYX_TEST_NODE22": str(node)})
                gate.semantic(crypto, [] if "1 passed; 0 failed" in gate.read("node22-crypto") else ["exact_crypto_case_not_executed"])
                receipt["legacy_node22_interop"] = crypto["status"]
        receipt["real_codex_interop"] = "NOT_RUN_explicit_codex_not_supplied"
        if args.codex_bin:
            codex = Path(args.codex_bin)
            if sys.platform != "linux" or not codex.is_absolute() or not codex.is_file() or not os.access(codex, os.X_OK):
                raise ValueError("linux_slice_requires_explicit_absolute_codex_executable")
            receipt["codex_input"] = {"path": str(codex), "sha256": sha(codex)}
            gate.run("codex-version", [str(codex), "--version"], timeout=30)
            exec_root = evidence / "owned-native-exec"
            exec_root.mkdir(mode=0o700)
            native = gate.run("real-codex", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", CODEX_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_CODEX": str(codex), "STYX_TEST_EXEC_ROOT": str(exec_root)})
            gate.semantic(native, [] if "1 passed; 0 failed" in gate.read("real-codex") else ["exact_real_codex_case_not_executed"])
            receipt["real_codex_interop"] = native["status"]
        gate.run("python-oracles", [sys.executable, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "src/acceptance/oracles", "-p", "test_oracles.py", "-v"], timeout=120)
        build = gate.run("cli-build", ["cargo", "build", "-p", "styx", "--locked", "--offline"])
        if build["status"] == "PASS":
            binary = target / "debug" / ("styx.exe" if os.name == "nt" else "styx")
            receipt["cli_binary_sha256"] = sha(binary)
            smoke = [ ("cli-help", ["--help"], lambda text: "build-info" in text and "Usage:" in text),
                      ("cli-version", ["--version"], lambda text: re.fullmatch(r"styx \S+\s*", text) is not None),
                      ("cli-build-info", ["build-info"], lambda text: "contract=1" in text and "stage=" in text) ]
            for name, argv, valid in smoke:
                step = gate.run(name, [str(binary), *argv], timeout=30)
                gate.semantic(step, [] if valid(gate.read(name)) else ["cli_response_not_expected"])
            # A skeleton must reject unimplemented business, never return empty success.
            reject = gate.run("cli-unimplemented-reject", [str(binary), "exec", "--command", "never-run"], timeout=30)
            if reject["exit_code"] is not None and reject["exit_code"] == 2 and "unrecognized subcommand" in gate.read("cli-unimplemented-reject", "stderr"):
                reject.update(status="PASS", expected_nonzero=True)
            else:
                reject["status"] = "FAIL"
            gate.save()
    except Exception as error:
        receipt["failure"] = {"category": type(error).__name__, "reason": str(error) if isinstance(error, ValueError) else "quality_input_or_analysis_failure"}
    finally:
        try:
            final = source_inputs(ROOT)
            head_end = gate.run("git-head-end", ["git", "rev-parse", "HEAD"], timeout=30)
            dirty_end = gate.run("git-status-end", ["git", "status", "--porcelain=v1", "--untracked-files=normal"], timeout=30)
            receipt["source_revision_end"] = gate.read("git-head-end").strip() if head_end["status"] == "PASS" else None
            receipt["dirty_status_end"] = gate.read("git-status-end") if dirty_end["status"] == "PASS" else None
            receipt["git_stability"] = "PASS" if receipt.get("source_revision") == receipt["source_revision_end"] and receipt.get("dirty_status") == receipt["dirty_status_end"] else "FAIL"
            receipt["input_stability"] = "PASS" if initial is not None and initial == final else "FAIL"
            receipt["changed_inputs"] = sorted(k for k in set(initial or {}) | set(final) if (initial or {}).get(k) != final.get(k))
            if args.node22 and "node22_input" in receipt:
                receipt["node22_stability"] = "PASS" if sha(args.node22) == receipt["node22_input"]["sha256"] else "FAIL"
            if args.codex_bin and "codex_input" in receipt:
                receipt["codex_stability"] = "PASS" if sha(args.codex_bin) == receipt["codex_input"]["sha256"] else "FAIL"
        except OSError:
            receipt["input_stability"] = "FAIL"
        required = {"git-head", "git-status", "git-head-end", "git-status-end", "rustc-version", "cargo-version", "dependency-metadata", "format", "clippy", "workspace-tests", "python-oracles", "cli-build", "cli-help", "cli-version", "cli-build-info", "cli-unimplemented-reject"}
        if args.node22:
            required |= {"node22-version", "node22-crypto"}
        if args.codex_bin:
            required |= {"codex-version", "real-codex"}
        receipt["missing_required_checks"] = sorted(required - {x["name"] for x in gate.checks})
        receipt["status"] = "PASS" if not receipt["missing_required_checks"] and gate.checks and all(x["status"] == "PASS" for x in gate.checks) and receipt.get("input_stability") == "PASS" and receipt.get("git_stability") == "PASS" and receipt.get("node22_stability", "PASS") == "PASS" and receipt.get("codex_stability", "PASS") == "PASS" and "failure" not in receipt else "FAIL"
        receipt["completed_at"] = now()
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "receipt": str(evidence / "receipt.json"), "scope": "foundation_development_only"}), flush=True)
    return receipt["status"] == "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, help="fresh absolute external evidence directory")
    parser.add_argument("--target-dir", help="absolute external Cargo build cache; reused only by explicit choice")
    parser.add_argument("--node22", help="absolute explicit Node22 executable for real legacy crypto interop")
    parser.add_argument("--codex-bin", help="explicit native Codex binary for the Linux owned-executor slice; not platform release acceptance")
    args = parser.parse_args()
    path = Path(args.evidence)
    if path.is_relative_to(ROOT) or not path.is_absolute():
        parser.error("evidence must be absolute and outside the product checkout")
    try:
        return 0 if execute(args) else 1
    except (ValueError, OSError) as error:
        print(json.dumps({"status": "FAIL", "category": type(error).__name__, "reason": "invalid_or_unavailable_quality_output"}), flush=True)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
