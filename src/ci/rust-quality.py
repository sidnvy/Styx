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
import stat
import subprocess
import sys
import time
import tomllib
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
POLICY = Path(__file__).with_name("rust-dependency-policy.json")
LINUX_DISCOVERY_TEST = "platform::linux::tests::actual_system_bus_snapshot_matches_independent_loginctl"
PAYLOAD_TEST = "store::payload::tests::payload_inventory_stream_pin_and_replacement_alias_budget_negatives"
CONFIGURATION_OWNER_TEST = "store::configuration::tests::shared_configuration_writer_fence_and_sticky_unknown_batch"
MANAGEMENT_PREPARATION_TEST = "store::management::tests::durable_prepare_preserves_exact_bytes_and_unsettled_high_water_batch"
NATIVE_ROOT_TEST = "store::native_root::tests::fresh_native_root_genesis_reopen_and_retained_unknown_batch"
MANAGEMENT_PHASE_TEST = "store::management::phase_tests::original_phase_chain_and_unknown_orphans_are_preserved_batch"
NATIVE_TRANSACTION_TEST = "store::native_transaction::tests::native_commit_reopen_and_scope_rejections_batch"
NATIVE_RUNTIME_UPDATE_TEST = "store::native_transaction::runtime_update::tests::runtime_update_interruption_and_forward_rollback_batch"
NATIVE_SERVICE_TIP_TEST = "store::native_transaction::tests::native_service_autostart_follow_and_refusal_batch"
ENROLLMENT_OWNED_TEST = "store::enrollment::owned::tests::owned_journal_thread_move_keeps_writer_and_initial_namespace_identity"
ENROLLMENT_PROFILE_TEST = "enrollment::profile::tests::actual_node22_profile_join_and_capability_proofs"
ENROLLMENT_SERVICE_TEST = "enrollment::service::tests::actual_strict_tls_enrollment_service_full_journey"
ENROLLMENT_CONTROLLER_TEST = "enrollment::service::controller_tests::expired_pending_collection_and_observed_store_failure_sticky_fence"
ENROLLMENT_RECOVERY_TEST = "enrollment::recovery::tests::linux::actual_core_journal_recovery_safety_scenario"
ENROLLMENT_CLOCK_TEST = "store::enrollment::clock::tests::durable_floor_atomic_updates_reopen_and_shared_budget_refuse_unsafe_state"
ENROLLMENT_STORE_TEST = "store::enrollment::tests::linux::immutable_material_commit_chain_and_process_crash_recovery"
CRYPTO_TEST = "crypto::tests::legacy_node22_bidirectional_crypto_batch"
CODEX_TESTS = [
    ("real-codex", "providers::codex::tests::real_codex_native_stdio_complete_scenario_batch"),
    ("raw-codex", "providers::codex::tests::real_codex_raw_page_focused_scenario"),
    ("host-coordinator", "host::coordinator::tests::real_owned_start_read_and_dropped_response_scenario"),
    ("codex-continuations", "providers::codex::tests::real_codex_continuation_permit_focused_scenario"),
    ("host-actions", "host::coordinator::tests::real_host_action_nonce_drop_ticket_and_terminate_scenario"),
    ("host-archival", "host::coordinator::tests::real_host_physical_retention_and_unknown_archival_scenario"),
]

TLS_TESTS = [
    ("tls-certificate-classification", "tls::tests::strict_verifier_certificate_classification_batch"),
    ("tls-loopback", "tls::tests::aws_lc_owned_loopback_tls_full_scenario_batch"),
    ("wss-loopback", "host::link::tests::strict_tls_wss_data_heartbeat_limits_close_cleanup_batch"),
    ("host-drain-faults", "host::protocol::tests::drain::actual_tls_wss_drain_negotiation_stale_result_and_loss"),
]
HTTP_TESTS = [
    ("official-http-sdk", "gateway::http::tests::official_sdk_tcp_auth_sessions_limits_and_pending_close"),
    ("http-control-pressure", "gateway::http::tests::actual_tcp_slow_post_readers_do_not_starve_bodyless_control"),
]
PAIRED_HOST_TEST = "enrollment::service::tests::paired_journey::actual_paired_tls_mcp_codex_nonce_owner_and_revocation_journey"
HOST_ACTION_WIRE_TEST = "host::protocol::tests::actual_canonical_tls_wss_host_action_journey"
MANAGEMENT_IMPORT_TEST = "management::tests::actual_legacy_management_raw_import_and_plan_batch"
BROWSER_REFERENCE_TEST = "host::coordinator::browser::browser_tests::references::actual_snapshot_refs_navigation_tabs_owner_and_reopen_batch"
BROWSER_HOST_TEST = "host::coordinator::browser::browser_tests::actual_owned_browser_host_nonce_policy_drop_and_cleanup"
HOST_WIRE_TEST = "host::protocol::tests::actual_tls_wss_codex_start_read_duplicate_and_lost_response_batch"


def tls_inputs(directory):
    root = Path(directory)
    if not root.is_absolute() or root.resolve() != root or root.is_relative_to(ROOT) or not root.is_dir():
        raise ValueError("external_test_only_tls_fixtures_required")
    result = {}
    for name in ("cert-a.pem", "cert-b.pem", "ca-a.pem", "ca-b.pem", "key-a.pem", "ca-key-a.pem"):
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
            raise ValueError("bounded_regular_test_tls_fixture_required")
        if name.startswith(("key-", "ca-key-")):
            stat = path.stat()
            if stat.st_mode & 0o077:
                raise ValueError("private_test_fixture_mode_required")
            # No private bytes/hashes in the receipt. Tests own private-key parsing.
            result[name] = {"inode": stat.st_ino, "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        else:
            result[name] = {"sha256": sha(path), "bytes": path.stat().st_size}
    return result


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
    for base in (root / "src/crates", root / "src/acceptance/oracles", root / "src/acceptance/interop-exec", root / "src/providers/browser-worker", root / "src/tools/release"):
        files += [p for p in base.rglob("*") if p.is_file() and "node_modules" not in p.parts and p.suffix in {".rs", ".toml", ".py", ".json", ".mjs"}]
    files += [root / "src/gateway/cua-portable-0.36.0.json", root / "src/packages/styx-browser-provider/playwright-contract-0.0.83.json", root / "src/shared/enrollment-protocol.mjs", root / "src/shared/deployment-scope.mjs", root / "src/scripts/legacy-deployment-hash-vectors.mjs", *[root / "src/docs/rust-core-rewrite" / name for name in ("LEGACY-WIRE-VECTORS-V1.json", "LEGACY-DEPLOYMENT-HASH-VECTORS.json", "CONTRACT-V1.json", "FEATURE-INVENTORY-V1.json", "PUBLIC-MCP-V1.json")]]
    return {str(p.relative_to(root)): sha(p) for p in sorted(set(files))}



def browser_inputs(executable):
    """Identity inventory of actual development closure; not npm authenticity proof."""
    worker_root = ROOT / "src/providers/browser-worker"
    modules = worker_root / "node_modules"
    browser = Path(executable)
    if not browser.is_absolute() or browser.resolve() != browser or not browser.is_file() or not os.access(browser, os.X_OK):
        raise ValueError("canonical_absolute_browser_executable_required")
    if modules.is_symlink() or modules.resolve() != modules or not modules.is_dir():
        raise ValueError("adjacent_browser_dependency_closure_required")
    package = json.loads((worker_root / "package.json").read_text())
    lock = json.loads((worker_root / "package-lock.json").read_text())
    if lock["packages"][""]["dependencies"] != package["dependencies"]:
        raise ValueError("browser_dependency_lock_mismatch")
    for name, version in package["dependencies"].items():
        if lock["packages"]["node_modules/" + name]["version"] != version or json.loads((modules / name / "package.json").read_text())["version"] != version:
            raise ValueError("browser_dependency_version_mismatch")
    inventory = {}
    total = 0
    for path in sorted(modules.rglob("*")):
        relative = str(path.relative_to(modules))
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = path.resolve(strict=True)
            if not target.is_relative_to(modules) or not target.is_file():
                raise ValueError("browser_dependency_external_or_directory_alias")
            inventory[relative] = {"link": os.readlink(path)}
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > 256 * 1024 * 1024 or info.st_size > 32 * 1024 * 1024:
                raise ValueError("browser_dependency_inventory_byte_limit")
            inventory[relative] = {"sha256": sha(path), "bytes": info.st_size}
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("browser_dependency_special_file")
        if len(inventory) > 10000:
            raise ValueError("browser_dependency_inventory_entry_limit")
    return {
        "worker": str(worker_root / "worker.mjs"),
        "browser": {"path": str(browser), "sha256": sha(browser)},
        "closure": inventory,
        "closure_bytes": total,
        "scope": "actual local bytes and locked versions; not registry authenticity or signed package proof",
    }


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
            # A test-only approval cannot authorize a runtime or build dependency.
            dev_allowed = rule.get("dev_external_allowed", []) if dep.get("kind") == "dev" else []
            if dep["name"] not in allowed and dep["name"] not in dev_allowed:
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
            escaped = re.escape(item).replace("::", r"\s*::\s*")
            # Bare crate names must be path/import references. A Rust slice's
            # .windows() method is not an import of the Windows OS bindings.
            pattern = (r"\b" + escaped + r"\b" if "::" in item else
                       r"\b" + escaped + r"\s*::|\b(?:use|extern\s+crate)\s+(?:::)?" + escaped + r"(?:\s|;)")
            if re.search(pattern, code):
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

    def run(self, name, command, *, timeout=900, extra_env=None, expected_exit=0):
        entry = {"name": name, "command": command, "cwd": str(ROOT), "started_at": now(), "expected_exit_code": expected_exit}
        started = time.monotonic()
        logs = {}
        with (self.directory / (name + ".stdout.log")).open("xb") as stdout, (self.directory / (name + ".stderr.log")).open("xb") as stderr:
            os.chmod(stdout.name, 0o600); os.chmod(stderr.name, 0o600)
            env = self.env | (extra_env or {})
            proc = None
            try:
                proc = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=os.name == "posix")
                entry["exit_code"] = proc.wait(timeout)
                entry["status"] = "PASS" if entry["exit_code"] == expected_exit else "FAIL"
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
    management_fixture = None
    try:
        if args.browser_references and not args.browser_host:
            raise ValueError("browser_references_requires_browser_host_inputs")
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
        gate.semantic(tc, [] if pin == policy["toolchain"] and re.match(r"^rustc " + re.escape(pin) + r"\s", gate.read("rustc-version")) else ["exact_rustc_and_toolchain_pin_required"])
        gate.semantic(cg, [] if re.match(r"^cargo " + re.escape(pin) + r"\s", gate.read("cargo-version")) else ["exact_cargo_required"])
        if tc["status"] != "PASS" or cg["status"] != "PASS":
            raise ValueError("toolchain_precondition_failed")
        md = gate.run("dependency-metadata", ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked", "--offline"], timeout=60)
        if md["status"] == "PASS":
            gate.semantic(md, metadata_errors(json.loads(gate.read("dependency-metadata")), policy, ROOT))
        gate.run("format", ["cargo", "fmt", "--all", "--", "--check"], timeout=120)
        clippy = gate.run("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--offline", "--", "-D", "warnings"])
        # Later scenario commands compile this same workspace. Preserve the first
        # failure and report required checks missing; do not repeatedly invoke a
        # known failing build or spend native fixtures on an invalid baseline.
        if clippy["status"] != "PASS":
            raise ValueError("workspace_lint_or_compile_precondition_failed")
        # Real-descriptor fixtures share the libtest process. Isolate unrelated
        # fixture lifetimes from another test's fork/exec descriptor window;
        # scenarios retain their own explicit concurrency and child processes.
        tests = gate.run("workspace-tests", ["cargo", "test", "--workspace", "--locked", "--offline", "--", "--test-threads=1"])
        if tests["status"] != "PASS":
            raise ValueError("workspace_regression_precondition_failed")
        # Child helper stdout can interleave with libtest's progress output.
        # The official list-only pass executes nothing and gives a complete,
        # stable ignored inventory without inferring it from progress lines.
        inventory = gate.run("ignored-inventory", ["cargo", "test", "--workspace", "--locked", "--offline", "--", "--ignored", "--list"])
        if inventory["status"] == "PASS":
            ignored = sorted(set(re.findall(r"^(.+): test$", gate.read("ignored-inventory"), re.MULTILINE)))
            receipt["ignored_inventory_source"] = "official_libtest_list_only_no_test_execution"
            receipt["ignored_tests"] = [{"test": name, **policy["known_ignored"].get(name, {"kind": "UNREVIEWED"})} for name in ignored]
            gate.semantic(inventory, ["unreviewed_ignored_test:" + name for name in ignored if name not in policy["known_ignored"]])
        receipt["official_http_sdk"] = {"backend": "owned_counter_fixture_not_native_exec_or_account", "checks": {}}
        for name, test_case in HTTP_TESTS:
            http_root = evidence / ("owned-" + name)
            http_root.mkdir(mode=0o700)
            http = gate.run(name, ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", test_case, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_HTTP_ROOT": str(http_root)})
            gate.semantic(http, [] if "1 passed; 0 failed" in gate.read(name) else ["exact_official_http_case_not_executed"])
            receipt["official_http_sdk"]["checks"][name] = http["status"]
        receipt["management_import"] = "NOT_RUN_explicit_owned_import_not_requested"
        if args.management_import:
            owned = evidence / "owned-management-import"
            owned.mkdir(mode=0o700)
            check = gate.run("management-import", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", MANAGEMENT_IMPORT_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_MANAGEMENT_ROOT":str(owned)})
            gate.semantic(check, [] if "1 passed; 0 failed" in gate.read("management-import") else ["exact_management_import_case_not_executed"])
            try:
                observed=json.loads((owned/"receipt.json").read_text())
                fixture=Path(observed["fixture"])
                valid=observed["status"]=="PASS" and fixture.is_absolute() and fixture.resolve()==fixture and fixture.is_relative_to(owned) and fixture.is_dir()
                gate.semantic(check, [] if valid else ["management_fixture_receipt_not_owned"])
                if valid: management_fixture=fixture
            except (OSError,ValueError,KeyError,TypeError):
                gate.semantic(check,["management_fixture_receipt_missing"])
            receipt["management_import"]=check["status"]
        receipt["enrollment_store"] = "NOT_RUN_explicit_linux_gnu_slice_not_requested"
        if args.enrollment_store:
            payload_root = evidence / "owned-payload-store"
            payload_root.mkdir(mode=0o700)
            payload = gate.run("payload-store", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", PAYLOAD_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_PAYLOAD_ROOT":str(payload_root)})
            gate.semantic(payload, [] if "1 passed; 0 failed" in gate.read("payload-store") else ["exact_payload_inventory_case_not_executed"])
            owned_root = evidence / "owned-enrollment-store"
            owned_root.mkdir(mode=0o700)
            check = gate.run("enrollment-store", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", ENROLLMENT_STORE_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_ENROLLMENT_ROOT": str(owned_root)})
            gate.semantic(check, [] if "1 passed; 0 failed" in gate.read("enrollment-store") else ["exact_linux_gnu_enrollment_store_case_not_executed"])
            receipt["enrollment_store"] = check["status"]
            clock_root = evidence / "owned-enrollment-clock"
            clock_root.mkdir(mode=0o700)
            clock_check = gate.run("enrollment-clock", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", ENROLLMENT_CLOCK_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_ENROLLMENT_CLOCK_ROOT": str(clock_root)})
            gate.semantic(clock_check, [] if "1 passed; 0 failed" in gate.read("enrollment-clock") else ["exact_linux_gnu_enrollment_clock_case_not_executed"])
            receipt["enrollment_clock"] = clock_check["status"]
            recovery_root = evidence / "owned-enrollment-recovery"
            recovery_root.mkdir(mode=0o700)
            recovery_check = gate.run("enrollment-recovery", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", ENROLLMENT_RECOVERY_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_ENROLLMENT_RECOVERY_ROOT": str(recovery_root)})
            gate.semantic(recovery_check, [] if "1 passed; 0 failed" in gate.read("enrollment-recovery") else ["exact_linux_gnu_enrollment_recovery_case_not_executed"])
            receipt["enrollment_recovery"] = recovery_check["status"]
            owned_owner = evidence / "owned-enrollment-owner"
            owned_owner.mkdir(mode=0o700)
            owned_check = gate.run("enrollment-owned", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", ENROLLMENT_OWNED_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_ENROLLMENT_OWNED_ROOT": str(owned_owner)})
            gate.semantic(owned_check, [] if "1 passed; 0 failed" in gate.read("enrollment-owned") else ["exact_enrollment_owned_case_not_executed"])
            receipt["enrollment_owned"] = owned_check["status"]
            fresh_gateway_root = evidence / "owned-fresh-gateway"
            fresh_gateway_root.mkdir(mode=0o700)
            fresh_gateway = gate.run("fresh-gateway-store", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", "store::native_root::gateway_tests::fresh_gateway_material_floor_ready_and_failure_custody", "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_NATIVE_GATEWAY_ROOT": str(fresh_gateway_root)})
            gate.semantic(fresh_gateway, [] if "1 passed; 0 failed" in gate.read("fresh-gateway-store") else ["exact_fresh_gateway_store_case_not_executed"])
            receipt["fresh_gateway_store"] = fresh_gateway["status"]
            fresh_host_root = evidence / "owned-fresh-host"
            fresh_host_root.mkdir(mode=0o700)
            fresh_host = gate.run("fresh-host-store", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", "store::native_root::host::tests::native_host_pending_closed_chain_reopen_and_sticky_unknown_aggregate", "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_NATIVE_HOST_ROOT": str(fresh_host_root)})
            gate.semantic(fresh_host, [] if "1 passed; 0 failed" in gate.read("fresh-host-store") else ["exact_fresh_host_store_case_not_executed"])
            receipt["fresh_host_store"] = fresh_host["status"]
            # Each case owns a distinct root; the gate-race case requires absence.
            for label, test, env_name in (
                ("configuration-owner", CONFIGURATION_OWNER_TEST, "STYX_TEST_CONFIGURATION_ROOT"),
                ("management-preparation", MANAGEMENT_PREPARATION_TEST, "STYX_TEST_MANAGEMENT_ROOT"),
                ("native-root", NATIVE_ROOT_TEST, "STYX_TEST_NATIVE_ROOT_ROOT"),
                ("management-phases", MANAGEMENT_PHASE_TEST, "STYX_TEST_MANAGEMENT_PHASE_ROOT"),
                ("native-transaction", NATIVE_TRANSACTION_TEST, "STYX_TEST_NATIVE_TRANSACTION_ROOT"),
                ("native-service-tip", NATIVE_SERVICE_TIP_TEST, "STYX_TEST_SERVICE_TIP_ROOT"),
                ("native-runtime-update", NATIVE_RUNTIME_UPDATE_TEST, "STYX_TEST_NATIVE_RUNTIME_UPDATE_ROOT"),
            ):
                check = gate.run(label, ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", test, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                    extra_env={env_name: str(evidence / ("owned-" + label))})
                gate.semantic(check, [] if "1 passed; 0 failed" in gate.read(label) else ["exact_" + label + "_case_not_executed"])
                receipt[label.replace("-", "_")] = check["status"]

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
        receipt["signed_enrollment_service"] = "NOT_RUN_explicit_complete_inputs_not_requested"
        if args.enrollment_service:
            if not args.enrollment_store or not args.node22 or not args.tls_fixtures or receipt.get("legacy_node22_interop") != "PASS":
                raise ValueError("enrollment_service_requires_store_node22_tls_inputs_and_valid_node22")
            receipt["tls_fixture_inputs"] = tls_inputs(args.tls_fixtures)
            receipt["tls_fixture_root"] = args.tls_fixtures
            receipt["signed_enrollment_service"] = {}
            for name, test_case, variable in (
                ("enrollment-profile", ENROLLMENT_PROFILE_TEST, None),
                ("enrollment-controller", ENROLLMENT_CONTROLLER_TEST, "STYX_TEST_ENROLLMENT_CONTROLLER_ROOT"),
                ("enrollment-service", ENROLLMENT_SERVICE_TEST, "STYX_TEST_ENROLLMENT_SERVICE_ROOT"),
            ):
                env = {"STYX_TEST_NODE22": str(Path(args.node22)), "STYX_TEST_TLS_FIXTURES": args.tls_fixtures}
                if variable:
                    owned = evidence / ("owned-" + name)
                    owned.mkdir(mode=0o700)
                    env[variable] = str(owned)
                check = gate.run(name, ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", test_case, "--", "--ignored", "--exact", "--nocapture"], timeout=180, extra_env=env)
                gate.semantic(check, [] if "1 passed; 0 failed" in gate.read(name) else ["exact_signed_enrollment_case_not_executed"])
                receipt["signed_enrollment_service"][name] = check["status"]
        receipt["tls_transport_interop"] = "NOT_RUN_explicit_test_pki_not_supplied"
        if args.tls_fixtures:
            receipt["tls_fixture_inputs"] = tls_inputs(args.tls_fixtures)
            receipt["tls_fixture_root"] = args.tls_fixtures
            receipt["tls_transport_interop"] = {}
            for name, test_case in TLS_TESTS:
                check = gate.run(name, ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", test_case, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                    extra_env={"STYX_TEST_TLS_FIXTURES": args.tls_fixtures})
                gate.semantic(check, [] if "1 passed; 0 failed" in gate.read(name) else ["exact_tls_case_not_executed"])
                receipt["tls_transport_interop"][name] = check["status"]
        receipt["real_codex_interop"] = "NOT_RUN_explicit_codex_not_supplied"
        if args.codex_bin:
            codex = Path(args.codex_bin)
            if sys.platform != "linux" or not codex.is_absolute() or not codex.is_file() or not os.access(codex, os.X_OK):
                raise ValueError("linux_slice_requires_explicit_absolute_codex_executable")
            receipt["codex_input"] = {"path": str(codex), "sha256": sha(codex)}
            gate.run("codex-version", [str(codex), "--version"], timeout=30)
            receipt["real_codex_interop"] = {}
            native_cases = CODEX_TESTS + ([("host-wire", HOST_WIRE_TEST), ("host-action-wire", HOST_ACTION_WIRE_TEST)] if args.tls_fixtures else [])
            for name, test_case in native_cases:
                exec_root = evidence / ("owned-native-" + name)
                exec_root.mkdir(mode=0o700)
                native = gate.run(name, ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", test_case, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                    extra_env={"STYX_TEST_CODEX": str(codex), "STYX_TEST_EXEC_ROOT": str(exec_root),
                        **({"STYX_TEST_TLS_FIXTURES": args.tls_fixtures} if args.tls_fixtures else {})})
                gate.semantic(native, [] if "1 passed; 0 failed" in gate.read(name) else ["exact_real_codex_case_not_executed"])
                receipt["real_codex_interop"][name] = native["status"]
        receipt["browser_host_native"] = "NOT_RUN_explicit_inputs_not_requested"
        if args.browser_host:
            if sys.platform != "linux" or not args.node22 or not args.codex_bin or not args.browser_executable or receipt.get("legacy_node22_interop") != "PASS":
                raise ValueError("browser_host_requires_linux_node22_codex_browser_executable")
            browser = browser_inputs(args.browser_executable)
            receipt["browser_inputs"] = browser
            check = gate.run("browser-worker-config", [args.node22, "--test", "src/providers/browser-worker/config.test.mjs"], timeout=30)
            version = gate.run("browser-version", [args.browser_executable, "--version"], timeout=30)
            owned = evidence / "owned-browser-host"
            owned.mkdir(mode=0o700)
            check = gate.run("browser-host", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", BROWSER_HOST_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=180,
                extra_env={"STYX_TEST_CODEX": args.codex_bin, "STYX_TEST_BROWSER_ROOT": str(owned), "STYX_TEST_BROWSER_NODE": args.node22,
                           "STYX_TEST_BROWSER_WORKER": browser["worker"], "STYX_TEST_BROWSER_EXECUTABLE": args.browser_executable})
            gate.semantic(check, [] if "1 passed; 0 failed" in gate.read("browser-host") else ["exact_actual_browser_host_case_not_executed"])
            try:
                receipts = list(owned.glob("*/receipt.json"))
                if len(receipts) != 1 or receipts[0].is_symlink() or receipts[0].resolve() != receipts[0]:
                    raise ValueError("unique_owned_browser_receipt_required")
                scenario = json.loads(receipts[0].read_text())
                gate.semantic(check, [] if scenario.get("status") == "PASS" and scenario.get("host_browser_cleanup_complete") is True and scenario.get("http_server_joined") is True else ["browser_independent_effect_or_cleanup_receipt_failed"])
            except (OSError, ValueError):
                gate.semantic(check, ["browser_scenario_receipt_missing_or_invalid"])
            receipt["browser_host_native"] = check["status"]
            if args.browser_references:
                refs = evidence / "owned-browser-references"
                refs.mkdir(mode=0o700)
                check = gate.run("browser-references", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", BROWSER_REFERENCE_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=180,
                    extra_env={"STYX_TEST_CODEX": args.codex_bin, "STYX_TEST_BROWSER_ROOT": str(refs), "STYX_TEST_BROWSER_NODE": args.node22,
                               "STYX_TEST_BROWSER_WORKER": browser["worker"], "STYX_TEST_BROWSER_EXECUTABLE": args.browser_executable})
                gate.semantic(check, [] if "1 passed; 0 failed" in gate.read("browser-references") else ["exact_actual_browser_reference_case_not_executed"])
                try:
                    receipts = list(refs.glob("*/receipt.json"))
                    if len(receipts) != 1 or receipts[0].is_symlink() or receipts[0].resolve() != receipts[0]:
                        raise ValueError("unique_owned_browser_reference_receipt_required")
                    scenario = json.loads(receipts[0].read_text())
                    gate.semantic(check, [] if scenario.get("status") == "PASS" and scenario.get("host_browser_cleanup_complete") is True and scenario.get("http_server_joined") is True else ["browser_reference_effect_or_cleanup_receipt_failed"])
                except (OSError, ValueError):
                    gate.semantic(check, ["browser_reference_receipt_missing_or_invalid"])
                receipt["browser_references_native"] = check["status"]
        receipt["paired_host_native"] = "NOT_RUN_explicit_inputs_not_requested"
        if args.paired_host:
            if not args.codex_bin or not args.enrollment_service or not args.node22 or not args.tls_fixtures:
                raise ValueError("paired_host_requires_codex_enrollment_service_node22_tls")
            owned = evidence / "owned-paired-host"
            owned.mkdir(mode=0o700)
            check = gate.run("paired-host", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", PAIRED_HOST_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=180,
                extra_env={"STYX_TEST_CODEX_BIN": str(Path(args.codex_bin)), "STYX_TEST_NODE22": str(Path(args.node22)), "STYX_TEST_TLS_FIXTURES": args.tls_fixtures, "STYX_TEST_PAIRED_ROOT": str(owned)})
            gate.semantic(check, [] if "1 passed; 0 failed" in gate.read("paired-host") else ["exact_paired_native_case_not_executed"])
            receipt["paired_host_native"] = check["status"]
        receipt["linux_discovery"] = "NOT_RUN_explicit_readonly_linux_snapshot_not_requested"
        if args.linux_discovery:
            if sys.platform != "linux":
                raise ValueError("linux_discovery_requires_linux")
            # Test creates its own leaf directory; no deployment/profile is opened.
            check = gate.run("linux-discovery", ["cargo", "test", "-p", "styx-runtime", "--locked", "--offline", LINUX_DISCOVERY_TEST, "--", "--ignored", "--exact", "--nocapture"], timeout=120,
                extra_env={"STYX_TEST_LINUX_DISCOVERY_ROOT": str(evidence / "owned-linux-discovery")})
            gate.semantic(check, [] if "1 passed; 0 failed" in gate.read("linux-discovery") else ["exact_linux_discovery_case_not_executed"])
            receipt["linux_discovery"] = check["status"]
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
            if args.linux_discovery:
                step = gate.run("cli-desktop-candidates", [str(binary), "doctor", "--desktop-sessions", "--json"], timeout=10,
                    extra_env={"DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/nonexistent-styx-negative-control", "WAYLAND_DISPLAY": "not-an-authorized-display", "HYPRLAND_INSTANCE_SIGNATURE": "not-an-authorized-compositor"})
                try:
                    snapshot = json.loads(gate.read("cli-desktop-candidates"))
                    valid = snapshot["schema"] == 1 and snapshot["connection_closed"] is True and all(
                        item["uid"] == os.getuid() and item["agent_association"] == "unknown" and item["compositor_association"] == "unknown"
                        for item in snapshot["candidates"])
                except (ValueError, KeyError, TypeError):
                    valid = False
                gate.semantic(step, [] if valid else ["candidate_diagnostics_not_unknown_only_actual_user"])
            if args.management_import:
                if management_fixture is None: raise ValueError("management_fixture_unavailable_for_cli")
                check=gate.run("cli-management-plan",[str(binary),"plan","--state-dir",str(management_fixture),"--json"],timeout=10)
                try:
                    view=json.loads(gate.read("cli-management-plan"))
                    valid=view["roles"]["gateway"]=="external" and view["host_manager"]=="unspecified" and view["app_login"]["desired_enabled"] is False and view["plan_execution"]=="not_authorized_read_only" and all(not step["replay_authorized"] for step in view["steps"])
                except (ValueError,KeyError,TypeError): valid=False
                gate.semantic(check,[] if valid else ["management_cli_did_not_preserve_read_only_unknown_intent"])
            # A skeleton must reject unimplemented business, never return empty success.
            reject = gate.run("cli-unimplemented-reject", [str(binary), "exec", "--command", "never-run"], timeout=30, expected_exit=2)
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
            if args.browser_host and "browser_inputs" in receipt:
                receipt["browser_input_stability"] = "PASS" if browser_inputs(args.browser_executable) == receipt["browser_inputs"] else "FAIL"
            if args.tls_fixtures and "tls_fixture_inputs" in receipt:
                receipt["tls_stability"] = "PASS" if tls_inputs(args.tls_fixtures) == receipt["tls_fixture_inputs"] else "FAIL"
        except (OSError, ValueError):
            receipt["input_stability"] = "FAIL"
            if args.tls_fixtures:
                receipt["tls_stability"] = "FAIL"
        required = {"git-head", "git-status", "git-head-end", "git-status-end", "rustc-version", "cargo-version", "dependency-metadata", "format", "clippy", "workspace-tests", "ignored-inventory", "official-http-sdk", "python-oracles", "cli-build", "cli-help", "cli-version", "cli-build-info", "cli-unimplemented-reject"}
        required |= {name for name, _ in HTTP_TESTS}
        if args.management_import:
            required |= {"management-import","cli-management-plan"}
        if args.linux_discovery:
            required |= {"linux-discovery", "cli-desktop-candidates"}
        if args.enrollment_store:
            required |= {"payload-store", "enrollment-store", "enrollment-clock", "enrollment-recovery", "enrollment-owned", "configuration-owner", "management-preparation", "native-root", "management-phases", "native-transaction", "native-service-tip", "native-runtime-update"}
        if args.enrollment_service:
            required |= {"enrollment-profile", "enrollment-controller", "enrollment-service"}
        if args.paired_host:
            required |= {"paired-host"}
        if args.browser_host:
            required |= {"browser-worker-config", "browser-version", "browser-host"}
        if args.browser_references:
            required |= {"browser-references"}
        if args.node22:
            required |= {"node22-version", "node22-crypto"}
        if args.codex_bin:
            required |= {"codex-version"} | {name for name, _ in CODEX_TESTS}
        if args.tls_fixtures:
            required |= {name for name, _ in TLS_TESTS}
            if args.codex_bin:
                required |= {"host-wire", "host-action-wire"}
        receipt["missing_required_checks"] = sorted(required - {x["name"] for x in gate.checks})
        receipt["status"] = "PASS" if not receipt["missing_required_checks"] and gate.checks and all(x["status"] == "PASS" for x in gate.checks) and receipt.get("input_stability") == "PASS" and receipt.get("git_stability") == "PASS" and receipt.get("node22_stability", "PASS") == "PASS" and receipt.get("codex_stability", "PASS") == "PASS" and receipt.get("tls_stability", "PASS") == "PASS" and receipt.get("browser_input_stability", "PASS") == "PASS" and "failure" not in receipt else "FAIL"
        receipt["completed_at"] = now()
        (evidence / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "receipt": str(evidence / "receipt.json"), "scope": "foundation_development_only"}), flush=True)
    return receipt["status"] == "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, help="fresh absolute external evidence directory")
    parser.add_argument("--target-dir", help="absolute external Cargo build cache; reused only by explicit choice")
    parser.add_argument("--management-import", action="store_true", help="owned Linux raw legacy management import and CLI plan only; no transaction/migration claim")
    parser.add_argument("--browser-references", action="store_true", help="actual owned Browser opaque references/navigation/tab/reopen scene; requires --browser-host, not platform acceptance")
    parser.add_argument("--browser-host", action="store_true", help="actual Linux headless Browser Host scenario; requires Node22, Codex and browser executable; no desktop/account/package claim")
    parser.add_argument("--browser-executable", help="canonical explicit Chrome/Chromium binary; no download or installed profile is opened")
    parser.add_argument("--linux-discovery", action="store_true", help="actual read-only fixed system-bus candidate snapshot plus CLI; no desktop authorization")
    parser.add_argument("--paired-host", action="store_true", help="actual paired TLS/MCP/WSS/native scene; requires Codex, Node22, TLS and enrollment service inputs")
    parser.add_argument("--enrollment-service", action="store_true", help="run actual signed enrollment TLS service; requires --enrollment-store, --node22 and --tls-fixtures")
    parser.add_argument("--enrollment-store", action="store_true", help="run the Linux GNU owned private-file/process-crash journal slice")
    parser.add_argument("--node22", help="absolute explicit Node22 executable for real legacy crypto interop")
    parser.add_argument("--tls-fixtures", help="explicit external test-only PKI directory; never product identity material")
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
