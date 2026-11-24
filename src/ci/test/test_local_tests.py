import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "local-tests.py"
ROOT = SCRIPT.parents[2]
PIN = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]


class LocalTestsEntry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        bindir = Path(self.tmp.name)
        cargo = bindir / "cargo"
        cargo.write_text('''#!/bin/sh
if [ "$1" = "--version" ]; then echo "cargo ${FAKE_VERSION} (fake)"; exit 0; fi
case "$FAKE_CASE" in
  failed) exit 7 ;;
  zero) echo 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out' ;;
  *) echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' ;;
esac
''')
        cargo.chmod(0o755)
        rustc = bindir / "rustc"
        rustc.write_text('#!/bin/sh\necho "rustc ${FAKE_VERSION} (fake)"\n')
        rustc.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""),
                        FAKE_VERSION=PIN)

    def run_entry(self, *args, case="pass"):
        return subprocess.run([sys.executable, str(SCRIPT), *args], env=dict(self.env, FAKE_CASE=case),
                              text=True, capture_output=True)

    def test_command_failure_and_zero_tests_fail(self):
        for case in ("failed", "zero"):
            with self.subTest(case=case):
                result = self.run_entry("unit", "--package", "styx-core", case=case)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("PASS: selected", result.stdout)
        result = self.run_entry("contracts", case="zero")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PASS: selected", result.stdout)

    def test_mismatched_tool_version_fails(self):
        self.env["FAKE_VERSION"] = "0.0.0"
        result = self.run_entry("unit", "--package", "styx-core")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match pinned", result.stderr)

    def test_valid_package_runs_locked_offline_serial(self):
        result = self.run_entry("unit", "--package", "styx-core")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--locked --offline", result.stdout)
        self.assertIn("--test-threads=1", result.stdout)

    def test_unknown_package_and_missing_evidence_fail_before_running(self):
        for args in (("unit", "--package", "unknown"), ("integration",)):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_entry(*args).returncode, 0)

    def test_dry_run_does_not_claim_pass(self):
        result = self.run_entry("--dry-run", "contracts")
        self.assertEqual(result.returncode, 0)
        self.assertIn("NOT RUN", result.stdout)
        self.assertNotIn("PASS: selected", result.stdout)


if __name__ == "__main__":
    unittest.main()
