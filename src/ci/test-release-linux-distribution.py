#!/usr/bin/env python3
"""User distribution fixtures; never install a real Styx or activate a runtime."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("release_linux", Path(__file__).with_name("release-linux.py"))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
PIN = "a" * 64


class LinuxDistribution(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="styx distribution fixture ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "signed runtime"
        self.payload = self.runtime / "payload"
        (self.payload / "bin").mkdir(parents=True)
        # This fake executable only reports argv; it performs no installation.
        (self.payload / "bin/styx").write_text("#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
        (self.payload / "bin/styx").chmod(0o755)
        (self.runtime / "publisher.pem").write_text("UNIT FIXTURE PUBLIC KEY\n")
        (self.payload / "manifest.sig").write_bytes(b"unit fixture signature")
        self.manifest = {"version": "0.4.1-preview.1", "target": "x86_64-unknown-linux-gnu",
                         "entrypoint": "bin/styx", "source": {"revision": "b" * 40},
                         "external_workers": ["tunnel_client"]}
        self.save_manifest()

    def save_manifest(self):
        (self.payload / "manifest.json").write_text(json.dumps(self.manifest))

    def args(self, mode="gateway"):
        return argparse.Namespace(runtime_dir=self.runtime, verifier=Path("/unit-fixture-verifier"),
                                  expected_publisher=PIN, mode=mode, output=self.root / "output")

    def produce(self, args):
        with mock.patch.object(RELEASE, "verified_runtime", return_value={"scope": "unit_fixture"}) as verify:
            RELEASE.distribution(args)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(verify.call_args_list[0].args, (args.verifier, self.payload, self.runtime / "publisher.pem", PIN))
        receipt = json.loads((args.output / "distribution.json").read_text())
        self.assertEqual(receipt["installation"], "NOT_RUN")
        self.assertEqual(receipt["runtime_activation"], "NOT_RUN")
        return receipt

    def test_gateway_archive_single_entry_and_quoted_paths(self):
        original = {str(p.relative_to(self.payload)): p.read_bytes() for p in self.payload.rglob("*") if p.is_file()}
        args = self.args()
        receipt = self.produce(args)
        archive = Path(receipt["archive"])
        self.assertTrue(archive.name.endswith("-gateway-only.tar.gz"))
        extracted = self.root / "user extraction with spaces"
        with tarfile.open(archive) as packaged:
            if hasattr(tarfile, "data_filter"):
                packaged.extractall(extracted, filter="data")
            else:
                packaged.extractall(extracted)  # Only this test's generated regular files.
        bundle = next(extracted.iterdir())
        self.assertEqual({p.name for p in bundle.iterdir()}, {"payload", "publisher.pem", "README.md", "install.sh"})
        self.assertEqual(original, {str(p.relative_to(bundle / "payload")): p.read_bytes()
                                    for p in (bundle / "payload").rglob("*") if p.is_file()})
        reply = subprocess.run([str(bundle / "install.sh")], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(reply.stdout), ["install", "--payload-dir", str(bundle / "payload"),
                         "--publisher-file", str(bundle / "publisher.pem"), "--expected-publisher", PIN,
                         "--authorize", "--setup", "--mode", "gateway"])
        self.assertIn("systemd linger", (bundle / "README.md").read_text())

    def test_desktop_keeps_all_signed_workers_and_selects_desktop_mode(self):
        self.manifest["external_workers"] += ["codex_exec", "browser_node22", "cua_native"]
        self.save_manifest()
        args = self.args("desktop")
        receipt = self.produce(args)
        self.assertTrue(receipt["archive"].endswith("-desktop.tar.gz"))
        bundle = next(p for p in args.output.iterdir() if p.is_dir())
        reply = subprocess.run([str(bundle / "install.sh")], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(reply.stdout)[-2:], ["--mode", "desktop"])
        self.assertEqual((bundle / "payload/manifest.json").read_bytes(), (self.payload / "manifest.json").read_bytes())

    def test_mode_mismatch_does_not_create_an_output(self):
        args = self.args("desktop")
        with mock.patch.object(RELEASE, "verified_runtime", return_value={}):
            with self.assertRaisesRegex(ValueError, "workers"):
                RELEASE.distribution(args)
        self.assertFalse(args.output.exists())

    def test_rejected_signature_never_copies_or_runs_the_runtime(self):
        args = self.args()
        with mock.patch.object(RELEASE, "verified_runtime", side_effect=subprocess.CalledProcessError(2, "fixture verifier")):
            with self.assertRaises(subprocess.CalledProcessError):
                RELEASE.distribution(args)
        self.assertFalse(args.output.exists())

    def test_existing_output_is_not_overwritten(self):
        args = self.args()
        args.output.mkdir()
        marker = args.output / "keep"
        marker.write_text("existing user output")
        with mock.patch.object(RELEASE, "verified_runtime", return_value={}):
            with self.assertRaises(FileExistsError):
                RELEASE.distribution(args)
        self.assertEqual(marker.read_text(), "existing user output")


if __name__ == "__main__":
    unittest.main()
