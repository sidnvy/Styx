"""Release boundaries: real archive/pin/asset failures must stop publication."""
import argparse
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'release-ci.py'
spec = importlib.util.spec_from_file_location('release_ci', SCRIPT)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_tar(self, name, kind=tarfile.REGTYPE):
        file = self.root / 'input.tar.gz'
        with tarfile.open(file, 'w:gz') as tar:
            row = tarfile.TarInfo(name)
            row.type = kind
            if kind == tarfile.REGTYPE:
                row.size = 2
                row.mode = 0o700
                tar.addfile(row, io.BytesIO(b'ok'))
            else:
                row.linkname = '/etc/passwd'
                tar.addfile(row)
        return file

    def test_extract_rejects_unsafe_members_before_writing(self):
        for name, kind in [('../outside', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('a//b', tarfile.REGTYPE), ('link', tarfile.SYMTYPE),
                           ('hardlink', tarfile.LNKTYPE), ('C:/drive', tarfile.REGTYPE)]:
            with self.subTest(name=name):
                target = self.root / 'output'
                with self.assertRaises(ValueError):
                    ci.extract(self.make_tar(name, kind), target)
                self.assertFalse(target.exists())

    def test_artifact_roundtrip_preserves_executable_and_private_modes(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'styx').write_bytes(b'binary')
        (source / 'styx').chmod(0o700)
        (source / 'manifest.sig').write_bytes(b'signature')
        (source / 'manifest.sig').chmod(0o600)
        archive = self.root / 'native.tar.gz'
        ci.bundle(argparse.Namespace(source=source, output=archive))
        output = self.root / 'restored'
        ci.extract(archive, output)
        self.assertEqual((output / 'styx').read_bytes(), b'binary')
        self.assertEqual((output / 'styx').stat().st_mode & 0o777, 0o700)
        self.assertEqual((output / 'manifest.sig').stat().st_mode & 0o777, 0o600)

    def test_worker_executable_contract_survives_non_posix_input_modes(self):
        source = self.root / 'workers'
        (source / 'worker-release/bin').mkdir(parents=True)
        image = source / 'worker-release/bin/codex.exe'
        image.write_bytes(b'PE fixture')
        image.chmod(0o600)
        (source / 'worker-release/manifest.json').write_text(
            '{"files":[{"path":"bin/codex.exe","executable":true}]}')
        archive = self.root / 'windows-workers.tar.gz'
        ci.bundle(argparse.Namespace(source=source, output=archive))
        ci.extract(archive, self.root / 'restored')
        self.assertEqual((self.root / 'restored/worker-release/bin/codex.exe').stat().st_mode & 0o777, 0o700)

    def test_publish_requires_matching_actual_tag(self):
        with patch.dict(os.environ, {'GITHUB_REF_NAME': 'v99.0.0', 'GITHUB_REF_TYPE': 'tag'}):
            with self.assertRaisesRegex(ValueError, 'matching immutable'):
                ci.metadata(argparse.Namespace(publish=True, build_number=1))

    def test_checksums_refuse_partial_release(self):
        (self.root / 'Styx-1.2.3-windows-x64.exe').write_bytes(b'exe')
        with self.assertRaisesRegex(ValueError, 'missing or unexpected'):
            ci.checksums(argparse.Namespace(output=self.root, version='1.2.3'))
        self.assertFalse((self.root / 'SHA256SUMS').exists())

    def test_checksums_cover_all_four_assets(self):
        names = ['windows-x64.exe', 'macos-arm64.dmg', 'linux-x64.tar.gz', 'gateway-debian12-x64.tar.gz']
        for name in names:
            (self.root / ('Styx-1.2.3-' + name)).write_bytes(name.encode())
        ci.checksums(argparse.Namespace(output=self.root, version='1.2.3'))
        rows = (self.root / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(rows), 4)
        for row in rows:
            digest, name = row.split('  ')
            self.assertEqual(digest, ci.digest(self.root / name))

    def test_linux_distribution_retains_signed_payload_and_includes_public_setup_inputs(self):
        sealed = self.root / 'sealed'
        for name in ['linux', 'linux-gateway']:
            folder = sealed / name
            (folder / 'payload/bin').mkdir(parents=True)
            (folder / 'payload/bin/styx').write_bytes(b'native fixture')
            (folder / 'payload/bin/styx').chmod(0o700)
            (folder / 'payload/manifest.sig').write_bytes(b'exact signed bytes')
            (folder / 'publisher.pem').write_bytes(b'public pin fixture')
            (folder / 'build-receipt.json').write_text('{"status":"PASS","version":"1.2.3"}')
        assets = self.root / 'assets'
        ci.linux_assets(argparse.Namespace(sealed=sealed, output=assets, version='1.2.3'))
        for file in assets.iterdir():
            with tarfile.open(file) as archive:
                self.assertEqual(archive.extractfile('payload/manifest.sig').read(), b'exact signed bytes')
                self.assertEqual(archive.extractfile('publisher.pem').read(), b'public pin fixture')
                self.assertIn(b'./payload/bin/styx setup', archive.extractfile('README.txt').read())

    def test_disposable_runner_cleanup_does_not_wait_for_security_dialogs(self):
        folder = self.root / 'signing'
        folder.mkdir()
        (folder / 'signing.keychain-db').write_bytes(b'private fixture')
        (folder / 'ephemeral-code-sign-trust').touch()
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}), \
             patch.object(ci, 'security', side_effect=AssertionError('cleanup opened an interactive Security API')), \
             patch.object(ci.subprocess, 'run', side_effect=AssertionError('cleanup launched a dialog')):
            ci.mac_keychain_clean(argparse.Namespace(directory=folder))
        self.assertFalse(folder.exists())

    def test_publisher_secret_must_match_compiled_pin_and_is_removed_on_failure(self):
        key = subprocess.check_output(['openssl', 'genpkey', '-algorithm', 'ED25519'])
        public = subprocess.check_output(['openssl', 'pkey', '-pubout', '-outform', 'DER'], input=key)
        output = self.root / 'temporary.pem'
        with patch.dict(os.environ, {'STYX_PUBLISHER_PRIVATE_KEY_PEM': key.decode()}):
            with self.assertRaisesRegex(ValueError, 'compiled public pin'):
                ci.publisher_key(argparse.Namespace(output=output))
        self.assertFalse(output.exists())
        with patch.dict(os.environ, {'STYX_PUBLISHER_PRIVATE_KEY_PEM': key.decode()}), \
             patch.object(ci, 'PIN', hashlib.sha256(public).hexdigest()):
            ci.publisher_key(argparse.Namespace(output=output))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
