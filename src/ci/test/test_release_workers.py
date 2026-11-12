"""Manifest refresh binding tests; signing observations below are synthetic."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]


class WorkerManifestRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='styx-worker-refresh-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.workers = self.root / 'worker-release'
        self.workers.mkdir()
        self.subject = runpy.run_path(str(ROOT / 'src/ci/release-workers.py'))
        self.revision = 'a' * 40
        for relative in ('bin/codex', 'bin/node', 'packages/example/package.json'):
            file = self.workers / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(('upstream fixture ' + relative).encode())
        for component in ('codex', 'node'):
            self.write(self.workers / f'provenance/{component}.json',
                       dict(binary_sha256=self.sha(self.workers / f'bin/{component}')))
        self.args = argparse.Namespace(worker_release=self.workers, platform='macos', version='0.4.0')
        self.refresh()
        self.original = (self.workers / 'manifest.json').read_bytes()
        self.write(self.root / 'preparation.json', dict(status='PASS', signed=False,
                   source_revision=self.revision, platform='macos', version='0.4.0',
                   producer='src/ci/release-workers.py', worker_manifest_sha256=self.sha(self.workers / 'manifest.json')))
        observations = []
        for relative in ('worker-release/bin/codex', 'worker-release/bin/node', 'tunnel/tunnel-client-runtime'):
            image = self.root / relative
            image.parent.mkdir(parents=True, exist_ok=True)
            if not image.exists():
                image.write_bytes(b'upstream tunnel fixture')
            upstream = self.sha(image)
            image.write_bytes(image.read_bytes() + b' synthetic signature bytes')
            signed = self.sha(image)
            observations.append(dict(path=relative, upstream_sha256=upstream, signed_sha256=signed,
                signature=dict(status='PASS', sign_actual_wait=True, verify_actual_wait=True,
                               sign_exit_code=0, verify_exit_code=0,
                               source_image_sha256=upstream, signed_image_sha256=signed)))
        self.write(self.root / 'worker-signing-receipt.json',
                   dict(status='PASS', source_revision=self.revision, workers=observations))

    def sha(self, file):
        return self.subject['digest'](file)

    def write(self, file, value):
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(value))

    def refresh(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.subject['manifest'](self.args)

    def test_refresh_binds_current_manifest_and_signing_receipt(self):
        self.refresh()
        refreshed = json.loads((self.root / 'manifest-refresh.json').read_text())
        self.assertEqual(refreshed['status'], 'PASS')
        self.assertEqual(refreshed['source_revision'], self.revision)
        self.assertEqual(refreshed['manifest_sha256'], self.sha(self.workers / 'manifest.json'))
        self.assertEqual(refreshed['signing_receipt_sha256'], self.sha(self.root / 'worker-signing-receipt.json'))
        node = json.loads((self.workers / 'provenance/node.json').read_text())
        self.assertEqual(node['binary_sha256'], self.sha(self.workers / 'bin/node'))
        self.assertIn('upstream_binary_sha256', node)

    def test_unsigned_dependency_change_is_refused_before_manifest_write(self):
        (self.workers / 'packages/example/package.json').write_bytes(b'changed unsigned dependency')
        with self.assertRaisesRegex(ValueError, 'unsigned dependency changed'):
            self.refresh()
        self.assertEqual((self.workers / 'manifest.json').read_bytes(), self.original)
        self.assertFalse((self.root / 'manifest-refresh.json').exists())

    def test_changed_signed_image_is_refused(self):
        (self.workers / 'bin/node').write_bytes(b'changed after signing')
        with self.assertRaisesRegex(ValueError, 'differs from completed signature'):
            self.refresh()

    def test_changed_original_manifest_is_refused(self):
        with (self.workers / 'manifest.json').open('ab') as stream:
            stream.write(b' ')
        with self.assertRaisesRegex(ValueError, 'manifest must match preparation'):
            self.refresh()

    def test_wrong_signing_source_is_refused(self):
        receipt = self.root / 'worker-signing-receipt.json'
        value = json.loads(receipt.read_text())
        value['source_revision'] = 'b' * 40
        self.write(receipt, value)
        with self.assertRaisesRegex(ValueError, 'must match preparation source'):
            self.refresh()

    def test_completed_refresh_cannot_be_replayed(self):
        self.refresh()
        with self.assertRaisesRegex(ValueError, 'refresh cannot be replayed'):
            self.refresh()


if __name__ == '__main__':
    unittest.main()
