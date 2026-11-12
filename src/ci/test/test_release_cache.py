"""Producer cache policy tests; subprocesses are fixtures, never native acceptance."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
PRODUCER = ROOT / 'src/tools/release/build-native-binary.py'


class NativeReleaseCacheTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix='styx-release-cache-test-')
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name).resolve()
        self.target = self.root / 'cargo-target'
        self.target.mkdir()
        self.revision = 'a' * 40
        self.inputs = {'Cargo.toml': 'b' * 64}
        self.gate = self.root / 'gate.json'
        self.gate.write_text(json.dumps(dict(status='PASS', input_stability='PASS',
                                             source_revision=self.revision, inputs=self.inputs)))
        self.output = self.root / 'native-output'
        self.subject = runpy.run_path(str(PRODUCER))
        self.calls = []

    def command(self, argv):
        if argv == ['git', 'rev-parse', 'HEAD']:
            return self.revision
        if argv == ['git', 'status', '--porcelain']:
            return ''
        if argv == ['rustc', '-vV']:
            return 'rustc fixture\nhost: x86_64-unknown-linux-gnu\n'
        raise AssertionError(argv)

    def child(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ['cargo', 'build']:
            binary = self.target / 'x86_64-unknown-linux-gnu/release/styx'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'explicit-test-fixture-not-an-executable')
        elif argv[1:] == ['build-info', '--json']:
            report = dict(schema=1, target='x86_64-unknown-linux-gnu',
                          minimum_release_reader='native_runtime_migrated_v1',
                          supported_state_readers=['native_management_state_v1', 'native_migrated_state_v1'])
            kwargs['stdout'].write(json.dumps(report).encode())
        elif argv[:2] != ['cargo', 'clean']:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0)

    def invoke(self, *flags):
        argv = [str(PRODUCER), '--source-revision', self.revision,
                '--gate-receipt', str(self.gate), '--target-dir', str(self.target),
                '--output', str(self.output), '--jobs', '8', *flags]
        globals_ = self.subject['main'].__globals__
        with patch.object(sys, 'argv', argv), \
             patch.dict(globals_, command=self.command), \
             patch.object(self.subject['subprocess'], 'run', self.child), \
             patch.object(self.subject['runpy'], 'run_path', return_value={'source_inputs': lambda root: self.inputs}), \
             contextlib.redirect_stdout(io.StringIO()):
            return self.subject['main']()

    def test_reuse_still_builds_and_observes_binary_without_clean(self):
        self.assertEqual(self.invoke('--reuse-workspace-cache'), 0)
        self.assertFalse(any(argv[:2] == ['cargo', 'clean'] for argv in self.calls))
        self.assertTrue(any(argv[:2] == ['cargo', 'build'] for argv in self.calls))
        self.assertTrue(any(argv[1:] == ['build-info', '--json'] for argv in self.calls))
        receipt = json.loads((self.output / 'receipt.json').read_text())
        self.assertEqual(receipt['status'], 'PASS')
        self.assertTrue(receipt['workspace_clean']['skipped'])
        self.assertEqual(receipt['cargo_jobs'], 8)

    def test_default_preserves_existing_clean_policy(self):
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.calls[0][:2], ['cargo', 'clean'])
        self.assertEqual(self.calls[1][:2], ['cargo', 'build'])

    def test_archive_cannot_opt_into_workspace_reuse(self):
        with self.assertRaisesRegex(RuntimeError, 'workspace_cache_reuse_requires_git_checkout'):
            self.invoke('--reuse-workspace-cache', '--source-archive-manifest', str(self.root / 'archive.json'),
                        '--expected-source-archive-sha256', 'c' * 64)
        self.assertFalse(self.calls)
        self.assertFalse(self.output.exists())

    def test_reuse_does_not_bypass_matching_gate(self):
        value = json.loads(self.gate.read_text())
        value['source_revision'] = 'd' * 40
        self.gate.write_text(json.dumps(value))
        self.assertEqual(self.invoke('--reuse-workspace-cache'), 1)
        self.assertFalse(self.calls)
        self.assertEqual(json.loads((self.output / 'receipt.json').read_text())['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
