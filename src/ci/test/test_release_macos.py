import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / 'release-macos.py'


class MacWorkerSigningTests(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(SCRIPT), run_name='mac_worker_signing_test')
        self.scratch = tempfile.TemporaryDirectory(prefix='styx-mac-sign-test-')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.cua = self.root / 'cua-driver'
        self.cua.write_bytes(b'current-source Cua helper fixture')
        preparation = dict(status='PASS', signed=False, source_revision='a' * 40,
                           platform='macos', producer='src/ci/release-workers.py',
                           cua_binary_sha256=hashlib.sha256(self.cua.read_bytes()).hexdigest())
        (self.root / 'preparation.json').write_text(json.dumps(preparation))
        for member in ('worker-release/bin/codex', 'worker-release/bin/node',
                       'tunnel/tunnel-client-runtime'):
            file = self.root / member
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(member.encode())
        self.args = types.SimpleNamespace(input_dir=self.root, local_signing=self.root / 'config.json',
                                          source_revision='a' * 40)

    def test_signs_only_fresh_unsigned_inputs_and_refuses_replay(self):
        calls = []

        def signer(command, **kwargs):
            file = Path(command[-1])
            calls.append(file.relative_to(self.root).as_posix())
            before = hashlib.sha256(file.read_bytes()).hexdigest()
            file.write_bytes(file.read_bytes() + b'-signed-fixture')
            return json.dumps(dict(status='PASS', sign_actual_wait=True, verify_actual_wait=True,
                                   sign_exit_code=0, verify_exit_code=0, source_image_sha256=before,
                                   signed_image_sha256=hashlib.sha256(file.read_bytes()).hexdigest())).encode()

        with mock.patch.object(self.module['subprocess'], 'check_output', side_effect=signer):
            self.module['sign_workers'](self.args)
            with self.assertRaises(FileExistsError):
                self.module['sign_workers'](self.args)
        self.assertEqual(calls, ['worker-release/bin/codex', 'worker-release/bin/node',
                                 'tunnel/tunnel-client-runtime'])
        receipt = json.loads((self.root / 'worker-signing-receipt.json').read_text())
        self.assertEqual(receipt['status'], 'PASS')
        self.assertFalse(receipt['publisher_manifest_created'])

    def test_failed_signing_keeps_unknown_outcome_and_cannot_replay(self):
        with mock.patch.object(self.module['subprocess'], 'check_output',
                               side_effect=subprocess.CalledProcessError(1, 'fixture-signer')) as signer:
            with self.assertRaises(subprocess.CalledProcessError):
                self.module['sign_workers'](self.args)
            with self.assertRaises(FileExistsError):
                self.module['sign_workers'](self.args)
        self.assertEqual(signer.call_count, 1)
        receipt = json.loads((self.root / 'worker-signing-receipt.json').read_text())
        self.assertEqual(receipt['status'], 'FAILED_OR_UNKNOWN_NO_REPLAY')

    def test_publisher_sealed_input_is_rejected_before_signing(self):
        (self.root / 'worker-release/manifest.sig').write_bytes(b'fixture seal')
        with mock.patch.object(self.module['subprocess'], 'check_output') as signer:
            with self.assertRaisesRegex(ValueError, 'publisher-sealed'):
                self.module['sign_workers'](self.args)
        signer.assert_not_called()
        self.assertFalse((self.root / 'worker-signing-receipt.json').exists())

    def package_args(self):
        runtime = self.root / 'runtime'
        (runtime / 'payload').mkdir(parents=True)
        (runtime / 'payload/manifest.json').write_text(json.dumps(dict(
            version='0.4.0', target='aarch64-apple-darwin', source=dict(revision='a' * 40))))
        self.args.local_signing.write_text('{}')
        return types.SimpleNamespace(runtime_dir=runtime, version='0.4.0', runtime_version='0.4.0',
                                     source_revision='a' * 40, output=self.root / 'package',
                                     cua_binary=self.cua, module_cache=self.root / 'swift-cache',
                                     build_number='42', local_signing=self.args.local_signing)

    def test_package_checks_current_cua_helper_before_app_producer(self):
        args = self.package_args()
        self.cua.write_bytes(b'wrong helper bytes')
        with mock.patch.dict(self.module['package'].__globals__, run=mock.Mock()) as state:
            with self.assertRaisesRegex(ValueError, 'bind exact App helper bytes'):
                self.module['package'](args)
            state['run'].assert_not_called()
        self.assertFalse(args.output.exists())

    def test_package_accepts_bound_helper_and_keeps_exact_validated_dmg(self):
        args = self.package_args()
        calls = []

        def producer(*argv):
            calls.append(argv)
            config = json.loads(Path(argv[-1]).read_text())
            destination = Path(config['destination'])
            destination.mkdir()
            if config.get('prepareOnly'):
                self.assertEqual(config['cuaBinary'], str(self.cua))
                (destination / 'prepared-native-app.json').write_text('{}')
            else:
                (destination / 'verified.dmg').write_bytes(b'verified native image fixture')
                (destination / 'native-app-receipt.json').write_text(json.dumps(dict(
                    primaryArtifact='verified.dmg', archiveVerification=dict(status='PASS'),
                    nativeReaderActualWait=True, nativeReaderExitCode=0,
                    signing='local_certificate_preview', notarization='NOT RUN')))

        with mock.patch.dict(self.module['package'].__globals__, run=producer):
            self.module['package'](args)
        self.assertEqual(len(calls), 2)
        self.assertEqual((args.output / 'assets/Styx-0.4.0-macos-arm64.dmg').read_bytes(),
                         b'verified native image fixture')


if __name__ == '__main__':
    unittest.main()
