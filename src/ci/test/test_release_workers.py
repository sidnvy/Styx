"""Manifest refresh binding tests; signing observations below are synthetic."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
import struct
import sys
from unittest.mock import patch


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


class WorkerRuntimeBudgetTests(unittest.TestCase):
    def test_copy_omits_only_declarations_maps_and_bin_links(self):
        subject = runpy.run_path(str(ROOT / 'src/ci/release-workers.py'))
        with tempfile.TemporaryDirectory(prefix='styx-worker-filter-test-') as temporary:
            source, destination = Path(temporary) / 'source', Path(temporary) / 'copied'
            source.mkdir()
            omitted = ('index.d.ts', 'index.d.mts', 'index.d.cts', 'index.js.map', '.bin/tool')
            retained = ('index.js', 'index.mjs', 'runtime.ts', 'package.json', 'LICENSE', 'assets/data.json')
            for name in omitted + retained:
                file = source / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('explicit packaging fixture')
            subject['copy_modules'](source, destination)
            self.assertEqual({p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()}, set(retained))

    @staticmethod
    def native_header(target):
        if target == 'x86_64-unknown-linux-gnu':
            raw = bytearray(64)
            raw[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<HHI', raw, 16, 2, 62, 1)
            struct.pack_into('<H', raw, 52, 64)
        elif target == 'aarch64-apple-darwin':
            raw = bytearray(40)
            raw[:4] = b'\xcf\xfa\xed\xfe'
            struct.pack_into('<I', raw, 4, 0x0100000c)
            struct.pack_into('<III', raw, 12, 2, 1, 8)
        else:
            raw = bytearray(200)
            raw[:2] = b'MZ'
            struct.pack_into('<I', raw, 60, 64)
            raw[64:68] = b'PE\0\0'
            struct.pack_into('<HH', raw, 68, 0x8664, 1)
            struct.pack_into('<HH', raw, 84, 112, 2)
            raw[88:90] = b'\x0b\x02'
            struct.pack_into('<I', raw, 104, 1)
        return bytes(raw)

    @unittest.skipUnless(sys.platform == 'linux', 'existing Runtime sealer is Linux-only')
    def test_actual_runtime_manifests_fit_budget_with_locked_npm_closure(self):
        # This executes the real selector, copy and manifest encoder. Only source
        # admission/signature verification is mocked: binaries are native header
        # fixtures, and no private key, actual executor or product identity runs.
        modules = ROOT / 'src/providers/browser-worker/node_modules'
        self.assertTrue(modules.is_dir(), 'npm ci --prefix src/providers/browser-worker is required')
        subject = runpy.run_path(str(ROOT / 'src/ci/release-workers.py'))
        sealer = runpy.run_path(str(ROOT / 'src/tools/release/build-native-runtime.py'))
        public = ROOT / 'src/release-publisher.pub'
        pin = json.loads((ROOT / 'src/release-publisher.json').read_text())['publisherSpkiSha256']
        sizes = {}
        with tempfile.TemporaryDirectory(prefix='styx-runtime-budget-test-') as temporary:
            parent = Path(temporary).resolve()
            for platform, target in [('linux', 'x86_64-unknown-linux-gnu'),
                                     ('windows', 'x86_64-pc-windows-msvc'),
                                     ('macos', 'aarch64-apple-darwin')]:
                with self.subTest(platform=platform):
                    fixture = parent / platform
                    worker = fixture / 'worker-release'
                    worker.mkdir(parents=True)
                    suffix = '.exe' if platform == 'windows' else ''
                    kinds = ['codex_exec', 'browser_node22'] + ([] if platform == 'macos' else ['cua_native'])
                    for name in ['codex', 'node'] + ([] if platform == 'macos' else ['cua-driver']):
                        image = worker / ('bin/' + name + suffix)
                        image.parent.mkdir(exist_ok=True)
                        image.write_bytes(self.native_header(target))
                    for name in ('codex-LICENSE', 'codex-NOTICE', 'cua-LICENSE'):
                        subject['copy'](ROOT / 'src/licenses' / name, worker / 'licenses' / name)
                    node_license = worker / 'licenses/node-LICENSE'
                    node_license.write_text('synthetic license fixture')
                    source_platform, arch, _, _ = subject['PLATFORMS'][platform]
                    subject['write'](worker / 'provenance/node.json', dict(schema=1, component='node',
                        version='22.23.3', platform=source_platform, arch=arch, archive_sha256='b' * 64,
                        binary_sha256=subject['digest'](worker / ('bin/node' + suffix)),
                        license_sha256=subject['digest'](node_license)))
                    subject['copy_modules'](modules, worker / subject['PREFIX'])
                    with contextlib.redirect_stdout(io.StringIO()):
                        subject['manifest'](argparse.Namespace(worker_release=worker, platform=platform, version='0.4.0'))
                    raw = (worker / 'manifest.json').read_bytes()
                    manifest = json.loads(raw)
                    signature = b'0' * 86 + b'\n'  # Explicit verification fixture; never a real signature.
                    (worker / 'manifest.sig').write_bytes(signature)
                    observations, directories = sealer['tree'](worker, (-1, -1))
                    source = dict(root=worker, manifest=manifest, raw=raw, pin=pin, public_file=public,
                        public_raw=public.read_bytes(), signature_raw=signature,
                        declared={row['path']: row for row in manifest['files']},
                        observations=observations, directories=directories)
                    image = fixture / ('styx' + suffix)
                    image.write_bytes(self.native_header(target))
                    receipt = fixture / 'receipt.json'
                    receipt.write_text(json.dumps(dict(status='PASS', input_stability='PASS',
                        source_revision='a' * 40, target=target, inputs={'Cargo.toml': 'c' * 64},
                        cli_binary_sha256=subject['digest'](image))))
                    tunnel = fixture / ('tunnel-client-runtime' + suffix)
                    tunnel.write_bytes(self.native_header(target))
                    notice = fixture / 'NOTICE'
                    notice.write_text('synthetic tunnel notice fixture')
                    args = argparse.Namespace(binary=image, build_receipt=receipt, output=fixture / 'runtime',
                        source_revision='a' * 40, version='0.4.0', target=target, expected_publisher=pin,
                        worker_kind=kinds, worker_release=worker, worker_publisher_file=public,
                        publisher_private_key=None, publisher_file=public, prepare_signing=True,
                        detached_signature=None, approved_manifest_sha256=None, relocated_binary=False,
                        tunnel_client=tunnel, tunnel_client_sha256=subject['digest'](tunnel),
                        tunnel_client_license=notice, tunnel_client_notice=notice)
                    with patch.dict(sealer['build'].__globals__, frozen_git=lambda revision: None,
                                    validate_inputs=lambda inputs, forbidden: None,
                                    inspect_worker=lambda *arguments: source), \
                         contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(sealer['build'](args), 0)
                    output = args.output / 'payload/manifest.json'
                    sizes[platform] = len(output.read_bytes())
                    self.assertLess(sizes[platform], 1024 * 1024)
                    actual = json.loads(output.read_bytes())
                    self.assertEqual(actual['target'], target)
                    self.assertTrue(actual['worker_closures'])
        print('actual encoded Runtime manifest bytes:', json.dumps(sizes, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
