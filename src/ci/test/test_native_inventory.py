import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from urllib.error import HTTPError
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('native_inventory', Path(__file__).parents[1] / 'native_inventory.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class NativeInventoryTests(unittest.TestCase):
    def package(self):
        return dict(name='fixture', version='1.0.0', checksum='0' * 64)

    def archive(self, symlink=False, license_file=None):
        out = io.BytesIO()
        manifest = '[package]\nname="fixture"\nversion="1.0.0"\nlicense="MIT OR Apache-2.0"\n'
        if license_file:
            manifest += 'license-file=' + json.dumps(license_file) + '\n'
        with tarfile.open(fileobj=out, mode='w:gz') as z:
            for name, data in [('Cargo.toml', manifest.encode()), ('LICENSE-MIT', b'actual notice')]:
                member = tarfile.TarInfo('fixture-1.0.0/' + name)
                member.size = len(data)
                if symlink and name == 'LICENSE-MIT':
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/untrusted'
                z.addfile(member, io.BytesIO(data))
        return out.getvalue()

    def test_lock_inventory_separates_registry_git_and_workspace_without_guessing_licenses(self):
        data = b'version=4\n[[package]]\nname="local"\nversion="1.0.0"\n[[package]]\nname="git"\nversion="1.0.0"\nsource="git+https://example.com/repo#fixed"\n[[package]]\nname="remote"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + b'0' * 64 + b'"\n'
        result = m.lock_packages(data, 'fixture')
        self.assertEqual({p['source_kind'] for p in result}, {'git', 'workspace', 'registry'})
        self.assertTrue(all(p['license']['status'] == 'UNRESOLVED' for p in result))
        bom = m.cyclonedx(result, [])
        self.assertEqual(bom['compositions'][0]['aggregate'], 'incomplete')
        self.assertFalse(any('licenses' in c for c in bom['components']))

    def test_missing_checksum_and_duplicate_lock_identity_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'checksum_missing'):
            m.lock_packages(b'version=4\n[[package]]\nname="x"\nversion="1"\nsource="registry+fake"', 'fixture')
        with self.assertRaisesRegex(ValueError, 'duplicate_locked'):
            m.lock_packages(b'version=4\n[[package]]\nname="x"\nversion="1"\n[[package]]\nname="x"\nversion="1"', 'fixture')

    def test_registry_license_requires_exact_identity_and_locked_archive_checksum(self):
        p = self.package()
        record = {'version': {'crate': 'fixture', 'num': '1.0.0', 'checksum': p['checksum'], 'license': 'MIT'}}
        self.assertEqual(m.registry_license(json.dumps(record).encode(), p)['status'], 'REGISTRY_METADATA')
        record['version']['checksum'] = '1' * 64
        with self.assertRaisesRegex(ValueError, 'checksum_mismatch'):
            m.registry_license(json.dumps(record).encode(), p)
        record['version']['crate'] = 'other'
        with self.assertRaisesRegex(ValueError, 'identity_mismatch'):
            m.registry_license(json.dumps(record).encode(), p)

    def test_archive_license_notices_are_derived_only_after_locked_checksum_verification(self):
        blob = self.archive()
        p = self.package()
        with self.assertRaisesRegex(ValueError, 'archive_checksum_mismatch'):
            m.crate_license(blob, p)
        p['checksum'] = m.sha(blob)
        result = m.crate_license(blob, p)
        self.assertEqual(result['status'], 'CHECKSUM_VERIFIED_ARCHIVE')
        self.assertEqual(result['declared_expression'], 'MIT OR Apache-2.0')
        self.assertEqual(result['notices'][0]['bytes'], b'actual notice')

    def test_symlink_notice_and_declared_traversal_are_rejected_without_extraction(self):
        for blob in [self.archive(symlink=True), self.archive(license_file='../outside')]:
            p = self.package()
            p['checksum'] = m.sha(blob)
            with self.assertRaisesRegex(ValueError, 'not_regular|unsafe_declared'):
                m.crate_license(blob, p)

    def test_cached_input_corruption_fails_closed_and_offline_mode_never_fetches(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            digest = m.sha(b'good')
            with patch.object(m, 'download') as fetch:
                with self.assertRaisesRegex(ValueError, 'missing_cached'):
                    m.cached(cache, digest, 'https://untrusted.invalid', False)
                fetch.assert_not_called()
            (cache / digest).write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'cached_source_checksum_mismatch'):
                m.cached(cache, digest, 'https://untrusted.invalid', True)

    def test_offline_snapshot_replay_is_deterministic_and_registry_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / 'cache'
            cache.mkdir()
            lock = b'version=4\n[[package]]\nname="fixture"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + b'0' * 64 + b'"\n'
            digest = m.sha(lock)
            (cache / digest).write_bytes(lock)
            pins = {'sources': [{'component': 'fixture', 'commit': 'fixed', 'files': [
                {'kind': 'cargo-lock', 'sha256': digest, 'size': len(lock), 'url': 'https://raw.githubusercontent.com/fixture'}]}]}
            metadata = {'version': {'crate': 'fixture', 'num': '1.0.0', 'checksum': '0' * 64, 'license': 'MIT'}}
            raw = json.dumps(metadata).encode()
            (cache / 'registry-fixture-1.0.0.json').write_bytes(raw)
            snapshot = {'fixture@1.0.0': m.sha(raw)}
            with patch.object(m, 'download') as fetch:
                m.build(pins, cache, root / 'first', metadata_limit=1, registry_pins=snapshot)
                m.build(pins, cache, root / 'second', metadata_limit=1, registry_pins=snapshot)
                self.assertEqual((root / 'first/inventory.json').read_bytes(), (root / 'second/inventory.json').read_bytes())
                self.assertEqual((root / 'first/source-inventory.cdx.json').read_bytes(), (root / 'second/source-inventory.cdx.json').read_bytes())
                metadata['version']['license'] = 'untrusted replacement'
                (cache / 'registry-fixture-1.0.0.json').write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError, 'snapshot_checksum_mismatch'):
                    m.build(pins, cache, root / 'third', metadata_limit=1, registry_pins=snapshot)
                self.assertFalse((root / 'third').exists())
                fetch.assert_not_called()

    def test_dependency_edges_preserve_ambiguity_instead_of_guessing_versions(self):
        packages = []
        for name, version in [('root', '1'), ('dep', '1'), ('dep', '2')]:
            packages.append({'origin': 'fixture', 'name': name, 'version': version, 'source': None,
                             'dependency_constraints': ['dep', 'dep 2', 'missing'] if name == 'root' else []})
        edges, errors = m.dependency_edges(packages)
        self.assertEqual(edges[0]['dependsOn'], [m.component_ref(packages[2])])
        self.assertEqual([x['reason'] for x in errors], ['ambiguous', 'unresolved'])

    def metadata_fixture(self, root, count=12):
        cache = root / 'cache'
        cache.mkdir()
        text = 'version=4\n' + ''.join('[[package]]\nname="pkg' + str(i).zfill(2) + '"\nversion="1"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + '0' * 64 + '"\n' for i in range(count))
        data = text.encode()
        (cache / m.sha(data)).write_bytes(data)
        pins = {'sources': [{'component': 'fixture', 'commit': 'fixed', 'files': [
            {'kind': 'cargo-lock', 'sha256': m.sha(data), 'size': len(data), 'url': 'https://raw.githubusercontent.com/fixture'}]}]}
        return cache, pins

    def test_queued_rate_limit_and_integrity_failures_stop_without_draining_network_queue(self):
        for error in ('rate', 'checksum'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                cache, pins = self.metadata_fixture(root)
                def fake_fetch(url):
                    if error == 'rate':
                        raise HTTPError(url, 429, 'limited', None, None)
                    name = url.split('/')[-2]
                    return json.dumps({'version': {'crate': name, 'num': '1', 'checksum': '1' * 64, 'license': 'MIT'}}).encode()
                with patch.object(m, 'download', side_effect=fake_fetch) as fetch, patch.object(m.time, 'sleep'):
                    with self.assertRaises((HTTPError, ValueError)):
                        m.build(pins, cache, root / 'output', fetch=True, metadata_limit=12, workers=2,
                                allow_incomplete_metadata=True)
                    self.assertLessEqual(fetch.call_count, 2)
                    self.assertFalse((root / 'output').exists())

    def test_explicit_incomplete_sweep_records_network_failure_as_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, pins = self.metadata_fixture(root, 3)
            with patch.object(m, 'download', side_effect=OSError('offline')), patch.object(m.time, 'sleep'):
                counts = m.build(pins, cache, root / 'output', fetch=True, metadata_limit=3,
                                 workers=2, allow_incomplete_metadata=True)
            report = json.loads((root / 'output/inventory.json').read_text())
            self.assertEqual(counts['registry_metadata_errors'], 3)
            self.assertEqual(report['gates']['registry_metadata'], 'FAIL')
            self.assertEqual(counts['license_expression_unresolved_entries'], 3)

    def test_exact_workspace_license_inheritance_never_applies_to_undeclared_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            documents = [('Cargo.toml', b'[workspace]\n[workspace.package]\nversion="1"\nlicense="MIT"'),
                         ('member/Cargo.toml', b'[package]\nname="member"\nversion.workspace=true\nlicense.workspace=true'),
                         ('other/Cargo.toml', b'[package]\nname="other"\nversion="1"')]
            items = []
            for path, data in documents:
                digest = m.sha(data)
                (cache / digest).write_bytes(data)
                items.append({'path': path, 'kind': 'package-manifest', 'sha256': digest,
                              'url': 'https://raw.githubusercontent.com/fixture/' + path})
            result = m.manifest_licenses({'sources': [{'component': 'fixture', 'files': items}]}, cache)
            self.assertEqual(result[('fixture', 'member', '1', None)]['declared_expression'], 'MIT')
            self.assertNotIn(('fixture', 'other', '1', None), result)

    def test_optional_curl_fallback_keeps_tls_and_never_retries_rate_limit(self):
        response = SimpleNamespace(returncode=0, stdout=b'public evidence', stderr=b'HTTP_STATUS:200')
        with patch.object(m, 'urlopen', side_effect=OSError('TLS EOF')), patch.object(m.time, 'sleep'), patch.object(m.shutil, 'which', return_value='/usr/bin/curl'), patch.object(m.subprocess, 'run', return_value=response) as curl:
            self.assertEqual(m.download('https://crates.io/api/v1/crates/fixture/1'), b'public evidence')
            command = curl.call_args.args[0]
            self.assertIn('--http1.1', command)
            self.assertNotIn('--insecure', command)
        with patch.object(m, 'urlopen', side_effect=HTTPError('https://crates.io', 429, 'limited', None, None)), patch.object(m.subprocess, 'run') as curl:
            with self.assertRaises(HTTPError):
                m.download('https://crates.io/api/v1/crates/fixture/1')
            curl.assert_not_called()

    def test_node_heading_inventory_does_not_invent_version_or_spdx(self):
        result = m.node_notices(b'- fixture, located at deps/fixture, is licensed as follows:\nnotice\n')
        self.assertEqual(result, [{'name': 'fixture', 'source_path': 'deps/fixture', 'line': 1}])

if __name__ == '__main__':
    unittest.main()
