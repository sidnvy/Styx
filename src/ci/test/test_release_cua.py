import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import tarfile
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / 'release-cua.py'


class CuaReleaseTests(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(SCRIPT), run_name='cua_release_test')
        self.state = self.module['download'].__globals__
        self.scratch = tempfile.TemporaryDirectory(prefix='styx-cua-release-test-')
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def test_verified_archive_cache_skips_network_and_rejects_corruption(self):
        data = b'public pinned source test fixture'
        expected = hashlib.sha256(data).hexdigest()
        cache = self.root / 'cache'
        cache.mkdir()
        archive = cache / f'cua-{self.module["COMMIT"]}.tar.gz'
        archive.write_bytes(data)
        with mock.patch.dict(self.state, ARCHIVE_SHA=expected), mock.patch.dict(
                self.state, urlopen=mock.Mock(side_effect=AssertionError('cache hit downloaded again'))):
            self.assertEqual(self.module['download'](cache), archive)
            archive.write_bytes(b'corrupt cached source')
            with self.assertRaisesRegex(ValueError, 'cached_cua_source_checksum_mismatch'):
                self.module['download'](cache)

    def test_failed_public_download_never_publishes_a_cache_entry(self):
        response = io.BytesIO(b'wrong upstream bytes')
        response.status = 200
        opener = mock.Mock(return_value=response)
        cache = self.root / 'cache'
        with mock.patch.dict(self.state, urlopen=opener):
            with self.assertRaisesRegex(ValueError, 'upstream_cua_archive_checksum_mismatch'):
                self.module['download'](cache)
        self.assertEqual(list(cache.iterdir()), [])
        self.assertEqual(opener.call_args.args[0],
                         f'https://codeload.github.com/trycua/cua/tar.gz/{self.module["COMMIT"]}')

    def test_native_build_accepts_a_locked_cache_hit_without_cleaning(self):
        source = self.root / 'source'
        workspace = source / 'libs/cua-driver/rust'
        workspace.mkdir(parents=True)
        (workspace / 'Cargo.lock').write_text('fixture locked graph')
        prepared = {'files': self.module['inventory'](source)}
        output = self.root / 'output'
        output.mkdir()
        target = self.root / 'cua-target'
        original = target / 'x86_64-unknown-linux-gnu/release/cua-driver'
        original.parent.mkdir(parents=True)
        original.write_bytes(b'cached native worker fixture')
        args = types.SimpleNamespace(platform='linux', target_dir=target, jobs=8,
                                     output=output, source_revision='a' * 40)
        calls = []

        def cargo(command, **kwargs):
            calls.append((command, kwargs))
            if command[1] == 'build':
                kwargs['stdout'].write((json.dumps({
                    'reason': 'compiler-artifact', 'fresh': True,
                    'target': {'name': 'cua-driver'}, 'executable': str(original)}) + '\n').encode())
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(self.module['subprocess'], 'run', side_effect=cargo), \
                mock.patch.object(self.module['subprocess'], 'check_output', return_value='cua-driver 0.36.0\n'), \
                mock.patch.dict(self.state, workspace_cache=mock.Mock(return_value={
                    'target': 'x86_64-unknown-linux-gnu', 'recipe_sha256': 'f' * 64,
                    'previous_recipe_matches': True, 'workspace_clean': None})):
            receipt = self.module['native_build'](args, source, prepared)
        self.assertEqual(receipt['status'], 'PASS')
        self.assertTrue(receipt['compiler_artifact_fresh'])
        self.assertEqual((output / 'bin/cua-driver').read_bytes(), original.read_bytes())
        self.assertEqual([command[1] for command, _ in calls], ['fetch', 'build'])
        self.assertIn('--locked', calls[1][0])
        self.assertIn('--offline', calls[1][0])
        self.assertIn('cua-driver/portal-input', calls[1][0])
        self.assertEqual(calls[1][1]['env']['CMAKE_BUILD_PARALLEL_LEVEL'], '8')

    def test_verified_source_mtimes_are_stable_without_changing_bytes(self):
        archive = self.root / 'upstream.tar'
        with tarfile.open(archive, 'w') as stream:
            root = tarfile.TarInfo(f'cua-{self.module["COMMIT"]}')
            root.type = tarfile.DIRTYPE
            root.mtime = 1792135295
            stream.addfile(root)
        source = self.root / 'third-party'
        (source / 'rust').mkdir(parents=True)
        file = source / 'rust/patched.rs'
        file.write_bytes(b'verified patched third-party source')
        expected = self.module['inventory'](source)
        with mock.patch.dict(self.state, ARCHIVE_SHA=self.module['digest'](archive)):
            first = self.module['source_cache_times'](archive, source, expected)
            file.touch()
            native_utime = self.module['os'].utime

            def portable_utime(*args, **kwargs):
                self.assertNotIn('follow_symlinks', kwargs)
                return native_utime(*args, **kwargs)

            with mock.patch.object(self.module['os'], 'supports_follow_symlinks', set()), \
                    mock.patch.object(self.module['os'], 'utime', side_effect=portable_utime):
                second = self.module['source_cache_times'](archive, source, expected)
            self.assertEqual(first, second)
            self.assertEqual(file.stat().st_mtime_ns, 1792135295 * 1_000_000_000)
            self.assertEqual(self.module['inventory'](source), expected)
            file.write_bytes(b'changed source cannot inherit a cached timestamp')
            with self.assertRaisesRegex(ValueError, 'changed_before_cache_times'):
                self.module['source_cache_times'](archive, source, expected)

    def workspace_fixture(self):
        source = self.root / 'source'
        workspace = source / 'libs/cua-driver/rust'
        packages = []
        for name in ('cua-driver', 'platform-linux'):
            manifest = workspace / f'crates/{name}/Cargo.toml'
            manifest.parent.mkdir(parents=True)
            manifest.write_text(f'[package]\nname="{name}"\nversion="0.36.0"\n')
            packages.append(dict(id=f'path+{manifest.parent}#{name}@0.36.0',
                                 name=name, manifest_path=str(manifest)))
        metadata = dict(workspace_members=[package['id'] for package in packages],
                        packages=packages + [dict(id='registry+crates.io#serde@1.0.0',
                                                  name='serde', manifest_path='/not-a-workspace/Cargo.toml')])
        args = types.SimpleNamespace(platform='linux', target_dir=self.root / 'target', jobs=8)
        return source, args, metadata

    def test_cache_recipe_match_skips_clean_but_requires_new_success_marker(self):
        source, args, metadata = self.workspace_fixture()
        env = self.module['build_environment'](args)
        with mock.patch.object(self.module['subprocess'], 'check_output',
                               return_value=json.dumps(metadata)) as inspect, \
                mock.patch.object(self.module['subprocess'], 'run') as clean:
            first = self.module['workspace_cache'](args, source, env)
            self.assertFalse(first['previous_recipe_matches'])
            self.module['mark_workspace_success'](args, first)
            second = self.module['workspace_cache'](args, source, env)
        self.assertTrue(second['previous_recipe_matches'])
        self.assertIsNone(second['workspace_clean'])
        self.assertTrue(second['actual_build_still_required'])
        self.assertEqual(inspect.call_count, 1)
        self.assertEqual(clean.call_count, 1)
        self.assertFalse((args.target_dir / '.styx-cua-workspace-recipe.json').exists())

    def test_different_recipe_cleans_only_metadata_workspace_release_target(self):
        source, args, metadata = self.workspace_fixture()
        env = self.module['build_environment'](args)
        with mock.patch.object(self.module['subprocess'], 'check_output', return_value=json.dumps(metadata)), \
                mock.patch.object(self.module['subprocess'], 'run') as clean:
            first = self.module['workspace_cache'](args, source, env)
            self.module['mark_workspace_success'](args, first)
            changed = self.module['workspace_cache'](args, source, dict(env, RUSTFLAGS='-Copt-level=2'))
        self.assertFalse(changed['previous_recipe_matches'])
        self.assertNotEqual(first['recipe_sha256'], changed['recipe_sha256'])
        self.assertEqual(clean.call_count, 2)
        for call in clean.call_args_list:
            self.assertEqual(call.args[0], ['cargo', 'clean', '--release', '--target',
                                           'x86_64-unknown-linux-gnu', '--package', 'cua-driver',
                                           '--package', 'platform-linux'])
        self.assertTrue(changed['dependency_cache_preserved'])


if __name__ == '__main__':
    unittest.main()
