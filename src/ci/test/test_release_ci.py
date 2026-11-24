"""Release boundaries: real archive/pin/asset failures must stop publication."""
import argparse
import contextlib
import json
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

    def test_checksums_cover_all_five_assets(self):
        names = ['Styx-1.2.3-windows-x64.exe', 'Styx-1.2.3-macos-arm64.dmg',
                 'styx-1.2.3-linux-x86_64-desktop.tar.gz',
                 'styx-1.2.3-linux-x86_64-gateway-only.tar.gz',
                 'Styx-1.2.3-android-arm64.apk']
        for name in names:
            (self.root / name).write_bytes(name.encode())
        ci.checksums(argparse.Namespace(output=self.root, version='1.2.3'))
        rows = (self.root / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(rows), 5)
        for row in rows:
            digest, name = row.split('  ')
            self.assertEqual(digest, ci.digest(self.root / name))

    def test_android_keystore_requires_secrets_and_cleans_up(self):
        target = self.root / 'android-signing'
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'STYX_ANDROID_KEYSTORE_BASE64'):
                ci.android_keystore(argparse.Namespace(directory=target))
        self.assertFalse(target.exists())
        target.mkdir(mode=0o700)
        (target / 'release.jks').write_bytes(b'dummy')
        ci.android_keystore_clean(argparse.Namespace(directory=target))
        self.assertFalse(target.exists())

    def test_linux_assets_delegate_both_modes_to_the_distribution_producer(self):
        sealed = self.root / 'sealed'
        for name in ['linux', 'linux-gateway']:
            folder = sealed / name
            folder.mkdir(parents=True)
            (folder / 'build-receipt.json').write_text('{"status":"PASS","version":"1.2.3"}')
        assets = self.root / 'assets'
        calls = []

        def producer(*argv):
            self.assertEqual(argv[1:5], ('-I', '-B', ci.ROOT / 'src/ci/release-linux.py', 'distribution'))
            flags = dict(zip(argv[5::2], argv[6::2]))
            self.assertEqual(flags['--verifier'], sealed / 'linux/payload/bin/styx')
            self.assertEqual(flags['--expected-publisher'], ci.PIN)
            mode = flags['--mode']
            source = 'linux' if mode == 'desktop' else 'linux-gateway'
            self.assertEqual(flags['--runtime-dir'], sealed / source)
            output = flags['--output']
            self.assertEqual(output.parent.parent, assets.parent)
            self.assertFalse(output.exists())
            output.mkdir()
            flavor = 'desktop' if mode == 'desktop' else 'gateway-only'
            (output / f'styx-1.2.3-linux-x86_64-{flavor}.tar.gz').write_bytes(mode.encode())
            calls.append(mode)

        with patch.object(ci, 'run', side_effect=producer):
            ci.linux_assets(argparse.Namespace(sealed=sealed, output=assets, version='1.2.3'))
        self.assertEqual(calls, ['desktop', 'gateway'])
        self.assertEqual({p.name: p.read_bytes() for p in assets.iterdir()}, {
            'styx-1.2.3-linux-x86_64-desktop.tar.gz': b'desktop',
            'styx-1.2.3-linux-x86_64-gateway-only.tar.gz': b'gateway',
        })

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



class ReleaseSourcePolicyTests(unittest.TestCase):
    """Exercise the real Git tag/ancestry checks, without signing or a network."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='styx-release-policy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.git('init', '--quiet', '--initial-branch=main')
        self.git('config', 'user.email', 'release-test@example.invalid')
        self.git('config', 'user.name', 'Release policy test')
        self.version('1.2.3')
        self.commit('base')
        self.git('update-ref', 'refs/remotes/origin/main', 'HEAD')
        self.git('tag', 'v1.2.3')

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root,
                                       stderr=subprocess.PIPE).decode().strip()

    def version(self, value):
        (self.root / 'Cargo.toml').write_text('[workspace.package]\nversion = "' + value + '"\n')

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '--quiet', '-m', message)

    def invoke(self, name='v1.2.3', kind='tag'):
        output = io.StringIO()
        with patch.object(ci, 'ROOT', self.root), patch.dict(os.environ, {
            'GITHUB_REF_NAME': name, 'GITHUB_REF_TYPE': kind, 'GITHUB_OUTPUT': '',
        }), contextlib.redirect_stdout(output):
            ci.metadata(argparse.Namespace(build_number=1200))
        return json.loads(output.getvalue())

    def test_matching_main_tag_is_the_only_publishable_identity(self):
        result = self.invoke()
        self.assertEqual(result['version'], '1.2.3')
        self.assertEqual(result['revision'], self.git('rev-parse', 'HEAD'))
        self.assertEqual(result['publish'], 'true')
        self.assertEqual(result['prerelease'], 'false')

    def test_main_develop_and_feature_branch_cannot_sign_a_release(self):
        for branch in ('main', 'develop', 'fix/input'):
            with self.subTest(branch=branch), self.assertRaisesRegex(ValueError, 'version tag'):
                self.invoke(branch, 'branch')

    def test_tagged_but_unmerged_source_is_rejected(self):
        self.git('checkout', '--quiet', '-b', 'fix/unreviewed')
        self.version('1.2.4')
        self.commit('unmerged change')
        self.git('tag', 'v1.2.4')
        with self.assertRaisesRegex(ValueError, 'merged to origin/main'):
            self.invoke('v1.2.4')

    def test_version_tag_must_match_workspace_version(self):
        with self.assertRaisesRegex(ValueError, 'matching immutable version tag'):
            self.invoke('v1.2.4')

    def test_checkout_must_be_the_exact_tagged_commit(self):
        (self.root / 'source').write_text('a later change')
        self.commit('later main')
        self.git('update-ref', 'refs/remotes/origin/main', 'HEAD')
        with self.assertRaisesRegex(ValueError, 'does not point'):
            self.invoke()

    def test_tagged_ancestor_remains_valid_when_main_advances(self):
        release = self.git('rev-parse', 'HEAD')
        (self.root / 'source').write_text('later main')
        self.commit('later main')
        self.git('update-ref', 'refs/remotes/origin/main', 'HEAD')
        self.git('checkout', '--quiet', '--detach', release)
        self.assertEqual(self.invoke()['revision'], release)

    def test_dirty_tag_checkout_is_rejected(self):
        (self.root / 'uncommitted').write_text('local-only input')
        with self.assertRaisesRegex(ValueError, 'must be clean'):
            self.invoke()

    def test_prerelease_tag_stays_explicit(self):
        self.version('1.2.4-rc.1')
        self.commit('candidate')
        self.git('update-ref', 'refs/remotes/origin/main', 'HEAD')
        self.git('tag', 'v1.2.4-rc.1')
        result = self.invoke('v1.2.4-rc.1')
        self.assertEqual(result['prerelease'], 'true')
        self.assertEqual(result['marketing'], '1.2.4')

    def test_workflow_has_one_early_source_authority_and_no_quick_signer(self):
        root = SCRIPT.parents[2]
        release = (root / '.github/workflows/styx-release.yml').read_text()
        self.assertNotIn('branches: [develop]', release)
        self.assertNotIn('inputs.publish', release)
        self.assertEqual(release.count('release-ci.py metadata'), 1)
        self.assertIn('  quality:\n    needs: source', release)
        self.assertIn('  dependencies:\n    needs: source', release)
        self.assertIn('  android:\n    needs: [source, quality]', release)
        android_section = release.split('  android:', 1)[1].split('  release:', 1)[0]
        self.assertIn('environment: release', android_section)
        self.assertIn('android-keystore-clean', android_section)
        source = release.split('  source:', 1)[1].split('  quality:', 1)[0]
        self.assertNotIn('environment: release', source)
        self.assertNotIn('secrets.', source)
        macos = (root / '.github/workflows/styx-macos-app.yml').read_text()
        for obsolete in ('quick_build', 'quick-build:', 'quick_seal:', 'quick_app:', 'secrets.'):
            self.assertNotIn(obsolete, macos)
        self.assertIn('  compile:', macos)

if __name__ == '__main__':
    unittest.main()
