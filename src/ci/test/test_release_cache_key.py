import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'cache-key.py'
SPEC = importlib.util.spec_from_file_location('cache_key', SCRIPT)
CACHE_KEY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE_KEY)


class CacheKeyTests(unittest.TestCase):
    def test_deps_hash_ignores_workspace_version_bumps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.97.1"\n')
            lock_v1 = (
                'version = 4\n\n'
                '[[package]]\nname = "styx"\nversion = "0.8.1-rc.9"\n\n'
                '[[package]]\nname = "serde"\nversion = "1.0.228"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                'checksum = "aaaa"\n'
            )
            (root / 'Cargo.lock').write_text(lock_v1)
            h1 = CACHE_KEY.external_deps_hash(root, [])

            # Workspace version bump keeps the exact same dependency cache key.
            (root / 'Cargo.lock').write_text(lock_v1.replace('0.8.1-rc.9', '0.8.1-rc.10'))
            h2 = CACHE_KEY.external_deps_hash(root, [])
            self.assertEqual(h1, h2)

            # External dependency change invalidates the dependency cache key.
            (root / 'Cargo.lock').write_text(lock_v1.replace('1.0.228', '1.0.229'))
            h3 = CACHE_KEY.external_deps_hash(root, [])
            self.assertNotEqual(h1, h3)

    def test_prune_target_strips_workspace_artifacts_but_preserves_third_party_deps(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'target'
            deps = target / 'debug' / 'deps'
            fp_ws = target / 'debug' / '.fingerprint' / 'styx-runtime-abcd'
            fp_ext = target / 'debug' / '.fingerprint' / 'serde-1234'
            inc = target / 'debug' / 'incremental' / 'old'
            for d in (deps, fp_ws, fp_ext, inc, target / 'cargo-timings'):
                d.mkdir(parents=True)
            (target / 'debug' / 'styx').write_bytes(b'ws-bin')
            (deps / 'styx_runtime-deadbeef').write_bytes(b'ws-test-bin')
            (deps / 'libstyx_core-deadbeef.rlib').write_bytes(b'ws-rlib')
            (deps / 'libserde-1234.rlib').write_bytes(b'ext-rlib')
            (fp_ws / 'invoked.timestamp').write_text('1')
            (fp_ext / 'invoked.timestamp').write_text('1')

            CACHE_KEY.prune_target(target)

            self.assertFalse((target / 'debug' / 'styx').exists())
            self.assertFalse((deps / 'styx_runtime-deadbeef').exists())
            self.assertFalse((deps / 'libstyx_core-deadbeef.rlib').exists())
            self.assertFalse(fp_ws.exists())
            self.assertFalse((target / 'debug' / 'incremental').exists())
            self.assertFalse((target / 'cargo-timings').exists())
            self.assertTrue((deps / 'libserde-1234.rlib').exists())
            self.assertTrue(fp_ext.exists())


if __name__ == '__main__':
    unittest.main()
