import importlib.util
import io
import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('prepare_node', Path(__file__).parents[1] / 'prepare-node.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class PrepareNodeTests(unittest.TestCase):
    def archive(self, symlink=False):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:xz') as z:
            for name, data in [('bin/node', b'node'), ('LICENSE', b'license')]:
                info = tarfile.TarInfo('node-v22.23.3-linux-x64/' + name)
                info.size = len(data)
                if symlink and name == 'bin/node':
                    info.type = tarfile.SYMTYPE
                    info.linkname = '/untrusted'
                z.addfile(info, io.BytesIO(data))
        return out.getvalue()

    def run_prepare(self, blob, checksum=None):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'prepared'
            digest = checksum or hashlib.sha256(blob).hexdigest()
            with patch.dict(m.ARTIFACTS, {('linux', 'x64'): ('linux-x64.tar.xz', digest)}), patch.object(m, 'urlopen', return_value=io.BytesIO(blob)):
                result = m.prepare(dest, 'linux', 'x64')
            self.assertEqual(Path(result).read_bytes(), b'node')
            self.assertEqual((dest / 'LICENSE').read_bytes(), b'license')
            self.assertTrue((dest / 'node-provenance.json').is_file())

    def test_verified_binary_license_and_provenance(self):
        self.run_prepare(self.archive())

    def test_archive_tampering_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'checksum_mismatch'):
            self.run_prepare(self.archive(), '0' * 64)

    def test_archive_symlink_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'nonregular'):
            self.run_prepare(self.archive(True))

if __name__ == '__main__':
    unittest.main()
