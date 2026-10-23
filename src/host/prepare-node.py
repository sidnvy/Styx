#!/usr/bin/env python3
"""Prepare official checksum-pinned Node; never installs services or runs Node."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tarfile
import tempfile
from urllib.request import urlopen
import zipfile

VERSION = '22.23.3'
ARTIFACTS = {
    ('linux', 'x64'): ('linux-x64.tar.xz', 'df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de'),
    ('darwin', 'arm64'): ('darwin-arm64.tar.gz', '23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53'),
    ('darwin', 'x64'): ('darwin-x64.tar.gz', '8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8'),
    ('win32', 'x64'): ('win-x64.zip', '2b0ff57b049cda1bbcea2240eec20467018713c1efe1f7360c2681859b90ed71'),
}

def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def prepare(destination, target, arch):
    suffix, expected = ARTIFACTS[(target, arch)]
    name = f'node-v{VERSION}-{suffix}'
    url = f'https://nodejs.org/dist/v{VERSION}/{name}'
    destination = Path(destination).resolve()
    if destination.exists():
        raise RuntimeError('destination_must_not_exist')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        tmp = Path(tmp)
        archive = tmp / name
        with urlopen(url, timeout=60) as source, archive.open('wb') as out:
            shutil.copyfileobj(source, out)
        if digest(archive) != expected:
            raise RuntimeError('node_archive_checksum_mismatch')
        payload = tmp / 'payload'
        payload.mkdir(mode=0o700)
        executable = 'node.exe' if target == 'win32' else 'node'
        prefix = name.removesuffix('.tar.xz').removesuffix('.tar.gz').removesuffix('.zip')
        wanted = {f'{prefix}/LICENSE': 'LICENSE',
                  f'{prefix}/' + (executable if target == 'win32' else 'bin/node'): executable}
        if suffix.endswith('.zip'):
            with zipfile.ZipFile(archive) as z:
                for member, output in wanted.items():
                    matches = [m for m in z.infolist() if m.filename == member]
                    if len(matches) != 1 or matches[0].is_dir() or (matches[0].external_attr >> 16) & 0o170000 == 0o120000:
                        raise RuntimeError('nonregular_or_duplicate_node_member')
                    with z.open(matches[0]) as source, (payload / output).open('xb') as out:
                        shutil.copyfileobj(source, out)
        else:
            with tarfile.open(archive) as z:
                for member, output in wanted.items():
                    matches = [m for m in z.getmembers() if m.name == member]
                    if len(matches) != 1 or not matches[0].isfile():
                        raise RuntimeError('nonregular_or_duplicate_node_member')
                    with z.extractfile(matches[0]) as source, (payload / output).open('xb') as out:
                        shutil.copyfileobj(source, out)
        os.chmod(payload / executable, 0o700)
        provenance = dict(schema=1, component='node', version=VERSION, platform=target, arch=arch,
                          url=url, archive_sha256=expected, binary_sha256=digest(payload / executable),
                          license_sha256=digest(payload / 'LICENSE'))
        (payload / 'node-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
        payload.rename(destination)
    return str(destination / executable)

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('destination')
    args = p.parse_args()
    machine = platform.machine().lower()
    arch = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine)
    target = 'win32' if sys.platform == 'win32' else sys.platform
    print(prepare(args.destination, target, arch))
