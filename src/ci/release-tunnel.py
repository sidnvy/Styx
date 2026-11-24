#!/usr/bin/env python3
"""Fetch the public, checksum-pinned Secure MCP runtime without executing it.

Only upstream release bytes are cached. macOS platform signing, when selected,
happens later in its native signing job; the raw download pin remains separate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import os
import shutil
import stat
import tempfile
import urllib.request
import zipfile

LOCK = Path(__file__).with_suffix('.json')
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MEMBER = 96 * 1024 * 1024


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(platform, cache, output):
    lock = json.loads(LOCK.read_text())
    if lock['schema'] != 1 or lock['version'] != '0.0.17':
        raise ValueError('Unsupported tunnel dependency lock')
    item = lock['platforms'][platform]
    cache, output = Path(cache), Path(output)
    if not cache.is_absolute() or not output.is_absolute() or output.exists():
        raise ValueError('Absolute cache and fresh output paths required')
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / (item['archive_sha256'] + '.zip')
    if not archive.exists():
        fd, pending = tempfile.mkstemp(prefix='tunnel-download-', dir=cache)
        try:
            with os.fdopen(fd, 'wb') as destination, urllib.request.urlopen(item['url'], timeout=60) as source:
                total = 0
                while block := source.read(1024 * 1024):
                    total += len(block)
                    if total > MAX_ARCHIVE:
                        raise ValueError('Tunnel archive exceeds size limit')
                    destination.write(block)
            if digest(pending) != item['archive_sha256']:
                raise ValueError('Upstream tunnel archive checksum mismatch')
            os.replace(pending, archive)
        finally:
            Path(pending).unlink(missing_ok=True)
    if archive.is_symlink() or archive.stat().st_size > MAX_ARCHIVE or digest(archive) != item['archive_sha256']:
        raise ValueError('Cached tunnel archive checksum mismatch')
    # Verify the closed archive and every member before creating output. Never
    # extract paths from the archive or accept links/device entries.
    with zipfile.ZipFile(archive) as bundle:
        rows = bundle.infolist()
        if len(rows) != len(item['members']) or set(bundle.namelist()) != set(item['members']):
            raise ValueError('Unexpected tunnel archive members')
        for row in rows:
            mode = row.external_attr >> 16
            if row.is_dir() or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)) or row.file_size > MAX_MEMBER:
                raise ValueError('Nonregular tunnel archive member')
            if '/' in row.filename or '\\' in row.filename or ':' in row.filename:
                raise ValueError('Unsafe tunnel archive member')
            if hashlib.sha256(bundle.read(row)).hexdigest() != item['members'][row.filename]:
                raise ValueError('Tunnel archive member checksum mismatch')
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        try:
            for name in (item['binary'], 'LICENSE', 'NOTICE'):
                with (output / name).open('xb') as destination, bundle.open(name) as source:
                    shutil.copyfileobj(source, destination)
                (output / name).chmod(0o700 if name == item['binary'] else 0o600)
            receipt = dict(schema=1, platform=platform, version=lock['version'],
                upstream=item['url'], archive_sha256=item['archive_sha256'],
                raw_binary_sha256=item['members'][item['binary']],
                binary=item['binary'], platform_signing='NOT_RUN', executed=False,
                files={name: item['members'][name] for name in (item['binary'], 'LICENSE', 'NOTICE')})
            (output / 'provenance.json').write_text(json.dumps(receipt, indent=2) + '\n')
            return receipt
        except BaseException:
            shutil.rmtree(output)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=['linux', 'macos', 'windows'])
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.platform, args.cache, args.output)))


if __name__ == '__main__':
    main()
