#!/usr/bin/env python3
"""Provision a second official Node only for isolated runtime-update acceptance.

Does not change Styx's production runtime pin, install services, or run Node.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

VERSION = '22.23.2'
ARCHIVE = 'node-v22.23.2-linux-x64.tar.xz'
ARCHIVE_SHA256 = 'd60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307'
BINARY_SHA256 = '3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327'
URL = 'https://nodejs.org/dist/v22.23.2/' + ARCHIVE


def digest(file):
    h = hashlib.sha256()
    with file.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def prepare(destination):
    destination = Path(destination).resolve()
    if destination.exists():
        raise RuntimeError('fresh_alternate_node_directory_required')
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        scratch = Path(directory)
        archive = scratch / ARCHIVE
        subprocess.run(['curl', '-fsSL', '--retry', '2', '--connect-timeout', '15',
                        '--max-time', '120', URL, '-o', str(archive)], check=True)
        if digest(archive) != ARCHIVE_SHA256:
            raise RuntimeError('alternate_node_archive_checksum_mismatch')
        output = scratch / 'payload'
        output.mkdir(mode=0o700)
        with tarfile.open(archive) as package:
            for source, target in [('node-v22.23.2-linux-x64/bin/node', 'node'),
                                   ('node-v22.23.2-linux-x64/LICENSE', 'LICENSE')]:
                members = [member for member in package.getmembers() if member.name == source]
                if len(members) != 1 or not members[0].isfile():
                    raise RuntimeError('alternate_node_member_not_regular_or_unique')
                with package.extractfile(members[0]) as stream, (output / target).open('xb') as dest:
                    shutil.copyfileobj(stream, dest)
        if digest(output / 'node') != BINARY_SHA256:
            raise RuntimeError('alternate_node_binary_checksum_mismatch')
        os.chmod(output / 'node', 0o700)
        provenance = dict(schema=1, component='node', version=VERSION, platform='linux', arch='x64',
                          url=URL, archive_sha256=ARCHIVE_SHA256,
                          binary_sha256=BINARY_SHA256, license_sha256=digest(output / 'LICENSE'))
        (output / 'node-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
        output.rename(destination)
    return str(destination / 'node')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination')
    print(prepare(parser.parse_args().destination))
