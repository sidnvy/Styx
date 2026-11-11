#!/usr/bin/env python3
"""Create a fresh, isolated, test-only TLS fixture set using OpenSSL."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

MINIMUM_REMAINING_SECONDS = 3600


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='new absolute fixture directory')
    args = parser.parse_args()
    raw = args.output
    output = Path(raw)
    if (not output.is_absolute() or raw != str(output) or raw != os.path.normpath(raw)
            or output.name in ('', '.', '..')):
        parser.error('output must be a normalized absolute path to a new directory')
    try:
        parent = output.parent.resolve(strict=True)
        if str(parent) != str(output.parent) or not parent.is_dir():
            raise ValueError('parent must exist and contain no path aliases or symlinks')
        os.umask(0o077)
        output.mkdir(mode=0o700)  # Atomic refusal of existing files, directories, and symlinks.
    except (OSError, ValueError) as exc:
        print(f'FAIL: output directory rejected: {exc}', file=sys.stderr)
        return 1

    receipt_path = output / 'receipt.json'
    receipt = {'status': 'FAIL', 'test_only': True, 'output': str(output), 'stages': []}
    try:
        executable = shutil.which('openssl')
        if not executable:
            raise RuntimeError('openssl not found on PATH')
        executable = str(Path(executable).resolve(strict=True))
        openssl_bytes = Path(executable).read_bytes()
        receipt['openssl'] = {'path': executable, 'sha256': hashlib.sha256(openssl_bytes).hexdigest()}

        def run(stage, argv, expected_success=True):
            proc = subprocess.run([executable, *argv], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
            (output / f'{stage}.stdout.log').write_bytes(proc.stdout)
            (output / f'{stage}.stderr.log').write_bytes(proc.stderr)
            receipt['stages'].append({'name': stage, 'exit_code': proc.returncode})
            if expected_success and proc.returncode != 0:
                raise RuntimeError(f'{stage} failed (exit {proc.returncode})')
            if not expected_success and (proc.returncode != 2 or b'verification failed' not in proc.stderr.lower()):
                raise RuntimeError(f'{stage} did not reject the mismatched CA as expected')
            return proc.stdout.decode('utf-8', errors='replace').strip()

        receipt['openssl']['version'] = run('openssl-version', ['version'])
        extensions = output / 'leaf.extensions'
        extensions.write_text('basicConstraints=critical,CA:FALSE\n'
                              'keyUsage=critical,digitalSignature,keyEncipherment\n'
                              'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
        for label in ('a', 'b'):
            ca_key, ca = output / f'ca-key-{label}.pem', output / f'ca-{label}.pem'
            key, csr = output / f'key-{label}.pem', output / f'leaf-{label}.csr'
            cert = output / f'cert-{label}.pem'
            run(f'generate-ca-{label}', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(ca_key), '-out', str(ca), '-days', '1', '-subj',
                f'/CN=Styx R10 owned test root {label}', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
            run(f'generate-csr-{label}', ['req', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(key), '-out', str(csr), '-subj', '/CN=localhost'])
            run(f'sign-leaf-{label}', ['x509', '-req', '-in', str(csr), '-CA', str(ca),
                '-CAkey', str(ca_key), '-CAcreateserial', '-out', str(cert), '-days', '1',
                '-sha256', '-extfile', str(extensions)])
        for leaf, ca, succeeds in (('a', 'a', True), ('b', 'b', True),
                                   ('a', 'b', False), ('b', 'a', False)):
            run(f'verify-{leaf}-{ca}', ['verify', '-CAfile', str(output / f'ca-{ca}.pem'),
                str(output / f'cert-{leaf}.pem')], expected_success=succeeds)
        receipt['certificates'] = {}
        for name in ('ca-a.pem', 'ca-b.pem', 'cert-a.pem', 'cert-b.pem'):
            path = output / name
            run(f'checkend-{name}', ['x509', '-in', str(path), '-noout', '-checkend',
                                    str(MINIMUM_REMAINING_SECONDS)])
            dates = run(f'dates-{name}', ['x509', '-in', str(path), '-noout', '-dates'])
            data = path.read_bytes()
            receipt['certificates'][name] = {'sha256': hashlib.sha256(data).hexdigest(),
                                              'bytes': len(data), 'validity': dates.splitlines()}
        receipt['private_files'] = {}
        for name in ('ca-key-a.pem', 'ca-key-b.pem', 'key-a.pem', 'key-b.pem'):
            info = (output / name).stat()
            mode = stat.S_IMODE(info.st_mode)
            receipt['private_files'][name] = {'mode': f'{mode:04o}', 'bytes': info.st_size}
            if mode != 0o600 or info.st_size == 0:
                raise RuntimeError(f'{name} has unexpected permissions or size')
        receipt['minimum_remaining_seconds'] = MINIMUM_REMAINING_SECONDS
        receipt['status'] = 'PASS'
    except Exception as exc:
        receipt['error'] = f'{type(exc).__name__}: {exc}'
    try:
        receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    except OSError as exc:
        print(f'FAIL: could not write receipt: {exc}; directory: {output}', file=sys.stderr)
        return 1
    print(f"{receipt['status']} receipt={receipt_path}")
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
