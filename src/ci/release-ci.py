#!/usr/bin/env python3
"""GitHub release orchestration; producers retain payload/signature authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import base64

ROOT = Path(__file__).resolve().parents[2]
PLATFORMS = {'linux': 'x86_64-unknown-linux-gnu', 'windows': 'x86_64-pc-windows-msvc',
             'macos': 'aarch64-apple-darwin'}
PIN = json.loads((ROOT / 'src/release-publisher.json').read_text())['publisherSpkiSha256']


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(file):
    h = hashlib.sha256()
    with Path(file).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def run(*argv):
    subprocess.run([str(x) for x in argv], cwd=ROOT, check=True)


def git(*argv):
    return subprocess.check_output(['git', *argv], cwd=ROOT).decode().strip()


def metadata(args):
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    require(re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?', version), 'invalid Cargo version')
    tag = os.environ.get('GITHUB_REF_NAME', '')
    publish = args.publish or os.environ.get('GITHUB_REF_TYPE') == 'tag'
    if publish:
        require(tag == 'v' + version, 'release must run at the matching immutable version tag')
        require(not git('status', '--porcelain'), 'release source must be clean')
    require(1 <= args.build_number <= 9999, 'macOS build sequence must be 1..9999')
    values = dict(version=version, marketing=version.split('-')[0], revision=git('rev-parse', 'HEAD'),
                  publish=str(publish).lower(), prerelease=str('-' in version).lower(),
                  build_number=str(args.build_number))
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a') as stream:
            stream.write(''.join(f'{key}={value}\n' for key, value in values.items()))
    print(json.dumps(values))


def archive(args):
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    revision = git('rev-parse', 'HEAD')
    run('git', 'archive', '--format=tar', '--output=' + str(args.output / 'source.tar'), revision)
    members = {}
    with tarfile.open(args.output / 'source.tar') as tar:
        for member in tar:
            if member.isfile():
                with tar.extractfile(member) as stream:
                    members[member.name] = hashlib.file_digest(stream, 'sha256').hexdigest()
            else:
                require(member.isdir(), 'source archive contains a nonregular member')
    (args.output / 'source-inputs.json').write_text(json.dumps(dict(sourceRevision=revision,
        archiveSha256=digest(args.output / 'source.tar'), members=members), sort_keys=True) + '\n')


def extract(source, destination):
    require(not destination.exists(), 'extraction destination must be fresh')
    with tarfile.open(source) as tar:
        rows = tar.getmembers()
        require(0 < len(rows) <= 24000, 'input archive member limit')
        seen, total = set(), 0
        for member in rows:
            parts = PurePosixPath(member.name).parts
            require(parts and not member.name.startswith('/') and '\\' not in member.name
                    and ':' not in member.name and not any(p in ('.', '..') for p in parts)
                    and member.name.rstrip('/') == PurePosixPath(member.name).as_posix()
                    and member.name not in seen and (member.isfile() or member.isdir()),
                    'input archive contains a link or unsafe member')
            seen.add(member.name)
            total += member.size
            require(0 <= member.size <= 1024**3 and total <= 8 * 1024**3, 'input archive size limit')
        destination.mkdir(mode=0o700, parents=True)
        # Validated regular files/directories only. Never restore links or owners.
        for member in rows:
            path = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with tar.extractfile(member) as src, path.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                path.chmod(0o700 if member.mode & 0o111 else 0o600)




def sign(args):
    require(sys.platform == 'linux', 'runtime sealing runs on Linux')
    require(args.key.is_file() and not args.key.is_relative_to(ROOT), 'external temporary signing key required')
    args.output.mkdir(mode=0o700, parents=True)
    revision = git('rev-parse', 'HEAD')
    for platform, target in PLATFORMS.items():
        source = args.native / platform
        binary = source / ('styx.exe' if platform == 'windows' else 'styx')
        deps = args.workers / platform
        preparation = json.loads((deps / 'preparation.json').read_text())
        require(preparation.get('status') == 'PASS' and preparation.get('source_revision') == revision
                and preparation.get('platform') == platform and preparation.get('version') == args.version
                and preparation.get('producer') == 'src/ci/release-workers.py',
                'current-source public worker preparation required')
        if platform == 'macos':
            signed = json.loads((deps / 'worker-signing-receipt.json').read_text())
            require(signed.get('status') == 'PASS' and signed.get('source_revision') == revision,
                    'macOS native worker signing must pass before publisher sealing')
            refresh = json.loads((deps / 'manifest-refresh.json').read_text())
            require(refresh.get('status') == 'PASS' and refresh.get('source_revision') == revision
                    and refresh.get('manifest_sha256') == digest(deps / 'worker-release/manifest.json')
                    and refresh.get('signing_receipt_sha256') == digest(deps / 'worker-signing-receipt.json'),
                    'macOS refreshed worker manifest binding mismatch')
        else:
            require(preparation.get('worker_manifest_sha256') == digest(deps / 'worker-release/manifest.json'),
                    'prepared public worker manifest changed')
        # Public/native inputs become a signed schema1 worker source, then the
        # existing Runtime producer admits that source and signs the final bundle.
        helper = runpy.run_path(str(ROOT / 'src/tools/release/build-native-preview.py'))
        context = args.output / ('worker-signing-' + platform)
        context.mkdir(mode=0o700)
        worker = deps / 'worker-release'
        require(not (worker / 'manifest.sig').exists(), 'worker source is already signed')
        require(helper['sign_manifest'](args.key, context, worker) == PIN, 'worker publisher pin mismatch')
        signature = (worker / 'manifest.sig').read_bytes()
        (worker / 'manifest.sig').write_bytes(base64.urlsafe_b64encode(signature).rstrip(b'=') + b'\n')
        shutil.copyfile(context / 'publisher.pem', deps / 'worker-publisher.pem')
        suffix = '.exe' if platform == 'windows' else ''
        tunnel = deps / ('tunnel/tunnel-client-runtime' + suffix)
        flavors = ['host', 'gateway'] if platform == 'linux' else ['host']
        for flavor in flavors:
            output = args.output / (platform + ('-gateway' if flavor == 'gateway' else ''))
            run(sys.executable, '-I', '-B', ROOT / 'src/ci/release-linux.py', 'package',
                '--source-revision', revision, '--target', target, '--version', args.version,
                '--flavor', flavor, '--binary', binary, '--build-receipt', source / 'receipt.json',
                '--output', output, '--expected-publisher', PIN, '--publisher-private-key', args.key,
                '--worker-release', deps / 'worker-release', '--worker-publisher-file', deps / 'worker-publisher.pem',
                '--tunnel-client', tunnel, '--tunnel-client-sha256', digest(tunnel),
                '--tunnel-client-license', deps / 'tunnel/LICENSE', '--tunnel-client-notice', deps / 'tunnel/NOTICE')
    # Public artifacts include only signed payloads, public pins and producer receipts.
    # The private key is outside this tree and is never archived.


def bundle(args):
    require(args.source.is_dir() and not args.output.exists(), 'fresh archive and existing source required')
    executables = {'styx', 'styx.exe', 'cua-driver', 'tunnel/tunnel-client-runtime',
                   'tunnel/tunnel-client-runtime.exe'}
    manifest = args.source / 'worker-release/manifest.json'
    if manifest.is_file():
        executables.update('worker-release/' + row['path'] for row in json.loads(manifest.read_text())['files'] if row['executable'])
    with tarfile.open(args.output, 'w:gz') as tar:
        for file in sorted(args.source.rglob('*')):
            require(not file.is_symlink(), 'artifact links refused')
            if file.is_file():
                relative = file.relative_to(args.source).as_posix()
                def mode(info):
                    info.mode = 0o700 if relative in executables or (os.name != 'nt' and info.mode & 0o111) else 0o600
                    return info
                tar.add(file, arcname=relative, recursive=False, filter=mode)




def checksums(args):
    expected = [f'Styx-{args.version}-windows-x64.exe', f'Styx-{args.version}-macos-arm64.dmg',
                f'Styx-{args.version}-linux-x64.tar.gz', f'Styx-{args.version}-gateway-debian12-x64.tar.gz']
    require(sorted(p.name for p in args.output.iterdir()) == sorted(expected), 'release assets missing or unexpected')
    (args.output / 'SHA256SUMS').write_text(''.join(f'{digest(args.output / name)}  {name}\n' for name in expected))
    shutil.copyfile(ROOT / 'src/release-publisher.pub', args.output / 'styx-publisher.pub')


def linux_assets(args):
    args.output.mkdir(mode=0o700)
    for name, suffix, role in [('linux', 'linux-x64', 'Join an existing Gateway'),
                               ('linux-gateway', 'gateway-debian12-x64', 'Gateway only on moedeu-apps')]:
        source = args.sealed / name
        receipt = json.loads((source / 'build-receipt.json').read_text())
        require(receipt.get('status') == 'PASS' and receipt.get('version') == args.version,
                'matching signed Runtime receipt required')
        with tempfile.TemporaryDirectory(dir=args.output.parent) as temporary:
            root = Path(temporary)
            shutil.copytree(source / 'payload', root / 'payload')
            shutil.copyfile(source / 'publisher.pem', root / 'publisher.pem')
            (root / 'README.txt').write_text(
                'Styx ' + args.version + '\n\nExtract into a permanent owner-private directory.\n'
                'From this directory run: ./payload/bin/styx setup\n'
                'Choose: ' + role + '.\n'
                'When setup asks for signed files, use the absolute path to ./payload,\n'
                'the absolute path to ./publisher.pem, and the public publisher fingerprint:\n' + PIN + '\n'
                'Compare the fingerprint with the trusted release source before first use.\n'
                'Keep configuration, pairing and identities when upgrading.\n'
                'No profile or identity is included in this package.\n')
            bundle(argparse.Namespace(source=root, output=args.output / f'Styx-{args.version}-{suffix}.tar.gz'))


def publisher_key(args):
    value = os.environ.pop('STYX_PUBLISHER_PRIVATE_KEY_PEM', '')
    require(value and not args.output.exists() and not args.output.is_relative_to(ROOT),
            'configure the existing publisher as STYX_PUBLISHER_PRIVATE_KEY_PEM')
    try:
        with open(args.output, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            stream.write(value)
        result = subprocess.run(['openssl', 'pkey', '-in', str(args.output), '-pubout', '-outform', 'DER'],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        require(result.returncode == 0 and hashlib.sha256(result.stdout).hexdigest() == PIN,
                'publisher secret does not match the compiled public pin')
    except BaseException:
        args.output.unlink(missing_ok=True)
        raise


def security(*arguments):
    # Credentials are passed directly to Apple's tool and never echoed in errors.
    result = subprocess.run(['/usr/bin/security', *map(str, arguments)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    require(result.returncode == 0, 'temporary macOS signing keychain operation failed')


def mac_keychain(args):
    require(sys.platform == 'darwin', 'macOS signing requires a native runner')
    encoded = os.environ.pop('STYX_MACOS_CERTIFICATE_P12_BASE64', '')
    password = os.environ.pop('STYX_MACOS_CERTIFICATE_PASSWORD', '')
    require(encoded, 'configure the existing macOS certificate P12 secret first')
    args.directory.mkdir(mode=0o700)
    p12 = args.directory / 'identity.p12'
    keychain = args.directory / 'signing.keychain-db'
    temporary_password = os.urandom(32).hex()
    try:
        p12.write_bytes(base64.b64decode(encoded, validate=True))
        p12.chmod(0o600)
        security('create-keychain', '-p', temporary_password, keychain)
        security('set-keychain-settings', '-lut', '21600', keychain)
        security('unlock-keychain', '-p', temporary_password, keychain)
        security('import', p12, '-k', keychain, '-P', password, '-T', '/usr/bin/codesign', '-T', '/usr/bin/security')
        security('set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', temporary_password, keychain)
        listed = subprocess.run(['/usr/bin/security', 'list-keychains', '-d', 'user'],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
        catalog = shlex.split(listed.stdout.decode())
        if str(keychain) not in catalog:
            security('list-keychains', '-d', 'user', '-s', *catalog, keychain)
        certificates = subprocess.run(['/usr/bin/security', 'find-certificate', '-a', '-p', str(keychain)],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
        require(certificates.count(b'-----BEGIN CERTIFICATE-----') == 1, 'one release certificate required')
        der = subprocess.run(['/usr/bin/openssl', 'x509', '-outform', 'DER'], input=certificates,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout
        require(hashlib.sha256(der).hexdigest() ==
                'f5a143072e85e8e393f199811937ceff4c884d2b74cf2509e08e9e53a4d0c1a9',
                'macOS Secret certificate fingerprint mismatch')
        certificate = args.directory / 'certificate.der'
        certificate.write_bytes(der)
        # A self-signed certificate needs an explicit codeSign trust anchor.
        # Limit this to GitHub-owned disposable runners, never owner devices.
        if os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted':
            result = subprocess.run(['sudo', '-n', '/usr/bin/security', 'add-trusted-cert', '-d',
                                     '-r', 'trustRoot', '-p', 'codeSign', '-k', str(keychain), str(certificate)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            require(result.returncode == 0, 'ephemeral runner codeSign trust setup failed')
            (args.directory / 'ephemeral-code-sign-trust').touch()
        config = dict(identitySha1='9a4c8c7e15d006f9d0a576b137c7696f143f46d8',
                      certificateSha256='f5a143072e85e8e393f199811937ceff4c884d2b74cf2509e08e9e53a4d0c1a9',
                      keychain=str(keychain))
        (args.directory / 'local-signing.json').write_text(json.dumps(config) + '\n')
    finally:
        p12.unlink(missing_ok=True)


def mac_keychain_clean(args):
    keychain = args.directory / 'signing.keychain-db'
    if (args.directory / 'ephemeral-code-sign-trust').exists():
        result = subprocess.run(['sudo', '-n', '/usr/bin/security', 'remove-trusted-cert', '-d',
                                 str(args.directory / 'certificate.der')],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(result.returncode == 0, 'ephemeral runner codeSign trust cleanup failed')
    if keychain.exists():
        security('delete-keychain', keychain)
    if args.directory.exists():
        shutil.rmtree(args.directory)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('metadata'); p.add_argument('--publish', action='store_true')
    p.add_argument('--build-number', type=int, required=True); p.set_defaults(action=metadata)
    p = commands.add_parser('source-archive'); p.add_argument('--output', type=Path, required=True); p.set_defaults(action=archive)
    p = commands.add_parser('sign')
    for name in ('native', 'workers', 'output', 'key'): p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--version', required=True); p.set_defaults(action=sign)
    p = commands.add_parser('bundle')
    for name in ('source', 'output'): p.add_argument('--' + name, type=Path, required=True)
    p.set_defaults(action=bundle)
    p = commands.add_parser('extract')
    for name in ('source', 'output'): p.add_argument('--' + name, type=Path, required=True)
    p.set_defaults(action=lambda args: extract(args.source, args.output))
    p = commands.add_parser('checksums'); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--version', required=True); p.set_defaults(action=checksums)
    p = commands.add_parser('linux-assets')
    for name in ('sealed', 'output'): p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--version', required=True); p.set_defaults(action=linux_assets)
    p = commands.add_parser('publisher-key'); p.add_argument('--output', type=Path, required=True)
    p.set_defaults(action=publisher_key)
    for name, action in [('mac-keychain', mac_keychain), ('mac-keychain-clean', mac_keychain_clean)]:
        p = commands.add_parser(name); p.add_argument('--directory', type=Path, required=True)
        p.set_defaults(action=action)
    args = parser.parse_args(); args.action(args)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'release orchestration failed: {type(error).__name__}: {error}', file=sys.stderr)
        raise SystemExit(1)
