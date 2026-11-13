#!/usr/bin/env python3
"""Assemble unsigned worker inputs from pinned public upstreams and built Cua.

The existing prepare-codex/prepare-node implementations verify their original
archive pins. Only their download transport is replaced with a verified public
archive cache. This producer never accesses profiles or signs a release.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform as native_platform
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
PLATFORMS = {'linux': ('linux', 'x64', 'Linux', 'x86_64'),
             'windows': ('win32', 'x64', 'Windows', 'AMD64'),
             'macos': ('darwin', 'arm64', 'Darwin', 'arm64')}
PREFIX = 'packages/styx-browser-provider/node_modules'
EXECUTABLES = {'bin/codex', 'bin/node', 'bin/cua-driver',
               'bin/codex.exe', 'bin/node.exe', 'bin/cua-driver.exe'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(file):
    value = hashlib.sha256()
    with Path(file).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def write(file, value):
    file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with file.open('w') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
    file.chmod(0o600)


def cached_archive(cache, url, expected):
    cache.mkdir(parents=True, mode=0o700, exist_ok=True)
    file = cache / expected
    if not file.is_file() or file.is_symlink() or digest(file) != expected:
        # Keep incomplete downloads separate from the immutable cache entry.
        fd, temporary = tempfile.mkstemp(prefix='download-', dir=cache)
        temporary = Path(temporary)
        try:
            with os.fdopen(fd, 'wb') as destination, urlopen(url, timeout=120) as source:
                total = 0
                while block := source.read(1048576):
                    total += len(block)
                    require(total <= 1024**3, 'upstream archive exceeds one GiB')
                    destination.write(block)
            require(digest(temporary) == expected, 'pinned upstream archive digest mismatch')
            temporary.replace(file)
        finally:
            temporary.unlink(missing_ok=True)
    return file


def cached_transport(cache, allowed_url, expected):
    def open_cached(url, timeout=None):
        require(url == allowed_url, 'preparer requested an unpinned URL')
        stream = cached_archive(cache, url, expected).open('rb')
        stream.status = 200
        return stream
    return open_cached


def copy(source, destination, executable=False):
    require(source.is_file() and not source.is_symlink(), 'regular worker source required')
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with source.open('rb') as src, destination.open('xb') as dst:
        shutil.copyfileobj(src, dst)
    destination.chmod(0o700 if executable else 0o600)


def copy_modules(source, destination):
    root = source.resolve(strict=True)
    copied = 0
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(source)
        # Declarations and source maps are development inputs, not executed by
        # the Browser worker. Keeping them duplicates thousands of long paths
        # in Runtime file rows and worker closures, exceeding its fixed manifest
        # budget. Preserve ordinary .ts files, JavaScript, assets and licenses.
        if '.bin' in relative.parts or path.name.endswith(('.map', '.d.ts', '.d.mts', '.d.cts')):
            continue
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            require(resolved.is_relative_to(root) and resolved.is_file(),
                    'npm directory link or external file link refused')
        else:
            resolved = path
        if resolved.is_dir():
            continue
        require(resolved.is_file() and re.fullmatch(r'[A-Za-z0-9@._/-]+', relative.as_posix()),
                'npm member is not a regular supported path')
        copy(resolved, destination / relative)
        copied += 1
        require(copied <= 4080, 'worker source exceeds runtime manifest member budget')


def validate_mac_refresh(args):
    """Bind the only permitted post-preparation transformation to native facts."""
    root = args.worker_release
    preparation_file = root.parent / 'preparation.json'
    if not preparation_file.exists():
        return None  # Initial assembly has not published its preparation receipt.
    require(args.platform == 'macos', 'prepared worker manifests cannot be rewritten without native signing')
    refresh_file = root.parent / 'manifest-refresh.json'
    require(not refresh_file.exists(), 'worker manifest refresh cannot be replayed')
    prepared = json.loads(preparation_file.read_text())
    require(prepared.get('status') == 'PASS' and prepared.get('signed') is False
            and prepared.get('platform') == 'macos' and prepared.get('version') == args.version
            and prepared.get('producer') == 'src/ci/release-workers.py'
            and prepared.get('worker_manifest_sha256') == digest(root / 'manifest.json'),
            'original unsigned worker manifest must match preparation')
    original = json.loads((root / 'manifest.json').read_text())
    rows = {row['path']: row for row in original['files']}
    require(len(rows) == len(original['files']), 'original worker manifest contains duplicate paths')
    actual = set()
    mutable = {'bin/codex', 'bin/node', 'provenance/node.json', 'provenance/codex.json'}
    for file in root.rglob('*'):
        require(not file.is_symlink(), 'worker refresh cannot follow symbolic links')
        if file.is_dir():
            continue
        relative = file.relative_to(root).as_posix()
        if relative == 'manifest.json':
            continue
        require(file.is_file() and relative in rows, 'worker refresh inventory changed')
        actual.add(relative)
        if relative not in mutable:
            row = rows[relative]
            require(file.stat().st_size == row['size'] and digest(file) == row['sha256']
                    and bool(file.stat().st_mode & 0o111) == row['executable'],
                    'unsigned dependency changed during native worker signing')
    require(actual == set(rows), 'worker refresh inventory changed')
    receipt_file = root.parent / 'worker-signing-receipt.json'
    receipt_hash = digest(receipt_file)
    signed = json.loads(receipt_file.read_text())
    require(signed.get('status') == 'PASS'
            and signed.get('source_revision') == prepared.get('source_revision'),
            'native worker signing receipt must match preparation source')
    members = signed.get('workers', [])
    expected = {'worker-release/bin/codex', 'worker-release/bin/node', 'tunnel/tunnel-client-runtime'}
    require(isinstance(members, list) and len(members) == 3
            and {row.get('path') for row in members} == expected,
            'all three native worker signature observations required')
    for row in members:
        image = root.parent / row['path']
        report = row.get('signature', {})
        require(image.is_file() and image.resolve(strict=True) == image
                and row.get('signed_sha256') == digest(image)
                and report.get('status') == 'PASS' and report.get('sign_actual_wait') is True
                and report.get('verify_actual_wait') is True and report.get('sign_exit_code') == 0
                and report.get('verify_exit_code') == 0
                and report.get('source_image_sha256') == row.get('upstream_sha256')
                and report.get('signed_image_sha256') == row.get('signed_sha256'),
                'native worker image differs from completed signature observation')
        if row['path'].startswith('worker-release/'):
            original_row = rows[row['path'].removeprefix('worker-release/')]
            require(row['upstream_sha256'] == original_row['sha256'],
                    'native signing source differs from original worker manifest')
    return dict(source_revision=prepared['source_revision'], signing_receipt_sha256=receipt_hash,
                signing_receipt=receipt_file, refresh_file=refresh_file)


def manifest(args):
    root = args.worker_release
    require(root.is_dir() and not root.is_symlink(), 'regular worker-release directory required')
    require(not (root / 'manifest.sig').exists(), 'signed worker release cannot be rewritten')
    refresh = validate_mac_refresh(args)
    platform, arch, _, _ = PLATFORMS[args.platform]
    browser = json.loads((ROOT / 'src/providers/browser-worker/package.json').read_text())['dependencies']
    node_pin = runpy.run_path(str(ROOT / 'src/host/prepare-node.py'))
    codex_pin = runpy.run_path(str(ROOT / 'src/host/prepare-codex.py'))
    suffix = '.exe' if args.platform == 'windows' else ''
    node_provenance = root / 'provenance/node.json'
    provenance = json.loads(node_provenance.read_text())
    actual_node = digest(root / ('bin/node' + suffix))
    if provenance['binary_sha256'] != actual_node:
        require(args.platform == 'macos', 'only native macOS signing may transform pinned Node bytes')
        provenance.setdefault('upstream_binary_sha256', provenance['binary_sha256'])
        provenance['binary_sha256'] = actual_node
        provenance['transformation'] = 'native_codesign'
        write(node_provenance, provenance)
    codex_provenance = root / 'provenance/codex.json'
    if args.platform == 'macos' and codex_provenance.exists():
        original = json.loads(codex_provenance.read_text())
        actual_codex = digest(root / 'bin/codex')
        if original['binary_sha256'] != actual_codex:
            original.setdefault('upstream_binary_sha256', original['binary_sha256'])
            original['binary_sha256'] = actual_codex
            original['transformation'] = 'native_codesign'
            write(codex_provenance, original)
    rows = []
    for file in sorted(root.rglob('*')):
        require(not file.is_symlink(), 'worker release must contain no symbolic links')
        if file.is_dir():
            continue
        relative = file.relative_to(root).as_posix()
        if relative == 'manifest.json':
            continue
        require(file.is_file() and re.fullmatch(r'[A-Za-z0-9@._/-]+', relative),
                'worker release contains an unsupported member')
        executable = relative in EXECUTABLES
        file.chmod(0o700 if executable else 0o600)
        rows.append(dict(path=relative, size=file.stat().st_size, sha256=digest(file), executable=executable))
    require(0 < len(rows) <= 4096, 'worker manifest file limit')
    upstream = dict(codex=codex_pin['RELEASE'].removeprefix('rust-v'), node=node_pin['VERSION'],
                    browserMcp=browser['@playwright/mcp'], playwright=browser['playwright'])
    if args.platform != 'macos':
        require((root / ('bin/cua-driver' + suffix)).is_file(), 'built native Cua required')
        upstream['cua'] = '0.47.24'
    write(root / 'manifest.json', dict(schema=1, platform=platform, arch=arch, version=args.version,
                                     upstream=upstream, files=rows))
    if refresh:
        require(digest(refresh['signing_receipt']) == refresh['signing_receipt_sha256'],
                'native worker signing receipt changed during manifest refresh')
        with refresh['refresh_file'].open('x') as stream:
            json.dump(dict(status='PASS', source_revision=refresh['source_revision'],
                           manifest_sha256=digest(root / 'manifest.json'),
                           signing_receipt_sha256=refresh['signing_receipt_sha256']), stream, sort_keys=True)
            stream.write('\n')
    print(json.dumps(dict(status='UNSIGNED_WORKER_INPUT', platform=args.platform, members=len(rows),
                         manifest_sha256=digest(root / 'manifest.json'))), flush=True)


def prepare(args):
    platform, arch, system, machine = PLATFORMS[args.platform]
    actual_machine = native_platform.machine().lower()
    require(native_platform.system() == system
            and actual_machine == machine.lower(), 'worker preparation requires its matching native runner')
    require(args.output.is_absolute() and not args.output.exists() and not args.output.is_relative_to(ROOT),
            'fresh external worker output required')
    require(args.cache.is_absolute(), 'absolute public archive cache required')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    require(args.cua_binary is not None and args.cua_receipt is not None,
            'source-built Cua binary and original build receipt required')
    cua_receipt = json.loads(args.cua_receipt.read_text())
    require(cua_receipt.get('status') == 'PASS' and cua_receipt.get('source_revision') == revision
            and cua_receipt.get('binary_sha256') == digest(args.cua_binary),
            'Cua build receipt must bind the exact current-source binary')
    args.output.mkdir(mode=0o700, parents=True)
    workers = args.output / 'worker-release'
    workers.mkdir(mode=0o700)
    suffix = '.exe' if args.platform == 'windows' else ''
    with tempfile.TemporaryDirectory(prefix='assemble-', dir=args.output) as temporary:
        temporary = Path(temporary)
        codex = runpy.run_path(str(ROOT / 'src/host/prepare-codex.py'))
        artifact, expected, _ = codex['ARTIFACTS'][(system, machine)]
        url = 'https://github.com/openai/codex/releases/download/' + codex['RELEASE'] + '/' + artifact
        codex['main'].__globals__['urlopen'] = cached_transport(args.cache / 'public-archives', url, expected)
        codex_output = temporary / 'codex'
        old_argv = sys.argv
        try:
            sys.argv = ['prepare-codex.py', '--output', str(codex_output)]
            codex['main']()
        finally:
            sys.argv = old_argv
        copy(codex_output / ('codex' + suffix), workers / ('bin/codex' + suffix), True)
        copy(codex_output / 'manifest.json', workers / 'provenance/codex.json')
        node = runpy.run_path(str(ROOT / 'src/host/prepare-node.py'))
        artifact, expected = node['ARTIFACTS'][(platform, arch)]
        url = f'https://nodejs.org/dist/v{node["VERSION"]}/node-v{node["VERSION"]}-{artifact}'
        node['prepare'].__globals__['urlopen'] = cached_transport(args.cache / 'public-archives', url, expected)
        node_output = temporary / 'node'
        node['prepare'](node_output, platform, arch)
        copy(node_output / ('node' + suffix), workers / ('bin/node' + suffix), True)
        copy(node_output / 'LICENSE', workers / 'licenses/node-LICENSE')
        copy(node_output / 'node-provenance.json', workers / 'provenance/node.json')
        npm_source = temporary / 'browser'
        npm_source.mkdir(mode=0o700)
        for name in ('package.json', 'package-lock.json'):
            copy(ROOT / 'src/providers/browser-worker' / name, npm_source / name)
        npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
        require(npm, 'npm required to install the locked Browser worker dependencies')
        subprocess.run([npm, 'ci', '--ignore-scripts', '--no-audit', '--no-fund',
                        '--cache', str(args.cache / 'npm')], cwd=npm_source, check=True,
                       env=dict(os.environ, PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD='1'))
        copy_modules(npm_source / 'node_modules', workers / PREFIX)
        for name in ('codex-LICENSE', 'codex-NOTICE'):
            copy(ROOT / 'src/licenses' / name, workers / 'licenses' / name)
        if args.cua_binary:
            if args.platform == 'macos':
                copy(args.cua_binary, args.output / 'cua-driver', True)
            else:
                copy(args.cua_binary, workers / ('bin/cua-driver' + suffix), True)
                copy(ROOT / 'src/licenses/cua-LICENSE', workers / 'licenses/cua-LICENSE')
            copy(args.cua_receipt, workers / 'provenance/cua.json')
    args.worker_release = workers
    manifest(args)
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == revision,
            'product source revision changed during worker preparation')
    write(args.output / 'preparation.json', dict(schema=1, status='PASS', source_revision=revision,
          platform=args.platform, version=args.version, producer='src/ci/release-workers.py',
          worker_manifest_sha256=digest(workers / 'manifest.json'), signed=False,
          source='checksum-pinned public archives, locked npm dependencies, current-source Cua build',
          cua_binary_sha256=cua_receipt['binary_sha256'], cua_receipt_sha256=digest(args.cua_receipt)))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, action in [('prepare', prepare), ('manifest', manifest)]:
        p = commands.add_parser(name)
        p.add_argument('--platform', choices=PLATFORMS, required=True)
        p.add_argument('--version', required=True)
        p.set_defaults(action=action)
        if name == 'prepare':
            p.add_argument('--cache', type=Path, required=True)
            p.add_argument('--output', type=Path, required=True)
            p.add_argument('--cua-binary', type=Path, required=True)
            p.add_argument('--cua-receipt', type=Path, required=True)
        else:
            p.add_argument('--worker-release', type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9._+-]{1,128}', args.version), 'safe worker version required')
    args.action(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'worker preparation failed: {type(error).__name__}: {error}', file=sys.stderr)
        raise SystemExit(1)
