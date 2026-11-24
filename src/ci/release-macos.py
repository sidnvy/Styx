#!/usr/bin/env python3
"""Native macOS CI adapter; retain the existing Core/App/DMG producers.

The publisher-sealed runtime is immutable. macOS executable signatures must
already exist before central runtime sealing; final packaging signs only the
App's unsealed shell using the same retained certificate. This adapter never
imports a key, installs an App, starts a profile, or claims notarization.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PIN = 'bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def existing(value):
    path = Path(value)
    require(path.is_absolute() and path.resolve(strict=True) == path,
            'existing canonical absolute path required')
    return path


def fresh(value):
    path = Path(value)
    require(path.is_absolute() and not path.exists() and not path.is_symlink()
            and not path.is_relative_to(ROOT), 'fresh external absolute output required')
    return path


def jobs(value):
    number = int(value)
    require(1 <= number <= 256, 'jobs must be in 1..256')
    return number


def run(*argv):
    subprocess.run([str(arg) for arg in argv], cwd=ROOT, check=True)


def write(file, value):
    with file.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def digest(file):
    value = hashlib.sha256()
    with file.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def build(args):
    count = args.jobs or jobs(os.environ.get('CARGO_BUILD_JOBS', str(min(os.cpu_count() or 1, 256))))
    node = Path(shutil.which('node') or '').resolve(strict=True)
    require(node.is_file(), 'Node executable required for existing signing helper')
    print(json.dumps({'stage': 'native-build', 'jobs': count, 'profile': 'release',
                      'target': 'aarch64-apple-darwin', 'target_dir': str(args.target_dir)}), flush=True)
    run(sys.executable, '-I', '-B', ROOT / 'src/tools/release/build-native-binary.py',
        '--source-revision', args.source_revision, '--gate-receipt', args.gate_receipt,
        '--target-dir', args.target_dir, '--output', args.output, '--jobs', count,
        '--reuse-workspace-cache', '--macos-local-signing', args.local_signing,
        '--macos-signing-node', node)


def sign_workers(args):
    """Sign this job's fresh upstream copies before publisher manifests exist."""
    root = args.input_dir
    preparation = json.loads((root / 'preparation.json').read_text())
    require(preparation.get('status') == 'PASS' and preparation.get('signed') is False
            and preparation.get('source_revision') == args.source_revision
            and preparation.get('platform') == 'macos'
            and preparation.get('producer') == 'src/ci/release-workers.py',
            'fresh current-source worker preparation required')
    require(not any(root.rglob('manifest.sig')), 'publisher-sealed worker input cannot be signed again')
    members = ('worker-release/bin/codex', 'worker-release/bin/node', 'tunnel/tunnel-client-runtime')
    receipt_file = root / 'worker-signing-receipt.json'
    facts = []
    receipt = {'schema': 1, 'source_revision': args.source_revision,
               'scope': 'PLATFORM_SIGNATURES_BEFORE_PUBLISHER_SEAL', 'status': 'STARTED',
               'workers': facts, 'publisher_manifest_created': False,
               'installation': 'NOT RUN', 'notarization': 'NOT RUN'}
    # A previous partial/unknown attempt is never automatically replayed.
    write(receipt_file, receipt)
    try:
        for member in members:
            binary = root / member
            require(binary.is_file() and not binary.is_symlink()
                    and binary.resolve(strict=True) == binary, 'regular upstream worker required')
            source_sha256 = digest(binary)
            report_raw = subprocess.check_output([
                'node', str(ROOT / 'src/tools/release/sign-native-macos.mjs'),
                str(args.local_signing), str(binary)], cwd=ROOT)
            report = json.loads(report_raw)
            require(report.get('status') == 'PASS' and report.get('sign_actual_wait') is True
                    and report.get('verify_actual_wait') is True
                    and report.get('sign_exit_code') == 0 and report.get('verify_exit_code') == 0
                    and report.get('source_image_sha256') == source_sha256
                    and report.get('signed_image_sha256') == digest(binary),
                    'native worker signature was not verified')
            facts.append({'path': member, 'upstream_sha256': source_sha256,
                          'signed_sha256': digest(binary), 'signature': report})
            receipt_file.write_text(json.dumps(receipt, indent=2) + '\n')
        receipt['status'] = 'PASS'
    except BaseException:
        receipt['status'] = 'FAILED_OR_UNKNOWN_NO_REPLAY'
        raise
    finally:
        receipt_file.write_text(json.dumps(receipt, indent=2) + '\n')


def package(args):
    require(re.fullmatch(r'\d+\.\d+\.\d+', args.version), 'marketing version required')
    require(re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z.+-]*', args.runtime_version), 'safe runtime version required')
    native = args.runtime_dir / 'payload'
    manifest = json.loads((native / 'manifest.json').read_text())
    require(manifest.get('version') == args.runtime_version
            and manifest.get('target') == 'aarch64-apple-darwin'
            and manifest.get('source', {}).get('revision') == args.source_revision,
            'sealed runtime version/source/architecture mismatch')
    cua_preparation = json.loads((args.cua_binary.parent / 'preparation.json').read_text())
    require(cua_preparation.get('status') == 'PASS'
            and cua_preparation.get('source_revision') == args.source_revision
            and cua_preparation.get('platform') == 'macos'
            and cua_preparation.get('producer') == 'src/ci/release-workers.py'
            and cua_preparation.get('cua_binary_sha256') == digest(args.cua_binary),
            'current-source Cua preparation must bind exact App helper bytes')
    # The existing producer authenticates the publisher pin, signature, complete
    # runtime closure and source binding before executing its native verifier.
    args.output.mkdir(mode=0o700, parents=True)
    prepare = args.output / 'prepared'
    finalized = args.output / 'final'
    configuration = args.output / 'prepare.json'
    write(configuration, {'destination': str(prepare), 'version': args.version,
                         'buildNumber': args.build_number, 'sourceRevision': args.source_revision,
                         'cuaBinary': str(args.cua_binary), 'moduleCachePath': str(args.module_cache),
                         'nativeRuntime': {'payloadDir': str(native),
                                           'publisherFile': str(args.runtime_dir / 'publisher.pem'),
                                           'expectedPublisher': PIN}, 'prepareOnly': True})
    producer = ROOT / 'src/host/build-macos-preview.mjs'
    run('node', producer, configuration)
    finalize_config = args.output / 'finalize.json'
    write(finalize_config, {'nativePreparedSource': str(prepare),
                            'preparedReceiptSha256': digest(prepare / 'prepared-native-app.json'),
                            'destination': str(finalized),
                            'localSigning': json.loads(args.local_signing.read_text()),
                            'expectedPublisherSha256': PIN, 'createDmg': True})
    run('node', producer, finalize_config)
    receipt = json.loads((finalized / 'native-app-receipt.json').read_text())
    require(receipt.get('archiveVerification', {}).get('status') == 'PASS'
            and receipt.get('nativeReaderActualWait') is True
            and receipt.get('nativeReaderExitCode') == 0,
            'native DMG verification did not pass')
    original = finalized / receipt['primaryArtifact']
    require(original.parent == finalized and original.suffix == '.dmg' and original.is_file(),
            'native producer DMG required')
    assets = args.output / 'assets'
    assets.mkdir(mode=0o700)
    asset = assets / f'Styx-{args.runtime_version}-macos-arm64.dmg'
    shutil.copyfile(original, asset)
    require(digest(asset) == digest(original), 'DMG asset copy changed')
    write(args.output / 'release-package-receipt.json', {
        'schema': 1, 'source_revision': args.source_revision, 'version': args.runtime_version,
        'asset': asset.name, 'sha256': digest(asset),
        'native_app_receipt_sha256': digest(finalized / 'native-app-receipt.json'),
        'signing': receipt.get('signing'), 'notarization': receipt.get('notarization'),
        'installation': 'NOT RUN', 'native_gui_acceptance': 'NOT RUN'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, action in [('build', build), ('sign-workers', sign_workers), ('package', package)]:
        command = commands.add_parser(name)
        command.add_argument('--source-revision', required=True)
        if name != 'sign-workers':
            command.add_argument('--output', required=True, type=fresh)
        command.add_argument('--local-signing', required=True, type=existing)
        command.set_defaults(action=action)
        if name == 'build':
            command.add_argument('--gate-receipt', required=True, type=existing)
            command.add_argument('--target-dir', required=True, type=existing)
            command.add_argument('--jobs', type=jobs)
        elif name == 'sign-workers':
            command.add_argument('--input-dir', required=True, type=existing)
        else:
            command.add_argument('--runtime-dir', required=True, type=existing)
            command.add_argument('--version', required=True)
            command.add_argument('--runtime-version', required=True)
            command.add_argument('--build-number', required=True)
            command.add_argument('--cua-binary', required=True, type=existing)
            # A cache may not exist on its first CI run.
            command.add_argument('--module-cache', required=True, type=Path)
    args = parser.parse_args()
    require(re.fullmatch(r'[a-f0-9]{40}', args.source_revision), 'full source revision required')
    require(sys.platform == 'darwin' and platform.machine() == 'arm64', 'native Apple silicon runner required')
    if args.command == 'package':
        require(args.module_cache.is_absolute(), 'absolute Swift module cache required')
    os.umask(0o077)
    args.action(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError) as error:
        print(f'macOS release adapter failed: {type(error).__name__}', file=sys.stderr)
        raise SystemExit(1)
