#!/usr/bin/env python3
"""Package a compile-only macOS build with unchanged signed worker inputs."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PIN = 'bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args):
    subprocess.run([str(a) for a in args], cwd=ROOT, check=True)


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def seal(args):
    if sys.platform != 'linux':
        raise ValueError('Linux publisher sealer required')
    worker = args.workers / 'worker-release'
    if not (worker / 'manifest.sig').exists():
        signing = args.output.parent / 'quick-worker-signing'
        signing.mkdir(mode=0o700)
        helper = runpy.run_path(str(ROOT / 'src/tools/release/build-native-preview.py'))
        if helper['sign_manifest'](args.key, signing, worker) != PIN:
            raise ValueError('publisher mismatch')
        signature = worker / 'manifest.sig'
        signature.write_bytes(base64.urlsafe_b64encode(signature.read_bytes()).rstrip(b'=') + b'\n')
        shutil.copyfile(signing / 'publisher.pem', args.workers / 'worker-publisher.pem')
    tunnel = args.workers / 'tunnel/tunnel-client-runtime'
    run(sys.executable, '-I', '-B', ROOT / 'src/tools/release/build-native-runtime.py',
        '--source-revision', args.revision, '--target', 'aarch64-apple-darwin',
        '--version', args.version, '--binary', args.native / 'styx',
        '--build-receipt', args.native / 'receipt.json', '--relocated-binary',
        '--publisher-private-key', args.key, '--expected-publisher', PIN,
        '--worker-release', worker, '--worker-publisher-file', args.workers / 'worker-publisher.pem',
        '--worker-kind', 'codex_exec', '--worker-kind', 'browser_node22',
        '--tunnel-client', tunnel, '--tunnel-client-sha256', digest(tunnel),
        '--tunnel-client-license', args.workers / 'tunnel/LICENSE',
        '--tunnel-client-notice', args.workers / 'tunnel/NOTICE', '--output', args.output)


def app(args):
    if sys.platform != 'darwin':
        raise ValueError('native macOS packaging required')
    args.output.mkdir(mode=0o700, parents=True)
    prepared, final = args.output / 'prepared', args.output / 'final'
    prepare, finalize = args.output / 'prepare.json', args.output / 'finalize.json'
    write(prepare, dict(destination=str(prepared), version='0.4.0',
                       buildNumber=args.build_number, sourceRevision=args.revision,
                       cuaBinary=str(args.cua), moduleCachePath=str(args.module_cache),
                       nativeRuntime=dict(payloadDir=str(args.runtime / 'payload'),
                                          publisherFile=str(args.runtime / 'publisher.pem'),
                                          expectedPublisher=PIN), prepareOnly=True))
    producer = ROOT / 'src/host/build-macos-preview.mjs'
    run('node', producer, prepare)
    write(finalize, dict(nativePreparedSource=str(prepared),
                         preparedReceiptSha256=digest(prepared / 'prepared-native-app.json'),
                         destination=str(final), localSigning=json.loads(args.local_signing.read_text()),
                         expectedPublisherSha256=PIN, createDmg=True))
    run('node', producer, finalize)
    write(args.output / 'quick-package-receipt.json',
          dict(source_revision=args.revision, qualification='COMPILE_ONLY_NOT_STABLE',
               quality='NOT RUN', tests='NOT RUN', installation='NOT RUN',
               artifact=str(final), native_receipt=str(final / 'native-app-receipt.json')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, action in [('seal', seal), ('app', app)]:
        command = commands.add_parser(name)
        command.add_argument('--revision', required=True)
        command.add_argument('--output', required=True, type=Path)
        command.set_defaults(action=action)
        fields = ('native', 'workers', 'key') if name == 'seal' else ('runtime', 'cua', 'local-signing', 'module-cache')
        for field in fields:
            command.add_argument('--' + field, required=True, type=Path)
        command.add_argument('--version' if name == 'seal' else '--build-number', required=True)
    args = parser.parse_args()
    args.action(args)


if __name__ == '__main__':
    main()
