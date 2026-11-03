#!/usr/bin/env python3
"""Build one ordinary pinned native Cua worker; never installs or opens a profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def inspect(root, receipt):
    observed = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'prepared_source_link_refused')
        if path.is_file() and path.name != 'prepared-inputs.json':
            observed[path.relative_to(root).as_posix()] = digest(path)
    require(observed == receipt['files'], 'prepared_source_changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared-source', required=True, type=Path)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--target-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    require(sys.platform == 'win32' and 1 <= args.jobs <= 4, 'bounded_native_windows_build_required')
    root, output, target = (p.resolve() for p in (args.prepared_source, args.output, args.target_dir))
    require(not output.exists() and not output.is_relative_to(root) and not target.is_relative_to(root),
            'fresh_external_candidate_and_owned_cache_required')
    receipt_path = root / 'prepared-inputs.json'
    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)
    require(receipt['schema'] == 1 and receipt['scope'] == 'THIRD_PARTY_BUILD_INPUT_NOT_BUILT_OR_SIGNED'
            and receipt['product_source_revision'] == args.source_revision
            and receipt['product_source_status'] == 'CLEAN' and receipt['development_check'] is False
            and receipt['upstream_commit'] == '6d6c734c127025fb39ad5d585a10382808b39dc1'
            and receipt['upstream_cargo_lock_sha256'] == 'f9d49ce2dccdc43b2f7f027185301138fdd45eab4f9a556aace4cb0f4a98d46c'
            and receipt.get('patched_cargo_lock_sha256') == '978a9b7e0bc2855af210f26c28dadc29f1a9b978df2677385332f1fc6bf39964'
            and receipt.get('native_baseline_manifest_sha256') == 'da892240124277eb707bc717774ab63bd7de117ee4a171b237cc207b85ad1b5b'
            and receipt.get('native_baseline_patch_sha256') == '0dbd26de72aa13076ee69a247e8ec3b362df771aa4d8c3515aeb5510d0052e71',
            'frozen_pinned_source_required')
    baseline_path = root / 'styx-native-baseline-source.json'
    require(baseline_path.is_file() and digest(baseline_path) == receipt['native_baseline_manifest_sha256'],
            'actual_native_baseline_manifest_required')
    baseline = json.loads(baseline_path.read_bytes())
    require(all((root / item['path']).is_file()
                and digest(root / item['path']) == item['final_sha256']
                for item in baseline['files']), 'actual_native_baseline_files_required')
    require(receipt['fragment_sha256'] == '4152524e7e238236842e80d6e6b77216c5376509eca2816d6007ea7e8119fb23'
            and digest(root / 'libs/cua-driver/rust/crates/platform-windows/src/capture.rs')
            == receipt['patched_capture_sha256'] == '18afbedb7ed7fb8638a6e37cb5ca2d891ed082a5b215b87db711f9d4d61c708f',
            'actual_reviewed_capture_required')
    inspect(root, receipt)
    output.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS=str(args.jobs),
               CMAKE_BUILD_PARALLEL_LEVEL='2', CUA_DRIVER_GIT_SHA=receipt['upstream_commit'])
    command = ['cargo', 'build', '--locked', '-p', 'cua-driver', '--release', '--target',
               'x86_64-pc-windows-msvc', '-j', str(args.jobs), '--timings',
               '--message-format=json-render-diagnostics']
    started = time.monotonic()
    with (output / 'cargo.stdout.jsonl').open('xb') as stdout, (output / 'cargo.stderr.log').open('xb') as stderr:
        result = subprocess.run(command, cwd=root / 'libs/cua-driver/rust', env=env,
                                stdout=stdout, stderr=stderr)
    build = {'schema': 1, 'scope': 'NATIVE_WORKER_BUILD_NOT_PLATFORM_ACCEPTANCE',
             'source_revision': args.source_revision, 'upstream_commit': receipt['upstream_commit'],
             'prepared_inputs_sha256': hashlib.sha256(raw).hexdigest(),
             'native_baseline_manifest_sha256': receipt['native_baseline_manifest_sha256'],
             'native_baseline_patch_sha256': receipt['native_baseline_patch_sha256'],
             'patched_cargo_lock_sha256': receipt['patched_cargo_lock_sha256'],
             'fragment_sha256': receipt['fragment_sha256'],
             'patched_capture_sha256': receipt['patched_capture_sha256'],
             'jobs': args.jobs, 'cmake_jobs': 2, 'command': command,
             'elapsed_seconds': time.monotonic() - started, 'exit_code': result.returncode,
             'status': 'FAILED_OR_UNVERIFIED'}
    def save():
        (output / 'receipt.json').write_text(json.dumps(build, sort_keys=True, indent=2) + '\n')
    save()
    require(result.returncode == 0, 'native_build_failed')
    require(receipt_path.read_bytes() == raw, 'prepared_receipt_changed')
    inspect(root, receipt)
    artifacts = [json.loads(line) for line in (output / 'cargo.stdout.jsonl').read_text().splitlines()]
    compiled = {item['target']['name'] for item in artifacts
                if item.get('reason') == 'compiler-artifact' and item.get('fresh') is False}
    require({'platform_windows', 'cua-driver'} <= compiled, 'affected_targets_must_recompile')
    selected = [item for item in artifacts if item.get('reason') == 'compiler-artifact'
                and item.get('target', {}).get('name') == 'cua-driver' and item.get('executable')]
    require(len(selected) == 1, 'one_native_executable_required')
    binary = Path(selected[0]['executable'])
    require(binary.is_relative_to(target) and binary.is_file(), 'owned_native_output_required')
    (output / 'bin').mkdir()
    shutil.copyfile(binary, output / 'bin/cua-driver.exe')
    built = output / 'bin/cua-driver.exe'
    require(digest(built) == digest(binary), 'copied_binary_changed')
    version = subprocess.run([str(built), '--version'], capture_output=True, text=True, check=True)
    require(version.stdout.strip() == 'cua-driver 0.36.0', 'pinned_worker_version_required')
    build.update(status='PASS', binary_sha256=digest(built), binary_bytes=built.stat().st_size,
                 version=version.stdout.strip(), affected_targets_recompiled=sorted(compiled),
                 prepared_files_unchanged=True)
    save()
    print(json.dumps(build, sort_keys=True))


if __name__ == '__main__':
    main()
