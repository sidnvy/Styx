#!/usr/bin/env python3
"""Build the pinned, source-patched Cua worker natively with a reusable Cargo cache.

Only public source archives are downloaded. Baseline patch contents and every
changed source file are checked against the retained source contract. Windows
also reuses the reviewed WGC/DPI preparation and native build producers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import runpy
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
PREPARER = ROOT / 'src/tools/release/prepare-cua-windows-wgc.py'
CONTRACT = runpy.run_path(str(PREPARER), run_name='cua_preparation_contract')
COMMIT = CONTRACT['COMMIT']
ARCHIVE_SHA = CONTRACT['ARCHIVE_SHA']
BASELINE = CONTRACT['BASELINE']
BASELINE_SHA = CONTRACT['BASELINE_SHA']
PATCH_SHA = CONTRACT['BASELINE_PATCH_SHA']
TARGETS = {'linux': 'x86_64-unknown-linux-gnu', 'windows': 'x86_64-pc-windows-msvc',
           'macos': 'aarch64-apple-darwin'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(file):
    value = hashlib.sha256()
    with file.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def write(file, value):
    with file.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def run(*argv, cwd=ROOT, env=None):
    subprocess.run([str(arg) for arg in argv], cwd=cwd, env=env, check=True)


def download(cache):
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = cache / f'cua-{COMMIT}.tar.gz'
    if destination.exists():
        require(destination.is_file() and not destination.is_symlink()
                and digest(destination) == ARCHIVE_SHA, 'cached_cua_source_checksum_mismatch')
        return destination
    # A failed partial download is never a cache hit. Publish only verified bytes.
    fd, temporary = tempfile.mkstemp(prefix='cua-download-', dir=cache)
    try:
        total = 0
        with os.fdopen(fd, 'wb') as output, urlopen(
                f'https://codeload.github.com/trycua/cua/tar.gz/{COMMIT}', timeout=120) as response:
            require(response.status == 200, 'cua_source_download_failed')
            while block := response.read(1048576):
                total += len(block)
                require(total <= 512 * 1048576, 'cua_source_archive_budget')
                output.write(block)
        require(digest(Path(temporary)) == ARCHIVE_SHA, 'upstream_cua_archive_checksum_mismatch')
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


def inventory(root):
    files = {}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'cua_source_alias_refused')
        if path.is_file():
            files[path.relative_to(root).as_posix()] = digest(path)
    return files


def source_cache_times(archive, source, expected):
    """Normalize only verified immutable third-party inputs, never product Git.

    The dedicated Cua target cache is keyed by the complete source/patch/build
    recipe. Stable source mtimes avoid invalidating Cargo merely because the
    identical verified archive was extracted on another fresh runner.
    """
    require(digest(archive) == ARCHIVE_SHA, 'fixed_cua_archive_required_for_cache_times')
    require(inventory(source) == expected, 'cua_source_changed_before_cache_times')
    with tarfile.open(archive) as stream:
        root = stream.next()
        require(root is not None and root.isdir() and root.name == f'cua-{COMMIT}'
                and isinstance(root.mtime, (int, float)) and root.mtime == int(root.mtime)
                and 0 < root.mtime < 2**32, 'fixed_cua_archive_root_time_required')
        epoch = int(root.mtime)
    timestamp = epoch * 1_000_000_000
    for file in sorted(source.rglob('*'), reverse=True):
        require(not file.is_symlink(), 'cua_source_alias_refused')
        if os.utime in os.supports_follow_symlinks:
            os.utime(file, ns=(timestamp, timestamp), follow_symlinks=False)
        else:
            # Windows Python lacks this keyword. The complete fresh source
            # inventory rejects links before and after this operation.
            os.utime(file, ns=(timestamp, timestamp))
    os.utime(source, ns=(timestamp, timestamp), follow_symlinks=False)
    require(inventory(source) == expected, 'cua_source_changed_after_cache_times')
    require(all(path.stat().st_mtime_ns == timestamp for path in source.rglob('*')),
            'cua_source_cache_time_mismatch')
    return {'schema': 1, 'scope': 'VERIFIED_THIRD_PARTY_SOURCE_ONLY',
            'mtime_policy': 'checksum_pinned_codeload_root_mtime_after_patch_verification',
            'source_mtime_epoch': epoch, 'upstream_archive_sha256': ARCHIVE_SHA,
            'content_inventory_sha256': hashlib.sha256(json.dumps(
                expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'files': len(expected), 'before_after_bytes_unchanged': True,
            'requires_cache_key': 'full_source_patch_helpers_target_toolchain_features_rustflags_recipe',
            'cargo_build_still_required': True, 'product_git_files_changed': False}


def prepare_baseline(archive, output, revision):
    require(digest(BASELINE) == BASELINE_SHA, 'fixed_cua_baseline_manifest_required')
    baseline = json.loads(BASELINE.read_bytes())
    patch = BASELINE.parent / baseline['patch']
    require(digest(patch) == PATCH_SHA == baseline['patch_sha256']
            and baseline['upstream_commit'] == COMMIT
            and baseline['official_archive_sha256'] == ARCHIVE_SHA,
            'fixed_cua_baseline_patch_required')
    output.mkdir(mode=0o700)
    total, names = 0, set()
    with tarfile.open(archive) as source:
        for member in source:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and name.parts,
                    'cua_archive_path_refused')
            relative = PurePosixPath(*name.parts[1:])
            selected = str(relative)
            if not (selected.startswith(('libs/cua-driver/', 'libs/cua/'))
                    or selected in ('LICENSE', 'LICENSE.md', 'libs/images/sandbox-images.json')):
                continue
            require(selected not in names and (member.isfile() or member.isdir()),
                    'cua_source_duplicate_or_link_refused')
            names.add(selected)
            require(len(names) <= 16384, 'cua_source_file_budget')
            destination = output.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            require(0 <= member.size <= 16 * 1048576 and total <= 128 * 1048576,
                    'cua_source_size_budget')
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as data, destination.open('xb') as target:
                shutil.copyfileobj(data, target)
            destination.chmod(0o600)
    for item in baseline['files']:
        file = output / item['path']
        require(not file.exists() if item['original_sha256'] is None else
                file.is_file() and digest(file) == item['original_sha256'],
                'original_cua_baseline_file_mismatch')
    run('patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch, cwd=output)
    for item in baseline['files']:
        require(digest(output / item['path']) == item['final_sha256'],
                'patched_cua_baseline_file_mismatch')
    require(digest(output / baseline['workspace'] / 'Cargo.lock') == baseline['patched_lock_sha256'],
            'patched_cua_lock_mismatch')
    return {'schema': 1, 'source_revision': revision, 'upstream_commit': COMMIT,
            'upstream_archive_sha256': ARCHIVE_SHA, 'baseline_manifest_sha256': BASELINE_SHA,
            'baseline_patch_sha256': PATCH_SHA, 'cargo_lock_sha256': baseline['patched_lock_sha256'],
            'files': inventory(output)}


def native_build(args, source, prepared):
    target = TARGETS[args.platform]
    workspace = source / 'libs/cua-driver/rust'
    args.target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(args.target_dir), CARGO_BUILD_JOBS=str(args.jobs),
               CMAKE_BUILD_PARALLEL_LEVEL=str(args.jobs), CUA_DRIVER_GIT_SHA=COMMIT)
    run('cargo', 'fetch', '--locked', '--target', target, cwd=workspace, env=env)
    command = ['cargo', 'build', '--locked', '--offline', '-p', 'cua-driver', '--release',
               '--target', target, '--jobs', str(args.jobs), '--message-format=json-render-diagnostics']
    if args.platform == 'linux':
        command += ['--features', 'cua-driver/portal-input']
    logs = args.output / 'native-build'
    logs.mkdir(mode=0o700)
    started = time.monotonic()
    with (logs / 'cargo.stdout.jsonl').open('xb') as stdout, (logs / 'cargo.stderr.log').open('xb') as stderr:
        result = subprocess.run(command, cwd=workspace, env=env, stdout=stdout, stderr=stderr)
    require(result.returncode == 0, 'native_cua_build_failed')
    require(inventory(source) == prepared['files'], 'cua_source_changed_during_build')
    selected = []
    for line in (logs / 'cargo.stdout.jsonl').read_text().splitlines():
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'cua-driver' and item.get('executable'):
            selected.append(item)
    require(len(selected) == 1, 'one_native_cua_executable_required')
    original = Path(selected[0]['executable']).resolve(strict=True)
    require(original.is_file() and original.is_relative_to(args.target_dir), 'owned_cua_output_required')
    binary = args.output / 'bin/cua-driver'
    binary.parent.mkdir(mode=0o700)
    shutil.copyfile(original, binary)
    binary.chmod(0o700)
    require(digest(binary) == digest(original), 'cua_binary_copy_changed')
    version = subprocess.check_output([str(binary), '--version'], text=True).strip()
    require(version == 'cua-driver 0.36.0', 'pinned_cua_worker_version_required')
    return {'status': 'PASS', 'schema': 1, 'scope': 'NATIVE_WORKER_BUILD_NOT_PLATFORM_ACCEPTANCE',
            'source_revision': args.source_revision, 'upstream_commit': COMMIT,
            'upstream_archive_sha256': ARCHIVE_SHA, 'baseline_manifest_sha256': BASELINE_SHA,
            'baseline_patch_sha256': PATCH_SHA, 'target': target, 'command': command,
            'jobs': args.jobs, 'cmake_jobs': args.jobs, 'exit_code': result.returncode,
            'elapsed_seconds': time.monotonic() - started, 'binary_sha256': digest(binary),
            'binary_bytes': binary.stat().st_size, 'version': version,
            'compiler_artifact_fresh': selected[0].get('fresh'), 'prepared_files_unchanged': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=TARGETS, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=int(os.environ.get('CARGO_BUILD_JOBS', os.cpu_count() or 1)))
    args = parser.parse_args()
    require(1 <= args.jobs <= 256 and re.fullmatch('[a-f0-9]{40}', args.source_revision), 'revision_and_jobs_required')
    actual = {'linux': 'linux', 'darwin': 'macos', 'win32': 'windows'}.get(sys.platform)
    machine = platform.machine().lower()
    require(actual == args.platform and machine in (('arm64', 'aarch64') if actual == 'macos' else ('x86_64', 'amd64')),
            'native_cua_platform_required')
    for path in (args.cache, args.target_dir, args.output):
        require(path.is_absolute() and not path.is_relative_to(ROOT), 'external_absolute_cua_paths_required')
    require(not args.output.exists() and not args.output.is_symlink(), 'fresh_cua_build_output_required')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
    require(args.source_revision == revision and not dirty, 'frozen_clean_product_source_required')
    os.umask(0o077)
    archive = download(args.cache)
    args.output.mkdir(mode=0o700, parents=True)
    source = args.output / 'source'
    if args.platform == 'windows':
        run(sys.executable, '-I', '-B', PREPARER, '--archive', archive, '--output', source,
            '--source-revision', args.source_revision)
        cache_contract = source_cache_times(archive, source, inventory(source))
        write(args.output / 'source-cache-contract.json', cache_contract)
        built = args.output / 'native-build'
        run(sys.executable, '-I', '-B', ROOT / 'src/tools/release/build-cua-windows-wgc.py',
            '--prepared-source', source, '--source-revision', args.source_revision,
            '--target-dir', args.target_dir, '--output', built, '--jobs', args.jobs)
        receipt = json.loads((built / 'receipt.json').read_text())
        require(receipt.get('status') == 'PASS', 'windows_cua_build_required')
        (args.output / 'bin').mkdir(mode=0o700)
        shutil.copyfile(built / 'bin/cua-driver.exe', args.output / 'bin/cua-driver.exe')
        require(digest(args.output / 'bin/cua-driver.exe') == receipt['binary_sha256'], 'windows_cua_copy_changed')
    else:
        prepared = prepare_baseline(archive, source, args.source_revision)
        cache_contract = source_cache_times(archive, source, prepared['files'])
        prepared['source_cache'] = cache_contract
        write(args.output / 'prepared-source.json', prepared)
        receipt = native_build(args, source, prepared)
    receipt['source_cache'] = cache_contract
    write(args.output / 'receipt.json', receipt)
    print(json.dumps({key: receipt[key] for key in ('status', 'binary_sha256', 'jobs')}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError) as error:
        print(f'Cua release build failed: {type(error).__name__}', file=sys.stderr)
        raise SystemExit(1)
