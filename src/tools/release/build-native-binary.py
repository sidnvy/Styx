#!/usr/bin/env python3
"""Build one native release CLI from an exact clean, already-passing source gate.
No installation, signing, foreign-image execution or runtime/profile startup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import tarfile
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
PRODUCER = 'src/tools/release/build-native-binary.py'
TARGETS = {'x86_64-unknown-linux-gnu', 'x86_64-apple-darwin',
           'aarch64-apple-darwin', 'x86_64-pc-windows-msvc'}


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            digest.update(block)
    return digest.hexdigest()


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def command(argv):
    return subprocess.check_output(argv, cwd=ROOT, text=True, timeout=30).strip()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def archive_source(manifest_path, revision, expected_archive_sha256):
    """Check the original git-archive inventory; never extract or manufacture Git."""
    require(manifest_path.is_absolute() and manifest_path.resolve(strict=True) == manifest_path
            and not manifest_path.is_relative_to(ROOT), 'external_archive_manifest_required')
    manifest_info = manifest_path.lstat()
    require(stat.S_ISREG(manifest_info.st_mode) and manifest_info.st_nlink == 1
            and not (getattr(manifest_info, 'st_file_attributes', 0) & 0x400)
            and manifest_info.st_size <= 8 * 1048576, 'archive_manifest_bound')
    raw = manifest_path.read_bytes()
    require(len(raw) <= 8 * 1048576, 'archive_manifest_bound')
    manifest = strict_json(raw)
    require(isinstance(manifest, dict) and manifest.get('sourceRevision') == revision
            and re.fullmatch('[a-f0-9]{64}', manifest.get('archiveSha256', '')) is not None,
            'archive_provenance_mismatch')
    require(isinstance(expected_archive_sha256, str)
            and re.fullmatch('[a-f0-9]{64}', expected_archive_sha256) is not None
            and manifest['archiveSha256'] == expected_archive_sha256, 'expected_source_archive_sha256_mismatch')
    members = manifest.get('members')
    require(isinstance(members, dict) and 0 < len(members) <= 16384, 'archive_members_bound')
    expected_directories = set()
    for name, digest in members.items():
        require(isinstance(name, str) and len(name) <= 1024 and not name.startswith('/')
                and all(part not in {'', '.', '..'} for part in name.split('/'))
                and not any(c in name for c in ('\\', ':', '\x00'))
                and isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest) is not None,
                'archive_member_invalid')
        expected_directories.update(parent.as_posix() for parent in Path(name).parents if str(parent) != '.')
    archive = manifest_path.with_name('source.tar')
    archive_info = archive.lstat()
    require(not stat.S_ISLNK(archive_info.st_mode)
            and not (getattr(archive_info, 'st_file_attributes', 0) & 0x400)
            and archive.resolve(strict=True) == archive and archive.is_file()
            and archive.stat().st_size <= 1024 ** 3
            and sha(archive) == manifest['archiveSha256'], 'original_archive_hash_mismatch')
    found = {}
    with tarfile.open(archive, mode='r:') as stream:
        for item in stream:
            if item.isdir():
                require(item.name.rstrip('/') in expected_directories, 'archive_directory_invalid')
                continue
            require(item.isfile() and item.name in members and item.name not in found
                    and 0 <= item.size <= 512 * 1048576, 'archive_nonregular_or_unexpected_member')
            digest = hashlib.sha256()
            with stream.extractfile(item) as data:
                for block in iter(lambda: data.read(1048576), b''):
                    digest.update(block)
            found[item.name] = digest.hexdigest()
    require(found == members, 'archive_complete_members_mismatch')
    actual = {}
    directories = set()
    for base, dirs, files in os.walk(ROOT, followlinks=False):
        for name in dirs + files:
            path = Path(base) / name
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'source_alias_or_reparse')
            relative = path.relative_to(ROOT).as_posix()
            if stat.S_ISDIR(info.st_mode):
                require(relative in expected_directories, 'source_extra_directory')
                directories.add(relative)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and relative in members and info.st_size <= 512 * 1048576,
                        'source_nonregular_alias_or_extra')
                actual[relative] = sha(path)
                after = path.lstat()
                require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'source_member_changed')
    require(actual == members and directories == expected_directories, 'source_complete_tree_mismatch')
    require(manifest_path.read_bytes() == raw and sha(archive) == manifest['archiveSha256'],
            'archive_inputs_changed')
    return {'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'archive_sha256': manifest['archiveSha256'], 'members': len(members)}


def normalized_inputs(inputs):
    # The passing gate may be Linux while this actual native producer is Windows.
    result = {name.replace('\\', '/'): digest for name, digest in inputs.items()}
    require(len(result) == len(inputs), 'source_input_path_collision')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source-revision', 'gate-receipt', 'target-dir', 'output']:
        parser.add_argument('--' + name, required=True, type=str if name == 'source-revision' else Path)
    parser.add_argument('--source-archive-manifest', type=Path,
                        help='external source-inputs.json; exact original source.tar must be adjacent')
    parser.add_argument('--expected-source-archive-sha256',
                        help='independent controller pin, required exactly in source-archive mode')
    args = parser.parse_args()
    require(bool(args.source_archive_manifest) == bool(args.expected_source_archive_sha256),
            'archive_manifest_and_expected_sha256_required_together')
    os.umask(0o077)
    require(re.fullmatch('[a-f0-9]{40}', args.source_revision) is not None, 'full_source_revision_required')
    for path in [args.gate_receipt, args.target_dir, args.output.parent]:
        require(path.is_absolute() and path.resolve(strict=True) == path, 'canonical_existing_input_required')
    require(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink()
            and not args.output.is_relative_to(ROOT), 'fresh_external_output_required')
    require(not args.target_dir.is_relative_to(ROOT), 'external_build_target_required')
    args.output.mkdir(mode=0o700)
    receipt = {'schema': 1, 'status': 'FAIL', 'source_revision': args.source_revision,
               'producer': PRODUCER, 'profile': 'release', 'installed': False,
               'deployed': False, 'platform_acceptance': False}
    started = time.monotonic()
    try:
        require(args.gate_receipt.stat().st_size <= 16 * 1048576, 'gate_receipt_bound')
        gate_raw = args.gate_receipt.read_bytes()
        require(len(gate_raw) <= 16 * 1048576, 'gate_receipt_bound')
        gate = strict_json(gate_raw)
        require(gate.get('status') == 'PASS' and gate.get('input_stability') == 'PASS'
                and gate.get('source_revision') == args.source_revision, 'same_source_passing_gate_required')
        if args.source_archive_manifest is None:
            require(command(['git', 'rev-parse', 'HEAD']) == args.source_revision
                    and not command(['git', 'status', '--porcelain']), 'clean_frozen_source_required')
        else:
            receipt['source_archive'] = archive_source(args.source_archive_manifest, args.source_revision,
                                                     args.expected_source_archive_sha256)
        q = runpy.run_path(str(ROOT / 'src/ci/rust-quality.py'))
        inputs = normalized_inputs(q['source_inputs'](ROOT))
        require(inputs == normalized_inputs(gate['inputs']), 'gate_complete_source_inputs_mismatch')
        rust = command(['rustc', '-vV'])
        target = re.search(r'^host: (.+)$', rust, re.M).group(1)
        require(target in TARGETS, 'supported_native_host_required')
        receipt.update(target=target, toolchain=rust, inputs=inputs,
                       gate_receipt_sha256=hashlib.sha256(gate_raw).hexdigest())
        env = dict(os.environ, CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
                   CARGO_TERM_COLOR='never', PYTHONDONTWRITEBYTECODE='1',
                   CARGO_TARGET_DIR=str(args.target_dir))
        argv = ['cargo', 'build', '--release', '-p', 'styx', '--target', target, '--locked', '--offline']
        receipt['command'] = argv
        with (args.output / 'cargo-build.log').open('x') as log:
            try:
                result = subprocess.run(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=subprocess.STDOUT, timeout=900)
                receipt.update(build_actual_exit=result.returncode, build_actual_wait=True)
            except subprocess.TimeoutExpired:
                # subprocess.run kills and waits its ORIGINAL direct child before raising.
                receipt.update(build_actual_wait=True, build_timeout=True)
                raise RuntimeError('native_build_timeout') from None
        require(result.returncode == 0, 'native_build_failed')
        name = 'styx.exe' if target.endswith('windows-msvc') else 'styx'
        original = args.target_dir / target / 'release' / name
        original_hash = sha(original)
        binary = args.output / name
        shutil.copyfile(original, binary)
        binary.chmod(0o700)
        require(sha(binary) == original_hash == sha(original), 'native_binary_copy_changed')
        info_argv = [str(binary), 'build-info', '--json']
        with (args.output / 'build-info.stdout.json').open('xb') as out, (args.output / 'build-info.stderr.log').open('xb') as err:
            try:
                info = subprocess.run(info_argv, cwd=args.output, env=env, stdin=subprocess.DEVNULL,
                                      stdout=out, stderr=err, timeout=15)
            except subprocess.TimeoutExpired:
                receipt['cli_build_info_failure'] = 'original_child_killed_and_waited_after_timeout'
                raise RuntimeError('native_build_info_timeout') from None
        require((args.output / 'build-info.stdout.json').stat().st_size <= 4096
                and (args.output / 'build-info.stderr.log').stat().st_size == 0, 'native_build_info_output_bound')
        raw = (args.output / 'build-info.stdout.json').read_bytes()
        error_raw = (args.output / 'build-info.stderr.log').read_bytes()
        require(info.returncode == 0 and 0 < len(raw) <= 4096 and not error_raw,
                'native_build_info_not_successful_bounded_json')
        report = json.loads(raw)
        require(report.get('schema') == 1 and report.get('target') == target
                and report.get('minimum_release_reader') == 'native_runtime_migrated_v1'
                and report.get('supported_state_readers') == ['native_management_state_v1', 'native_migrated_state_v1'],
                'native_build_info_reader_contract_mismatch')
        if args.source_archive_manifest is None:
            source_stable = (command(['git', 'rev-parse', 'HEAD']) == args.source_revision
                             and not command(['git', 'status', '--porcelain']))
        else:
            source_stable = (archive_source(args.source_archive_manifest, args.source_revision,
                                                     args.expected_source_archive_sha256)
                             == receipt['source_archive'])
        stable = (source_stable and inputs == normalized_inputs(q['source_inputs'](ROOT))
                  and sha(binary) == original_hash == sha(original)
                  and args.gate_receipt.read_bytes() == gate_raw)
        receipt.update(cli_binary=str(binary), cli_binary_sha256=original_hash,
            cli_build_info={'command': info_argv, 'actual_wait': True, 'exit_code': info.returncode,
                'binary_sha256': original_hash, 'stdout_utf8': raw.decode('utf-8'),
                'stdout_sha256': hashlib.sha256(raw).hexdigest(), 'stdout_bytes': len(raw),
                'stderr_sha256': hashlib.sha256(error_raw).hexdigest(), 'stderr_bytes': len(error_raw),
                'report': report}, input_stability='PASS' if stable else 'FAIL')
        require(stable, 'native_build_inputs_or_binary_changed')
        receipt['status'] = 'PASS'
    except (RuntimeError, OSError, ValueError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        receipt['elapsed_seconds'] = time.monotonic() - started
        write(args.output / 'receipt.json', receipt)
    print(json.dumps({k: receipt.get(k) for k in ['status', 'source_revision', 'cli_binary', 'cli_binary_sha256', 'error']}))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
