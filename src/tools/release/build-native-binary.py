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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source-revision', 'gate-receipt', 'target-dir', 'output']:
        parser.add_argument('--' + name, required=True, type=str if name == 'source-revision' else Path)
    args = parser.parse_args()
    os.umask(0o077)
    require(re.fullmatch('[a-f0-9]{40}', args.source_revision) is not None, 'full_source_revision_required')
    for path in [args.gate_receipt, args.target_dir, args.output.parent]:
        require(path.is_absolute() and path.resolve(strict=True) == path, 'canonical_existing_input_required')
    require(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink()
            and not args.output.is_relative_to(ROOT), 'fresh_external_output_required')
    args.output.mkdir(mode=0o700)
    receipt = {'schema': 1, 'status': 'FAIL', 'source_revision': args.source_revision,
               'producer': PRODUCER, 'profile': 'release', 'installed': False,
               'deployed': False, 'platform_acceptance': False}
    started = time.monotonic()
    try:
        q = runpy.run_path(str(ROOT / 'src/ci/rust-quality.py'))
        require(args.gate_receipt.stat().st_size <= 16 * 1048576, 'gate_receipt_bound')
        gate_raw = args.gate_receipt.read_bytes()
        require(len(gate_raw) <= 16 * 1048576, 'gate_receipt_bound')
        gate = json.loads(gate_raw)
        require(gate.get('status') == 'PASS' and gate.get('input_stability') == 'PASS'
                and gate.get('source_revision') == args.source_revision, 'same_source_passing_gate_required')
        require(command(['git', 'rev-parse', 'HEAD']) == args.source_revision
                and not command(['git', 'status', '--porcelain']), 'clean_frozen_source_required')
        inputs = q['source_inputs'](ROOT)
        require(inputs == gate['inputs'], 'gate_complete_source_inputs_mismatch')
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
        stable = (inputs == q['source_inputs'](ROOT)
                  and command(['git', 'rev-parse', 'HEAD']) == args.source_revision
                  and not command(['git', 'status', '--porcelain'])
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
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        receipt['elapsed_seconds'] = time.monotonic() - started
        write(args.output / 'receipt.json', receipt)
    print(json.dumps({k: receipt.get(k) for k in ['status', 'source_revision', 'cli_binary', 'cli_binary_sha256', 'error']}))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
