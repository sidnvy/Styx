#!/usr/bin/env python3
"""Compile and sign a macOS Core only; never run or manufacture a quality gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
TARGET = 'aarch64-apple-darwin'
PRODUCER = 'src/ci/macos-quick-build.py'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def head():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                   text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--target-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--local-signing', required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == 'darwin' and platform.machine() == 'arm64',
            'native Apple silicon required')
    require(head() == args.source_revision, 'source revision does not match checkout')
    os.umask(0o077)
    args.target_dir = args.target_dir.resolve()
    args.target_dir.mkdir(parents=True, exist_ok=True)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    args.local_signing = args.local_signing.resolve(strict=True)
    jobs = os.cpu_count() or 1
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir),
               CARGO_BUILD_JOBS=str(jobs), CARGO_INCREMENTAL='0',
               CARGO_TERM_COLOR='never', PYTHONDONTWRITEBYTECODE='1')
    # Keep the release command's inherited RUSTFLAGS/features/profile; no clean.
    collect = runpy.run_path(str(ROOT / 'src/ci/rust-quality.py'))['source_inputs']
    inputs = {name.replace('\\', '/'): digest for name, digest in collect(ROOT).items()}
    receipt = dict(schema=1, producer=PRODUCER, status='FAIL',
                   qualification='COMPILE_ONLY_NOT_STABLE', quality='NOT RUN',
                   tests='NOT RUN', installed=False, deployed=False,
                   platform_acceptance=False, source_revision=args.source_revision,
                   target=TARGET, profile='release', inputs=inputs,
                   input_stability='NOT RUN', cargo_jobs=jobs,
                   producer_sha256=sha(Path(__file__)),
                   toolchain=subprocess.check_output(['rustc', '-vV'], cwd=ROOT,
                                                     text=True).strip(),
                   build_actual_wait=False, build_actual_exit=None)
    started = time.monotonic()
    try:
        command = ['cargo', 'build', '--release', '--locked', '--target', TARGET,
                   '-p', 'styx', '--bin', 'styx', '--jobs', str(jobs), '--timings']
        receipt['command'] = command
        print(json.dumps(dict(stage='compile-only', jobs=jobs, target=TARGET,
                              target_dir=str(args.target_dir), quality='NOT RUN')), flush=True)
        result = subprocess.run(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL)
        receipt.update(build_actual_wait=True, build_actual_exit=result.returncode,
                       build_elapsed_seconds=time.monotonic() - started)
        require(result.returncode == 0, 'native compilation failed')
        original = args.target_dir / TARGET / 'release/styx'
        original_hash = sha(original)
        binary = args.output / 'styx'
        shutil.copyfile(original, binary)
        binary.chmod(0o700)
        receipt.update(source_image_sha256=original_hash,
                       source_image_bytes=original.stat().st_size)
        sign_command = ['node', str(ROOT / 'src/tools/release/sign-native-macos.mjs'),
                        str(args.local_signing), str(binary)]
        signed = subprocess.run(sign_command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (args.output / 'codesign.stdout.json').write_bytes(signed.stdout)
        (args.output / 'codesign.stderr.log').write_bytes(signed.stderr)
        signature = json.loads(signed.stdout)
        receipt['platform_signature'] = dict(kind='macos_local_certificate_codesign',
            actual_wait=True, exit_code=signed.returncode, report=signature)
        require(signed.returncode == 0 and signature.get('status') == 'PASS'
                and signature.get('sign_actual_wait') is True
                and signature.get('verify_actual_wait') is True
                and signature.get('sign_exit_code') == 0
                and signature.get('verify_exit_code') == 0, 'native signing failed')
        final_hash = sha(binary)
        require(signature.get('source_image_sha256') == original_hash
                and signature.get('signed_image_sha256') == final_hash,
                'signing report does not match original output')
        info_command = [str(binary), 'build-info', '--json']
        info = subprocess.run(info_command, cwd=args.output, env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=15)
        (args.output / 'build-info.stdout.json').write_bytes(info.stdout)
        (args.output / 'build-info.stderr.log').write_bytes(info.stderr)
        report = json.loads(info.stdout)
        receipt['cli_build_info'] = dict(command=info_command, actual_wait=True,
            exit_code=info.returncode, binary_sha256=final_hash,
            stdout_utf8=info.stdout.decode('utf-8'),
            stdout_sha256=hashlib.sha256(info.stdout).hexdigest(), stdout_bytes=len(info.stdout),
            stderr_sha256=hashlib.sha256(info.stderr).hexdigest(), stderr_bytes=len(info.stderr),
            report=report)
        require(info.returncode == 0 and not info.stderr and 0 < len(info.stdout) <= 4096
                and report.get('schema') == 1 and report.get('target') == TARGET,
                'native build-info failed')
        # Fingerprints only: this invokes no quality commands, tests or gate.
        stable = (head() == args.source_revision
                  and inputs == {name.replace('\\', '/'): digest
                                 for name, digest in collect(ROOT).items()}
                  and sha(original) == original_hash and sha(binary) == final_hash
                  and sha(Path(__file__)) == receipt['producer_sha256'])
        receipt.update(input_stability='PASS' if stable else 'FAIL',
                       cli_binary=str(binary), cli_binary_sha256=final_hash)
        require(stable, 'source or binary changed during compilation')
        receipt['status'] = 'PASS'
    finally:
        receipt['elapsed_seconds'] = time.monotonic() - started
        (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({key: receipt.get(key) for key in
              ('status', 'qualification', 'quality', 'source_revision', 'cli_binary',
               'cli_binary_sha256')}), flush=True)


if __name__ == '__main__':
    main()
