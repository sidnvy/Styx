#!/usr/bin/env python3
"""Build one native release CLI from an exact clean, already-passing source gate.
Optional macOS local or cross-machine signing changes only a fresh output copy.
No installation, foreign-image execution or runtime/profile startup.
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


def signing_input(path, limit):
    require(path.is_absolute() and path.resolve(strict=True) == path,
            'canonical_signing_input_required')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not (getattr(info, 'st_file_attributes', 0) & 0x400)
            and info.st_size <= limit, 'bounded_regular_signing_input_required')
    return sha(path)


def sign_macos_output(binary, config, node, output, receipt):
    helper = ROOT / 'src/tools/release/sign-native-macos.mjs'
    planner = ROOT / 'src/host/build-macos-app.mjs'
    config_hash = signing_input(config, 4096)
    node_hash = signing_input(node, 256 * 1048576)
    helper_hash, planner_hash = sha(helper), sha(planner)
    argv = [str(node), str(helper), str(config), str(binary)]
    facts = {'schema': 1, 'kind': 'macos_local_certificate_codesign',
             'configuration_sha256': config_hash, 'node': str(node),
             'node_sha256': node_hash, 'helper_sha256': helper_hash,
             'planner_sha256': planner_hash, 'actual_wait': False}
    receipt['platform_signature'] = facts
    with (output / 'codesign.stdout.json').open('xb') as out, (output / 'codesign.stderr.log').open('xb') as err:
        # Own the helper through actual completion. Its synchronous codesign
        # calls retain/wait their original children; do not kill the helper on an
        # outer timer and abandon an uncertain codesign descendant.
        result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=err)
        facts.update(actual_wait=True, exit_code=result.returncode)
    require((output / 'codesign.stdout.json').stat().st_size <= 16384
            and (output / 'codesign.stderr.log').stat().st_size == 0,
            'macos_signing_output_bound')
    report = strict_json((output / 'codesign.stdout.json').read_bytes())
    facts['report'] = report
    require(result.returncode == 0 and report.get('status') == 'PASS'
            and report.get('sign_actual_wait') is True and report.get('sign_exit_code') == 0
            and report.get('verify_actual_wait') is True and report.get('verify_exit_code') == 0,
            'macos_signing_not_verified')
    require(config_hash == signing_input(config, 4096)
            and node_hash == signing_input(node, 256 * 1048576)
            and helper_hash == sha(helper) and planner_hash == sha(planner),
            'macos_signing_inputs_changed')
    return facts


def complete_external_macos_signature(args, output, receipt, target, inputs):
    """Complete a native build using an original remote signing report.

    Reports are retained provenance data. Actual identity is checked by Apple's
    verifier on the native consumer; no report creates runtime/admission proof.
    The original native build receipt is preserved byte-for-byte, never edited.
    """
    require(sys.platform == 'darwin' and target.endswith('apple-darwin'),
            'external_macos_completion_requires_native_darwin')
    specs = [(args.macos_unsigned_build_receipt, 16 * 1048576),
             (args.macos_unsigned_image, 1024 ** 3),
             (args.macos_signed_image, 1024 ** 3),
             (args.macos_signing_receipt, 65536)]
    before = {str(path): (signing_input(path, limit), limit) for path, limit in specs}
    raw_build = args.macos_unsigned_build_receipt.read_bytes()
    raw_signing = args.macos_signing_receipt.read_bytes()
    built, signed = strict_json(raw_build), strict_json(raw_signing)
    require(built.get('schema') == 1 and built.get('status') == 'PASS'
            and built.get('input_stability') == 'PASS' and built.get('producer') == PRODUCER
            and built.get('source_revision') == args.source_revision
            and built.get('target') == target and built.get('profile') == 'release'
            and built.get('inputs') == inputs and built.get('toolchain') == receipt['toolchain']
            and built.get('build_actual_wait') is True
            and type(built.get('build_actual_exit')) is int and built['build_actual_exit'] == 0
            and 'platform_signature' not in built,
            'original_unsigned_native_build_required')
    require(Path(built.get('cli_binary', '')).is_absolute()
            and Path(built['cli_binary']).resolve(strict=True) == args.macos_unsigned_image,
            'original_unsigned_locator_mismatch')
    unsigned_hash = before[str(args.macos_unsigned_image)][0]
    signed_hash = before[str(args.macos_signed_image)][0]
    require(built.get('cli_binary_sha256') == unsigned_hash
            and signed.get('schema') == 1 and signed.get('status') == 'PASS'
            and signed.get('source_image_sha256') == unsigned_hash
            and signed.get('signed_image_sha256') == signed_hash
            and signed.get('source_image_bytes') == args.macos_unsigned_image.stat().st_size
            and signed.get('signed_image_bytes') == args.macos_signed_image.stat().st_size
            and signed.get('helper_sha256') == inputs.get('src/tools/release/sign-native-macos.mjs')
            and signed.get('planner_sha256') == sha(ROOT / 'src/host/build-macos-app.mjs')
            and signed.get('sign_actual_wait') is True and signed.get('verify_actual_wait') is True
            and type(signed.get('sign_exit_code')) is int and signed['sign_exit_code'] == 0
            and type(signed.get('verify_exit_code')) is int and signed['verify_exit_code'] == 0,
            'original_signing_report_binding_mismatch')
    identity = 'cb50cee601419f28b43756f4fc8aefdbf60abae2'
    certificate_hash = '90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e'
    # Existing App planner's fixed Resources/native/bin/styx identifier. Do not
    # accept a remote caller-selected signing identity or executable identity.
    identifier = 'app.styx.host.code.234ae9e3c9e0237f929adc7841ecb090'
    require(signed.get('certificate') == {'schema': 1, 'certificateSha1': identity,
                                        'certificateSha256': certificate_hash}
            and signed.get('identifier') == identifier, 'original_macos_identity_required')
    binary = output / 'styx'
    shutil.copyfile(args.macos_signed_image, binary)
    binary.chmod(0o700)
    require(sha(binary) == signed_hash, 'signed_image_copy_changed')
    requirement = '=identifier "' + identifier + '" and certificate leaf = H"' + identity + '"'
    prefix = output / 'macos-signing-certificate-'
    commands = [('verify', ['/usr/bin/codesign', '--verify', '--strict', '-R', requirement, str(binary)]),
                ('certificate', ['/usr/bin/codesign', '-d', '--extract-certificates', str(prefix), str(binary)])]
    observations = []
    for kind, argv in commands:
        with (output / ('macos-' + kind + '.stdout')).open('xb') as out, \
             (output / ('macos-' + kind + '.stderr')).open('xb') as err:
            child = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=15)
        observations.append({'command': argv, 'actual_wait': True, 'exit_code': child.returncode})
        require(child.returncode == 0 and (output / ('macos-' + kind + '.stdout')).stat().st_size <= 65536
                and (output / ('macos-' + kind + '.stderr')).stat().st_size <= 65536,
                'native_signed_image_verification_failed')
    require(signing_input(Path(str(prefix) + '0'), 65536) == certificate_hash,
            'native_signing_certificate_sha256_mismatch')
    # Raw originals are evidence attachments, not reconstructed JSON receipts.
    (output / 'original-unsigned-build-receipt.json').write_bytes(raw_build)
    (output / 'original-macos-signing-receipt.json').write_bytes(raw_signing)
    receipt['source_image_sha256'] = unsigned_hash
    receipt['source_image_bytes'] = args.macos_unsigned_image.stat().st_size
    receipt['original_unsigned_build'] = {
        'receipt_sha256': hashlib.sha256(raw_build).hexdigest(),
        'command': built['command'], 'actual_wait': True, 'exit_code': 0,
        'binary_sha256': unsigned_hash, 'recompiled_in_completion': False}
    receipt['platform_signature'] = {
        'schema': 1, 'kind': 'macos_external_original_identity_codesign',
        'source_image_sha256': unsigned_hash, 'signed_image_sha256': signed_hash,
        'original_signing_receipt_sha256': hashlib.sha256(raw_signing).hexdigest(),
        'report': signed, 'native_verification': observations,
        'certificate_der_sha256': certificate_hash}
    return args.macos_unsigned_image, unsigned_hash, binary, before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source-revision', 'gate-receipt', 'target-dir', 'output']:
        parser.add_argument('--' + name, required=True, type=str if name == 'source-revision' else Path)
    parser.add_argument('--source-archive-manifest', type=Path,
                        help='external source-inputs.json; exact original source.tar must be adjacent')
    parser.add_argument('--expected-source-archive-sha256',
                        help='independent controller pin, required exactly in source-archive mode')
    parser.add_argument('--macos-local-signing', type=Path,
                        help='explicit original localSigning JSON; signs only fresh macOS output')
    parser.add_argument('--macos-signing-node', type=Path,
                        help='explicit existing Node executable for the original App signing planner')
    for name in ['macos-unsigned-build-receipt', 'macos-unsigned-image',
                 'macos-signed-image', 'macos-signing-receipt']:
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    completion = [args.macos_unsigned_build_receipt, args.macos_unsigned_image,
                  args.macos_signed_image, args.macos_signing_receipt]
    require(not any(completion) or all(completion), 'complete_macos_signing_inputs_required')
    require(not any(completion) or args.macos_local_signing is None,
            'local_and_external_macos_signing_are_exclusive')
    require(bool(args.macos_local_signing) == bool(args.macos_signing_node),
            'macos_signing_inputs_required_together')
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
        require(args.macos_local_signing is None or target.endswith('apple-darwin'),
                'macos_signing_requires_native_darwin')
        if args.macos_local_signing is not None:
            signing_input(args.macos_local_signing, 4096)
            strict_json(args.macos_local_signing.read_bytes())
            signing_input(args.macos_signing_node, 256 * 1048576)
            require('src/tools/release/sign-native-macos.mjs' in inputs,
                    'macos_signing_helper_missing_from_gate_inputs')
        receipt.update(target=target, toolchain=rust, inputs=inputs,
                       gate_receipt_sha256=hashlib.sha256(gate_raw).hexdigest())
        env = dict(os.environ, CARGO_BUILD_JOBS='2', CARGO_NET_OFFLINE='true',
                   CARGO_TERM_COLOR='never', PYTHONDONTWRITEBYTECODE='1',
                   CARGO_TARGET_DIR=str(args.target_dir))
        external_signing_inputs = None
        if all(completion):
            original, original_hash, binary, external_signing_inputs = complete_external_macos_signature(
                args, args.output, receipt, target, inputs)
        else:
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
        if args.macos_local_signing is not None:
            receipt['source_image_sha256'] = original_hash
            receipt['source_image_bytes'] = original.stat().st_size
            sign_macos_output(binary, args.macos_local_signing, args.macos_signing_node,
                              args.output, receipt)
            require(sha(original) == original_hash, 'original_cached_image_changed')
        final_hash = sha(binary)
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
        signing_stable = True
        if args.macos_local_signing is not None:
            signing = receipt['platform_signature']
            signing_stable = (
                signing_input(args.macos_local_signing, 4096) == signing['configuration_sha256']
                and signing_input(args.macos_signing_node, 256 * 1048576) == signing['node_sha256']
                and sha(ROOT / 'src/tools/release/sign-native-macos.mjs') == signing['helper_sha256']
                and sha(ROOT / 'src/host/build-macos-app.mjs') == signing['planner_sha256'])
        if external_signing_inputs is not None:
            signing_stable = all(signing_input(Path(name), limit) == digest
                                 for name, (digest, limit) in external_signing_inputs.items())
        stable = (signing_stable and source_stable and inputs == normalized_inputs(q['source_inputs'](ROOT))
                  and sha(binary) == final_hash and sha(original) == original_hash
                  and args.gate_receipt.read_bytes() == gate_raw)
        receipt.update(cli_binary=str(binary), cli_binary_sha256=final_hash,
            cli_build_info={'command': info_argv, 'actual_wait': True, 'exit_code': info.returncode,
                'binary_sha256': final_hash, 'stdout_utf8': raw.decode('utf-8'),
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
