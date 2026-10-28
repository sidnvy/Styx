#!/usr/bin/env python3
"""Build a publisher-signed internal runtime candidate, never install or activate it.

The build receipt and one complete original schema1 worker release are external
proof inputs. No foreign image, executor, model, or installed profile is run.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import runpy
import shutil
import stat
import struct
import sys
import tarfile

# Reuse the existing audited source-closure, safe-file and OpenSSL orchestration.
_HELPERS = runpy.run_path(str(Path(__file__).with_name('build-native-preview.py')),
                         run_name='styx_runtime_preview_helpers')
for _name in ('BuildError', 'require', 'strict_json', 'digest_file', 'sha', 'absolute',
              'no_symlinks', 'signature', 'open_regular', 'read_bounded',
              'write_private', 'encode', 'git', 'frozen_git', 'validate_inputs',
              'elf_header', 'openssl', 'sign_manifest', 'member', 'REPO', 'HEX'):
    globals()[_name] = _HELPERS[_name]

TARGETS = {'x86_64-unknown-linux-gnu': ('linux', 'x64'),
           'x86_64-apple-darwin': ('darwin', 'x64'),
           'aarch64-apple-darwin': ('darwin', 'arm64'),
           'x86_64-pc-windows-msvc': ('win32', 'x64')}
KINDS = {'codex_exec': ('codex-exec', 'codex', 'codex'),
         'browser_node22': ('browser-node22', 'node', 'node'),
         'cua_native': ('cua-native', 'cua-driver', 'cua')}
SCOPE = 'INTERNAL_NATIVE_RUNTIME_CANDIDATE_NOT_INSTALLED_OR_ACTIVATED'
MAX_FILES, MAX_MEMBER, MAX_TOTAL = 4096, 1024**3, 4 * 1024**3
PACKAGE_PREFIX = 'packages/styx-browser-provider/node_modules/'
PACKAGES = ('@playwright/mcp', 'playwright', 'playwright-core', '@modelcontextprotocol/sdk')


def relative(name):
    return (isinstance(name, str) and 0 < len(name) <= 512
            and re.fullmatch(r'[A-Za-z0-9@._/-]+', name) is not None
            and all(p and p not in ('.', '..') for p in name.split('/')))


def version(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._+-]{1,128}', value) is not None


def nonsecret(path, forbidden, limit=MAX_MEMBER):
    fd, observed = open_regular(path, limit)
    try:
        require(observed.st_nlink == 1 and (observed.st_dev, observed.st_ino) != forbidden,
                'input_alias_refused')
        return observed
    finally:
        os.close(fd)


def hash_checked(path, forbidden, limit=MAX_MEMBER):
    fd, observed = open_regular(path, limit)
    try:
        require(observed.st_nlink == 1 and (observed.st_dev, observed.st_ino) != forbidden,
                'input_alias_refused')
        h = hashlib.sha256()
        for chunk in iter(lambda: os.read(fd, 1024 * 1024), b''):
            h.update(chunk)
        require(signature(observed) == signature(os.fstat(fd)) == signature(path.lstat()),
                'input_changed_during_hash')
        return h.hexdigest(), observed
    finally:
        os.close(fd)


def image_header(fd, target):
    """Closed native header admission, not a loader or executable invocation."""
    if target == 'x86_64-unknown-linux-gnu':
        elf_header(fd)
    elif target.endswith('apple-darwin'):
        raw = os.pread(fd, 32, 0)
        cpu = 0x01000007 if target.startswith('x86_64') else 0x0100000c
        require(len(raw) == 32 and raw[:4] == b'\xcf\xfa\xed\xfe'
                and struct.unpack_from('<I', raw, 4)[0] == cpu
                and struct.unpack_from('<I', raw, 12)[0] == 2
                and 0 < struct.unpack_from('<I', raw, 16)[0] <= 65536
                and 0 < struct.unpack_from('<I', raw, 20)[0] <= os.fstat(fd).st_size - 32,
                'binary_not_matching_thin_macho64')
    else:
        dos = os.pread(fd, 64, 0)
        require(len(dos) == 64 and dos[:2] == b'MZ', 'binary_not_windows_pe32plus')
        offset = struct.unpack_from('<I', dos, 60)[0]
        require(64 <= offset <= 1024 * 1024, 'binary_pe_header_offset_invalid')
        pe = os.pread(fd, 24, offset)
        require(len(pe) == 24 and pe[:4] == b'PE\0\0'
                and struct.unpack_from('<H', pe, 4)[0] == 0x8664
                and 0 < struct.unpack_from('<H', pe, 6)[0] <= 96
                and 112 <= struct.unpack_from('<H', pe, 20)[0] <= 4096
                and struct.unpack_from('<H', pe, 22)[0] & 2
                and not struct.unpack_from('<H', pe, 22)[0] & 0x2000,
                'binary_not_windows_x64_executable')
        optional_size = struct.unpack_from('<H', pe, 20)[0]
        optional = os.pread(fd, optional_size, offset + 24)
        require(len(optional) == optional_size and optional[:2] == b'\x0b\x02'
                and struct.unpack_from('<I', optional, 16)[0] != 0,
                'binary_not_windows_pe32plus')


def private_parents(path):
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    no_symlinks(path)
    require(path.is_dir(), 'output_parent_not_directory')
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)


def copy_checked(source, destination, expected, forbidden, executable=False, target=None):
    fd, observed = open_regular(source, MAX_MEMBER)
    try:
        require(observed.st_nlink == 1 and (observed.st_dev, observed.st_ino) != forbidden,
                'input_alias_refused')
        if target is not None:
            image_header(fd, target)
            require(observed.st_size > 0, 'empty_binary')
        private_parents(destination.parent)
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o700 if executable else 0o600)
        with os.fdopen(output, 'wb') as out:
            os.fchmod(out.fileno(), 0o700 if executable else 0o600)
            with os.fdopen(os.dup(fd), 'rb') as pinned:
                shutil.copyfileobj(pinned, out, length=1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        os.lseek(fd, 0, os.SEEK_SET)
        h = hashlib.sha256()
        for chunk in iter(lambda: os.read(fd, 1024 * 1024), b''):
            h.update(chunk)
        require(signature(observed) == signature(os.fstat(fd)) == signature(source.lstat())
                and h.hexdigest() == expected and digest_file(destination) == expected,
                'copy_or_source_changed')
        return observed
    finally:
        os.close(fd)


def public_pin(path, forbidden):
    nonsecret(path, forbidden, 4096)
    raw = read_bounded(path, 4096)
    details = openssl(['pkey', '-pubin', '-in', str(path), '-text_pub', '-noout'])
    require(re.search(rb'^ED25519 Public-Key:', details, re.MULTILINE) is not None,
            'publisher_not_ed25519')
    der = openssl(['pkey', '-pubin', '-in', str(path), '-outform', 'DER'])
    require(read_bounded(path, 4096) == raw, 'publisher_public_file_changed')
    return sha(der), raw


def key_pin(key, output, original):
    # The private descriptor is consumed only by mature OpenSSL public extraction;
    # Styx never reads, hashes, prints or archives private key bytes.
    fd, observed = open_regular(key, 64 * 1024, private=True)
    try:
        require(signature(observed) == signature(original), 'publisher_key_metadata_changed')
        public = openssl(['pkey', '-in', f'/proc/self/fd/{fd}', '-pubout'], (fd,))
        path = output / 'preflight-publisher.pem'
        write_private(path, public)
        pin, _ = public_pin(path, (observed.st_dev, observed.st_ino))
        require(signature(observed) == signature(os.fstat(fd)) == signature(key.lstat()),
                'publisher_key_metadata_changed')
        return pin
    finally:
        os.close(fd)


def tree(root, forbidden):
    no_symlinks(root)
    require(root.is_dir(), 'worker_release_directory_required')
    files, directories, identities = {}, {}, set()
    pending = [root]
    while pending:
        current = pending.pop()
        observation = current.lstat()
        require(stat.S_ISDIR(observation.st_mode) and not stat.S_IMODE(observation.st_mode) & 0o022,
                'worker_directory_untrusted')
        relative_dir = str(current.relative_to(root))
        require(relative_dir == '.' or len(Path(relative_dir).parts) <= 32, 'worker_directory_depth')
        directories[relative_dir] = signature(observation)
        require(len(directories) <= 4096, 'worker_directory_capacity')
        for path in sorted(current.iterdir()):
            value = path.lstat()
            require(not stat.S_ISLNK(value.st_mode), 'worker_symlink_refused')
            if stat.S_ISDIR(value.st_mode):
                pending.append(path)
            else:
                require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1
                        and not stat.S_IMODE(value.st_mode) & 0o022
                        and (value.st_dev, value.st_ino) != forbidden,
                        'worker_file_or_alias_refused')
                identity = (value.st_dev, value.st_ino)
                require(identity not in identities, 'worker_alias_refused')
                identities.add(identity)
                name = path.relative_to(root).as_posix()
                require(relative(name), 'worker_member_path_invalid')
                files[name] = signature(value)
                require(len(files) <= MAX_FILES + 2, 'worker_file_capacity')
    return files, directories


def inspect_worker(root, public_file, target, expected_pin, forbidden, output):
    observations, directories = tree(root, forbidden)
    raw = read_bounded(root / 'manifest.json', 1024 * 1024)
    signature_raw = read_bounded(root / 'manifest.sig', 256)
    text = signature_raw[:-1] if signature_raw.endswith(b'\n') else signature_raw
    require(re.fullmatch(rb'[A-Za-z0-9_-]{86}', text) is not None, 'worker_signature_codec_invalid')
    decoded = base64.b64decode(text + b'==', altchars=b'-_', validate=True)
    require(len(decoded) == 64 and base64.urlsafe_b64encode(decoded).rstrip(b'=') == text,
            'worker_signature_codec_invalid')
    pin, public_raw = public_pin(public_file, forbidden)
    require(pin == expected_pin, 'worker_publisher_pin_mismatch')
    write_private(output / 'worker-source-manifest.json', raw)
    write_private(output / 'worker-source-signature.raw', decoded)
    write_private(output / 'worker-source-publisher.pem', public_raw)
    openssl(['pkeyutl', '-verify', '-pubin', '-inkey', str(output / 'worker-source-publisher.pem'),
             '-rawin', '-in', str(output / 'worker-source-manifest.json'),
             '-sigfile', str(output / 'worker-source-signature.raw')])
    manifest = strict_json(raw)
    require(isinstance(manifest, dict) and type(manifest.get('schema')) is int and manifest['schema'] == 1
            and (manifest.get('platform'), manifest.get('arch')) == TARGETS[target]
            and version(manifest.get('version'))
            and isinstance(manifest.get('files'), list) and 0 < len(manifest['files']) <= MAX_FILES,
            'worker_manifest_target_or_schema_invalid')
    declared, total = {}, 0
    for item in manifest['files']:
        require(isinstance(item, dict) and set(item) == {'path', 'size', 'sha256', 'executable'}
                and relative(item['path']) and item['path'] not in declared
                and type(item['size']) is int and 0 <= item['size'] <= MAX_MEMBER
                and isinstance(item['sha256'], str) and HEX.fullmatch(item['sha256'])
                and type(item['executable']) is bool, 'worker_member_invalid')
        total += item['size']
        require(total <= MAX_TOTAL, 'worker_total_capacity')
        digest, observed = hash_checked(root / item['path'], forbidden)
        require(digest == item['sha256'] and observed.st_size == item['size']
                and bool(stat.S_IMODE(observed.st_mode) & 0o111) == item['executable'],
                'worker_member_hash_size_or_executable_mismatch')
        declared[item['path']] = item
    require(set(observations) == set(declared) | {'manifest.json', 'manifest.sig'},
            'worker_inventory_not_exact')
    ancestors = {'.'} | {str(parent) for name in observations for parent in Path(name).parents if str(parent) != '.'}
    require(set(directories) == ancestors, 'worker_extra_directory')
    require(tree(root, forbidden) == (observations, directories), 'worker_inventory_changed')
    return dict(root=root, public_file=public_file, public_raw=public_raw, pin=pin,
                manifest=manifest, raw=raw, signature_raw=signature_raw,
                declared=declared, observations=observations, directories=directories)


def worker_bytes(source, name, limit, forbidden):
    require(name in source['declared'], 'worker_required_member_missing')
    nonsecret(source['root'] / name, forbidden, limit)
    raw = read_bounded(source['root'] / name, limit)
    require(sha(raw) == source['declared'][name]['sha256'], 'worker_metadata_hash_mismatch')
    return raw


def scoped_npm_path(name):
    if not relative(name):
        return False
    parts = name.split('/')
    for index, part in enumerate(parts):
        if '@' in part:
            if (not part.startswith('@') or part.count('@') != 1 or len(part) == 1
                    or index == 0 or parts[index - 1] != 'node_modules'
                    or index + 1 == len(parts) or parts[index + 1].startswith('@')):
                return False
    return True


def selected_worker(source, kind, target, forbidden):
    root, declared = source['root'], source['declared']
    folder, executable, upstream_name = KINDS[kind]
    suffix = '.exe' if TARGETS[target][0] == 'win32' else ''
    entry = f'bin/{executable}{suffix}'
    require(entry in declared, 'worker_binary_missing')
    selected = [entry]
    upstream = source['manifest'].get('upstream')
    require(isinstance(upstream, dict), 'worker_upstream_metadata_missing')
    upstream_version = upstream.get(upstream_name)
    if kind == 'codex_exec':
        if isinstance(upstream_version, str) and upstream_version.startswith('codex-cli '):
            upstream_version = upstream_version[len('codex-cli '):]
        selected += ['licenses/codex-LICENSE', 'licenses/codex-NOTICE']
    elif kind == 'cua_native':
        require(TARGETS[target][0] != 'darwin', 'mac_cua_requires_retained_app_binding')
        if isinstance(upstream_version, str) and upstream_version.startswith('cua-driver '):
            upstream_version = upstream_version[len('cua-driver '):]
        selected += ['licenses/cua-LICENSE']
    else:
        require(isinstance(upstream_version, str) and re.fullmatch(r'22\.[0-9]+\.[0-9]+', upstream_version),
                'browser_node22_version_required')
        selected += ['licenses/node-LICENSE', 'provenance/node.json']
        selected += sorted(name for name in declared if name.startswith(PACKAGE_PREFIX))
        require(all(scoped_npm_path(name) for name in selected if name.startswith(PACKAGE_PREFIX)),
                'browser_scoped_member_invalid')
        configuration = strict_json(read_bounded(REPO / 'src/providers/browser-worker/package.json', 65536))
        versions = configuration['dependencies']
        expected_versions = {'@playwright/mcp': versions['@playwright/mcp'],
                             'playwright': versions['playwright'], 'playwright-core': versions['playwright'],
                             '@modelcontextprotocol/sdk': versions['@modelcontextprotocol/sdk']}
        for package in PACKAGES:
            metadata_path = PACKAGE_PREFIX + package + '/package.json'
            license_path = PACKAGE_PREFIX + package + '/LICENSE'
            require(metadata_path in declared and license_path in declared
                    and declared[license_path]['size'] > 0, 'browser_package_metadata_or_license_missing')
            metadata = strict_json(worker_bytes(source, metadata_path, 256 * 1024, forbidden))
            require(metadata.get('name') == package and metadata.get('version') == expected_versions[package],
                    'browser_package_version_not_fixed_worker_compatible')
        require(upstream.get('browserMcp') == expected_versions['@playwright/mcp']
                and upstream.get('playwright') == expected_versions['playwright'],
                'browser_source_upstream_version_mismatch')
        provenance = strict_json(worker_bytes(source, 'provenance/node.json', 65536, forbidden))
        require(provenance.get('schema') == 1 and provenance.get('component') == 'node'
                and provenance.get('version') == upstream_version
                and (provenance.get('platform'), provenance.get('arch')) == TARGETS[target]
                and provenance.get('binary_sha256') == declared[entry]['sha256']
                and provenance.get('license_sha256') == declared['licenses/node-LICENSE']['sha256']
                and isinstance(provenance.get('archive_sha256'), str)
                and HEX.fullmatch(provenance['archive_sha256']), 'node_provenance_mismatch')
    require(version(upstream_version), 'worker_version_invalid')
    require(all(name in declared and declared[name]['size'] > 0 for name in selected
                if not name.startswith(PACKAGE_PREFIX)), 'worker_binary_or_license_missing')
    require(declared[entry]['executable'] and all(not declared[name]['executable'] for name in selected if name != entry),
            'worker_unexpected_executable')
    fd, _ = open_regular(root / entry, MAX_MEMBER)
    try:
        image_header(fd, target)
    finally:
        os.close(fd)
    prefix = f'workers/{folder}/'
    return dict(kind=kind, version=upstream_version, source_manifest_sha256=sha(source['raw']),
                source_publisher_spki_sha256=source['pin'], entrypoint=prefix + entry,
                members=[prefix + name for name in sorted(selected)]), selected


def deterministic_archive(payload, destination, names, executable):
    # tarfile owns format/header/padding and gzip owns compression; explicit names
    # avoid recursive discovery, links and incidental timestamps in the artifact.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    directories = sorted({parent.as_posix() for name in names for parent in Path(name).parents if str(parent) != '.'})
    with os.fdopen(fd, 'wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name in directories + sorted(names):
                    require(relative(name), 'archive_path_invalid')
                    item = tarfile.TarInfo(name)
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ''
                    if name in directories:
                        item.type, item.mode = tarfile.DIRTYPE, 0o700
                        archive.addfile(item)
                    else:
                        path = payload / name
                        require(not path.is_symlink() and path.is_file(), 'archive_nonregular_member')
                        item.mode, item.size = (0o700 if name in executable else 0o600), path.stat().st_size
                        with path.open('rb') as stream:
                            archive.addfile(item, stream)
        raw.flush()
        os.fsync(raw.fileno())



def release_reader(receipt, binary_hash, target, inputs):
    """Missing historical evidence never upgrades an old signed candidate.

    The producer's native CLI observation is bound to the same complete frozen
    source inputs and exact executable digest, not a packaging CLI flag.
    """
    evidence = receipt.get('cli_build_info')
    if evidence is None:
        return 'native_runtime_v1'
    require(isinstance(evidence, dict) and receipt.get('producer') == 'src/tools/release/build-native-binary.py'
            and receipt['producer'] in inputs, 'reader_evidence_original_producer_required')
    require(evidence.get('actual_wait') is True and type(evidence.get('exit_code')) is int
            and evidence['exit_code'] == 0 and evidence.get('binary_sha256') == binary_hash,
            'reader_evidence_original_binary_or_wait_mismatch')
    argv = evidence.get('command')
    require(argv == [receipt.get('cli_binary'), 'build-info', '--json'], 'reader_evidence_command_mismatch')
    text = evidence.get('stdout_utf8')
    require(isinstance(text, str) and 0 < len(text.encode('utf-8')) <= 4096, 'reader_evidence_output_bound')
    raw = text.encode('utf-8')
    require(evidence.get('stdout_sha256') == sha(raw) and evidence.get('stdout_bytes') == len(raw)
            and evidence.get('stderr_bytes') == 0 and evidence.get('stderr_sha256') == sha(b''),
            'reader_evidence_output_digest_mismatch')
    report = strict_json(raw)
    require(report == evidence.get('report') and report.get('schema') == 1 and report.get('target') == target,
            'reader_evidence_typed_report_mismatch')
    require((report.get('minimum_release_reader'), report.get('supported_state_readers')) in [
                ('native_runtime_migrated_v1', ['native_management_state_v1', 'native_migrated_state_v1']),
                ('native_runtime_migrated_v2', ['native_management_state_v1', 'native_migrated_state_v1', 'native_migrated_state_v2']),
                ('native_runtime_migrated_v3', ['native_management_state_v1', 'native_migrated_state_v1', 'native_migrated_state_v2']),
                    ('native_runtime_selected_v1', ['native_management_state_v1', 'native_migrated_state_v1', 'native_migrated_state_v2', 'native_runtime_selected_state_v1']),
                    ('native_app_runtime_selected_v1', ['native_management_state_v1', 'native_migrated_state_v1', 'native_migrated_state_v2', 'native_runtime_selected_state_v1', 'native_app_runtime_selected_state_v1']),
                    ('native_service_runtime_selected_v1', ['native_management_state_v1', 'native_migrated_state_v1', 'native_migrated_state_v2', 'native_runtime_selected_state_v1', 'native_app_runtime_selected_state_v1', 'native_service_runtime_selected_state_v1']),
                    ('native_app_service_transferred_v1', ['native_management_state_v1', 'native_migrated_state_v1', 'native_migrated_state_v2', 'native_runtime_selected_state_v1', 'native_app_runtime_selected_state_v1', 'native_service_runtime_selected_state_v1', 'native_app_service_transferred_state_v1'])],
            'reader_evidence_supported_contract_mismatch')
    return report['minimum_release_reader']


def validate_binary_location(receipt, binary, target, relocated, minimum_reader):
    if not relocated:
        if 'cli_binary' in receipt:
            require(Path(receipt['cli_binary']).is_absolute()
                    and Path(receipt['cli_binary']).resolve(strict=True) == binary.resolve(strict=True),
                    'receipt_cli_binary_path_mismatch')
        return
    # A copied artifact is bound by the original producer's SHA and actual
    # build-info observation. Its original locator is provenance, never opened
    # on this machine. This flag cannot upgrade historical receipts.
    require(minimum_reader in ['native_runtime_migrated_v1', 'native_runtime_migrated_v2', 'native_runtime_migrated_v3', 'native_runtime_selected_v1', 'native_app_runtime_selected_v1', 'native_service_runtime_selected_v1', 'native_app_service_transferred_v1']
            and receipt.get('producer') == 'src/tools/release/build-native-binary.py'
            and isinstance(receipt.get('cli_build_info'), dict),
            'relocation_original_producer_evidence_required')
    original = receipt.get('cli_binary')
    require(isinstance(original, str) and 0 < len(original) <= 4096
            and '\x00' not in original, 'relocation_original_locator_invalid')
    if target == 'x86_64-pc-windows-msvc':
        path = PureWindowsPath(original)
        require(path.is_absolute() and re.fullmatch('[A-Za-z]:', path.drive) is not None
                and len(original) >= 3 and original[2] in ('/', '\\')
                and all(part not in {'', '.', '..'} for part in re.split(r'[\\/]', original[3:]))
                and ':' not in original[2:], 'relocation_original_locator_invalid')
    else:
        path = PurePosixPath(original)
        require(path.is_absolute() and not original.startswith('//')
                and '\\' not in original
                and all(part not in {'', '.', '..'} for part in original[1:].split('/')),
                'relocation_original_locator_invalid')


def detached_public(args, output, forbidden):
    pin, raw = public_pin(args.publisher_file, forbidden)
    require(pin == args.expected_publisher, 'expected_publisher_pin_mismatch')
    write_private(output / 'publisher.pem', raw)
    der = openssl(['pkey', '-pubin', '-in', str(output / 'publisher.pem'), '-outform', 'DER'])
    require(sha(der) == pin, 'publisher_der_pin_mismatch')
    write_private(output / 'publisher.der', der)
    return raw


def accept_detached_signature(args, output, payload, manifest_raw, forbidden):
    # The signer authorizes these exact bytes. Rebuilding never edits a prepared
    # payload or substitutes a remotely supplied manifest for local validation.
    require(HEX.fullmatch(args.approved_manifest_sha256 or '') is not None
            and sha(manifest_raw) == args.approved_manifest_sha256,
            'approved_manifest_sha256_mismatch')
    nonsecret(args.detached_signature, forbidden, 64)
    raw = read_bounded(args.detached_signature, 64)
    require(len(raw) == 64, 'manifest_signature_not_64_bytes')
    write_private(payload / 'manifest.sig', raw)
    openssl(['pkeyutl', '-verify', '-pubin', '-inkey', str(output / 'publisher.pem'),
             '-rawin', '-in', str(payload / 'manifest.json'), '-sigfile', str(payload / 'manifest.sig')])
    require(read_bounded(args.detached_signature, 64) == raw,
            'detached_signature_changed')
    return raw


def tunnel_inputs(args, forbidden):
    supplied = (args.tunnel_client, args.tunnel_client_sha256,
                args.tunnel_client_license, args.tunnel_client_notice)
    require(not any(supplied) or all(supplied), 'tunnel_client_inputs_incomplete')
    if not any(supplied):
        return None
    require(HEX.fullmatch(args.tunnel_client_sha256) is not None, 'tunnel_client_sha256_invalid')
    paths = [args.tunnel_client, args.tunnel_client_license, args.tunnel_client_notice]
    for path in paths:
        absolute(path)
        no_symlinks(path)
    binary_hash, binary_stat = hash_checked(args.tunnel_client, forbidden)
    require(binary_hash == args.tunnel_client_sha256, 'tunnel_client_sha256_mismatch')
    filename = 'tunnel-client-runtime.exe' if args.target == 'x86_64-pc-windows-msvc' else 'tunnel-client-runtime'
    inputs = [(args.tunnel_client, filename, binary_hash, binary_stat, True)]
    for path, name in [(args.tunnel_client_license, 'LICENSE'), (args.tunnel_client_notice, 'NOTICE')]:
        digest, observed = hash_checked(path, forbidden, 1024 * 1024)
        require(observed.st_size > 0, 'tunnel_client_notice_empty')
        inputs.append((path, name, digest, observed, False))
    # Raw upstream inputs are pinned by the operator and attested by this package's
    # publisher. This digest identifies that exact input inventory, not an upstream signature.
    inventory = encode(dict(version='0.0.17', files=[dict(path=name, sha256=digest, size=observed.st_size)
                                                   for _, name, digest, observed, _ in inputs]))
    prefix = 'workers/tunnel-client/'
    closure = dict(kind='tunnel_client', version='0.0.17', source_manifest_sha256=sha(inventory),
                   source_publisher_spki_sha256=args.expected_publisher, entrypoint=prefix + filename,
                   members=[prefix + name for _, name, _, _, _ in inputs])
    return closure, inputs


def build(args):
    require(sys.platform == 'linux', 'builder_linux_only')
    require(re.fullmatch(r'[a-f0-9]{40}', args.source_revision) is not None, 'full_source_revision_required')
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', args.version) is not None, 'safe_version_required')
    require(HEX.fullmatch(args.expected_publisher) is not None, 'expected_publisher_fingerprint_required')
    kinds = sorted(args.worker_kind)
    require(len(kinds) == len(set(kinds)), 'duplicate_worker_kind')
    require(bool(kinds) == bool(args.worker_release) == bool(args.worker_publisher_file), 'worker_inputs_incomplete')
    public_only = args.publisher_private_key is None
    require(public_only == bool(args.publisher_file), 'public_publisher_required_only_for_detached_modes')
    require(bool(args.detached_signature) == bool(args.approved_manifest_sha256),
            'detached_signature_and_approved_manifest_required_together')
    paths = [args.binary, args.build_receipt, args.output]
    paths += [p for p in (args.publisher_private_key, args.publisher_file, args.detached_signature) if p is not None]
    paths += [p for p in (args.worker_release, args.worker_publisher_file) if p is not None]
    for path in paths:
        absolute(path)
        no_symlinks(path)
    require(not args.output.is_relative_to(REPO)
            and not (args.worker_release and args.output.is_relative_to(args.worker_release)),
            'output_must_not_change_source_tree')
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    output = args.output
    try:
        frozen_git(args.source_revision)
        private_metadata, public_raw = None, None
        forbidden = (-1, -1)
        if not public_only:
            fd, private_metadata = open_regular(args.publisher_private_key, 64 * 1024, private=True)
            os.close(fd)
            forbidden = (private_metadata.st_dev, private_metadata.st_ino)
        else:
            public_raw = detached_public(args, output, forbidden)
        for path in [args.binary, args.build_receipt, REPO / 'LICENSE'] + ([args.worker_publisher_file] if kinds else []):
            nonsecret(path, forbidden)
        if not public_only:
            require(key_pin(args.publisher_private_key, output, private_metadata) == args.expected_publisher,
                    'expected_publisher_pin_mismatch')
        raw_receipt = read_bounded(args.build_receipt, 16 * 1024 * 1024)
        receipt = strict_json(raw_receipt)
        require(receipt.get('status') == 'PASS' and receipt.get('input_stability') == 'PASS', 'build_receipt_not_pass_stable')
        require(receipt.get('source_revision') == args.source_revision and receipt.get('target') == args.target,
                'receipt_revision_or_target_mismatch')
        inputs = receipt.get('inputs')
        validate_inputs(inputs, forbidden)
        binary_hash = receipt.get('cli_binary_sha256')
        require(isinstance(binary_hash, str) and HEX.fullmatch(binary_hash), 'receipt_cli_binary_sha256_missing')
        actual_binary_hash, binary_metadata = hash_checked(args.binary, forbidden)
        require(actual_binary_hash == binary_hash, 'binary_receipt_hash_mismatch')
        minimum_reader = release_reader(receipt, binary_hash, args.target, inputs)
        validate_binary_location(receipt, args.binary, args.target, args.relocated_binary, minimum_reader)
        source = inspect_worker(args.worker_release, args.worker_publisher_file, args.target,
                                args.expected_publisher, forbidden, output) if kinds else None
        selections = [selected_worker(source, kind, args.target, forbidden) for kind in kinds]
        tunnel = tunnel_inputs(args, forbidden)
        if tunnel:
            kinds = sorted(kinds + ['tunnel_client'])
        require(b'LICENSE\0' in git('ls-files', '-z', '--', 'LICENSE'), 'source_license_not_tracked')
        license_raw = read_bounded(REPO / 'LICENSE', 1024 * 1024)
        require(bool(license_raw), 'source_license_missing')
        source_raw = encode(dict(schema=1, revision=args.source_revision, build_receipt_sha256=sha(raw_receipt), inputs=inputs, target=args.target))
        projected_files = 3 + sum(len(selected) for _, selected in selections) + (3 if tunnel else 0)
        projected_bytes = binary_metadata.st_size + len(license_raw) + len(source_raw)
        if tunnel:
            projected_bytes += sum(observed.st_size for _, _, _, observed, _ in tunnel[1])
        if source:
            projected_bytes += sum(source['declared'][name]['size'] for _, selected in selections for name in selected)
        require(projected_files <= MAX_FILES and projected_bytes <= MAX_TOTAL, 'runtime_payload_capacity')
        payload = output / 'payload'
        payload.mkdir(mode=0o700)
        entrypoint = 'bin/styx.exe' if TARGETS[args.target][0] == 'win32' else 'bin/styx'
        binary_observation = copy_checked(args.binary, payload / entrypoint, binary_hash, forbidden, True, args.target)
        write_private(payload / 'LICENSE', license_raw)
        write_private(payload / 'source-inputs.json', source_raw)
        members = [member(entrypoint, payload, True), member('LICENSE', payload), member('source-inputs.json', payload)]
        closures = []
        for closure, selected in selections:
            prefix = f"workers/{KINDS[closure['kind']][0]}/"
            for name in sorted(selected):
                item = source['declared'][name]
                destination = prefix + name
                executable = destination == closure['entrypoint']
                copy_checked(source['root'] / name, payload / destination, item['sha256'], forbidden,
                             executable, args.target if executable else None)
                members.append(member(destination, payload, executable))
            closures.append(closure)
        if tunnel:
            closure, tunnel_files = tunnel
            for path, name, digest, observed, executable in tunnel_files:
                destination = 'workers/tunnel-client/' + name
                copy_checked(path, payload / destination, digest, forbidden, executable,
                             args.target if executable else None)
                members.append(member(destination, payload, executable))
            closures.append(closure)
        require(len(members) <= MAX_FILES and sum(item['size'] for item in members) <= MAX_TOTAL,
                'runtime_payload_capacity')
        manifest = dict(schema=2, runtime_format='native_rust_v1', component='styx', scope='runtime_candidate',
                        minimum_reader=minimum_reader, target=args.target, version=args.version,
                        entrypoint=entrypoint, source=dict(revision=args.source_revision, inputs_sha256=sha(source_raw)),
                        contracts=dict(control=1, management_state=6 if minimum_reader == 'native_app_service_transferred_v1' else (5 if minimum_reader == 'native_service_runtime_selected_v1' else (4 if minimum_reader == 'native_app_runtime_selected_v1' else (3 if minimum_reader == 'native_runtime_selected_v1' else 2)))), files=members, external_workers=kinds)
        if closures:
            manifest['worker_closures'] = closures
        manifest_raw = encode(manifest)
        require(len(manifest_raw) <= 1024 * 1024, 'manifest_capacity')
        write_private(payload / 'manifest.json', manifest_raw)
        signature_raw = None
        if not public_only:
            require(signature(args.publisher_private_key.lstat()) == signature(private_metadata), 'publisher_key_metadata_changed_before_sign')
            require(sign_manifest(args.publisher_private_key, output, payload) == args.expected_publisher,
                    'signed_publisher_pin_mismatch')
            signature_raw = read_bounded(payload / 'manifest.sig', 64)
            require(len(signature_raw) == 64, 'manifest_signature_not_64_bytes')
        elif args.detached_signature:
            signature_raw = accept_detached_signature(args, output, payload, manifest_raw, forbidden)
        names = [item['path'] for item in members] + ['manifest.json']
        if signature_raw is not None:
            names.append('manifest.sig')
            bundle = output / 'native-runtime-candidate.tar.gz'
            deterministic_archive(payload, bundle, names, {item['path'] for item in members if item['executable']})
        frozen_git(args.source_revision)
        validate_inputs(inputs, forbidden)
        require(read_bounded(args.build_receipt, 16 * 1024 * 1024) == raw_receipt, 'build_receipt_changed')
        require(signature(args.binary.lstat()) == signature(binary_observation)
                and hash_checked(args.binary, forbidden)[0] == binary_hash, 'binary_changed_after_packaging')
        if not public_only:
            require(signature(args.publisher_private_key.lstat()) == signature(private_metadata), 'publisher_key_metadata_changed_after_sign')
        else:
            require(public_pin(args.publisher_file, forbidden) == (args.expected_publisher, public_raw),
                    'publisher_public_file_changed')
        if source:
            require(tree(source['root'], forbidden) == (source['observations'], source['directories']), 'worker_inventory_changed')
            require(read_bounded(source['root'] / 'manifest.json', 1024 * 1024) == source['raw']
                    and read_bounded(source['root'] / 'manifest.sig', 256) == source['signature_raw']
                    and read_bounded(source['public_file'], 4096) == source['public_raw'], 'worker_metadata_changed')
            for name, item in source['declared'].items():
                require(hash_checked(source['root'] / name, forbidden)[0] == item['sha256'], 'worker_source_changed_after_packaging')
        if tunnel:
            for path, _, digest, observed, _ in tunnel[1]:
                current_digest, current_stat = hash_checked(path, forbidden)
                require(current_digest == digest and signature(current_stat) == signature(observed),
                        'tunnel_client_source_changed_after_packaging')
        actual_files, _ = tree(payload, forbidden)
        require(set(actual_files) == set(names), 'payload_inventory_not_exact')
        for item in members:
            current = (payload / item['path']).lstat()
            require(member(item['path'], payload, item['executable']) == item
                    and stat.S_IMODE(current.st_mode) == (0o700 if item['executable'] else 0o600),
                    'payload_changed_after_packaging')
        require(read_bounded(payload / 'manifest.json', 1024 * 1024) == manifest_raw, 'manifest_changed')
        require(public_pin(output / 'publisher.pem', forbidden)[0] == args.expected_publisher
                and digest_file(output / 'publisher.der') == args.expected_publisher,
                'signature_or_publisher_artifact_changed')
        if args.prepare_signing:
            # All source, receipt, worker and resulting payload checks above are
            # shared with finalization. This is not a signed package or PASS.
            request = dict(schema=1, status='SIGNING_REQUIRED', scope=SCOPE,
                           source_revision=args.source_revision, target=args.target,
                           version=args.version, publisher_spki_der_sha256=args.expected_publisher,
                           manifest_sha256=sha(manifest_raw), manifest_bytes=len(manifest_raw),
                           build_receipt_sha256=sha(raw_receipt), cli_binary_sha256=binary_hash,
                           input_stability='PASS', signed=False, archive_created=False)
            write_private(output / 'signing-request.json', encode(request))
            print(encode(request).decode('utf-8').strip())
            return 0
        require(read_bounded(payload / 'manifest.sig', 64) == signature_raw,
                'signature_or_publisher_artifact_changed')
        if args.detached_signature:
            require(read_bounded(args.detached_signature, 64) == signature_raw, 'detached_signature_changed')
        openssl(['pkeyutl', '-verify', '-pubin', '-inkey', str(output / 'publisher.pem'),
                 '-rawin', '-in', str(payload / 'manifest.json'), '-sigfile', str(payload / 'manifest.sig')])
        artifacts = ['payload/manifest.json', 'payload/manifest.sig', 'publisher.pem', 'publisher.der', 'native-runtime-candidate.tar.gz']
        result = dict(schema=1, status='PASS', scope=SCOPE, source_revision=args.source_revision, target=args.target,
                      version=args.version, input_stability='PASS', build_receipt_sha256=sha(raw_receipt),
                      cli_binary_sha256=binary_hash, minimum_release_reader=minimum_reader,
                      binary_relocated=args.relocated_binary,
                      source_inputs_sha256=sha(source_raw), members=len(members),
                      external_workers=kinds, worker_closures=closures, publisher_spki_der_sha256=args.expected_publisher,
                      signature='Ed25519 exact raw manifest bytes, raw64 signature; OpenSSL verified',
                      worker_source_signature='schema1 exact raw manifest bytes, canonical base64url raw64; OpenSSL verified' if source else None,
                      artifacts={name: dict(size=(output/name).stat().st_size, sha256=digest_file(output/name)) for name in artifacts},
                      not_tested=['runtime readiness', 'installation', 'activation', 'profile migration', 'platform permissions', 'stable release'])
        write_private(output / 'build-receipt.json', encode(result))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, BuildError) else type(error).__name__
        if not (output / 'build-failure.json').exists():
            write_private(output / 'build-failure.json', encode(dict(schema=1, status='FAIL', scope=SCOPE, error=code)))
        print(json.dumps(dict(schema=1, status='FAIL', error=code)), file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'build-receipt', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    signing = parser.add_mutually_exclusive_group(required=True)
    signing.add_argument('--publisher-private-key', type=Path)
    signing.add_argument('--prepare-signing', action='store_true')
    signing.add_argument('--detached-signature', type=Path, help='external raw64 Ed25519 signature, finalization only')
    parser.add_argument('--publisher-file', type=Path, help='original externally pinned public PEM; required for detached modes')
    parser.add_argument('--approved-manifest-sha256', help='exact approved prepared manifest SHA; required for finalization')
    for name in ('source-revision', 'expected-publisher', 'version'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--relocated-binary', action='store_true',
                        help='accept copied bytes only with complete original producer/build-info evidence; preserve original receipt')
    parser.add_argument('--tunnel-client', type=Path, help='pinned upstream v0.0.17 native binary; never executed')
    parser.add_argument('--tunnel-client-sha256', help='required with --tunnel-client')
    parser.add_argument('--tunnel-client-license', type=Path, help='required upstream LICENSE with --tunnel-client')
    parser.add_argument('--tunnel-client-notice', type=Path, help='required upstream NOTICE with --tunnel-client')
    parser.add_argument('--worker-release', type=Path)
    parser.add_argument('--worker-publisher-file', type=Path)
    parser.add_argument('--worker-kind', action='append', choices=KINDS, default=[])
    try:
        return build(parser.parse_args())
    except Exception as error:
        code = str(error) if isinstance(error, BuildError) else type(error).__name__
        print(json.dumps(dict(schema=1, status='FAIL', error=code)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
