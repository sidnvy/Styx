#!/usr/bin/env python3
"""Build an internal Linux configuration preview from a proven frozen binary.

No Cargo, installer, executor, identity generation, existing profile access or
publisher trust bootstrap. The supplied publisher remains an external trust pin.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile

REPO = Path(__file__).resolve().parents[3]
TARGET = 'x86_64-unknown-linux-gnu'
SCOPE = 'INTERNAL_LINUX_CONFIG_PREVIEW_NO_RUNTIME_DEPLOYMENT'
OPENSSL = Path('/usr/bin/openssl')
HEX = re.compile(r'[0-9a-f]{64}\Z')


class BuildError(Exception):
    """Static secret-free failure code."""


def require(ok, code):
    if not ok:
        raise BuildError(code)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for part in iter(lambda: source.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute(path):
    require(path.is_absolute() and '..' not in path.parts, 'absolute_normal_path_required')
    return path


def no_symlinks(path):
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_path_refused')


def signature(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def open_regular(path, limit, private=False):
    no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        observed = os.fstat(fd)
        require(stat.S_ISREG(observed.st_mode) and observed.st_size <= limit, 'regular_bounded_file_required')
        if private:
            require(observed.st_uid == os.geteuid() and stat.S_IMODE(observed.st_mode) in (0o400, 0o600)
                    and observed.st_nlink == 1 and observed.st_size > 0, 'private_key_permissions_refused')
        require(signature(observed) == signature(path.lstat()), 'input_changed_during_open')
        return fd, observed
    except BaseException:
        os.close(fd)
        raise


def read_bounded(path, limit):
    fd, initial = open_regular(path, limit)
    try:
        raw = bytearray()
        while len(raw) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        require(len(raw) <= limit and signature(initial) == signature(os.fstat(fd))
                == signature(path.lstat()), 'input_changed_during_read')
        return bytes(raw)
    finally:
        os.close(fd)


def write_private(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def encode(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def git(*args):
    proc = subprocess.run(['git', '-C', str(REPO), *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
    require(proc.returncode == 0 and len(proc.stdout) <= 16 * 1024 * 1024, 'git_inspection_failed')
    return proc.stdout


def frozen_git(revision):
    require(git('rev-parse', 'HEAD').decode().strip() == revision, 'source_revision_mismatch')
    require(not git('status', '--porcelain=v1', '--untracked-files=all'), 'product_tree_not_clean')


def validate_inputs(inputs, forbidden_private_identity):
    require(isinstance(inputs, dict) and 0 < len(inputs) <= 4096, 'receipt_inputs_invalid')
    require({'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'} <= set(inputs), 'receipt_foundation_inputs_missing')
    tracked = {p.decode('utf8') for p in git('ls-files', '-z').split(b'\0') if p}
    for relative, expected in inputs.items():
        require(isinstance(relative, str) and 0 < len(relative) <= 1024
                and isinstance(expected, str) and HEX.fullmatch(expected), 'receipt_input_binding_invalid')
        path = Path(relative)
        require(not path.is_absolute() and all(p not in ('.', '..') for p in path.parts)
                and relative in tracked, 'receipt_input_not_tracked_relative')
        candidate = REPO / path
        no_symlinks(candidate)
        require(candidate.is_file(), 'receipt_input_not_regular')
        current = candidate.lstat()
        require((current.st_dev, current.st_ino) != forbidden_private_identity, 'private_key_cannot_be_source_input')
        require(digest_file(candidate) == expected, 'receipt_input_current_hash_mismatch')


def elf_header(fd):
    header = os.pread(fd, 64, 0)
    require(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01'
            and header[7] in (0, 3) and struct.unpack_from('<H', header, 16)[0] in (2, 3)
            and struct.unpack_from('<H', header, 18)[0] == 62
            and struct.unpack_from('<I', header, 20)[0] == 1
            and struct.unpack_from('<H', header, 52)[0] == 64, 'binary_not_linux_x86_64_elf')


def copy_binary(source, destination, expected):
    fd, original = open_regular(source, 1024 * 1024 * 1024)
    try:
        require(original.st_size > 0, 'empty_binary')
        elf_header(fd)
        h = hashlib.sha256()
        target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        os.fchmod(target_fd, 0o700)
        with os.fdopen(target_fd, 'wb') as target:
            # copyfileobj uses mature buffered copying from the pinned original;
            # hashing the actual source descriptor prevents a pathname swap.
            with os.fdopen(os.dup(fd), 'rb') as pinned:
                shutil.copyfileobj(pinned, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            h.update(part)
        require(signature(os.fstat(fd)) == signature(original) == signature(source.lstat())
                and h.hexdigest() == expected and digest_file(destination) == expected,
                'binary_copy_or_source_changed')
        return original
    finally:
        os.close(fd)


def openssl(args, pass_fds=()):
    require(OPENSSL.is_file() and os.access(OPENSSL, os.X_OK), 'official_openssl_missing')
    proc = subprocess.run([str(OPENSSL), *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          pass_fds=pass_fds, timeout=30, check=False)
    # Private parser/signing stderr is deliberately never exposed or persisted.
    require(proc.returncode == 0 and len(proc.stdout) <= 256 * 1024, 'openssl_operation_failed')
    return proc.stdout


def sign_manifest(key, output, payload):
    fd, initial = open_regular(key, 64 * 1024, private=True)
    try:
        key_arg = f'/proc/self/fd/{fd}'
        os.lseek(fd, 0, os.SEEK_SET)
        public = openssl(['pkey', '-in', key_arg, '-pubout'], (fd,))
        write_private(output / 'publisher.pem', public)
        details = openssl(['pkey', '-pubin', '-in', str(output / 'publisher.pem'), '-text_pub', '-noout'])
        require(re.search(rb'^ED25519 Public-Key:', details, re.MULTILINE) is not None, 'publisher_not_ed25519')
        der = openssl(['pkey', '-pubin', '-in', str(output / 'publisher.pem'), '-outform', 'DER'])
        write_private(output / 'publisher.der', der)
        os.lseek(fd, 0, os.SEEK_SET)
        raw_sig = openssl(['pkeyutl', '-sign', '-rawin', '-inkey', key_arg,
                           '-in', str(payload / 'manifest.json')], (fd,))
        require(len(raw_sig) == 64, 'manifest_signature_not_64_bytes')
        write_private(payload / 'manifest.sig', raw_sig)
        openssl(['pkeyutl', '-verify', '-pubin', '-inkey', str(output / 'publisher.pem'),
                 '-rawin', '-in', str(payload / 'manifest.json'), '-sigfile', str(payload / 'manifest.sig')])
        require(signature(initial) == signature(os.fstat(fd)) == signature(key.lstat()), 'publisher_key_metadata_changed')
        return sha(der)
    finally:
        os.close(fd)


def member(path, payload, executable=False):
    file = payload / path
    return dict(path=path, size=file.stat().st_size, sha256=digest_file(file), executable=executable)


def archive(payload, destination):
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
                directory = tarfile.TarInfo('bin')
                directory.type, directory.mode = tarfile.DIRTYPE, 0o700
                directory.uid = directory.gid = directory.mtime = 0
                bundle.addfile(directory)
                for name in ('LICENSE', 'bin/styx', 'source-inputs.json', 'manifest.json', 'manifest.sig'):
                    path = payload / name
                    info = tarfile.TarInfo(name)
                    info.size = path.stat().st_size
                    info.mode = 0o700 if name == 'bin/styx' else 0o600
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    with path.open('rb') as source:
                        bundle.addfile(info, source)
        raw.flush()
        os.fsync(raw.fileno())


def build(args):
    require(sys.platform == 'linux', 'builder_linux_only')
    require(re.fullmatch(r'[a-f0-9]{40}', args.source_revision) is not None, 'full_source_revision_required')
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', args.version) is not None, 'safe_version_required')
    for path in (args.binary, args.build_receipt, args.publisher_private_key, args.output):
        absolute(path)
    no_symlinks(args.output)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(args.output, 0o700)
    output = args.output
    try:
        frozen_git(args.source_revision)
        # Never hash the supplied private key even if arguments or a receipt
        # accidentally alias it as binary, license, receipt or tracked input.
        private_fd, private_metadata = open_regular(args.publisher_private_key, 64 * 1024, private=True)
        os.close(private_fd)
        forbidden_private_identity = (private_metadata.st_dev, private_metadata.st_ino)
        for nonsecret in (args.binary, args.build_receipt, REPO / 'LICENSE'):
            no_symlinks(nonsecret)
            observed = nonsecret.lstat()
            require((observed.st_dev, observed.st_ino) != forbidden_private_identity, 'private_key_argument_alias')
        raw_receipt = read_bounded(args.build_receipt, 16 * 1024 * 1024)
        receipt = strict_json(raw_receipt)
        require(receipt.get('status') == 'PASS' and receipt.get('input_stability') == 'PASS', 'build_receipt_not_pass_stable')
        if 'source_revision' in receipt:
            require(receipt['source_revision'] == args.source_revision, 'receipt_revision_mismatch')
        if 'target' in receipt:
            require(receipt['target'] == TARGET, 'receipt_target_mismatch')
        inputs = receipt.get('inputs')
        validate_inputs(inputs, forbidden_private_identity)
        binary_hash = receipt.get('cli_binary_sha256')
        require(isinstance(binary_hash, str) and HEX.fullmatch(binary_hash), 'receipt_cli_binary_sha256_missing')
        if 'cli_binary' in receipt:
            require(Path(receipt['cli_binary']).is_absolute()
                    and Path(receipt['cli_binary']).resolve(strict=True) == args.binary.resolve(strict=True), 'receipt_cli_binary_path_mismatch')
        require(digest_file(args.binary) == binary_hash, 'binary_receipt_hash_mismatch')
        license_path = REPO / 'LICENSE'
        require(license_path.is_file() and b'LICENSE\0' in git('ls-files', '-z', '--', 'LICENSE'), 'source_license_missing')
        license_raw = read_bounded(license_path, 1024 * 1024)
        require(bool(license_raw), 'source_license_empty')
        payload = output / 'payload'
        payload.mkdir(mode=0o700)
        os.chmod(payload, 0o700)
        (payload / 'bin').mkdir(mode=0o700)
        os.chmod(payload / 'bin', 0o700)
        original_binary = copy_binary(args.binary, payload / 'bin/styx', binary_hash)
        write_private(payload / 'LICENSE', license_raw)
        provenance = dict(schema=1, revision=args.source_revision, build_receipt_sha256=sha(raw_receipt), inputs=inputs)
        for name in ('toolchain', 'target'):
            value = receipt.get(name)
            if isinstance(value, str) and len(value) <= 256:
                provenance[name] = value
        source_raw = encode(provenance)
        write_private(payload / 'source-inputs.json', source_raw)
        members = [member('bin/styx', payload, True), member('LICENSE', payload), member('source-inputs.json', payload)]
        manifest = dict(schema=2, runtime_format='native_rust_v1', component='styx', scope='configuration_preview',
                        minimum_reader='native_release_v1', target=TARGET, version=args.version, entrypoint='bin/styx',
                        source=dict(revision=args.source_revision, inputs_sha256=sha(source_raw)),
                        contracts=dict(control=1, management_state=2), files=members, external_workers=[])
        manifest_raw = encode(manifest)
        require(len(manifest_raw) <= 1024 * 1024, 'manifest_capacity')
        write_private(payload / 'manifest.json', manifest_raw)
        require(signature(args.publisher_private_key.lstat()) == signature(private_metadata), 'publisher_key_metadata_changed_before_sign')
        publisher = sign_manifest(args.publisher_private_key, output, payload)
        bundle = output / 'native-configuration-preview.tar.gz'
        archive(payload, bundle)
        # Recheck every frozen source and copied member after signing/archive;
        # copied package identity may not drift during receipt publication.
        frozen_git(args.source_revision)
        validate_inputs(inputs, forbidden_private_identity)
        require(read_bounded(args.build_receipt, 16 * 1024 * 1024) == raw_receipt, 'build_receipt_changed')
        require(signature(args.binary.lstat()) == signature(original_binary)
                and digest_file(args.binary) == binary_hash, 'binary_changed_after_packaging')
        require(signature(args.publisher_private_key.lstat()) == signature(private_metadata), 'publisher_key_metadata_changed_after_sign')
        for item in members:
            require(member(item['path'], payload, item['executable']) == item, 'payload_changed_after_packaging')
        require(read_bounded(payload / 'manifest.json', 1024 * 1024) == manifest_raw, 'manifest_changed')
        artifact_paths = ['payload/bin/styx', 'payload/LICENSE', 'payload/source-inputs.json',
                          'payload/manifest.json', 'payload/manifest.sig', 'publisher.pem', 'publisher.der',
                          'native-configuration-preview.tar.gz']
        result = dict(schema=1, status='PASS', scope=SCOPE, revision=args.source_revision, version=args.version,
                      build_receipt_sha256=sha(raw_receipt), binary_sha256=binary_hash,
                      publisher_spki_der_sha256=publisher, publisher_trust='EXTERNAL_EXPECTED_FINGERPRINT_REQUIRED',
                      target=TARGET, signature='Ed25519 raw manifest bytes, raw64 signature; OpenSSL verified',
                      legacy_signature_wire='NOT_IDENTICAL: legacy manifest.sig is base64url text; native manifest.sig is raw64',
                      artifacts={name:dict(size=(output/name).stat().st_size, sha256=digest_file(output/name)) for name in artifact_paths},
                      not_tested=['installation', 'runtime deployment', 'external workers', 'three-platform release', 'stable publisher identity continuity'])
        write_private(output / 'build-receipt.json', encode(result))
        return 0
    except Exception as error:
        # Preserve every produced byte. A failed output directory is never reused
        # or removed, and no parser/key contents are emitted into its receipt.
        code = str(error) if isinstance(error, BuildError) else type(error).__name__
        failure = output / 'build-failure.json'
        if not failure.exists():
            write_private(failure, encode(dict(schema=1, status='FAIL', scope=SCOPE, error=code)))
        print(json.dumps(dict(schema=1, status='FAIL', error=code)), file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--build-receipt', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--publisher-private-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', default='0.0.0-internal-native-preview')
    args = parser.parse_args()
    try:
        return build(args)
    except Exception as error:
        # Pre-output validation and mkdir failures cannot safely create evidence
        # at an unvalidated or existing destination.
        code = str(error) if isinstance(error, BuildError) else type(error).__name__
        print(json.dumps(dict(schema=1, status='FAIL', error=code)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
