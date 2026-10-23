#!/usr/bin/env python3
"""Persistent current-user signing identity for isolated Mac development only.

No Apple account, system trust store, TCC changes or private-key distribution.
An incomplete identity fails closed: rerunning never rotates an existing key.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile


def run(args, *, input=None):
    result = subprocess.run(args, input=input, capture_output=True, timeout=45)
    if result.returncode:
        # Command arguments may contain a keychain password. Never include the
        # command, stdout, stderr or subprocess exception in a diagnostic.
        raise RuntimeError(Path(args[0]).name + ' ' + (args[1] if len(args) > 1 else '') + ' failed: ' + str(result.returncode))
    return result.stdout


def private_file(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError('private owned regular file required')


def write_private(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def keychains():
    return shlex.split(run(['/usr/bin/security', 'list-keychains', '-d', 'user']).decode())


def unlock_existing_keychain(keychain, password):
    # Keep the dedicated builder password out of child argv/process listings.
    security = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
    security.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    security.SecKeychainUnlock.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_bool]
    handle = ctypes.c_void_p()
    result = security.SecKeychainOpen(str(keychain).encode(), ctypes.byref(handle))
    if result:
        raise RuntimeError('existing keychain open failed: ' + str(result))
    encoded = password.encode()
    buffer = ctypes.create_string_buffer(encoded)
    try:
        result = security.SecKeychainUnlock(handle, len(encoded), buffer, True)
        if result:
            raise RuntimeError('existing keychain unlock failed: ' + str(result))
    finally:
        ctypes.memset(buffer, 0, len(buffer))
        core = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        core.CFRelease.argtypes = [ctypes.c_void_p]
        core.CFRelease(handle)


def prepare(root, *, existing_only=False):
    if existing_only and (not root.is_dir() or not (root / 'identity.json').is_file()):
        raise RuntimeError('existing signing identity required; creation disabled')
    root.mkdir(mode=0o700, parents=False, exist_ok=True)
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError('private owned identity directory required')
    lock = os.open(root / 'identity.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = root / 'identity.json'
        password_file = root / 'keychain-password'
        keychain = root / 'styx-development.keychain-db'
        cert = root / 'certificate.der'
        if receipt.exists():
            for file in [receipt, password_file, keychain, cert]:
                private_file(file)
            value = json.loads(receipt.read_text())
            if value.get('schema') != 1 or value.get('keychain') != str(keychain):
                raise RuntimeError('existing identity receipt is inconsistent')
            der = cert.read_bytes()
            if hashlib.sha1(der).hexdigest() != value['identitySha1'] or hashlib.sha256(der).hexdigest() != value['certificateSha256']:
                raise RuntimeError('existing certificate changed; refusing identity rotation')
            run(['/usr/bin/openssl', 'x509', '-inform', 'DER', '-in', str(cert), '-checkend', '0', '-noout'])
            password = password_file.read_text().strip()
            current = keychains()
            if str(keychain) not in current:
                run(['/usr/bin/security', 'list-keychains', '-d', 'user', '-s', *current, str(keychain)])
            unlock_existing_keychain(keychain, password)
            return value
        if existing_only:
            raise RuntimeError('existing signing identity required; creation disabled')
        # Never silently replace a partially prepared key or keychain.
        if any(file.exists() for file in [password_file, keychain, cert]):
            raise RuntimeError('incomplete identity requires review; refusing to generate another key')
        password = secrets.token_urlsafe(48)
        write_private(password_file, password.encode() + b'\n')
        initial = keychains()
        run(['/usr/bin/security', 'create-keychain', '-p', password, str(keychain)])
        # Keep this dedicated identity in the user search catalog: codesign's
        # --keychain filters certificate discovery but still needs normal key
        # lookup. Preserve every previous entry and the default login keychain.
        current = keychains()
        if any(item not in current for item in initial):
            raise RuntimeError('pre-existing keychain search list changed; review required')
        run(['/usr/bin/security', 'set-keychain-settings', '-lut', '3600', str(keychain)])
        run(['/usr/bin/security', 'unlock-keychain', '-p', password, str(keychain)])
        # Always delete temporary plaintext keys, including import failures.
        # The keychain/public certificate remain for review; no automatic retry
        # may replace a partially prepared identity.
        with tempfile.TemporaryDirectory(prefix='provision-', dir=root) as temporary:
            tmp = Path(temporary)
            config = tmp / 'certificate.cnf'
            config.write_text('''[req]
prompt = no
distinguished_name = subject
x509_extensions = code_signing
[subject]
CN = Styx Local Development
O = Styx Internal Testing
[code_signing]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
''')
            # All unencrypted material exists only in this owner-only temporary
            # directory and is deleted after importing into the dedicated keychain.
            previous = os.umask(0o077)
            try:
                run(['/usr/bin/openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-x509', '-sha256', '-days', '3650', '-config', str(config), '-keyout', str(tmp / 'private.pem'), '-out', str(tmp / 'certificate.pem')])
                run(['/usr/bin/openssl', 'x509', '-in', str(tmp / 'certificate.pem'), '-outform', 'DER', '-out', str(cert)])
                run(['/usr/bin/openssl', 'rsa', '-in', str(tmp / 'private.pem'), '-out', str(tmp / 'rsa.pem')])
                run(['/usr/bin/security', 'import', str(tmp / 'rsa.pem'), '-f', 'openssl', '-t', 'priv', '-P', '', '-x', '-k', str(keychain), '-T', '/usr/bin/codesign'])
                run(['/usr/bin/security', 'import', str(cert), '-t', 'cert', '-k', str(keychain)])
                # This dedicated keychain contains only the new development key;
                # no ACL or partition of an existing login key is changed.
                run(['/usr/bin/security', 'set-key-partition-list', '-S', 'apple-tool:,apple:', '-s', '-k', password, str(keychain)])
            finally:
                os.umask(previous)
        os.chmod(keychain, 0o600)
        der = cert.read_bytes()
        value = {'schema': 1, 'kind': 'local_development_only', 'identitySha1': hashlib.sha1(der).hexdigest(), 'certificateSha256': hashlib.sha256(der).hexdigest(), 'keychain': str(keychain), 'certificateFile': str(cert), 'privateKeyDistributed': False, 'systemTrustChanged': False, 'tccChanged': False}
        write_private(receipt, (json.dumps(value, indent=2) + '\n').encode())
        return value
    finally:
        os.close(lock)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--authorize', action='store_true')
    args = parser.parse_args()
    root = Path(args.root)
    if sys.platform != 'darwin' or not args.authorize or not root.is_absolute() or root != root.resolve():
        parser.error('explicit authorization and a canonical absolute macOS identity directory are required')
    try:
        print(json.dumps(prepare(root), indent=2))
    except Exception as error:
        # Never print a subprocess error carrying secret argv.
        print('Styx local identity preparation stopped: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        sys.exit(2)
