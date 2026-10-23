#!/usr/bin/env python3
"""One existing-identity signing session for native or transported Mac previews.

No identity provisioning, private-key transfer, application installation or retry.
"""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

spec = importlib.util.spec_from_file_location('styx_identity', Path(__file__).with_name('local-signing-identity.py'))
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


def run_session(root, config_file, node):
    if not root.is_dir() or root != root.resolve():
        raise RuntimeError('existing canonical signing directory required')
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError('private owned signing directory required')
    identity.private_file(root / 'identity.json')
    config = json.loads(config_file.read_text())
    recorded = json.loads((root / 'identity.json').read_text())
    expected = {key: recorded[key] for key in ['identitySha1', 'certificateSha256', 'keychain']}
    if config.get('localSigning') != expected or config.get('prepareOnly'):
        raise RuntimeError('signing configuration does not match existing identity')
    publisher = config.get('hostPublisher', {})
    if publisher != {'mode': 'persistent', 'privateKeyFile': str(root / 'host-publisher-private.pem')}:
        raise RuntimeError('existing persistent publisher required')
    identity.private_file(root / 'host-publisher-private.pem')
    # Separate from the short provisioning lock: hold across prepare, codesign,
    # Host manifest signing and archive verification. Never unlink a live lock.
    lock = os.open(root / 'signing-session.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(lock)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_nlink != 1:
            raise RuntimeError('private owned signing lock required')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        prepared = identity.prepare(root, existing_only=True)
        if {key: prepared[key] for key in expected} != expected:
            raise RuntimeError('signing identity changed during preparation')
        if json.loads(config_file.read_text()) != config:
            raise RuntimeError('signing configuration changed during preparation')
        builder = Path(__file__).resolve().parents[1] / 'build-macos-preview.mjs'
        # Both stages use the same builder; x64 payloads are never executed by
        # its finalizer on an arm64 signer. Failure returns without retry.
        return subprocess.run([str(node), str(builder), str(config_file)], check=False).returncode
    finally:
        os.close(lock)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--node', required=True)
    parser.add_argument('--authorize', action='store_true')
    args = parser.parse_args()
    paths = [Path(args.root), Path(args.config), Path(args.node)]
    if sys.platform != 'darwin' or not args.authorize or any(not p.is_absolute() or p != p.resolve() for p in paths):
        parser.error('authorized canonical macOS signing paths required')
    try:
        return run_session(*paths)
    except Exception as error:
        # Keychain passwords and subprocess diagnostics are never echoed here.
        print('Styx signing session stopped: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
