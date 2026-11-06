#!/usr/bin/env python3
"""Real terminal reference: cancel before setup writes; no Gateway or key use."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import termios
import time


def scenario(args, name, color, payload, tunnel=False, cancel=False):
    out = args.evidence / name
    out.mkdir(mode=0o700)
    root = out / 'never-created-profile'
    child, master = pty.fork()
    if child == 0:
        os.environ['TERM'] = 'xterm-256color'
        if color:
            os.environ.pop('NO_COLOR', None)
        else:
            os.environ['NO_COLOR'] = '1'
        os.execv(str(args.binary), [str(args.binary), 'setup', '--root', str(root), '--foreground'])
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 55, 140, 0, 0))
    transcript = bytearray()
    cursor = 0
    wait_status = None
    failure = None

    def expect(text):
        nonlocal cursor
        needle = text.encode()
        until = time.monotonic() + 12
        while True:
            found = transcript.find(needle, cursor)
            if found >= 0:
                cursor = found + len(needle)
                return
            if time.monotonic() > until:
                raise RuntimeError('terminal did not reach ' + text)
            ready, _, _ = select.select([master], [], [], .1)
            if ready:
                try:
                    part = os.read(master, 65536)
                except OSError:
                    part = b''
                if not part:
                    raise RuntimeError('terminal exited before ' + text)
                transcript.extend(part)

    def send(value):
        os.write(master, value.encode())

    try:
        expect('Role')
        if cancel:
            send('\x03')
        else:
            send('\x1b[B\x1b[B\r' if color else '3\n')
            expect('Installed payload directory')
            send(str(payload) + ('\r' if color else '\n'))
            expect('Publisher public PEM file')
            send(str(args.publisher) + ('\r' if color else '\n'))
            expect('Publisher fingerprint shown on the download page')
            send(args.fingerprint + ('\r' if color else '\n'))
            expect('Hub HTTPS port')
            send('22129' + ('\r' if color else '\n'))
            expect('Networks other computers can use' if color else 'Network numbers, separated by commas')
            send('\r' if color else '\n')
            expect('Configure a tunnel now?')
            send(('y' if tunnel else 'n') + ('\r' if color else '\n'))
            if tunnel:
                expect('Tunnel ID')
                send('tunnel_00000000000000000000000000000000\n')
            expect("This computer's label")
            send('Styx terminal reference' + ('\r' if color else '\n'))
            if tunnel:
                expect('setup_tunnel_client_missing')
            else:
                expect('Set up Styx now?')
                send('n' + ('\r' if color else '\n'))
        until = time.monotonic() + 12
        while time.monotonic() < until:
            ready, _, _ = select.select([master], [], [], .05)
            if ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b''
                transcript.extend(data)
            got, value = os.waitpid(child, os.WNOHANG)
            if got:
                wait_status = value
                break
        assert wait_status is not None, 'original process still running'
        code = os.waitstatus_to_exitcode(wait_status)
        if cancel:
            assert code == 2 and transcript.rfind(b'\x1b[?25h') > transcript.rfind(b'\x1b[?25l'), 'Ctrl-C must restore cursor before normal error exit'
            assert termios.tcgetattr(master)[3] & termios.ECHO, 'Ctrl-C must restore terminal echo'
        assert code != 0 and not root.exists(), 'cancel/preflight must not create a configuration'
        if color:
            assert b'\x1b[' in transcript, 'real color/cursor rendering not observed'
        else:
            assert b'\x1b[' not in transcript, 'NO_COLOR leaked terminal escapes'
        assert b'Tunnel API key (input hidden)' not in transcript
        assert b'Runtime: gateway_loading' not in transcript
        if tunnel:
            assert b'Use the Gateway package with tunnel-client' in transcript
        result = {'status': 'PASS', 'original_exit_code': code, 'profile_created': False,
                  'actual_PTY': True, 'color_enabled': color, 'key_prompted': False,
                  'Gateway_started': False, 'input_replayed': False}
    except Exception as error:
        failure = error
        result = {'status': 'NOT_PASSED', 'error': str(error), 'profile_created': root.exists()}
    finally:
        if wait_status is None:
            # This reference has not authorized any mutation or started a role.
            # Close only its own terminal; retain the original outcome and logs.
            os.close(master)
            _, wait_status = os.waitpid(child, 0)
            result['original_cleanup_wait_status'] = wait_status
        else:
            os.close(master)
        (out / 'terminal.bin').write_bytes(transcript)
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2))
    if failure:
        raise failure
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ['binary', 'gateway-payload', 'host-payload', 'publisher', 'evidence']:
        p.add_argument('--' + key, required=True, type=Path)
    p.add_argument('--fingerprint', required=True)
    args = p.parse_args()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    cases = {}
    cases['interactive_cancel'] = scenario(args, 'interactive-cancel', True, args.gateway_payload)
    cases['no_color_cancel'] = scenario(args, 'no-color-cancel', False, args.gateway_payload)
    cases['missing_worker'] = scenario(args, 'missing-worker', False, args.host_payload, tunnel=True)
    cases['ctrl_c'] = scenario(args, 'ctrl-c', True, args.gateway_payload, cancel=True)
    root = args.evidence / 'noninteractive-never-created'
    q = subprocess.run([str(args.binary), 'setup', '--root', str(root)],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    value = json.loads(q.stderr)
    assert q.returncode == 2 and value['error'] == 'setup_noninteractive_requires_answers'
    assert b'\x1b[' not in q.stdout + q.stderr and not root.exists()
    cases['noninteractive'] = {'status': 'PASS', 'machine_error': value, 'profile_created': False}
    result = {'status': 'PASS', 'scope': 'real PTY presentation/cancel/no-color and signed missing-worker preflight; no setup mutation, API request or desktop action', 'cases': cases}
    (args.evidence / 'RESULT.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
