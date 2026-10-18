#!/usr/bin/env python3
"""Headless native Cua owner-death check, never TCC or GUI acceptance.

Uses Styx's production launch helper via its explicit fixture entrypoint.
Only the subprocess created here receives SIGKILL. No daemon PID is signalled.
"""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile
import time


def accepts(endpoint):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(0.2)
        try:
            client.connect(str(endpoint))
            return True
        except OSError:
            return False


def alive(pid):
    try:
        os.kill(pid, 0)  # Existence check only, not signal delivery.
        return True
    except ProcessLookupError:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("owner")
    parser.add_argument("driver")
    args = parser.parse_args()
    owner, driver = str(Path(args.owner).resolve()), str(Path(args.driver).resolve())
    version = subprocess.check_output([driver, "--version"], text=True, timeout=10).strip()
    if version.split()[:2] != ["cua-driver", "0.36.0"]:
        raise RuntimeError("pinned Cua 0.36.0 required")
    directory = Path(tempfile.mkdtemp(prefix="styx-life-", dir="/tmp"))
    endpoint = directory / "cua.sock"
    process = None
    daemon_pid = None
    try:
        process = subprocess.Popen([owner, "--liveness-owner-fixture", driver, str(endpoint)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if not select.select([process.stdout], [], [], 10)[0]:
            raise RuntimeError("owner did not report its own child")
        descriptor = json.loads(process.stdout.readline())
        daemon_pid = descriptor["daemon_pid"]
        if not isinstance(daemon_pid, int) or daemon_pid <= 1:
            raise RuntimeError("invalid child pid")
        deadline = time.monotonic() + 20
        while not accepts(endpoint):
            if process.poll() is not None:
                raise RuntimeError("native daemon exited before accepting its private socket")
            if time.monotonic() > deadline:
                raise RuntimeError("native daemon socket readiness timed out")
            time.sleep(0.05)
        process.kill()  # Exact subprocess object created here, never a discovered PID.
        process.wait(timeout=5)
        deadline = time.monotonic() + 40
        while endpoint.exists() or alive(daemon_pid):
            if time.monotonic() > deadline:
                raise RuntimeError("Cua did not exit and release socket after owner SIGKILL")
            time.sleep(0.05)
        print(json.dumps({"schema": 1, "test": "native_cua_owner_sigkill_eof",
                          "result": "PASS", "cua_version": version,
                          "native_gui": "NOT_RUN", "tcc_attribution": "NOT_VERIFIED"}))
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if accepts(endpoint):
            # Official shutdown of this test's private endpoint only. Never send
            # a signal to a stored PID that could have been reused.
            subprocess.run([driver, "stop", "--socket", str(endpoint)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
        if not endpoint.exists() and (daemon_pid is None or not alive(daemon_pid)):
            shutil.rmtree(directory)


if __name__ == "__main__":
    main()
