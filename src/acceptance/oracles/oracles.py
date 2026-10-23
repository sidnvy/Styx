"""Independent effect observers. Test tooling; imports no Styx implementation.

Ledger writes are the fixture's side effect, not evidence that an executor ran.
Only external candidate journeys can promote observations to native acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HEX = re.compile(r"^[a-f0-9]{64}$")
NONCE = re.compile(r"^[a-f0-9]{32}$")
MAX_LEDGER = 1024 * 1024


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def private_root(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise ValueError("root_alias")
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("root_not_private")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("root_owner")
    return path


class EffectLedger:
    """Fresh exclusively-created ledger. No dedup: replay must remain observable."""
    def __init__(self, root, nonce):
        if not NONCE.fullmatch(nonce):
            raise ValueError("invalid_nonce")
        self.root = private_root(root)
        self.nonce = nonce
        self.path = self.root / "effects.jsonl"
        self.lock = threading.Lock()
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        self.fd = os.open(self.path, flags, 0o600)
        info = os.fstat(self.fd)
        self.identity = (info.st_dev, info.st_ino)
        self.closed = False

    def append(self, nonce, channel):
        if nonce != self.nonce or channel not in {"exec", "browser", "cua_fixture"}:
            raise ValueError("wrong_effect_scope")
        with self.lock:
            if self.closed:
                raise ValueError("ledger_closed")
            row = json.dumps({"nonce": nonce, "channel": channel,
                              "observed_monotonic_ns": time.monotonic_ns()}, separators=(",", ":")) + "\n"
            if os.fstat(self.fd).st_size + len(row.encode()) > MAX_LEDGER:
                raise ValueError("ledger_capacity")
            data = row.encode()
            while data:
                n = os.write(self.fd, data)
                data = data[n:]
            os.fsync(self.fd)

    def observe(self):
        with self.lock:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self.identity:
                raise ValueError("ledger_replaced")
            if info.st_size > MAX_LEDGER:
                raise ValueError("ledger_capacity")
            rows = [json.loads(x) for x in self.path.read_text().splitlines()]
            if any(row.get("nonce") != self.nonce for row in rows):
                raise ValueError("ledger_scope_changed")
            return {"count": len(rows), "ledger_sha256": digest(self.path), "rows": rows}

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                os.close(self.fd)


def append_exec_effect(path, nonce):
    """Executable probe for the command UNDER TEST; reader is a separate observer.

    The fresh private run root is the authorization boundary. This utility does
    not establish isolation from hostile same-UID code.
    """
    if not NONCE.fullmatch(nonce):
        raise ValueError("invalid_nonce")
    path = Path(path).absolute()
    private_root(path.parent)
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > MAX_LEDGER - 256:
            raise ValueError("unsafe_ledger")
        row = json.dumps({"nonce": nonce, "channel": "exec",
                          "observed_monotonic_ns": time.monotonic_ns()}) + "\n"
        # One bounded append preserves each observed duplicate; no retry of action.
        if os.write(fd, row.encode()) != len(row.encode()):
            raise ValueError("partial_effect_unknown")
        os.fsync(fd)
    finally:
        os.close(fd)


def linux_process_identity(pid):
    """Read-only kernel identity, never kill or infer effect outcome from exit.

    PID namespace is explicitly recorded. Non-Linux requires a native observer;
    returning unsupported is safer than PID-only continuity.
    """
    if not Path("/proc/sys/kernel/random/boot_id").exists():
        return {"status": "UNSUPPORTED", "reason": "native_process_observer_required"}
    if type(pid) is not int or pid < 1:
        raise ValueError("invalid_pid")
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        # comm can contain spaces and parentheses; fields after its LAST ')' start at 3.
        fields = raw[raw.rfind(")") + 2:].split()
        start = fields[19]  # field 22: starttime since boot, not wall clock
        namespace = os.readlink(f"/proc/{pid}/ns/pid")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        raw2 = Path(f"/proc/{pid}/stat").read_text()
        if raw2[raw2.rfind(")") + 2:].split()[19] != start:
            return {"status": "UNKNOWN", "reason": "identity_changed_during_observation"}
        return {"status": "OBSERVED", "pid": pid, "start_ticks": start,
                "boot_id": boot, "pid_namespace": namespace,
                "process_state": fields[0]}
    except FileNotFoundError:
        return {"status": "ABSENT", "pid": pid}
    except (PermissionError, OSError, IndexError):
        return {"status": "UNKNOWN", "reason": "kernel_observation_unavailable"}


class BrowserOracle:
    """Loopback-only owned site. Raw effects counted independently of Browser MCP."""
    def __init__(self, ledger):
        self.ledger = ledger
        nonce = ledger.nonce
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass  # never leak URLs/nonces into generic logs
            def do_GET(self):
                if self.path != "/":
                    self.send_error(404)
                    return
                body = ("<!doctype html><title>Owned oracle fixture</title>"
                        "<button id='effect'>Record effect</button><output id='result'></output>"
                        "<script>document.querySelector('#effect').onclick=async()=>{"
                        "let r=await fetch('/effect',{method:'POST',body:'" + nonce + "'});"
                        "document.querySelector('#result').textContent=r.ok?'stored':'failed'};</script>").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            def do_POST(self):
                if self.path != "/effect":
                    self.send_error(404)
                    return
                try:
                    # Fixture nonce scopes the run, not a production authentication scheme.
                    if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                        raise ValueError()
                    n = int(self.headers["Content-Length"])
                    if n != 32:
                        raise ValueError()
                    value = self.rfile.read(n).decode("ascii")
                    ledger.append(value, "browser")
                except (ValueError, UnicodeError):
                    self.send_error(400)
                    return
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
        class Server(ThreadingHTTPServer):
            daemon_threads = False  # server_close joins owned request workers
            def get_request(self):
                sock, address = super().get_request()
                sock.settimeout(2)
                return sock, address
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.started = False
        self.closed = False
    def start(self):
        if self.started or self.closed:
            raise ValueError("oracle_already_started_or_closed")
        self.started = True
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}/"
    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.started:
            self.server.shutdown()
        self.server.server_close()
        if self.started:
            self.thread.join(3)
        if self.thread.is_alive():
            raise ValueError("oracle_cleanup_unconfirmed")


def validate_cua_observation(value, expected):
    """Owned GUI app must produce this state itself, via a separate read channel.

    Validating JSON is NOT native execution or proof of app identity. Future
    platform observer must bind instance to kernel process+window/session facts.
    """
    keys = {"schema", "fixture_id", "instance_id", "session_generation", "nonce", "effect_count"}
    if not isinstance(value, dict) or set(value) != keys or value["schema"] != 1:
        raise ValueError("cua_fixture_shape")
    for key in ("fixture_id", "instance_id", "session_generation", "nonce"):
        if value[key] != expected[key] or not isinstance(value[key], str) or not value[key]:
            raise ValueError("cua_fixture_binding")
    if type(value["effect_count"]) is not int or value["effect_count"] < 0:
        raise ValueError("cua_fixture_count")
    return value["effect_count"]


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    effect = sub.add_parser("exec-effect")
    effect.add_argument("ledger")
    effect.add_argument("nonce")
    process = sub.add_parser("process")
    process.add_argument("pid", type=int)
    args = parser.parse_args()
    if args.command == "exec-effect":
        append_exec_effect(args.ledger, args.nonce)
    else:
        print(json.dumps(linux_process_identity(args.pid)))

if __name__ == "__main__":
    main()
