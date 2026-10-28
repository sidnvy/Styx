"""Linux v1 journey: the REDUCED-SCOPE.md acceptance steps against one signed payload.

usage: linux-journey.py PAYLOAD_DIR PUBLISHER_PEM PUBLISHER_PIN WORK_DIR PORT

Fresh private Gateway and Host roots under WORK_DIR, loopback Gateway on PORT.
Steps: verify payload, bootstrap and run Gateway, pair a Host, Exec file effect,
headless Browser page effect, one Computer Use click on a zenity dialog this
script opens itself, quit and reopen without re-pairing, Exec again. Every step
is logged with timings to WORK_DIR/journey.jsonl. Stops at the first unexpected
result; never retries a command whose outcome is unknown.
"""
import atexit, json, os, subprocess, sys, time, threading, signal, hashlib, uuid
from pathlib import Path

payload, publisher, pin, work, port = sys.argv[1:6]
work = Path(work)
styx = str(Path(payload) / "bin/styx")
inputs, gparent, hparent, hcwd = (work / n for n in ("inputs", "gateway-parent", "host-parent", "host-cwd"))
for d in (work, inputs, gparent, hparent, hcwd):
    d.mkdir(mode=0o700, parents=False, exist_ok=False)
gateway, host = gparent / "gateway", hparent / "host"
url = f"https://127.0.0.1:{port}/"
log = open(work / "journey.jsonl", "a")
T0 = time.monotonic()
env = dict(os.environ, STYX_GATEWAY_STARTUP_DIAGNOSTICS="1")


def note(event, **fields):
    rec = {"t": round(time.monotonic() - T0, 3), "event": event, **fields}
    log.write(json.dumps(rec) + "\n"); log.flush()
    print(json.dumps(rec), flush=True)


def run(name, args, stdout_file=None):
    start = time.monotonic()
    if stdout_file:
        with open(stdout_file, "x") as out:
            os.chmod(stdout_file, 0o600)
            p = subprocess.run([styx, *args], stdout=out, stderr=subprocess.PIPE, text=True, env=env)
        report = None
    else:
        p = subprocess.run([styx, *args], capture_output=True, text=True, env=env)
        report = json.loads(p.stdout) if p.stdout.strip() else None
    note(name, exit=p.returncode, seconds=round(time.monotonic() - start, 3))
    if p.returncode != 0:
        note(name + "_failed", stderr=p.stderr[-2000:], stdout=(p.stdout or "")[-2000:] if not stdout_file else "")
        raise SystemExit(f"{name} failed")
    return report


ROLES = []


@atexit.register
def stop_leftovers():
    for role in ROLES:
        if role.p.poll() is None:
            role.p.send_signal(signal.SIGTERM)
            try:
                note(role.name + "_cleanup_stopped", code=role.p.wait(timeout=60))
            except subprocess.TimeoutExpired:
                note(role.name + "_cleanup_timeout")


class Role:
    """Foreground role process; records each JSON event line with a timestamp."""

    def __init__(self, name, args):
        ROLES.append(self)
        self.name, self.events = name, []
        self.start = time.monotonic()
        self.p = subprocess.Popen([styx, *args], stdout=subprocess.PIPE, stderr=open(work / f"{name}.stderr.log", "a"), text=True, env=env)
        note(name + "_spawned", pid=self.p.pid)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                ev = json.loads(line)
            except ValueError:
                ev = {"raw": line.strip()[:300]}
            ev["_t"] = round(time.monotonic() - self.start, 3)
            self.events.append(ev)
            with open(work / f"{self.name}.events.jsonl", "a") as f:
                f.write(json.dumps(ev) + "\n")

    def wait_for(self, predicate, label, timeout=180):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for ev in self.events:
                if predicate(ev):
                    note(f"{self.name}_{label}", since_spawn=ev["_t"])
                    return ev
            if self.p.poll() is not None:
                note(f"{self.name}_exited_early", code=self.p.returncode)
                raise SystemExit(f"{self.name} exited")
            time.sleep(0.05)
        note(f"{self.name}_{label}_timeout")
        raise SystemExit(f"{self.name} {label} timeout")

    def stop(self):
        start = time.monotonic()
        self.p.send_signal(signal.SIGTERM)
        code = self.p.wait(timeout=120)
        note(self.name + "_stopped", code=code, seconds=round(time.monotonic() - start, 3))
        if code != 0:
            raise SystemExit(f"{self.name} stop exit {code}")


def ev_name(ev):
    return str(ev.get("event", ev.get("status", "")))


def plan_apply(root, component, tx, seq):
    plan = run(f"{component}_plan_{tx}", ["plan", "--native", "--state-dir", str(root), "--component", component, "--run", "running", "--transaction-id", tx, "--sequence", str(seq), "--json"])
    note(f"{component}_plan_report_keys", keys=sorted(plan) if isinstance(plan, dict) else str(type(plan)))
    plan_file = plan.get("plan_file") or plan.get("planFile")
    run(f"{component}_apply_{tx}", ["apply", "--state-dir", str(root), "--plan-file", plan_file, "--authorize", "--json"])


def mcp(cmd, *args):
    p = subprocess.run([sys.executable, "-I", str(Path(__file__).parent / "mcp_client.py"), str(gateway), url, str(gateway / "gateway-ca.pem"), cmd, *args], capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        note("mcp_failed", cmd=cmd, stderr=p.stderr[-2000:])
        raise SystemExit("mcp failed")
    return json.loads(p.stdout)


def exec_effect(device, label):
    nonce = uuid.uuid4().hex
    target = hcwd / f"effect-{label}-{nonce}.txt"
    command = f'set -C; printf %s "$HOME:{nonce}" > {target}'
    result = mcp("call", "exec_command", json.dumps({"environment_id": device, "cmd": command}))
    note("exec_result_" + label, result=json.dumps(result)[:1500])
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not target.exists():
        time.sleep(0.1)
    import pwd
    ok = target.exists() and target.read_text() == pwd.getpwuid(os.getuid()).pw_dir + ":" + nonce
    note("exec_effect_" + label, ok=ok)
    if not ok:
        raise SystemExit("exec effect missing")


def tool_text(reply):
    result = reply.get("result", {})
    if result.get("isError"):
        note("tool_error", result=json.dumps(reply)[:1500])
        raise SystemExit("tool error")
    return result


def computer_click(device):
    """One click on a dialog this script owns; the dialog's exit code is the effect."""
    nonce = uuid.uuid4().hex[:12]
    dialog = subprocess.Popen(["zenity", "--question", "--title", f"styx-click-{nonce}",
        "--text", f"Styx journey click test {nonce}", "--ok-label", "Confirm", "--cancel-label", "Cancel"])
    atexit.register(lambda: dialog.poll() is None and dialog.kill())
    start = time.monotonic()
    windows = []
    while time.monotonic() - start < 15 and not windows:
        listed = tool_text(mcp("call", "list_windows", json.dumps({"environment_id": device, "pid": dialog.pid})))
        windows = (listed.get("structuredContent") or {}).get("windows") or []
        if not windows:
            time.sleep(0.5)
    note("computer_list_windows", seconds=round(time.monotonic() - start, 3), windows=json.dumps(windows)[:600])
    if not windows:
        raise SystemExit("dialog window not listed")
    window_id = windows[0].get("window_id", windows[0].get("windowId"))
    state = tool_text(mcp("call", "get_window_state", json.dumps({"environment_id": device, "pid": dialog.pid,
        "window_id": window_id, "query": "Confirm", "include_screenshot": False})))
    structured = state.get("structuredContent") or {}
    tokens = [e.get("element_token") for e in structured.get("elements", [])
              if "confirm" in json.dumps(e).lower() and e.get("element_token")]
    note("computer_state", tokens=tokens, tree=str(structured.get("tree_markdown", ""))[:600])
    if not tokens:
        raise SystemExit("Confirm button not found in the accessibility tree")
    clicked = tool_text(mcp("call", "click", json.dumps({"environment_id": device, "element_token": tokens[-1]})))
    note("computer_click_result", result=json.dumps(clicked)[:600])
    try:
        code = dialog.wait(timeout=10)
    except subprocess.TimeoutExpired:
        code = None
    note("computer_click_effect", ok=code == 0, dialog_exit=code)
    if code != 0:
        raise SystemExit("click effect missing")


# --- verify payload, bootstrap Gateway -------------------------------------------
selection = inputs / "runtime-selection.json"
run("release_verify", ["release", "verify", "--payload-dir", payload, "--publisher-file", publisher, "--expected-publisher", pin, "--runtime-selection"], stdout_file=selection)
gdep = inputs / "gateway.json"
gdep.write_text(json.dumps({"schema": 1, "mode": "create-local", "gateway": {"url": url, "listenHost": "127.0.0.1"}})); os.chmod(gdep, 0o600)
run("gateway_bootstrap", ["gateway", "bootstrap", "--parent-dir", str(gparent), "--name", "gateway", "--deployment-file", str(gdep), "--runtime-selection-file", str(selection), "--json"])
plan_apply(gateway, "gateway", "gateway-first-run", 1)
g = Role("gateway", ["gateway", "run", "--state-dir", str(gateway)])
g.wait_for(lambda e: "listen" in ev_name(e) or e.get("listening") is True, "listening")

# --- pair Host ---------------------------------------------------------------------
invitation = inputs / "invitation.txt"
run("gateway_invite", ["gateway", "invite", "--state-dir", str(gateway), "--invitation-file", str(invitation), "--ttl-seconds", "600", "--authorize", "--json"])
ca_der = subprocess.run(["openssl", "x509", "-in", str(gateway / "gateway-ca.pem"), "-outform", "DER"], capture_output=True, check=True).stdout
hdep = inputs / "host.json"
hdep.write_text(json.dumps({"schema": 1, "mode": "join-existing",
    "gateway": {"url": url.rstrip("/"), "caFile": str(gateway / "gateway-ca.pem"), "expectedCaSha256": hashlib.sha256(ca_der).hexdigest()},
    "host": {"label": "linux-journey", "cwd": str(hcwd), "shell": "/bin/bash", "computer": True, "browser": {"enabled": True, "headless": True, "channel": "chrome", "persistLogin": False}},
    "runtimeSelectionFile": str(selection), "invitationFile": str(invitation)})); os.chmod(hdep, 0o600)
req = run("host_join_request", ["host", "join", "request", "--parent-dir", str(hparent), "--name", "host", "--deployment-file", str(hdep), "--json"])
pending = run("gateway_pending", ["gateway", "pending", "--state-dir", str(gateway), "--json"])
note("join_request_keys", request=sorted(req), pending=json.dumps(pending)[:800])
pick = lambda *k: next(req[x] for x in k if x in req)
run("gateway_approve", ["gateway", "approve", "--state-dir", str(gateway), "--request-id", pick("request_id", "requestId"), "--device-id", pick("device_id", "deviceId"), "--fingerprint", pick("fingerprint"), "--comparison-code", pick("comparison_code", "comparisonCode"), "--enable-browser", "--enable-computer", "--authorize", "--json"])
claim = run("host_join_claim", ["host", "join", "claim", "--state-dir", str(host), "--json"])
note("claim", status=claim.get("status"))
device = pick("device_id", "deviceId")
plan_apply(host, "host", "host-first-run", 1)
h = Role("host", ["host", "run", "--state-dir", str(host)])
h.wait_for(lambda e: ev_name(e) == "connected", "connected")
note("first_setup_connected_total", seconds=round(time.monotonic() - T0, 3))

# --- real effect, then reopen without re-pairing -----------------------------------
note("tools", names=mcp("list"))
envs = mcp("call", "list_execution_environments", "{}")
note("environments", result=json.dumps(envs)[:1500])
text = json.dumps(envs)
if device not in text:
    raise SystemExit("paired device not listed as an execution environment")
note("status",result=json.dumps(mcp("call", "get_execution_environment_status", json.dumps({"environment_id": device})))[:1500])
exec_effect(device, "first")
nonce = uuid.uuid4().hex
import http.server
class Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"<title>styx-{nonce}</title><p>{nonce}</p>".encode()
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a):
        pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Page)
threading.Thread(target=server.serve_forever, daemon=True).start()
page = f"http://127.0.0.1:{server.server_address[1]}/styx-journey"
for attempt in range(30):
    st = json.loads(mcp("call", "get_execution_environment_status", json.dumps({"environment_id": device}))["result"]["content"][0]["text"])
    if st["browser"]["connection"] == "connected" and st["computer"]["connection"] == "connected":
        break
    time.sleep(1)
note("lanes", browser=st["browser"], computer=st["computer"], waited_s=attempt)
nav = mcp("call", "browser_navigate", json.dumps({"environment_id": device, "url": page}))
snap = mcp("call", "browser_snapshot", json.dumps({"environment_id": device}))
note("browser_effect", ok=nonce in json.dumps(snap), navigate=json.dumps(nav)[:600], snapshot=json.dumps(snap)[:600])
computer_click(device)
h.stop(); g.stop()
R0 = time.monotonic()
g = Role("gateway", ["gateway", "run", "--state-dir", str(gateway)])
g.wait_for(lambda e: "listen" in ev_name(e) or e.get("listening") is True, "reopen_listening")
h = Role("host", ["host", "run", "--state-dir", str(host)])
h.wait_for(lambda e: ev_name(e) == "connected", "reopen_connected")
note("reopen_connected_total", seconds=round(time.monotonic() - R0, 3))
exec_effect(device, "reopen")
h.stop(); g.stop()
note("journey_complete")
