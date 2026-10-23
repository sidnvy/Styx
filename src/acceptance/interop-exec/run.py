#!/usr/bin/env python3
"""One owned Linux CLI/immutable legacy Gateway/native Codex acceptance journey.
Profiles are fresh trusted bootstrap fixtures, not an onboarding/migration PASS.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import subprocess
import time
from prepare import BASELINE, digest, inventory

PUBLISHER_PIN = "54d01dc134f2f11d385a471c583bfb761c248767416712b58b8a39b1b28073d6"

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n" if not isinstance(value,str) else value)
    path.chmod(0o600)

def process_facts(pid, identity_only=False):
    # Only a missing stat record proves absence. Permission/parse/other I/O is
    # unknown and fails the owned-identity observation, never a fabricated exit.
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError,ProcessLookupError):
        return None
    end=raw.rfind(")")
    if end < 0:
        raise RuntimeError("kernel process identity malformed")
    suffix = raw[end+2:].split()
    if len(suffix) < 20:
        raise RuntimeError("kernel process identity incomplete")
    result={"pid":pid,"starttime":suffix[19],"ppid":int(suffix[1]),"cwd":None,"pid_namespace":None}
    if identity_only:
        return result
    for key,path in [("cwd",f"/proc/{pid}/cwd"),("pid_namespace",f"/proc/{pid}/ns/pid")]:
        try:
            result[key]=os.readlink(path)
        except (FileNotFoundError,ProcessLookupError):
            # A zombie may still have its exact stat birth but no cwd. Keep it
            # alive/unknown until its stat actually disappears or birth changes.
            result[key]=None
    return result

# Only processes born during this owned harness can have been created by it.
# Do not turn inaccessible, pre-existing same-user daemons into fake exits.
OBSERVER_BIRTH = int(process_facts(os.getpid(),identity_only=True)["starttime"])
def owned_processes(root):
    records = []
    for p in Path("/proc").iterdir():
        if p.name.isdigit():
            other_uid=False
            try:
                other_uid=p.stat().st_uid != os.getuid()
                identity=process_facts(int(p.name),identity_only=True)
                if identity is None or int(identity["starttime"]) < OBSERVER_BIRTH:
                    continue
                facts = process_facts(int(p.name))
            except (FileNotFoundError,ProcessLookupError):
                continue
            except PermissionError:
                if other_uid:continue
                raise
            if facts and facts["cwd"] is not None and Path(facts["cwd"]).is_relative_to(root):
                records.append(facts)
    return records

def same_process(original):
    current = process_facts(original["pid"])
    return current is not None and current["starttime"] == original["starttime"]

async def until(check, description, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        await asyncio.sleep(.05)
    raise AssertionError(description)

class Child:
    def __init__(self, process, log, stderr, name, started):
        self.process, self.log, self.stderr = process, log, stderr
        self.name,self.started,self.observations=name,started,[]
        self.lines = asyncio.Queue(maxsize=128)
        self.reader = asyncio.create_task(self.collect())
        self.error_reader=asyncio.create_task(self.collect_errors())
        self.next_id = 0
    @classmethod
    async def start(cls, argv, root, name, env):
        stderr = (root / f"{name}.stderr.log").open("wb")
        log = (root / f"{name}.stdout.log").open("wb")
        started=time.monotonic()
        proc = await asyncio.create_subprocess_exec(*map(str,argv), cwd=root, env=env,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        return cls(proc,log,stderr,name,started)
    async def collect(self):
        while line := await self.process.stdout.readline():
            self.log.write(line); self.log.flush()
            try:
                value=json.loads(line)
                if value.get("schema")==1 and "event" in value:
                    self.observations.append({"event":value["event"],"elapsed_seconds":time.monotonic()-self.started})
                await self.lines.put(value)
            except json.JSONDecodeError:
                await self.lines.put({"invalid_json":True})
    async def collect_errors(self):
        while line := await self.process.stderr.readline():
            self.stderr.write(line);self.stderr.flush()
            try:
                value=json.loads(line)
                if value.get("schema")==1 and isinstance(value.get("error"),str):
                    self.observations.append({"event":"error","code":value["error"],"elapsed_seconds":time.monotonic()-self.started})
            except json.JSONDecodeError:
                pass
    async def rpc(self, operation, **args):
        self.next_id += 1
        expected = self.next_id
        self.process.stdin.write((json.dumps({"id":expected,"operation":operation,**args})+"\n").encode())
        await self.process.stdin.drain()
        reply = await asyncio.wait_for(self.lines.get(),45)
        assert reply.get("id") == expected and reply.get("ok"), "official client operation failed"
        return reply["data"]
    async def finish(self, sig=signal.SIGTERM, timeout=15):
        if self.process.returncode is None:
            self.process.send_signal(sig)
        forced = False
        try:
            await asyncio.wait_for(self.process.wait(),timeout)
        except asyncio.TimeoutError:
            forced = True
            self.process.kill()
            await self.process.wait()
        if self.process.stdin is not None:
            self.process.stdin.close()
            try:
                await self.process.stdin.wait_closed()
            except (BrokenPipeError,ConnectionResetError):
                pass
        await self.reader
        await self.error_reader
        self.log.close();self.stderr.close()
        return {"exit":self.process.returncode,"forced_kill":forced}

def tool_data(result):
    if result.get("isError"):
        raise AssertionError("actual legacy tool returned an error; original result preserved in private log")
    if "structuredContent" in result:
        return result["structuredContent"]
    text = result["content"][0]["text"]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"output":text}

async def call(client, owner, name, arguments):
    return await client.rpc("call",owner=owner,name=name,arguments=arguments)

async def drain(client, owner, result):
    for _ in range(100):
        value = tool_data(result)
        if "exit_code" in value:
            assert value["exit_code"] == 0
            return
        assert isinstance(value.get("session_id"),int), "owned session handle missing"
        result = await call(client,owner,"write_stdin",{"session_id":value["session_id"],"chars":"","yield_time_ms":0,"max_output_tokens":10000})
        await asyncio.sleep(.025)
    raise AssertionError("native resource did not report exit and output drain")

def fixture(root, signed, publisher, port, node, legacy, tls_style):
    gateway = root/"gateway"
    state = root/"state"
    base = root/"host"
    cwd = root/"native-work"
    for p in [gateway,state,base,cwd,base/"device",base/"install",base/"install/releases"]:
        p.mkdir(parents=True,exist_ok=True);p.chmod(0o700)
    key,cert = gateway/"server-key.pem",gateway/"server-cert.pem"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:3072","-nodes","-days","1","-subj","/CN=Styx owned interop fixture","-addext","subjectAltName=IP:127.0.0.1","-addext","basicConstraints=critical,CA:TRUE","-keyout",str(key),"-out",str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    key.chmod(0o600);cert.chmod(0o600)
    ca=gateway/"ca-cert.pem"
    if tls_style == "standard-chain":
        # New independent fixture only: never mutate a prior selfsigned cert or
        # change original Gateway/TLS verifier bytes to bypass CA constraints.
        write(ca,cert.read_text())
        ca_key=gateway/"ca-key.pem"
        ca_key.write_bytes(key.read_bytes());ca_key.chmod(0o600)
        csr=gateway/"server.csr"
        extensions=gateway/"server-extensions.cnf"
        write(extensions,"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
        subprocess.run(["openssl","req","-new","-newkey","rsa:3072","-nodes","-subj","/CN=Styx owned standard leaf","-keyout",str(key),"-out",str(csr)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["openssl","x509","-req","-in",str(csr),"-CA",str(ca),"-CAkey",str(ca_key),"-CAcreateserial","-days","1","-sha256","-extfile",str(extensions),"-out",str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        key.chmod(0o600);cert.chmod(0o600)
    else:
        write(ca,cert.read_text())

    identity_config = root/"fixture-identity-config.json"
    write(identity_config,{"gateway_url":f"https://127.0.0.1:{port}","storage_dir":str(base/"device"),"label":"Rust CLI interop fixture","cwd":str(cwd),"shell":"/bin/sh","exec_binary":"/untrusted-mutable-binary-must-not-run","gateway_ca_file":str(ca)})
    record=json.loads(subprocess.check_output([str(node),str(Path(__file__).with_name("fixture.mjs")),str(legacy),"identity",str(identity_config)]))
    device=record["device_id"]
    write(base/"device/host.token",secrets.token_urlsafe(48)+"\n")
    write(gateway/"mcp.token",secrets.token_urlsafe(48)+"\n")
    codex_home = root/"native-codex-home"
    codex_home.mkdir(mode=0o700)
    manifest = json.loads((signed/"manifest.json").read_text())
    release = base/"install/releases"/manifest["version"]
    subprocess.run(["cp","--reflink=auto","-a","--",str(signed),str(release)],check=True)
    write(base/"publisher.pem",publisher.read_text())
    write(base/"install/active.json",{"schema":1,"version":manifest["version"],"manifest_sha256":digest(release/"manifest.json"),"previous":None})
    url = f"https://127.0.0.1:{port}"
    write(base/"device/host.json",{"host_id":device,"gateway_ws_url":url.replace("https:","wss:")+"/","token_file":str(base/"device/host.token"),"gateway_ca_file":str(ca),"exec":{"binary":"/untrusted-mutable-binary-must-not-run","cwd":str(cwd),"env":{"CODEX_HOME":str(codex_home)},"timeout_ms":35000}})
    deployment = {"schema":1,"mode":"join-existing","gateway":{"url":url+"/","caFile":str(ca)},"host":{"baseDir":str(base),"publisherSha256":PUBLISHER_PIN,"bundle":str(release),"publisherKeyFile":str(base/"publisher.pem"),"label":"Rust CLI interop fixture","computer":False,"wayland":False,"shell":"/bin/sh"}}
    write(state/"deployment.json",deployment)
    validation_input=root/"fixture-schema-input.json"
    write(validation_input,{"deployment":deployment,"host":json.loads((base/"device/host.json").read_text())})
    validated=subprocess.check_output([str(node),str(Path(__file__).with_name("fixture.mjs")),str(legacy),"validate",str(validation_input)])
    write(root/"original-schema-validation.json",json.loads(validated))
    write(state/"state.json",{"schema":1,"mode":"join-existing","configSha256":digest(state/"deployment.json"),"steps":[{"name":name,"id":name,"status":"succeeded","evidence":"synthetic isolated trusted bootstrap, NOT an onboarding pass"} for name in ["host.prepare","host.pair","host.doctor"]],"activeStep":None,"uncertain":False})
    write(gateway/"catalog.json",{"version":1,"default_environment_id":device,"targets":[{"id":device,"kind":"host","platform":"linux","generation":"isolated-legacy-interop-v1","cwd":str(cwd),"shell":"/bin/sh","shells":["/bin/sh"],"allowed":True,"env":{},"exec":{"transport":"outbound","token_file":str(base/"device/host.token")}}]})
    assert not (base/"service.json").exists(), "fixture must not claim an installed service stopped"
    return state,base,cwd,gateway,device,url

async def journey(args):
    os.umask(0o077)
    root = args.evidence.absolute()
    root.mkdir(parents=True,exist_ok=False)
    inputs = json.loads((args.prepared/"prepared.json").read_text())
    assert inputs["baseline"] == BASELINE
    legacy = Path(inputs["source_root"])
    assert inventory(legacy.parent) == json.loads((args.prepared/"legacy-input-inventory.json").read_text()), "immutable legacy inputs changed"
    node = Path(inputs["node22"])
    assert digest(node) == inputs["node22_sha256"]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
    state,base,cwd,gateway,device,url = fixture(root,args.signed_host.resolve(strict=True),args.publisher_key.resolve(strict=True),port,node,legacy,args.tls_style)
    preserved = {str(p.relative_to(root)):digest(p) for p in [state/"deployment.json",state/"state.json",base/"device/identity.json",base/"device/identity.pem",base/"device/host.token",base/"device/host.json",base/"publisher.pem",base/"install/active.json",gateway/"server-cert.pem",gateway/"server-key.pem",gateway/"ca-cert.pem"]}
    records=[];children=[];outcome={"schema":1,"case":args.case,"tls_style":args.tls_style,"status":"FAIL","scope":"owned Linux actual CLI + immutable legacy Gateway + native Codex; synthetic trusted profile bootstrap, not onboarding/package/platform/account acceptance","baseline":BASELINE,"styx_binary_sha256":digest(args.styx),"node22_sha256":digest(node),"signed_host_manifest_sha256":digest(args.signed_host/"manifest.json"),"publisher_pin":PUBLISHER_PIN,"observer_pid_namespace":os.readlink("/proc/self/ns/pid"),"observer_collected_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"scenarios":records}
    env = {"PATH":"/usr/bin:/bin","HOME":str(root),"TMPDIR":str(root),"LANG":"C.UTF-8"}
    try:
        inspection_times={}
        for cmd in ["doctor","status"]:
            inspection_started=time.monotonic()
            result = await asyncio.create_subprocess_exec(str(args.styx),cmd,"--state-dir",str(state),"--json",cwd=root,env=env,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            stdout,stderr = await result.communicate()
            (root/f"{cmd}.stdout.log").write_bytes(stdout);(root/f"{cmd}.stderr.log").write_bytes(stderr)
            assert result.returncode == 0, "readonly CLI profile inspection failed"
            json.loads(stdout)
            inspection_times[cmd]=time.monotonic()-inspection_started
        assert not owned_processes(cwd), "doctor must not start native executor"
        records.append({"scenario":"real_cli_readonly_doctor_status","status":"PASS","elapsed_seconds":inspection_times})
        env_gateway = {**env,"STYX_MCP_TOKEN_FILE":str(gateway/"mcp.token"),"STYX_LISTEN_HOST":"127.0.0.1","STYX_LISTEN_PORT":str(port),"STYX_ALLOWED_HOSTS":f"127.0.0.1:{port}","STYX_TLS_CERT_FILE":str(gateway/"server-cert.pem"),"STYX_TLS_KEY_FILE":str(gateway/"server-key.pem")}
        old = await Child.start([node,legacy/"gateway/cli.mjs",gateway/"catalog.json"],root,"legacy-gateway",env_gateway);children.append(old)
        ready = await asyncio.wait_for(old.lines.get(),10)
        assert ready.get("status") == "listening"
        host = await Child.start([args.styx,"host","run","--state-dir",state,"--legacy-gateway"],root,"rust-host",env);children.append(host)
        client = await Child.start([node,Path(__file__).with_name("client.mjs"),legacy,url+"/mcp",gateway/"mcp.token"],root,"official-client",{**env,"NODE_EXTRA_CA_CERTS":str(gateway/"ca-cert.pem")});children.append(client)
        await client.rpc("open",owner="A");await client.rpc("open",owner="B")
        definitions=await client.rpc("list",owner="A")
        assert {"exec_command","write_stdin"}.issubset({t["name"] for t in definitions["tools"]})
        bootstrap_deadline=time.monotonic()+60
        while time.monotonic() < bootstrap_deadline:
            assert host.process.returncode is None, "Rust foreground exited before connection; inspect timed event/error observations"
            status=tool_data(await asyncio.wait_for(call(client,"A","get_execution_environment_status",{"environment_id":device}),max(.01,bootstrap_deadline-time.monotonic())))
            if status["exec"]["connection"]=="connected":break
            await asyncio.sleep(.1)
        else:raise AssertionError("Rust Host not connected within 60s bootstrap budget; TLS not inferred without connecting/error evidence")
        def foreground_ready():
            assert host.process.returncode is None,"foreground exited before native ready; inspect timed errors"
            return any(item["event"]=="connected" for item in host.observations)
        await until(foreground_ready,"WSS accepted but native foreground was not ready within bootstrap budget",max(.01,bootstrap_deadline-time.monotonic()))
        if args.probe_only:
            await client.finish(signal.SIGKILL)
            await old.finish(signal.SIGTERM)
            ended=await host.finish(signal.SIGTERM)
            assert ended=={"exit":0,"forced_kill":False},"TLS probe foreground cleanup incomplete"
            assert all(digest(root/name)==sha for name,sha in preserved.items()),"profile bytes changed during TLS probe"
            outcome["status"]="PASS"
            outcome["scope"]="actual CLI legacy selfsigned TLS admission probe only; nonce/PTY/interoperability scenarios NOT_RUN"
            outcome["preserved_private_hashes"]=preserved
            records.append({"scenario":"actual_cli_legacy_selfsigned_tls_admission","status":"PASS"})
            return
        native = await until(lambda:next((p for p in owned_processes(cwd) if p["ppid"]==host.process.pid),None),"real Host-owned native executor absent")
        native["exe_sha256"]=digest(Path(f"/proc/{native['pid']}/exe"))
        assert native["exe_sha256"]==digest(args.signed_host/"bin/codex"), "executor did not come from signed payload"
        records.append({"scenario":"real_cli_signed_native_executor_start","status":"PASS","executor":native})
        for tty in ([False,True] if args.case == "graceful" else []):
            nonce=secrets.token_hex(24);effect=cwd/("pty-effect" if tty else "pipe-effect");pidfile=cwd/("pty-pid" if tty else "pipe-pid")
            start_count=cwd/("pty-start-count" if tty else "pipe-start-count")
            stop="__owned_stop_"+secrets.token_hex(12)
            command=f"printf '%s\\n' {shlex.quote(nonce)} >> {shlex.quote(str(start_count))}; printf '%s\\n' \"$$\" > {shlex.quote(str(pidfile))}; printf 'READY'; while IFS= read -r line; do [ \"$line\" = {shlex.quote(stop)} ] && break; printf '%s\\n' \"$line\" >> {shlex.quote(str(effect))}; done; printf 'DONE'"
            started=await call(client,"A","exec_command",{"cmd":command,"shell":"/bin/sh","login":False,"tty":tty,"environment_id":device,"workdir":str(cwd),"yield_time_ms":0})
            value=tool_data(started);session=value["session_id"]
            await until(pidfile.exists,"native PID oracle absent")
            assert start_count.read_bytes()==(nonce+"\n").encode(),"independent start effect was duplicated"
            assert not effect.exists(),"zero-input negative control did not remain zero"
            denied=await call(client,"B","write_stdin",{"session_id":session,"chars":"foreign\n","yield_time_ms":0})
            assert denied.get("isError") is True and not effect.exists(),"foreign owner mutated native stdin"
            reply=await call(client,"A","write_stdin",{"session_id":session,"chars":nonce+"\n","yield_time_ms":0})
            await until(effect.exists,"authorized native stdin effect absent")
            assert effect.read_bytes()==(nonce+"\n").encode(),"independent file oracle mismatch or duplicate input"
            await asyncio.sleep(.1)
            stopped=await call(client,"A","write_stdin",{"session_id":session,"chars":stop+"\n","yield_time_ms":0})
            await drain(client,"A",stopped)
            assert effect.read_bytes()==(nonce+"\n").encode(),"independent stdin effect count was duplicated"
            assert start_count.read_bytes()==(nonce+"\n").encode(),"native start was replayed"
            records.append({"scenario":"pty_nonce_stdin_exit_drain" if tty else "pipe_nonce_stdin_exit_drain","status":"PASS","effect_sha256":digest(effect),"foreign_owner":"refused_without_effect"})
        if args.case == "graceful":
            close_pid=cwd/"owner-close-pid"
            live=f"printf '%s\\n' \"$$\" > {shlex.quote(str(close_pid))}; while IFS= read -r line; do :; done"
            tool_data(await call(client,"A","exec_command",{"cmd":live,"login":False,"environment_id":device,"yield_time_ms":0}))
            await until(close_pid.exists,"owner cleanup native PID absent");original=process_facts(int(close_pid.read_text()));assert original
            await client.rpc("close",owner="A")
            await asyncio.sleep(.25)
            assert same_process(original),"immutable baseline DELETE unexpectedly changed the source-derived legacy behavior"
            records.append({"scenario":"original_mcp_delete_retains_exec","status":"OBSERVED_LEGACY_LIMITATION","original":original,"host_per_chat_owner":"not available on raw legacy wire"})
            stopped = await old.finish(signal.SIGTERM)
            assert stopped=={"exit":0,"forced_kill":False},"original Gateway graceful shutdown failed"
            await until(lambda:not same_process(original),"original Gateway SIGTERM cleanup did not terminate exact native process")
            assert host.process.returncode is None and same_process(native),"Gateway disconnect stopped or restarted native executor"
            await client.finish(signal.SIGKILL)
            result=await host.finish(signal.SIGTERM)
            assert result=={"exit":0,"forced_kill":False},"Rust foreground failed real graceful cleanup"
            assert not same_process(native) and not owned_processes(cwd),"owned native executor survived explicit Host shutdown"
            records.append({"scenario":"original_gateway_sigterm_raw_terminate_then_host_cleanup","status":"PASS","original":original,"forced_kill":False})
        else:
            drop_pid=cwd/"disconnect-pid";drop_effect=cwd/"disconnect-once";nonce=secrets.token_hex(24)
            live=f"printf '%s\\n' \"$$\" > {shlex.quote(str(drop_pid))}; printf '%s\\n' {shlex.quote(nonce)} >> {shlex.quote(str(drop_effect))}; while IFS= read -r line; do :; done"
            tool_data(await call(client,"B","exec_command",{"cmd":live,"login":False,"environment_id":device,"yield_time_ms":0}))
            await until(drop_effect.exists,"disconnect fixture native effect absent");assert drop_effect.read_bytes()==(nonce+"\n").encode()
            live_before=process_facts(int(drop_pid.read_text()));assert live_before
            await old.finish(signal.SIGKILL);await client.finish(signal.SIGKILL)
            await asyncio.sleep(.3)
            assert host.process.returncode is None and same_process(native),"network loss restarted/stopped native executor"
            assert same_process(live_before),"network loss silently claimed owner-end cleanup"
            assert drop_effect.read_bytes()==(nonce+"\n").encode(),"network loss replayed native start"
            result=await host.finish(signal.SIGTERM)
            assert result=={"exit":0,"forced_kill":False},"Rust foreground did not complete real graceful cleanup"
            assert not same_process(native) and not same_process(live_before),"owned executor/process survived foreground cleanup"
            assert not owned_processes(cwd),"owned native cwd residual processes"
            records.append({"scenario":"real_network_disconnect_retains_executor_then_cli_sigterm_cleanup","status":"PASS","native_before":native,"process_before":live_before,"forced_kill":False})
        assert all(digest(root/name)==sha for name,sha in preserved.items()),"original private profile bytes changed"
        assert inventory(legacy.parent)==json.loads((args.prepared/"legacy-input-inventory.json").read_text()),"legacy source/dependency bytes changed"
        outcome["status"]="PASS";outcome["preserved_private_hashes"]=preserved
    except Exception as error:
        outcome["failure_type"]=type(error).__name__
        outcome["failure_reason"]=str(error)
        raise
    finally:
        cleanup=[]
        for child in reversed(children):
            if child.process.returncode is None:cleanup.append(await child.finish())
        outcome["harness_final_cleanup"]=cleanup
        outcome["timed_process_observations"]={child.name:child.observations for child in children}
        outcome["observer_min_process_birth"]=OBSERVER_BIRTH
        outcome["observer_scope"]="processes created during this owned harness; exact original PID/birth checks are strict"
        try:
            outcome["final_owned_native_processes"]=owned_processes(cwd)
            outcome["final_owned_processes"]=owned_processes(root)
            if outcome["final_owned_processes"] or any(item["forced_kill"] for item in cleanup):outcome["status"]="FAIL"
        except Exception as observation_error:
            outcome["status"]="FAIL"
            outcome["final_observer"]="UNKNOWN"
            outcome["final_observer_error"]=type(observation_error).__name__
        outcome["elapsed_observer_monotonic"]=time.monotonic()
        (root/"receipt.json").write_text(json.dumps(outcome,indent=2)+"\n")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ["prepared","styx","signed-host","publisher-key","evidence"]:parser.add_argument("--"+name,required=True,type=Path)
    parser.add_argument("--case",required=True,choices=["graceful","disconnect"])
    parser.add_argument("--probe-only",action="store_true")
    parser.add_argument("--tls-style",choices=["legacy-selfsigned","standard-chain"],default="legacy-selfsigned")
    args=parser.parse_args()
    args.styx=args.styx.resolve(strict=True);args.prepared=args.prepared.resolve(strict=True)
    asyncio.run(journey(args))
if __name__=="__main__":main()
