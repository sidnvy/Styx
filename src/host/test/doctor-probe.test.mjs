import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {doctor,probeRuntimeVersion} from '../doctor.mjs';

const unix=process.platform!=='win32';
function fixture(t,body){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-doctor-probe-'));
 fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 // A real process with no child/grandchild: cancellation can assert its PID died.
 const file=path.join(root,'version-probe');
 fs.writeFileSync(file,'#!'+process.execPath+'\n'+body+'\n',{mode:0o700});
 return {root,file};
}
test('Doctor accepts a one-shot real component version after the old four-second deadline',{skip:!unix,timeout:10000},async t=>{
 const f=fixture(t,'setTimeout(()=>console.log("codex-cli 0.163.0"),4200);');
 const token=path.join(f.root,'token');fs.writeFileSync(token,'a'.repeat(48),{mode:0o600});
 const result=await doctor({host_id:'owned-doctor-delay',gateway_ws_url:'wss://example.invalid',token_file:token,exec:{binary:f.file,cwd:f.root}});
 assert.equal(result.status,'ready_for_exec');assert.equal(result.checks.executor_version,'codex-cli 0.163.0');
 const p=result.checks.executor_probe;assert.equal(p.status,'ok');assert.equal(p.timeoutMs,30000);assert(p.elapsedMs>=4000);assert.equal(p.exitCode,0);assert.equal(p.signal,null);
});
test('a timed-out version child is dead before the probe returns and arbitrary stderr is not retained',{skip:!unix,timeout:5000},async t=>{
 const f=fixture(t,'const fs=require("node:fs");fs.writeFileSync(__filename+".pid",String(process.pid));console.error("private-env-value");process.on("SIGTERM",()=>{});setInterval(()=>{},1000);');
 const result=await probeRuntimeVersion(f.file,{timeoutMs:500});
 assert.equal(result.probe.status,'timeout');assert.equal(result.probe.signal,'SIGKILL');assert.equal(result.version,null);
 const pid=Number(fs.readFileSync(f.file+'.pid','utf8'));assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});
 assert(!JSON.stringify(result).includes('private-env-value'));assert(!JSON.stringify(result).includes(f.root));
});
test('nonzero exit retains bounded failure evidence without output or path disclosure',{skip:!unix},async t=>{
 const f=fixture(t,'console.error("secret-stderr-value");console.log("secret-stdout-value");process.exitCode=7;');
 const result=await probeRuntimeVersion(f.file);assert.equal(result.probe.status,'exit_nonzero');assert.equal(result.probe.exitCode,7);assert.equal(result.version,null);assert.equal(result.probe.timeoutMs,30000);
 assert(!JSON.stringify(result).includes('secret'));assert(!JSON.stringify(result).includes(f.root));
});
test('a missing component has a whitelisted OS error and no arbitrary message',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-doctor-missing-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const result=await probeRuntimeVersion(path.join(root,'missing'));
 assert.equal(result.probe.status,'binary_unavailable');assert.equal(result.probe.errorCode,'ENOENT');assert.equal(result.version,null);assert(!JSON.stringify(result).includes(root));
});
