import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {resolveWindowsDesktopSession,runWindowsDesktopLifecycle} from '../windows-session.mjs';
const live={schema:1,status:'available',sessionId:1,interactive:true,windowStation:'WinSta0',inputDesktop:'Default'};
test('Windows desktop requires a pinned helper and actual nonzero interactive Default desktop',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-session-probe-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const binary=path.join(dir,'StyxSessionProbe.exe');fs.writeFileSync(binary,'probe fixture');
 const probe={binary,sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex')};let calls=0;
 const options=value=>({platform:'win32',run(_file,args,opts){calls++;assert.equal(_file,binary);assert.deepEqual(args,[]);assert.deepEqual(Object.keys(opts.env).filter(key=>!['SystemRoot','WINDIR'].includes(key)),[]);assert.equal(opts.timeout,1500);return JSON.stringify(value);}});
 assert.equal((await resolveWindowsDesktopSession(probe,options(live))).available,true);
 for(const patch of [{sessionId:0},{interactive:false},{inputDesktop:'Winlogon'},{windowStation:'Service-0x0'},{status:'session_unavailable'}])assert.equal((await resolveWindowsDesktopSession(probe,options({...live,...patch}))).available,false);
 assert.equal((await resolveWindowsDesktopSession(null,options(live))).reason,'windows_session_probe_missing');
 fs.appendFileSync(binary,'tamper');const before=calls;assert.equal((await resolveWindowsDesktopSession(probe,options(live))).reason,'windows_session_probe_changed');assert.equal(calls,before);
});
test('Windows session lifecycle drains locked Computer then reconnects without replay or other-lane ownership',async()=>{
 const abort=new AbortController(),events=[],statuses=[];let state={available:false,reason:'windows_interactive_desktop_unavailable'},starts=0;
 const until=async predicate=>{const end=Date.now()+2000;while(!predicate()&&Date.now()<end)await new Promise(r=>setTimeout(r,5));assert(predicate());};
 const task=runWindowsDesktopLifecycle({signal:abort.signal,pollMs:10,resolveSession:async()=>state,onStatus:(s,m)=>statuses.push([s,m?.reason]),onReady:()=>events.push('ready'),connect:({signal,onReady})=>{starts++;events.push('start');onReady({});return new Promise(resolve=>{const finish=()=>{events.push('stop');resolve();};if(signal.aborted)finish();else signal.addEventListener('abort',finish,{once:true});});}});
 await new Promise(r=>setTimeout(r,25));assert.equal(starts,0);state={available:true,key:'1'};await until(()=>events.includes('ready'));
 state={available:false,reason:'windows_interactive_desktop_unavailable'};await until(()=>events.includes('stop'));assert.equal(starts,1);
 state={available:true,key:'1'};await until(()=>starts===2);abort.abort();await task;
 assert.deepEqual(events,['start','ready','stop','start','ready','stop']);assert(statuses.some(([s,r])=>s==='unavailable'&&r==='windows_interactive_desktop_unavailable'));
});
test('a lock during connection prevents a stale ready notification',async()=>{
 const abort=new AbortController();let state={available:true,key:'1'},ready=0;
 const task=runWindowsDesktopLifecycle({signal:abort.signal,pollMs:10,resolveSession:()=>state,onReady:()=>ready++,connect:async({signal,onReady})=>{state={available:false,reason:'windows_interactive_desktop_unavailable'};await onReady({});assert(signal.aborted);abort.abort();}});
 await task;assert.equal(ready,0);
});
test('Windows native helper reports the caller session; missing probe never starts a Computer connector',{skip:process.platform!=='win32'||!process.env.STYX_TEST_WINDOWS_SESSION_PROBE},async()=>{
 const binary=process.env.STYX_TEST_WINDOWS_SESSION_PROBE,probe={binary,sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex')};
 const value=await resolveWindowsDesktopSession(probe);
 assert.equal(value.available,process.env.STYX_TEST_WINDOWS_SESSION_AVAILABLE==='true');
 if(!value.available)assert.equal(value.reason,'windows_interactive_desktop_unavailable');
 const {runComputerConnectors}=await import('../computer.mjs');
 const statuses=[];
 // No token or executable exists: reaching either would fail. The session gate
 // must return before authenticating/connecting/spawning the Computer lane.
 await runComputerConnectors({host_id:'session-gate',gateway_ws_url:'ws://127.0.0.1/',token_file:path.resolve('nonexistent-token'),exec:{binary:path.resolve('nonexistent-exec.exe'),cwd:process.cwd()},computer:{enabled:true,binary:path.resolve('nonexistent-cua.exe')}},{once:true,onReady:()=>assert.fail('missing probe became ready'),onStatus:(s,m)=>statuses.push([s,m.reason])});
 assert.deepEqual(statuses,[['unavailable','windows_session_probe_missing']]);
});
test('Windows signed launcher replaces mutable probe paths with the active signed generation',{skip:process.platform!=='win32'},async t=>{
 const {activeHostConfig}=await import('../launch.mjs');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-probe-pin-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));fs.mkdirSync(path.join(root,'bin'));
 for(const name of ['codex.exe','cua-driver.exe','StyxSessionProbe.exe'])fs.writeFileSync(path.join(root,'bin',name),'fixture');
 const pin=createHash('sha256').update('fixture').digest('hex'),raw={exec:{},computer:{enabled:true,sessionProbe:{binary:'untrusted',sha256:'0'.repeat(64)}}};
 fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify({files:[{path:'bin/StyxSessionProbe.exe',sha256:pin,executable:true}]}));
 assert.deepEqual(activeHostConfig(raw,root).computer.sessionProbe,{binary:path.join(root,'bin','StyxSessionProbe.exe'),sha256:pin});
 fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify({files:[]}));
 const legacy=activeHostConfig(raw,root);assert.equal(legacy.computer.enabled,true);assert.equal(legacy.computer.sessionProbe,null);
});
