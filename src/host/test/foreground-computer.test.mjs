import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {WebSocketServer} from 'ws';
import {connectComputerOnce} from '../computer.mjs';
import {runWindowsDesktopLifecycle} from '../windows-session.mjs';
const wait=ms=>new Promise(r=>setTimeout(r,ms));
test('computer abort waits for its ignoring-TERM child to exit and leaves unrelated processes alive',{skip:process.platform!=='linux',timeout:10000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-owned-computer-')),binary=path.join(root,'cua-fixture'),pidFile=path.join(root,'pid'),token=path.join(root,'token');
 fs.writeFileSync(binary,'#!'+process.execPath+'\n'+`import fs from 'node:fs';process.on('SIGTERM',()=>{});fs.writeFileSync(process.env.STYX_TEST_PID,String(process.pid));setInterval(()=>{},1000);\n`,{mode:0o700});fs.writeFileSync(token,'a'.repeat(48),{mode:0o600});
 const unrelated=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'}),unrelatedClosed=once(unrelated,'close');
 const server=new WebSocketServer({host:'127.0.0.1',port:0});await once(server,'listening');
 t.after(async()=>{unrelated.kill('SIGTERM');await unrelatedClosed;for(const client of server.clients)client.terminate();await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true})});
 const abort=new AbortController();let ready;
 const connected=new Promise(r=>{ready=r});
 const running=connectComputerOnce({host_id:'fixture',gateway_ws_url:'ws://127.0.0.1:'+server.address().port,token_file:token,exec:{binary:process.execPath,cwd:root},computer:{enabled:true,binary,env:{STYX_TEST_PID:pidFile}}},{signal:abort.signal,onReady:ready});
 await connected;for(let i=0;!fs.existsSync(pidFile)&&i<100;i++)await wait(20);assert.equal(fs.existsSync(pidFile),true);const pid=Number(fs.readFileSync(pidFile));assert.doesNotThrow(()=>process.kill(pid,0));
 abort.abort();await running;assert.throws(()=>process.kill(pid,0),e=>e.code==='ESRCH');assert.doesNotThrow(()=>process.kill(unrelated.pid,0));
});

test('closed Computer socket cannot publish late ready after an asynchronous desktop probe',{skip:process.platform!=='linux',timeout:5000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ready-race-')),binary=path.join(root,'cua-fixture'),token=path.join(root,'token');
 fs.writeFileSync(binary,'#!'+process.execPath+'\nsetInterval(()=>{},1000);\n',{mode:0o700});fs.writeFileSync(token,'a'.repeat(48),{mode:0o600});
 const server=new WebSocketServer({host:'127.0.0.1',port:0});await once(server,'listening');
 const abort=new AbortController();let releaseProbe,probeStarted,connectionClosed,ready=0,calls=0;
 const probing=new Promise(r=>probeStarted=r),closed=new Promise(r=>connectionClosed=r),pending=new Promise(r=>releaseProbe=r),session={available:true,key:'windows:1'};
 const running=runWindowsDesktopLifecycle({signal:abort.signal,pollMs:60000,resolveSession:()=>{if(++calls===1)return session;probeStarted();return pending},onReady:()=>ready++,
  connect:async({signal,onReady})=>{await connectComputerOnce({host_id:'fixture',gateway_ws_url:'ws://127.0.0.1:'+server.address().port,token_file:token,exec:{binary:process.execPath,cwd:root},computer:{enabled:true,binary}},{signal,onReady});connectionClosed();await new Promise(resolve=>{if(signal.aborted)resolve();else signal.addEventListener('abort',resolve,{once:true})})}});
 t.after(async()=>{abort.abort();releaseProbe(session);await running;for(const client of server.clients)client.terminate();await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true})});
 await probing;for(const client of server.clients)client.terminate();await closed;releaseProbe(session);await wait(20);assert.equal(ready,0);
});
