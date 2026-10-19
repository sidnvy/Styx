import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {EventEmitter,once} from 'node:events';
import {spawn} from 'node:child_process';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {createDeployment} from '../core.mjs';
import {configureTunnel,TunnelRuntime} from '../tunnel-runtime.mjs';
const key='sk-test_'+ 'a'.repeat(40),token='b'.repeat(64),tunnelId='tunnel_12345678';
test('first-open status, health, resume and stop before deployment are read-only and safe',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-fresh-tunnel-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const stateDir=path.join(root,'not-created'),runtime=new TunnelRuntime({stateDir,binary:process.execPath,sha256:'a'.repeat(64)});
 assert.equal(runtime.status().status,'not_configured');assert.equal((await runtime.health()).transport,'not_running');assert.equal((await runtime.resume()).status,'not_configured');assert.equal((await runtime.stop()).status,'not_configured');assert.equal(fs.existsSync(stateDir),false);
});
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx tunnel '));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));fs.chmodSync(root,0o700);
 const stateDir=path.join(root,'state'),cfg=path.join(root,'input.json');
 fs.writeFileSync(cfg,JSON.stringify({schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:8795',openssl:process.execPath},host:{bundle:root,publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'host'),label:'Test',computer:false}}),{mode:0o600});
 createDeployment(cfg,{stateDir});const gateway=path.join(stateDir,'gateway');fs.mkdirSync(gateway,{mode:0o700});
 const model=path.join(gateway,'model.token'),cert=path.join(gateway,'certificate.pem');fs.writeFileSync(model,token,{mode:0o600});fs.writeFileSync(cert,'fixture certificate',{mode:0o600});
 fs.writeFileSync(path.join(gateway,'runtime.json'),JSON.stringify({schema:1,url:'https://127.0.0.1:8795',listenHost:'127.0.0.1',modelTokenFile:model,tlsCertificateFile:cert}),{mode:0o600});
 const binary=path.join(root,'client');fs.writeFileSync(binary,'fixture',{mode:0o700});const sha256=createHash('sha256').update('fixture').digest('hex');
 const calls=[],children=[];const spawnProcess=(...args)=>{calls.push(args);const child=new EventEmitter();child.kill=signal=>{queueMicrotask(()=>child.emit('exit',null,signal));return true;};children.push(child);queueMicrotask(()=>child.emit('spawn'));return child;};
 return {root,stateDir,binary,sha256,spawnProcess,calls,children,model};
}
test('status and stopping an unused tunnel do not create a tunnel directory in an existing deployment',async t=>{
 const f=fixture(t),runtime=new TunnelRuntime(f);assert.equal(runtime.status().status,'not_configured');await runtime.stop();assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel')),false);
});
test('private configuration never returns credentials and supports atomic credential replacement',t=>{
 const f=fixture(t);const result=configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});
 assert.equal(result.status,'configured');assert.equal(JSON.stringify(result).includes(key),false);
 const dir=path.join(f.stateDir,'tunnel');const old=JSON.parse(fs.readFileSync(path.join(dir,'connection.json')));
 configureTunnel(f.stateDir,{tunnelId,apiKey:key+'x',authorize:true});assert.equal(fs.existsSync(path.join(dir,old.keyFile)),false);
 if(process.platform!=='win32')for(const name of fs.readdirSync(dir))assert.equal(fs.statSync(path.join(dir,name)).mode&0o077,0);
});
test('child gets fixed server-derived arguments and file references, never raw secrets or inherited env',async t=>{
 const f=fixture(t);configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});const runtime=new TunnelRuntime(f);
 const result=await runtime.start({authorize:true});assert.equal(result.status,'running');assert.equal(result.accountAcceptance,'NOT RUN');
 const [binary,runnerArgs,opts]=f.calls[0],args=JSON.parse(runnerArgs[3]);assert.equal(binary,process.execPath);assert.equal(runnerArgs[1],f.binary);assert.ok(args.includes('https://127.0.0.1:8795/mcp'));assert.ok(args.includes('--mcp.discovery-extra-headers'));
 assert.equal(JSON.stringify(f.calls).includes(key),false);assert.equal(JSON.stringify(f.calls).includes(token),false);assert.deepEqual(Object.keys(opts.env).sort(),['HOME','PATH','XDG_CONFIG_HOME']);assert.deepEqual(opts.stdio,['pipe','ignore','ignore']);
 assert.equal(fs.readFileSync(path.join(f.stateDir,'tunnel','gateway-header'),'utf8'),'Bearer '+token);
 assert.throws(()=>configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true}),/running_or_interrupted/);
 await runtime.start({authorize:true});assert.equal(f.calls.length,1);assert.equal((await runtime.stop()).status,'configured');
});
test('integrity mismatch, foreign token references, missing approval and malformed keys fail before process launch',async t=>{
 const f=fixture(t);assert.throws(()=>configureTunnel(f.stateDir,{tunnelId,apiKey:key}),/authorization/);
 for(const apiKey of ['sk-bad\nvalue',key+'\n',null])assert.throws(()=>configureTunnel(f.stateDir,{tunnelId,apiKey,authorize:true}),/runtime_key/);
 configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});await assert.rejects(new TunnelRuntime({...f,sha256:'0'.repeat(64)}).start({authorize:true}),/integrity/);
 await assert.rejects(new TunnelRuntime(f).start(),/authorization/);
 const file=path.join(f.stateDir,'gateway','runtime.json'),raw=JSON.parse(fs.readFileSync(file));raw.modelTokenFile=path.join(f.root,'unrelated');fs.writeFileSync(file,JSON.stringify(raw));
 await assert.rejects(new TunnelRuntime(f).start({authorize:true}),/owned_loopback/);assert.equal(f.calls.length,0);
});
test('persisted stale owner lock is never treated as a killable process or silently replayed',async t=>{
 const f=fixture(t);configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});fs.writeFileSync(path.join(f.stateDir,'tunnel','owner.lock'),'12345',{mode:0o600});
 const runtime=new TunnelRuntime(f);assert.equal(runtime.status().status,'interrupted');assert.equal((await runtime.stop()).status,'interrupted');await assert.rejects(runtime.start({authorize:true}),/running_or_interrupted/);assert.equal(f.calls.length,0);
});
test('child startup failure releases only its lock without leaking native error details',async t=>{
 const f=fixture(t);configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});f.spawnProcess=()=>{const child=new EventEmitter();queueMicrotask(()=>child.emit('error',Error(key)));return child;};
 const runtime=new TunnelRuntime(f);await assert.rejects(runtime.start({authorize:true}),/^Error: tunnel_client_start_failed$/);assert.equal(runtime.status().status,'configured');
});

test('actual supervisor terminates its owned child when parent lifetime pipe closes',{timeout:10000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-tunnel-lifetime-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const lockToken='a'.repeat(48);fs.writeFileSync(path.join(root,'owner.lock'),lockToken,{mode:0o600});
 const pidFile=path.join(root,'pid'),pin=createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex');
 const runner=spawn(process.execPath,[fileURLToPath(new URL('../tunnel-runner.mjs',import.meta.url)),process.execPath,pin,JSON.stringify(['-e',"require('fs').writeFileSync(process.argv[1],String(process.pid));setInterval(()=>{},1000)",pidFile]),lockToken],{cwd:root,stdio:['pipe','ignore','ignore']});
 t.after(()=>runner.kill('SIGKILL'));
 const exit=once(runner,'exit');for(let n=0;n<100&&!fs.existsSync(pidFile);n++)await new Promise(r=>setTimeout(r,25));
 assert.ok(fs.existsSync(pidFile),'owned child started');const pid=Number(fs.readFileSync(pidFile,'utf8'));
 runner.stdin.end();assert.equal((await exit)[0],0);assert.throws(()=>process.kill(pid,0),/ESRCH/);assert.equal(fs.existsSync(path.join(root,'owner.lock')),false);
});

test('resume requires saved opt-in and health checks only owned fixed loopback endpoints',{timeout:10000},async t=>{
 const f=fixture(t);configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});const runtime=new TunnelRuntime(f);
 await runtime.resume();assert.equal(f.calls.length,0);
 configureTunnel(f.stateDir,{tunnelId,apiKey:key,autoStart:true,authorize:true});await runtime.resume();assert.equal(f.calls.length,1);
 const requested=[],server=http.createServer((req,res)=>{requested.push(req.url);res.writeHead(200).end('ready');});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());
 const healthFile=path.join(f.stateDir,'tunnel','health.url');fs.writeFileSync(healthFile,'http://127.0.0.1:'+server.address().port+'/');
 assert.equal((await runtime.health()).transport,'ready');assert.deepEqual(requested.sort(),['/healthz','/readyz']);
 fs.writeFileSync(healthFile,'https://example.com/');assert.equal((await runtime.health()).transport,'unavailable');assert.equal(requested.length,2);
 await runtime.stop();assert.equal((await runtime.health()).transport,'not_running');
});

test('configuration holds cross-process owner lock while replacing credentials',t=>{
 const f=fixture(t);configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});
 const original=fs.renameSync;let inspected=false;
 fs.renameSync=(from,to)=>{
  if(to===path.join(f.stateDir,'tunnel','connection.json')){
   inspected=true;
   assert.throws(()=>configureTunnel(f.stateDir,{tunnelId,apiKey:key+'r',authorize:true}),/running_or_interrupted/);
  }
  return original(from,to);
 };
 try{configureTunnel(f.stateDir,{tunnelId,apiKey:key+'n',authorize:true})}finally{fs.renameSync=original}
 assert.equal(inspected,true);
 const dir=path.join(f.stateDir,'tunnel'),config=JSON.parse(fs.readFileSync(path.join(dir,'connection.json')));
 assert.equal(fs.readFileSync(path.join(dir,config.keyFile),'utf8'),key+'n');
 assert.equal(fs.existsSync(path.join(dir,'owner.lock')),false);
});

test('startup rereads the credential selected before it acquires ownership',async t=>{
 const f=fixture(t);configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true});
 const original=fs.openSync;let rotated=false;
 fs.openSync=(file,...args)=>{
  if(file===path.join(f.stateDir,'tunnel','owner.lock')&&!rotated){
   rotated=true;configureTunnel(f.stateDir,{tunnelId,apiKey:key+'r',authorize:true});
  }
  return original(file,...args);
 };
 const runtime=new TunnelRuntime(f);
 try{await runtime.start({authorize:true})}finally{fs.openSync=original}
 try{
  assert.equal(rotated,true);
  const args=JSON.parse(f.calls[0][1][3]);
  const keyFile=args[args.indexOf('--control-plane.api-key')+1].slice(5);
  assert.equal(fs.readFileSync(keyFile,'utf8'),key+'r');
 }finally{await runtime.stop()}
});

test('unexpected exit retries after login delay, explicit stop cancels recovery',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture(t);configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true,autoStart:true});
 const runtime=new TunnelRuntime(f);await runtime.resume();
 f.children[0].emit('exit',1,null);assert.equal(runtime.status().status,'configured');
 t.mock.timers.tick(14999);assert.equal(f.calls.length,1);
 t.mock.timers.tick(1);await new Promise(resolve=>setImmediate(resolve));assert.equal(f.calls.length,2);assert.equal(runtime.status().status,'running');
 await runtime.stop();t.mock.timers.tick(30000);await new Promise(resolve=>setImmediate(resolve));assert.equal(f.calls.length,2);
});
test('temporary startup failure retries, then stop suppresses the next attempt',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture(t),spawnGood=f.spawnProcess;let attempts=0;
 f.spawnProcess=(...args)=>{attempts++;if(attempts>1)return spawnGood(...args);const child=new EventEmitter();queueMicrotask(()=>child.emit('error',Error('offline')));return child;};
 configureTunnel(f.stateDir,{tunnelId,apiKey:key,authorize:true,autoStart:true});const runtime=new TunnelRuntime(f);
 await assert.rejects(runtime.resume(),/start_failed/);t.mock.timers.tick(15000);await new Promise(resolve=>setImmediate(resolve));assert.equal(runtime.status().status,'running');
 await runtime.stop();t.mock.timers.tick(30000);assert.equal(attempts,2);
});
