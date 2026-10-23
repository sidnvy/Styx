// Contract fixtures exercise CLI plumbing and owned-process cleanup, not an
// official tunnel-client, OpenAI account, cloud discovery or native acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {EventEmitter,once} from 'node:events';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createDeployment} from '../core.mjs';
import {main} from '../cli.mjs';
import {TunnelRuntime} from '../tunnel-runtime.mjs';
import {configureCliTunnel,readCliTunnel,runCliTunnel} from '../cli-tunnel.mjs';
const tunnelId='tunnel_'+ 'a'.repeat(32),key='sk-contract_'+ 'b'.repeat(40),model='c'.repeat(64);
const cli=fileURLToPath(new URL('../cli.mjs',import.meta.url));
const write=(file,value)=>fs.writeFileSync(file,JSON.stringify(value)+'\n',{mode:0o600});
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-cli-tunnel-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const stateDir=path.join(root,'state'),input=path.join(root,'deployment-input.json');
 write(input,{schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:8795',openssl:process.execPath},host:{bundle:root,publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'host'),label:'Contract fixture',computer:false}});
 createDeployment(input,{stateDir});const gateway=path.join(stateDir,'gateway');fs.mkdirSync(gateway,{mode:0o700});
 const modelFile=path.join(gateway,'model.token'),cert=path.join(gateway,'certificate.pem');
 fs.writeFileSync(modelFile,model,{mode:0o600});fs.writeFileSync(cert,'contract fixture certificate',{mode:0o600});
 write(path.join(gateway,'runtime.json'),{schema:1,url:'https://127.0.0.1:8795',listenHost:'127.0.0.1',modelTokenFile:modelFile,tlsCertificateFile:cert});
 const connectionFile=path.join(root,'connection.json');write(connectionFile,{tunnelId,apiKey:key,autoStart:false});
 const binary=path.join(root,'client-fixture');fs.writeFileSync(binary,'fixture bytes',{mode:0o700});
 const clientFile=path.join(root,'client.json');write(clientFile,{binary,sha256:hash(binary)});
 return {root,stateDir,gateway,modelFile,connectionFile,clientFile,binary};
}
function fakeSpawn(calls,{signals,signal,fail=false}={}){
 return (...args)=>{
  calls.push(args);const child=new EventEmitter();child.stdin={end(){}};
  child.kill=value=>{calls.push({ownedChildSignal:value});queueMicrotask(()=>child.emit('exit',null,value));return true};
  if(signals&&signal)signals.emit(signal);
  queueMicrotask(()=>child.emit(fail?'error':'spawn',...(fail?[Error(key)]:[])));
  return child;
 };
}
test('Tunnel commands are documented and require the exact authorization/file argument shape',async()=>{
 const help=await main(['help']);
 for(const name of ['tunnel-configure STATE PRIVATE_CONNECTION_JSON --authorize','tunnel-status STATE','tunnel-run STATE --authorize','tunnel-run STATE PRIVATE_CLIENT_JSON --authorize','device-ingress-status STATE'])assert.ok(help.commands.includes(name));
 for(const args of [['tunnel-configure','/unused','/unused.json'],['tunnel-run','/unused','/unused.json'],['tunnel-configure','/unused',key,'--authorize','--extra'],['tunnel-status','/unused','--authorize']])await assert.rejects(main(args),/usage_/);
});
test('configuration uses the existing private schema and exposes no credentials or auto-start effect',async t=>{
 const f=fixture(t),before=fs.readFileSync(path.join(f.stateDir,'deployment.json'));
 const result=await main(['tunnel-configure',f.stateDir,f.connectionFile,'--authorize']);
 assert.equal(result.status,'configured');assert.equal(result.transport,'not_observed');assert.equal(result.accountAcceptance,'NOT RUN');
 assert.doesNotMatch(JSON.stringify(result),new RegExp(key+'|'+model+'|keyFile|apiKey|modelCredential'));
 const dir=path.join(f.stateDir,'tunnel'),config=JSON.parse(fs.readFileSync(path.join(dir,'connection.json')));
 assert.deepEqual(Object.keys(config).sort(),['autoStart','keyFile','schema','tunnelId']);
 assert.equal(fs.readFileSync(path.join(dir,config.keyFile),'utf8'),key);
 assert.equal(fs.existsSync(path.join(dir,'owner.lock')),false);
 assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'deployment.json')),before);
 assert.equal(fs.readFileSync(f.modelFile,'utf8'),model);
});
test('private input permissions, symlinks, extra fields and invalid descriptors fail before configuration/start',async t=>{
 const f=fixture(t);
 write(f.connectionFile,{tunnelId,apiKey:key,authorize:true});
 assert.throws(()=>configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true}),/invalid_tunnel_cli_input/);
 assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel')),false);
 write(f.connectionFile,{tunnelId,apiKey:key});
 if(process.platform!=='win32'){
  fs.chmodSync(f.connectionFile,0o644);
  assert.throws(()=>configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true}),/private_file_permissions/);
  fs.chmodSync(f.connectionFile,0o600);
  const link=path.join(f.root,'connection-link.json');fs.symlinkSync(f.connectionFile,link);
  assert.throws(()=>configureCliTunnel(f.stateDir,link,{authorize:true}),/not_regular/);
 }
 fs.writeFileSync(f.connectionFile,'{"apiKey":"'+key+'",');
 assert.throws(()=>configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true}),/^Error: invalid_tunnel_cli_json$/);
 for(const descriptor of [{binary:f.binary,sha256:hash(f.binary),args:[key]},{binary:'relative-client',sha256:hash(f.binary)},{binary:f.binary,sha256:'bad'}]){
  write(f.clientFile,descriptor);
  await assert.rejects(runCliTunnel(f.stateDir,f.clientFile,{authorize:true}),/invalid_tunnel_cli_input|pinned_tunnel_cli_client_required/);
 }
 assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel')),false);
});
test('read-only status neither creates state nor claims another owner lock is live or stale',async t=>{
 const f=fixture(t),missing=path.join(f.root,'missing');
 assert.equal(readCliTunnel(missing).status,'not_configured');assert.equal(fs.existsSync(missing),false);
 assert.equal(readCliTunnel(f.stateDir).status,'not_configured');assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel')),false);
 configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true});
 const lock=path.join(f.stateDir,'tunnel','owner.lock');fs.writeFileSync(lock,'foreign-unobserved-lock',{mode:0o600});
 const value=await main(['tunnel-status',f.stateDir]);
 assert.equal(value.status,'owner_unobserved');assert.equal(value.ownership,'not_observed');assert.equal(value.transport,'not_observed');
 assert.equal(fs.readFileSync(lock,'utf8'),'foreign-unobserved-lock');
 assert.throws(()=>configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true}),/running_or_interrupted/);
 const calls=[];
 await assert.rejects(runCliTunnel(f.stateDir,f.clientFile,{authorize:true},{onStarted(){},createRuntime:options=>new TunnelRuntime({...options,spawnProcess:fakeSpawn(calls)})}),/running_or_interrupted/);
 assert.equal(calls.length,0);assert.equal(fs.readFileSync(lock,'utf8'),'foreign-unobserved-lock');
});
test('foreground owner passes only pinned runtime arguments, then cleans up on either signal',async t=>{
 for(const signal of ['SIGINT','SIGTERM']){
  const f=fixture(t),signals=new EventEmitter(),calls=[];configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true});
  const value=await runCliTunnel(f.stateDir,f.clientFile,{authorize:true},{signals,
   createRuntime:options=>new TunnelRuntime({...options,spawnProcess:fakeSpawn(calls)}),
   onStarted:status=>{assert.equal(status.status,'running');assert.equal(status.ownership,'current_process');assert.equal(status.transport,'not_observed');signals.emit(signal);}});
  assert.equal(value.status,'stopped');assert.equal(value.serviceMutation,'NOT RUN');
  assert.equal(signals.listenerCount('SIGINT')+signals.listenerCount('SIGTERM'),0);
  assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel','owner.lock')),false);
  const spawned=calls.filter(Array.isArray);assert.equal(spawned.length,1);
  assert.equal(spawned[0][1][1],f.binary);assert.equal(spawned[0][1][2],hash(f.binary));
  const args=JSON.parse(spawned[0][1][3]);assert.ok(args.includes('--mcp.discovery-extra-headers'));
  assert.equal(JSON.stringify(spawned).includes(key),false);assert.equal(JSON.stringify(spawned).includes(model),false);
  assert.deepEqual(Object.keys(spawned[0][2].env).sort(),['HOME','PATH','XDG_CONFIG_HOME']);
  assert.deepEqual(calls.filter(x=>x.ownedChildSignal).map(x=>x.ownedChildSignal),['SIGTERM']);
 }
});
test('signal during startup still stops the owned child after start resolves',async t=>{
 const f=fixture(t),signals=new EventEmitter(),calls=[];configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true});
 const result=await runCliTunnel(f.stateDir,f.clientFile,{authorize:true},{signals,onStarted(){},createRuntime:options=>new TunnelRuntime({...options,spawnProcess:fakeSpawn(calls,{signals,signal:'SIGTERM'})})});
 assert.equal(result.status,'stopped');assert.equal(calls.filter(Array.isArray).length,1);
 assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel','owner.lock')),false);
});
test('failed integrity/startup cancels Runtime recovery and never returns raw executor errors',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture(t),calls=[];configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true});
 write(f.clientFile,{binary:f.binary,sha256:'0'.repeat(64)});
 await assert.rejects(runCliTunnel(f.stateDir,f.clientFile,{authorize:true},{onStarted(){}}),/tunnel_client_integrity_failed/);
 write(f.clientFile,{binary:f.binary,sha256:hash(f.binary)});
 await assert.rejects(runCliTunnel(f.stateDir,f.clientFile,{authorize:true},{onStarted(){},createRuntime:options=>new TunnelRuntime({...options,spawnProcess:fakeSpawn(calls,{fail:true})})}),/^Error: tunnel_client_start_failed$/);
 t.mock.timers.tick(30000);await new Promise(resolve=>setImmediate(resolve));
 assert.equal(calls.filter(Array.isArray).length,1);assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel','owner.lock')),false);
});
test('actual CLI lifetime signals clean its real supervisor/fixture process and suppress child secret output',{skip:process.platform==='win32',timeout:15000},async t=>{
 for(const signal of ['SIGINT','SIGTERM']){
  const f=fixture(t);configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true});
  // A local shell fixture, deliberately not an official/account-connected client.
  fs.writeFileSync(f.binary,'#!/bin/sh\nprintf "%s" "$$" > cli-fixture.pid\nprintf "%s" "'+key+'"\nprintf "%s" "'+model+'" >&2\ntrap "exit 0" TERM INT\nwhile :; do /bin/sleep 0.1; done\n',{mode:0o700});
  write(f.clientFile,{binary:f.binary,sha256:hash(f.binary)});
  const child=spawn(process.execPath,[cli,'tunnel-run',f.stateDir,f.clientFile,'--authorize'],{stdio:['ignore','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM')});
  const exit=once(child,'exit');let stdout='',stderr='';child.stdout.on('data',bytes=>stdout+=bytes);child.stderr.on('data',bytes=>stderr+=bytes);
  const pidFile=path.join(f.stateDir,'tunnel','cli-fixture.pid');
  for(let n=0;n<120&&!fs.existsSync(pidFile);n++)await new Promise(resolve=>setTimeout(resolve,25));
  assert.ok(fs.existsSync(pidFile),'real supervisor launched its owned fixture');const pid=Number(fs.readFileSync(pidFile));
  child.kill(signal);assert.deepEqual(await exit,[0,null]);
  assert.equal(JSON.parse(stdout).status,'stopped');assert.match(stderr,/foreground owner started/);
  assert.equal((stdout+stderr).includes(key),false);assert.equal((stdout+stderr).includes(model),false);
  assert.throws(()=>process.kill(pid,0),error=>error.code==='ESRCH');
  assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel','owner.lock')),false);
 }
});
test('CLI errors suppress secret-bearing malformed input without a stack or raw path error',t=>{
 const f=fixture(t);fs.writeFileSync(f.connectionFile,'{"apiKey":"'+key+'",');
 const result=spawnSync(process.execPath,[cli,'tunnel-configure',f.stateDir,f.connectionFile,'--authorize'],{encoding:'utf8'});
 assert.equal(result.status,2);assert.equal(result.stdout,'');assert.match(result.stderr,/Styx onboarding failed/);
 assert.equal(result.stderr.includes(key),false);assert.equal(result.stderr.includes('SyntaxError'),false);
});


async function packagedFixture(t){
 const f=fixture(t),install=path.join(f.root,'installed'),onboarding=path.join(install,'app','onboarding'),runtime=path.join(install,'runtime');
 fs.mkdirSync(onboarding,{recursive:true,mode:0o700});fs.mkdirSync(runtime,{mode:0o700});
 const moduleFile=path.join(onboarding,'cli-tunnel.mjs'),source=fileURLToPath(new URL('../cli-tunnel.mjs',import.meta.url));
 // Keep the production module body and import.meta.url derivation intact.
 // Only imports are redirected to existing dependencies for this layout fixture.
 const relocated=fs.readFileSync(source,'utf8')
  .replace("from '../host/private-storage.mjs'",'from '+JSON.stringify(new URL('../../host/private-storage.mjs',import.meta.url).href))
  .replace("from './tunnel-runtime.mjs'",'from '+JSON.stringify(new URL('../tunnel-runtime.mjs',import.meta.url).href));
 fs.writeFileSync(moduleFile,relocated,{mode:0o600});
 const cliFile=path.join(onboarding,'cli.mjs'),cliSource=fs.readFileSync(cli,'utf8')
  .replace("from '../host/private-storage.mjs'",'from '+JSON.stringify(new URL('../../host/private-storage.mjs',import.meta.url).href))
  .replace("from './core.mjs'",'from '+JSON.stringify(new URL('../core.mjs',import.meta.url).href))
  .replace("from './journey.mjs'",'from '+JSON.stringify(new URL('../journey.mjs',import.meta.url).href));
 fs.writeFileSync(cliFile,cliSource,{mode:0o600});
 const binary=path.join(runtime,'tunnel-client');fs.writeFileSync(binary,'packaged-client-contract-fixture',{mode:0o700});
 const manifest=path.join(runtime,'tunnel-client.json'),pin={schema:1,path:'tunnel-client',sha256:hash(binary),version:'0.0.17'};write(manifest,pin);
 return {...f,install,runtime,moduleFile,cliFile,binary,manifest,pin,api:await import(pathToFileURL(moduleFile).href)};
}
test('default manifest resolves only beside the installed module, with availability separate from live transport',async t=>{
 const f=await packagedFixture(t);
 const descriptor=f.api.packagedCliTunnelClient();assert.deepEqual(descriptor,{binary:f.binary,sha256:f.pin.sha256,version:'0.0.17'});
 const status=f.api.readCliTunnel(f.stateDir);assert.equal(status.status,'not_configured');assert.equal(status.transport,'not_observed');
 assert.deepEqual(status.packagedClient,{available:true,status:'available',version:'0.0.17'});
 configureCliTunnel(f.stateDir,f.connectionFile,{authorize:true});const signals=new EventEmitter(),calls=[];
 const result=await f.api.runCliTunnel(f.stateDir,undefined,{authorize:true},{signals,
  createRuntime:options=>new TunnelRuntime({...options,spawnProcess:fakeSpawn(calls)}),
  onStarted:()=>signals.emit('SIGTERM')});
 assert.equal(result.status,'stopped');const spawnCall=calls.find(Array.isArray);
 assert.equal(spawnCall[1][1],f.binary);assert.equal(spawnCall[1][2],f.pin.sha256);
 assert.equal(JSON.stringify(spawnCall).includes(key),false);
});
test('default manifest rejects path escapes, schema/field changes, bad pins and malformed version before runtime creation',async t=>{
 const f=await packagedFixture(t);
 for(const value of [
  {...f.pin,path:'../tunnel-client'}, {...f.pin,path:f.binary}, {...f.pin,path:'nested/tunnel-client'},
  {...f.pin,path:'tunnel-client.exe'}, {...f.pin,schema:2}, {...f.pin,sha256:'0'.repeat(64)},
  {...f.pin,sha256:'X'.repeat(64)}, {...f.pin,version:'not-a-version'}, {...f.pin,version:null},
  {...f.pin,args:[key]}, {...f.pin,env:{TOKEN:key}}
 ]){
  write(f.manifest,value);assert.throws(()=>f.api.packagedCliTunnelClient(),/^Error: packaged_tunnel_client_invalid$/);
  const status=f.api.readCliTunnel(f.stateDir);assert.equal(status.packagedClient.available,false);assert.equal(status.packagedClient.status,'invalid');
  await assert.rejects(f.api.runCliTunnel(f.stateDir,undefined,{authorize:true},{createRuntime(){assert.fail('invalid packaged client must not create a runtime')}}),/^Error: packaged_tunnel_client_invalid$/);
 }
 write(f.manifest,f.pin);fs.writeFileSync(f.binary,'tampered fixture');
 assert.throws(()=>f.api.packagedCliTunnelClient(),/packaged_tunnel_client_invalid/);
});
test('default manifest refuses symlinked runtime/manifest/executable and missing client without environment fallback',{skip:process.platform==='win32'},async t=>{
 const f=await packagedFixture(t),outside=path.join(f.root,'unrelated-client');fs.writeFileSync(outside,'unrelated',{mode:0o700});
 const saved=process.env.STYX_TUNNEL_CLIENT;process.env.STYX_TUNNEL_CLIENT=outside;
 t.after(()=>{if(saved===undefined)delete process.env.STYX_TUNNEL_CLIENT;else process.env.STYX_TUNNEL_CLIENT=saved});
 fs.unlinkSync(f.manifest);
 assert.throws(()=>f.api.packagedCliTunnelClient(),/^Error: packaged_tunnel_client_unavailable$/);
 assert.equal(f.api.readCliTunnel(f.stateDir).packagedClient.status,'unavailable');
 await assert.rejects(f.api.runCliTunnel(f.stateDir,undefined,{authorize:true}),/^Error: packaged_tunnel_client_unavailable$/);
 const outsideManifest=path.join(f.root,'manifest.json');write(outsideManifest,f.pin);fs.symlinkSync(outsideManifest,f.manifest);
 assert.throws(()=>f.api.packagedCliTunnelClient(),/packaged_tunnel_client_invalid/);
 fs.unlinkSync(f.manifest);write(f.manifest,f.pin);
 fs.unlinkSync(f.binary);fs.symlinkSync(outside,f.binary);
 assert.throws(()=>f.api.packagedCliTunnelClient(),/packaged_tunnel_client_invalid/);
 fs.unlinkSync(f.binary);fs.writeFileSync(f.binary,'packaged-client-contract-fixture',{mode:0o600});
 assert.throws(()=>f.api.packagedCliTunnelClient(),/packaged_tunnel_client_invalid/);
 fs.chmodSync(f.binary,0o700);
 const moved=path.join(f.install,'runtime-elsewhere');fs.renameSync(f.runtime,moved);fs.symlinkSync(moved,f.runtime,'dir');
 assert.throws(()=>f.api.packagedCliTunnelClient(),/packaged_tunnel_client_invalid/);
});


test('installed CLI default entry reports fixed unavailable/invalid reasons without downloading or starting a runtime',async t=>{
 const f=await packagedFixture(t);
 for(const scenario of ['missing','invalid']){
  if(scenario==='missing')fs.unlinkSync(f.manifest);else write(f.manifest,{...f.pin,path:'../elsewhere'});
  const result=spawnSync(process.execPath,[f.cliFile,'tunnel-run',f.stateDir,'--authorize'],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',HOME:f.root}});
  assert.equal(result.status,2);assert.equal(result.stderr,'');
  assert.deepEqual(JSON.parse(result.stdout),{schema:1,status:'blocked',reason:'packaged_tunnel_client_'+(scenario==='missing'?'unavailable':'invalid'),accountAcceptance:'NOT RUN'});
  assert.equal(fs.existsSync(path.join(f.stateDir,'tunnel')),false);
 }
});
