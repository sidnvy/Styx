// unit_contract fixtures only: fake user home and systemctl runner. The one
// systemd-analyze check validates native unit syntax without starting a service.
// No official Tunnel client, cloud account, logout/login or network acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createDeployment} from '../core.mjs';
import {main} from '../cli.mjs';
import {configureCliTunnel} from '../cli-tunnel.mjs';
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const write=(file,value)=>fs.writeFileSync(file,JSON.stringify(value)+'\n',{mode:0o600});
const key='sk-unit-contract_'+'b'.repeat(40);
async function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-tunnel-unit-contract-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const home=path.join(root,'home'),stateDir=path.join(root,'state 50% "$STYX"'),install=path.join(root,'distribution 50% $STYX');
 fs.mkdirSync(home,{mode:0o700});
 const input=path.join(root,'input.json');
 write(input,{schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:8795',openssl:process.execPath},host:{bundle:root,publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'host'),label:'Unit contract',computer:false}});
 createDeployment(input,{stateDir});
 const gateway=path.join(stateDir,'gateway');fs.mkdirSync(gateway,{mode:0o700});
 const modelFile=path.join(gateway,'model.token'),certificate=path.join(gateway,'certificate.pem');
 fs.writeFileSync(modelFile,'c'.repeat(64),{mode:0o600});fs.writeFileSync(certificate,'unit-contract certificate',{mode:0o600});
 write(path.join(gateway,'runtime.json'),{schema:1,url:'https://127.0.0.1:8795',listenHost:'127.0.0.1',modelTokenFile:modelFile,tlsCertificateFile:certificate});
 const connection=path.join(root,'connection.json');write(connection,{tunnelId:'tunnel_'+'a'.repeat(32),apiKey:key,autoStart:false});configureCliTunnel(stateDir,connection,{authorize:true});
 const profile=path.join(stateDir,'profile-preserved');fs.writeFileSync(profile,'existing profile',{mode:0o600});
 const onboarding=path.join(install,'app','onboarding'),runtime=path.join(install,'runtime');fs.mkdirSync(onboarding,{recursive:true,mode:0o700});fs.mkdirSync(runtime,{mode:0o700});
 for(const name of ['linux-tunnel-service.mjs','cli-tunnel.mjs']){
  let source=fs.readFileSync(new URL('../'+name,import.meta.url),'utf8');
  source=source.replace("from '../host/private-storage.mjs'",'from '+JSON.stringify(new URL('../../host/private-storage.mjs',import.meta.url).href));
  if(name==='cli-tunnel.mjs')source=source.replace("from './tunnel-runtime.mjs'",'from '+JSON.stringify(new URL('../tunnel-runtime.mjs',import.meta.url).href));
  fs.writeFileSync(path.join(onboarding,name),source,{mode:0o600});
 }
 const cli=path.join(onboarding,'cli.mjs');fs.copyFileSync(new URL('../cli.mjs',import.meta.url),cli);
 const node=path.join(runtime,'node');fs.writeFileSync(node,'#!/bin/sh\nexit 0\n',{mode:0o700});
 const provenance=path.join(runtime,'node-provenance.json');write(provenance,{schema:1,component:'node',platform:'linux',arch:'x64',binary_sha256:hash(node)});
 const client=path.join(runtime,'tunnel-client');fs.writeFileSync(client,'unit-contract client',{mode:0o700});
 const clientManifest=path.join(runtime,'tunnel-client.json');write(clientManifest,{schema:1,path:'tunnel-client',sha256:hash(client),version:'0.0.17'});
 const api=await import(pathToFileURL(path.join(onboarding,'linux-tunnel-service.mjs')).href);
 const plan=api.linuxTunnelServicePlan(stateDir,{home});
 return {root,home,stateDir,install,runtime,cli,node,provenance,client,clientManifest,profile,api,plan};
}
function manager(f){
 const calls=[],state={load:'not-found',active:'inactive',substate:'dead',enabled:'disabled',pid:0,reload:'no',fragment:''};
 const result={calls,state,hook:null,run(command,args,options){
  assert.equal(command,'/usr/bin/systemctl');assert.equal(args[0],'--user');assert.ok(options.timeout>0);
  calls.push([...args]);result.hook?.(args);
  const action=args[1];
  if(action==='show'){
   assert.equal(args[2],f.plan.name);assert.match(args[3],/^--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,NeedDaemonReload$/);
   return ['Id='+f.plan.name,'LoadState='+state.load,'ActiveState='+state.active,'SubState='+state.substate,'UnitFileState='+state.enabled,'MainPID='+state.pid,'FragmentPath='+state.fragment,'NeedDaemonReload='+state.reload].join('\n')+'\n';
  }
  if(action==='daemon-reload'){
   assert.equal(args.length,2);state.reload='no';state.load=fs.existsSync(f.plan.unitFile)?'loaded':'not-found';state.fragment=state.load==='loaded'?f.plan.unitFile:'';return '';
  }
  assert.equal(args.length,3);assert.equal(args[2],f.plan.name);
  if(action==='enable')state.enabled='enabled';else if(action==='disable')state.enabled='disabled';
  else if(action==='start'){state.active='active';state.substate='running';state.pid=7123;}
  else if(action==='stop'){state.active='inactive';state.substate='dead';state.pid=0;}
  else assert.fail('unexpected systemctl operation '+action);return '';
 }};
 result.control=(action,extra={})=>f.api.controlLinuxTunnelService(f.stateDir,{action,...(action==='status'?{}:{authorize:true}),...extra},{home:f.home,run:result.run});
 return result;
}
const operations=m=>m.calls.map(args=>args[1]);
test('unit_contract CLI permits only the fixed lifecycle and explicit mutation authorization',{skip:process.platform!=='linux'},async()=>{
 assert.ok((await main(['help'])).commands.includes('tunnel-service STATE install|status|start|stop|uninstall [--authorize]'));
 for(const action of ['install','start','stop','uninstall'])await assert.rejects(main(['tunnel-service','/unused',action]),/authorization_required/);
 for(const args of [['/unused','restart','--authorize'],['/unused','status','/tmp/custom-unit'],['/unused','start','--authorize','--binary=/tmp/exe']])await assert.rejects(main(['tunnel-service',...args]),/authorization_required|usage_/);
});
test('unit_contract status creates no directories, distinguishes enabled from active and refuses unknown manager status',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),m=manager(f),missing=path.join(f.root,'never-created');
 const missingManager=manager({...f,stateDir:missing,plan:f.api.linuxTunnelServicePlan(missing,{home:f.home})});
 assert.equal(missingManager.control('status').status,'not_installed');assert.equal(fs.existsSync(missing),false);assert.equal(fs.existsSync(path.join(f.home,'.config')),false);
 assert.equal(m.control('status').status,'not_installed');assert.equal(fs.existsSync(path.join(f.home,'.config')),false);
 m.control('install');m.state.enabled='enabled';const stopped=m.control('status');
 assert.equal(stopped.status,'stopped');assert.equal(stopped.enabled,'enabled');assert.equal(stopped.active,'inactive');assert.equal(stopped.pid,null);
 assert.equal(stopped.transport,'not_observed');assert.equal(stopped.accountAcceptance,'NOT RUN');assert.equal(stopped.systemBootWithoutLogin,'NOT CONFIGURED');
 m.hook=args=>{if(args[1]==='show')throw Error(key)};const unknown=m.control('status');assert.equal(unknown.status,'needs_reconciliation');assert.equal(JSON.stringify(unknown).includes(key),false);
});
test('unit_contract install only writes/reloads; start enables; stop disables; uninstall preserves state and profile',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),m=manager(f),deployment=fs.readFileSync(path.join(f.stateDir,'deployment.json')),connection=fs.readFileSync(path.join(f.stateDir,'tunnel/connection.json'));
 const installed=m.control('install');assert.equal(installed.status,'installed_not_started');assert.equal(installed.activation,'not_requested');assert.deepEqual(operations(m),['show','daemon-reload','show']);
 assert.equal(fs.readFileSync(f.plan.unitFile,'utf8'),f.plan.unit);assert.equal(fs.statSync(f.plan.unitFile).mode&0o777,0o600);
 assert.equal(m.control('start').status,'running');assert.deepEqual(operations(m).slice(-6),['show','daemon-reload','show','enable','start','show']);
 assert.equal(m.control('stop').status,'stopped');assert.deepEqual(operations(m).slice(-4),['show','disable','stop','show']);
 assert.equal(m.control('uninstall').status,'uninstalled_state_preserved');assert.equal(fs.existsSync(f.plan.unitFile),false);
 assert.deepEqual(operations(m).slice(-6),['show','disable','stop','show','daemon-reload','show']);
 assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'deployment.json')),deployment);assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'tunnel/connection.json')),connection);assert.equal(fs.readFileSync(f.profile,'utf8'),'existing profile');
 assert.equal(JSON.stringify(operations(m)).includes('sudo'),false);
});
test('unit_contract rejects altered/symlinked units, redirected directories and a foreign manager FragmentPath',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),m=manager(f);m.control('install');const original=fs.readFileSync(f.plan.unitFile);
 fs.appendFileSync(f.plan.unitFile,'Environment=UNOWNED=1\n');m.calls.length=0;assert.throws(()=>m.control('stop'),/definition_changed/);assert.equal(m.calls.length,0);
 fs.writeFileSync(f.plan.unitFile,original);m.state.fragment='/etc/systemd/user/'+f.plan.name;const refused=m.control('start');assert.equal(refused.reason,'linux_tunnel_service_manager_definition_not_owned');assert.deepEqual(operations(m),['show']);
 m.state.fragment=f.plan.unitFile;fs.unlinkSync(f.plan.unitFile);const outside=path.join(f.root,'outside-unit');fs.writeFileSync(outside,original,{mode:0o600});fs.symlinkSync(outside,f.plan.unitFile);assert.throws(()=>m.control('uninstall'),/not_regular/);assert.deepEqual(fs.readFileSync(outside),original);
 fs.unlinkSync(f.plan.unitFile);const moved=path.join(f.root,'moved-systemd');fs.renameSync(path.join(f.home,'.config/systemd'),moved);fs.symlinkSync(moved,path.join(f.home,'.config/systemd'));assert.throws(()=>m.control('install'),/directory_not_owned/);
});
test('unit_contract package pins are fixed to the installed layout; no binary/unit override or missing configuration is accepted',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),m=manager(f);
 assert.equal(f.plan.nodeBinary,f.node);assert.equal(f.plan.cli,f.cli);assert.match(f.plan.unit,/ tunnel-run .* --authorize/);assert.match(f.plan.unit,/ExecStart=:/);assert.match(f.plan.unit,/50%%/);
 for(const extra of [{binary:'/tmp/custom'},{unitFile:'/tmp/custom'},{home:'/tmp/custom'}])assert.throws(()=>m.control('install',extra),/invalid_linux_tunnel_service_action/);
 const clientManifest=fs.readFileSync(f.clientManifest);write(f.clientManifest,{schema:1,path:'../client',sha256:hash(f.client),version:'0.0.17'});assert.throws(()=>m.control('install'),/packaged_tunnel_client_invalid/);assert.equal(fs.existsSync(f.plan.unitFile),false);
 fs.writeFileSync(f.clientManifest,clientManifest);fs.appendFileSync(f.node,'tampered');assert.throws(()=>m.control('install'),/packaged_node_invalid/);assert.equal(fs.existsSync(f.plan.unitFile),false);
 write(f.provenance,{schema:1,component:'node',platform:'linux',arch:'x64',binary_sha256:hash(f.node)});fs.rmSync(path.join(f.stateDir,'tunnel'),{recursive:true});assert.throws(()=>m.control('install'),/configuration_required/);assert.equal(fs.existsSync(f.plan.unitFile),false);
});
test('unit_contract start retains an unobserved owner lock, while cleanup still works with damaged package material',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),m=manager(f);m.control('install');const lock=path.join(f.stateDir,'tunnel/owner.lock');fs.writeFileSync(lock,'foreign owner evidence',{mode:0o600});
 m.calls.length=0;const result=m.control('start');assert.equal(result.reason,'linux_tunnel_owner_unobserved');assert.deepEqual(operations(m),['show']);assert.equal(fs.readFileSync(lock,'utf8'),'foreign owner evidence');
 fs.appendFileSync(f.node,'changed');assert.equal(m.control('stop').status,'stopped');assert.equal(m.control('uninstall').status,'uninstalled_state_preserved');assert.equal(fs.readFileSync(lock,'utf8'),'foreign owner evidence');
});
test('unit_contract partial mutation failure retains exact definition and reports needs_reconciliation without secret errors',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),m=manager(f);m.control('install');m.hook=args=>{if(args[1]==='start')throw Error(key)};
 const result=m.control('start');assert.equal(result.status,'needs_reconciliation');assert.equal(result.reason,'linux_tunnel_service_operation_failed');assert.equal(result.definition,'retained');assert.equal(JSON.stringify(result).includes(key),false);assert.equal(fs.readFileSync(f.plan.unitFile,'utf8'),f.plan.unit);assert.equal(m.state.active,'inactive');assert.equal(m.state.enabled,'enabled');
 m.hook=null;assert.equal(m.control('status').status,'stopped');m.hook=args=>{if(args[1]==='daemon-reload'&&!fs.existsSync(f.plan.unitFile))throw Error('reload failure')};
 const uninstall=m.control('uninstall');assert.equal(uninstall.status,'needs_reconciliation');assert.equal(uninstall.definition,'retained');assert.equal(fs.readFileSync(f.plan.unitFile,'utf8'),f.plan.unit);
});
test('unit_contract replacement between manager operations is not executed, removed or overwritten',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),m=manager(f);m.control('install');m.hook=args=>{if(args[1]==='enable'){fs.renameSync(f.plan.unitFile,f.plan.unitFile+'.prior');fs.writeFileSync(f.plan.unitFile,'foreign replacement',{mode:0o600});}};
 const result=m.control('start');assert.equal(result.status,'needs_reconciliation');assert.equal(result.reason,'linux_tunnel_service_definition_changed');assert.equal(fs.readFileSync(f.plan.unitFile,'utf8'),'foreign replacement');assert.equal(operations(m).includes('start'),false);
});

test('unit_contract refuses a package executable location systemd cannot accept before writing a unit',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),directory=path.join(f.root,'unsupported "package','app/onboarding');fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const source=fs.readFileSync(new URL('../linux-tunnel-service.mjs',import.meta.url),'utf8')
  .replace("from '../host/private-storage.mjs'",'from '+JSON.stringify(new URL('../../host/private-storage.mjs',import.meta.url).href))
  .replace("from './cli-tunnel.mjs'",'from '+JSON.stringify(new URL('../cli-tunnel.mjs',import.meta.url).href));
 const file=path.join(directory,'linux-tunnel-service.mjs');fs.writeFileSync(file,source,{mode:0o600});
 const api=await import(pathToFileURL(file).href);assert.throws(()=>api.linuxTunnelServicePlan(f.stateDir,{home:f.home}),/package_path_not_supported/);assert.equal(fs.existsSync(path.join(f.home,'.config')),false);
});
test('native systemd-analyze validates generated unit syntax against the actual installed executable layout without starting it',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);fs.copyFileSync(process.execPath,f.node);fs.chmodSync(f.node,0o700);write(f.provenance,{schema:1,component:'node',platform:'linux',arch:'x64',binary_sha256:hash(f.node)});
 const m=manager(f);assert.equal(m.control('install').status,'installed_not_started');
 const checked=spawnSync('/usr/bin/systemd-analyze',['verify',f.plan.unitFile],{encoding:'utf8',timeout:15000,env:{PATH:'/usr/bin:/bin',HOME:f.home}});
 assert.equal(checked.error,undefined);assert.equal(checked.status,0,checked.stdout+checked.stderr);assert.deepEqual(operations(m),['show','daemon-reload','show']);
 t.diagnostic('native unit grammar check only; fake systemctl lifecycle and local fixture configuration, no service or cloud client started');
});
