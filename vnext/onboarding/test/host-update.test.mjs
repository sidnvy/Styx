import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {createDeployment} from '../core.mjs';
import {stageSignedRelease,activateRelease} from '../../host/installer.mjs';
import * as api from '../host-update.mjs';
import {createHostUpdateRuntime} from '../host-update-runtime.mjs';
import {linuxUserUnit} from '../../host/linux-service.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const hash=file=>sha(fs.readFileSync(file));
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-host-update-review-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const keys=generateKeyPairSync('ed25519'),pem=keys.publicKey.export({format:'pem',type:'spki'}),base=path.join(root,'host');fs.mkdirSync(base,{mode:0o700});
 const installRoot=path.join(base,'install'),suffix=process.platform==='win32'?'.exe':'',releases={};
 for(const version of ['1.0.0','2.0.0']){
  const source=path.join(root,'source-'+version);fs.mkdirSync(path.join(source,'host'),{recursive:true,mode:0o700});fs.mkdirSync(path.join(source,'bin'),{mode:0o700});
  const files=['host/private-storage.mjs','host/installer.mjs','host/launch.mjs','host/connect.mjs','bin/node'+suffix,'bin/codex'+suffix].map(name=>{const bytes=Buffer.from('// nonexecuted signed review fixture '+version+' '+name+'\n');fs.writeFileSync(path.join(source,name),bytes);return {path:name,size:bytes.length,sha256:sha(bytes),executable:name.startsWith('bin/')};});
  const raw=JSON.stringify({schema:1,version,platform:process.platform,arch:process.arch,files});fs.writeFileSync(path.join(source,'manifest.json'),raw);fs.writeFileSync(path.join(source,'manifest.sig'),sign(null,Buffer.from(raw),keys.privateKey).toString('base64url'));
  stageSignedRelease({sourceDir:source,installRoot,publicKeyPem:pem});releases[version]={source,files,manifestSha256:sha(raw)};
 }
 activateRelease(installRoot,'1.0.0',pem);
 const pub=path.join(base,'publisher.pem'),device=path.join(base,'device');fs.writeFileSync(pub,pem,{mode:0o600});fs.mkdirSync(device,{mode:0o700});
 const identity=path.join(device,'identity.json'),identityKey=path.join(device,'identity.pem'),token=path.join(device,'host.token'),host=path.join(device,'host.json');
 fs.writeFileSync(identity,JSON.stringify({device_id:'owned-test-device'}),{mode:0o600});fs.writeFileSync(identityKey,'SECRET_PRIVATE_IDENTITY\n',{mode:0o600});fs.writeFileSync(token,'SECRET_CREDENTIAL_TOKEN_'+'a'.repeat(48),{mode:0o600});
 fs.writeFileSync(host,JSON.stringify({host_id:'owned-test-device',gateway_ws_url:'wss://verified.example',token_file:token,exec:{binary:path.join(installRoot,'releases/1.0.0/bin/codex'+suffix),cwd:root}}),{mode:0o600});
 const node=path.join(installRoot,'releases/1.0.0/bin/node'+suffix),serviceFile=path.join(base,'service.json');
 const service=process.platform==='win32'?{task_name:'Styx-Host',install_root:installRoot,host_config_file:host,publisher_key_file:pub,node_binary:node}:{[process.platform==='darwin'?'label':'unitName']:process.platform==='darwin'?'app.styx.connector':'styx-host.service',installRoot,hostConfigFile:host,trustPublicKeyFile:pub,nodeBinary:node};fs.writeFileSync(serviceFile,JSON.stringify(service),{mode:0o600});
 const config={schema:1,mode:'join-existing',gateway:{url:'https://verified.example'},host:{bundle:releases['1.0.0'].source,publisherKeyFile:pub,publisherSha256:sha(keys.publicKey.export({format:'der',type:'spki'})),baseDir:base,label:'Review fixture',computer:false}},input=path.join(root,'input.json'),stateDir=path.join(root,'deployment');
 fs.writeFileSync(input,JSON.stringify(config),{mode:0o600});createDeployment(input,{stateDir});const stateFile=path.join(stateDir,'state.json'),state=JSON.parse(fs.readFileSync(stateFile,'utf8'));state.steps.find(step=>step.id==='host.prepare').status='succeeded';fs.writeFileSync(stateFile,JSON.stringify(state),{mode:0o600});
 return {root,base,installRoot,device,pub,host,identity,identityKey,token,serviceFile,stateDir,releases};
}
function snapshot(root){
 const result={};function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,entry.name),key=path.relative(root,file),stat=fs.lstatSync(file);result[key]={mode:stat.mode,mtime:stat.mtimeMs,...(entry.isFile()?{sha256:hash(file)}:{})};if(entry.isDirectory())walk(file);}}walk(root);return result;
}
function receipt(f,phase='stop_intent'){
 const transactionId='a'.repeat(32),records=path.join(f.installRoot,'update-transactions'),lock=path.join(f.installRoot,'.health-update-lock');fs.mkdirSync(records,{mode:0o700});fs.mkdirSync(lock,{mode:0o700});fs.writeFileSync(path.join(lock,'owner'),transactionId,{mode:0o600});
 const originalPointer=fs.readFileSync(path.join(f.installRoot,'active.json'),'utf8'),candidatePointer=JSON.stringify({schema:1,version:'2.0.0',previous:'1.0.0',manifest_sha256:f.releases['2.0.0'].manifestSha256});
 const record={schema:1,transactionId,phase,previousVersion:'1.0.0',candidateVersion:'2.0.0',previousManifest:f.releases['1.0.0'].manifestSha256,candidateManifest:f.releases['2.0.0'].manifestSha256,platform:process.platform,arch:process.arch,originalPointer,candidatePointer,expectedPointer:originalPointer,candidateBootstrap:f.releases['2.0.0'].files.filter(e=>['host/private-storage.mjs','host/installer.mjs','host/launch.mjs','bin/node'+(process.platform==='win32'?'.exe':'')].includes(e.path)).map(e=>({destination:path.basename(e.path),sha256:e.sha256})),updatedAt:'2026-10-19T00:00:00.000Z'};
 const file=path.join(records,transactionId+'.json');fs.writeFileSync(file,JSON.stringify(record),{mode:0o600});return {transactionId,record,file};
}
test('Host upgrade plan verifies signed generations and preserves all files without pretending executable lifecycle support',t=>{
 const f=fixture(t),before=snapshot(f.root),plan=api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source});
 assert.equal(plan.status,'blocked');assert.equal(plan.current.version,'1.0.0');assert.equal(plan.target.version,'2.0.0');assert.equal(plan.preservedEvidence.hostConfiguration,hash(f.host));assert.equal(plan.preservedEvidence.identityPrivateKey,hash(f.identityKey));assert.equal(plan.preservedEvidence.credential,hash(f.token));
 assert.equal(plan.blockers.includes('durably_inhibited_native_candidate_start_required'),process.platform!=='linux');assert.ok(plan.blockers.includes('service_generation_node_pin_migration_required'));assert.ok(plan.blockers.includes('real_candidate_exec_health_and_gateway_connection_identity_required'));
 assert.equal(plan.candidateHealth,'NOT RUN');assert.equal(plan.service.state,'not_observed');assert.equal(plan.accountAcceptance,'NOT RUN');assert.match(plan.reviewSha256,/^[a-f0-9]{64}$/);
 const inspection=api.readHostUpdate({stateDir:f.stateDir});assert.equal(inspection.transactions.length,0);assert.equal(inspection.current.runtimeHealth,'not_observed');assert.equal(inspection.recovery.status,'not_implemented');
 assert.deepEqual(snapshot(f.root),before);assert.deepEqual(Object.keys(api).sort(),['applyHostUpdate','planHostUpdate','readHostUpdate','recoverHostUpdate']);assert.doesNotMatch(JSON.stringify({plan,inspection}),/SECRET_PRIVATE|SECRET_CREDENTIAL/);
});
test('receipt inspection verifies signed evidence, transaction lock and pointer without executing native recovery',t=>{
 const f=fixture(t),r=receipt(f),before=snapshot(f.root),inspection=api.readHostUpdate({stateDir:f.stateDir,transactionId:r.transactionId});
 assert.equal(inspection.status,'needs_recovery');
 assert.equal(inspection.lock.transactionId,r.transactionId);const row=inspection.transactions[0];assert.equal(row.status,'needs_recovery');assert.equal(row.phase,'stop_intent');assert.equal(row.ownsUpdateLock,true);assert.equal(row.activePointer.matchesExpected,true);assert.equal(row.receiptEvidence,'signed_generations_verified');assert.equal(row.candidateHealth,'not_observed');assert.equal(row.service,'not_observed');
 assert.ok(api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source}).blockers.includes('existing_host_update_requires_receipt_inspection_and_reconciliation'));
 assert.deepEqual(snapshot(f.root),before);assert.doesNotMatch(JSON.stringify(inspection),/SECRET_PRIVATE|SECRET_CREDENTIAL|originalPointer|candidateBootstrap/);
});
test('damaged active pointer remains inspectable through independently verified signed receipt generations',t=>{
 const f=fixture(t),r=receipt(f);fs.writeFileSync(path.join(f.installRoot,'active.json'),'interrupted-pointer');const before=snapshot(f.root);
 const inspection=api.readHostUpdate({stateDir:f.stateDir,transactionId:r.transactionId});assert.equal(inspection.status,'needs_recovery');assert.equal(inspection.current.signature,'unverified');assert.equal(inspection.current.runtimeHealth,'not_observed');assert.equal(inspection.current.version,null);
 assert.equal(inspection.transactions[0].receiptEvidence,'signed_generations_verified');assert.equal(inspection.transactions[0].activePointer.matchesExpected,false);assert.equal(inspection.transactions[0].activePointer.selectedGeneration,null);
 assert.throws(()=>api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source}),/active_host_release_unavailable_or_changed/);assert.deepEqual(snapshot(f.root),before);
});
test('terminal receipt does not become a current health or connectivity claim',t=>{
 const f=fixture(t),r=receipt(f,'activated');r.record.expectedPointer=r.record.candidatePointer;fs.writeFileSync(r.file,JSON.stringify(r.record));fs.writeFileSync(path.join(f.installRoot,'active.json'),r.record.candidatePointer);
 const before=snapshot(f.root),row=api.readHostUpdate({stateDir:f.stateDir}).transactions[0];assert.equal(row.status,'activated');assert.equal(row.candidateHealth,'not_observed');assert.equal(row.service,'not_observed');assert.deepEqual(snapshot(f.root),before);
});
test('tampered receipt or signed candidate is reported unverified and leaves identity and secrets intact',t=>{
 const f=fixture(t),r=receipt(f);fs.appendFileSync(path.join(f.installRoot,'releases/2.0.0/host/connect.mjs'),'unsigned');const before=snapshot(f.root);
 const row=api.readHostUpdate({stateDir:f.stateDir}).transactions[0];assert.equal(row.status,'unverified');assert.equal(row.candidateHealth,'not_observed');assert.throws(()=>api.readHostUpdate({stateDir:f.stateDir,transactionId:r.transactionId}),/release_file_/);assert.deepEqual(snapshot(f.root),before);
});
test('changed publisher pin, device identity or service path binding fail before planning',t=>{
 for(const mutation of ['publisher','identity','service']){
  const f=fixture(t);if(mutation==='publisher')fs.writeFileSync(f.pub,generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'}));
  if(mutation==='identity')fs.writeFileSync(f.identity,JSON.stringify({device_id:'different-device'}));
  if(mutation==='service'){const raw=JSON.parse(fs.readFileSync(f.serviceFile));raw[process.platform==='win32'?'host_config_file':'hostConfigFile']=f.token;fs.writeFileSync(f.serviceFile,JSON.stringify(raw));}
  const before=snapshot(f.root);assert.throws(()=>api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source}),/publisher_fingerprint_mismatch|device_identity_changed|service_binding_changed/);assert.deepEqual(snapshot(f.root),before);
 }
});

 test('orphan operation and recovery guards remain visible and block a new Host update plan',t=>{
  for(const name of ['.health-operation-lock','.health-recovery-guard']){
   const f=fixture(t),file=path.join(f.installRoot,name);
   fs.writeFileSync(file,'unknown-or-interrupted-owner',{mode:0o600});const before=snapshot(f.root);
   const status=api.readHostUpdate({stateDir:f.stateDir});assert.equal(status.status,'needs_recovery');
   assert.ok(Object.values(status.operation).includes('present_requires_owner_inspection'));
   assert.ok(api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source}).blockers.includes('existing_host_update_requires_receipt_inspection_and_reconciliation'));
   assert.deepEqual(snapshot(f.root),before);
  }
 });

function managedFixture(t){
 const f=fixture(t),configFile=path.join(f.stateDir,'deployment.json'),config=JSON.parse(fs.readFileSync(configFile));
 config.mode='create-local';config.gateway={url:'https://127.0.0.1:41119',openssl:'/usr/bin/openssl'};fs.writeFileSync(configFile,JSON.stringify(config),{mode:0o600});
 const stateFile=path.join(f.stateDir,'state.json'),state=JSON.parse(fs.readFileSync(stateFile));state.mode='create-local';state.configSha256=hash(configFile);fs.writeFileSync(stateFile,JSON.stringify(state),{mode:0o600});
 const host=JSON.parse(fs.readFileSync(f.host));host.gateway_ws_url='wss://127.0.0.1:41119';fs.writeFileSync(f.host,JSON.stringify(host),{mode:0o600});
 const service=JSON.parse(fs.readFileSync(f.serviceFile));service.nodeBinary=path.join(f.installRoot,'node');fs.writeFileSync(f.serviceFile,JSON.stringify(service),{mode:0o600});
 for(const file of ['private-storage.mjs','installer.mjs','launch.mjs','node'])fs.copyFileSync(path.join(f.installRoot,'releases/1.0.0',file==='node'?'bin/node':'host/'+file),path.join(f.installRoot,file));
 return f;
}
function controlledRuntime({unhealthy=false,hang=false,failFinish=false}={}){
 // Test seam exercises actual signed file switching/journals. These callbacks
 // are fixtures, explicitly not native-service or real-Exec acceptance.
 const calls=[],state={enabled:false,running:false},runtime={
  async prepare(save,old){calls.push('prepare');if(!old)await save({fixture:true})},
  async stop(){calls.push('stop');state.running=false;state.enabled=false;return true},
  async start({version}){assert.equal(state.enabled,false);calls.push('start:'+version);state.running=true;return true},
  async health({version}){calls.push('health:'+version);if(hang&&version==='2.0.0')return new Promise(resolve=>{state.finishLateHealth=resolve});return !(unhealthy&&version==='2.0.0')},
  async confirmStopped(){calls.push('confirmStopped');return !state.enabled&&!state.running},
  async finish(save,options){calls.push('finish');if(failFinish)throw Error('fixture finalization failure');state.enabled=options?.restoreEnabled!==false;return {fixture:true}}
 };
 return {calls,state,runtimeFactory:()=>runtime};
}
test('review-bound managed Host update activates signed generation and keeps preserved bytes',{skip:process.platform!=='linux'},async t=>{
 const f=managedFixture(t),ops=controlledRuntime(),plan=api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source});
 assert.equal(plan.status,'ready');const identity=[f.host,f.identity,f.identityKey,f.token,f.serviceFile,path.join(f.stateDir,'deployment.json')].map(file=>[file,hash(file)]);
 await assert.rejects(api.applyHostUpdate({stateDir:f.stateDir,plan}),/authorization_required/);
 const result=await api.applyHostUpdate({stateDir:f.stateDir,plan,authorize:true},ops);
 assert.equal(result.status,'activated');assert.match(result.transactionId,/^[a-f0-9]{32}$/);assert.match(result.engineTransactionId,/^[a-f0-9]{32}$/);
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.installRoot,'active.json'))).version,'2.0.0');
 assert.deepEqual(ops.calls,['prepare','stop','start:2.0.0','health:2.0.0','finish']);
 for(const [file,digest]of identity)assert.equal(hash(file),digest);
 assert.equal(api.readHostUpdate({stateDir:f.stateDir}).managed.phase,'completed');
 assert.equal(result.accountAcceptance,'NOT RUN');assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),false);
});
test('managed update rejects stale review and foreground ownership before native mutations',{skip:process.platform!=='linux'},async t=>{
 for(const change of ['profile','foreground','pointer']){
  const f=managedFixture(t),ops=controlledRuntime(),plan=api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source});
  if(change==='profile')fs.writeFileSync(path.join(f.stateDir,'onboarding-plugin.json'),'{}',{mode:0o600});
  if(change==='foreground')fs.writeFileSync(path.join(f.stateDir,'foreground.lock'),'another owner',{mode:0o600});
  if(change==='pointer')fs.appendFileSync(path.join(f.installRoot,'active.json'),'\n');
  await assert.rejects(api.applyHostUpdate({stateDir:f.stateDir,plan,authorize:true},ops),/review_stale/);assert.deepEqual(ops.calls,[]);
  assert.equal(fs.existsSync(path.join(f.stateDir,'host-update.json')),false);
 }
});
test('unhealthy candidate restores the prior signed bootstrap before startup is restored',{skip:process.platform!=='linux'},async t=>{
 const f=managedFixture(t),ops=controlledRuntime({unhealthy:true}),plan=api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source}),pointer=fs.readFileSync(path.join(f.installRoot,'active.json'));
 const result=await api.applyHostUpdate({stateDir:f.stateDir,plan,authorize:true},ops);assert.equal(result.status,'rolled_back');
 assert.deepEqual(fs.readFileSync(path.join(f.installRoot,'active.json')),pointer);
 assert.deepEqual(ops.calls,['prepare','stop','start:2.0.0','health:2.0.0','stop','start:1.0.0','health:1.0.0','finish']);
});
test('uncertain health remains inhibited and explicit recovery restores signed bytes without restart',{skip:process.platform!=='linux'},async t=>{
 const f=managedFixture(t),ops=controlledRuntime({hang:true}),plan=api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source});
 const result=await api.applyHostUpdate({stateDir:f.stateDir,plan,authorize:true},{...ops,timeoutMs:20});
 assert.equal(result.status,'needs_recovery');assert.equal(ops.calls.includes('finish'),false);assert.equal(ops.state.enabled,false);
 const held=fs.readFileSync(path.join(f.stateDir,'host-update.json'));ops.state.finishLateHealth(true);await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'host-update.json')),held);
 assert.ok(api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['1.0.0'].source}).blockers.includes('managed_host_update_requires_recovery'));
 const before=ops.calls.length,recovered=await api.recoverHostUpdate({stateDir:f.stateDir,transactionId:result.transactionId,authorize:true},ops);
 assert.equal(recovered.status,'recovered_stopped');assert.deepEqual(ops.calls.slice(before),['prepare','stop','confirmStopped','finish']);assert.equal(ops.state.running,false);assert.equal(ops.state.enabled,false);
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.installRoot,'active.json'))).version,'1.0.0');
 assert.equal(api.readHostUpdate({stateDir:f.stateDir}).managed.phase,'recovered');
});
test('failed preflight writes no pending update and candidate tampering is refused',{skip:process.platform!=='linux'},async t=>{
 const f=managedFixture(t),plan=api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source});
 await assert.rejects(api.applyHostUpdate({stateDir:f.stateDir,plan,authorize:true},{runtimeFactory:()=>({prepare(){throw Error('native service not owned')}})}),/not owned/);
 assert.equal(fs.existsSync(path.join(f.stateDir,'host-update.json')),false);
 fs.appendFileSync(path.join(f.releases['2.0.0'].source,'host/connect.mjs'),'tampered');
 await assert.rejects(api.applyHostUpdate({stateDir:f.stateDir,plan,authorize:true},controlledRuntime()),/release_file_/);
});

function nativeAdapterFixture(t){
 const f=managedFixture(t),home=path.join(f.root,'home'),service=JSON.parse(fs.readFileSync(f.serviceFile));
 const unitFile=path.join(home,'.config/systemd/user',service.unitName),dropFile=unitFile+'.d/90-styx-reviewed-update.conf';
 fs.mkdirSync(path.dirname(unitFile),{recursive:true,mode:0o700});
 fs.writeFileSync(unitFile,linuxUserUnit(service),{mode:0o600});
 const state={enabled:'enabled',active:'inactive',pid:0,drop:false,commands:[]},ctx={stateDir:f.stateDir,base:f.base,installRoot:f.installRoot,config:JSON.parse(fs.readFileSync(path.join(f.stateDir,'deployment.json'))),host:JSON.parse(fs.readFileSync(f.host)),current:{version:'1.0.0'},service:{id:service.unitName,installRoot:f.installRoot,hostConfigFile:f.host,publisherKeyFile:f.pub,nodeBinary:service.nodeBinary}};
 const run=(binary,args)=>{
  assert.equal(binary,'/usr/bin/systemctl');assert.equal(args[0],'--user');state.commands.push(args.slice(1));
  const cmd=args[1];
  if(cmd==='show')return 'LoadState=loaded\nActiveState='+state.active+'\nUnitFileState='+state.enabled+'\nMainPID='+state.pid+'\nFragmentPath='+unitFile+'\nDropInPaths='+(state.drop?dropFile:'')+'\nRestart='+(state.drop?'no':'on-failure')+'\n';
  if(cmd==='disable'){state.enabled='disabled';return ''}
  if(cmd==='stop'){state.active='inactive';state.pid=0;return ''}
  if(cmd==='daemon-reload'){state.drop=fs.existsSync(dropFile);return ''}
  if(cmd==='start'){assert.equal(state.enabled,'disabled');assert.equal(state.drop,true);state.active='active';state.pid=12345;return ''}
  if(cmd==='enable'){assert.equal(state.drop,false);state.enabled='enabled';return ''}
  assert.fail('unexpected native operation '+cmd);
 };
 const runtime=createHostUpdateRuntime(ctx,{home,run,observeProcess:(pid,ctx,version)=>({pid,connectorPid:12346}),observeConnection:async()=>state.active==='active'});
 return {...f,home,unitFile,dropFile,state,runtime,ctx,run};
}
test('Linux adapter disables startup and Restart before candidate start, restores only at finish',{skip:process.platform!=='linux'},async t=>{
 const f=nativeAdapterFixture(t);let saved;const save=x=>{saved=structuredClone(x)};
 await f.runtime.prepare(save);assert.equal(saved.initialEnabled,'enabled');
 await f.runtime.stop({signal:new AbortController().signal},save);
 assert.equal(f.state.enabled,'disabled');assert.match(fs.readFileSync(f.dropFile,'utf8'),/Restart=no/);
 await f.runtime.start({version:'2.0.0',signal:new AbortController().signal});
 assert.equal(f.state.enabled,'disabled');assert.equal(f.state.commands.some(x=>x[0]==='enable'),false);
 await f.runtime.finish(save);assert.equal(f.state.enabled,'enabled');assert.equal(fs.existsSync(f.dropFile),false);
 const mutations=f.state.commands.map(x=>x[0]).filter(x=>x!=='show');
 assert.deepEqual(mutations,['disable','stop','daemon-reload','start','stop','daemon-reload','enable']);
});
test('Linux adapter refuses foreign definitions/overrides and leaves recovery stopped/disabled',{skip:process.platform!=='linux'},async t=>{
 const foreign=nativeAdapterFixture(t);fs.appendFileSync(foreign.unitFile,'foreign override');
 await assert.rejects(foreign.runtime.prepare(()=>{}),/definition_changed/);assert.equal(foreign.state.commands.length,0);
 const f=nativeAdapterFixture(t);let saved;const save=x=>{saved=structuredClone(x)};
 await f.runtime.prepare(save);await f.runtime.stop({signal:new AbortController().signal},save);
 assert.equal(await f.runtime.confirmStopped(),true);
 fs.appendFileSync(f.dropFile,'Restart=always');await assert.rejects(f.runtime.start({version:'2.0.0',signal:new AbortController().signal}),/inhibition_changed/);
 assert.equal(f.state.commands.some(x=>x[0]==='start'),false);
});

test('recovery refuses changed credentials and wrong transaction IDs before any service mutation',{skip:process.platform!=='linux'},async t=>{
 const f=managedFixture(t),ops=controlledRuntime({hang:true}),plan=api.planHostUpdate({stateDir:f.stateDir,bundle:f.releases['2.0.0'].source});
 const result=await api.applyHostUpdate({stateDir:f.stateDir,plan,authorize:true},{...ops,timeoutMs:20}),before=ops.calls.length;
 await assert.rejects(api.recoverHostUpdate({stateDir:f.stateDir,transactionId:'b'.repeat(32),authorize:true},ops),/binding_mismatch/);
 fs.appendFileSync(f.token,'changed');
 await assert.rejects(api.recoverHostUpdate({stateDir:f.stateDir,transactionId:result.transactionId,authorize:true},ops),/preserved_identity_changed/);
 assert.equal(ops.calls.length,before);assert.equal(ops.state.enabled,false);
});
test('Linux recovery cleanup keeps startup disabled and never starts the unit',{skip:process.platform!=='linux'},async t=>{
 const f=nativeAdapterFixture(t);let saved;const save=x=>{saved=structuredClone(x)};
 await f.runtime.prepare(save);await f.runtime.stop({signal:new AbortController().signal},save);
 const recovering=createHostUpdateRuntime(f.ctx,{home:f.home,run:f.run,observeConnection:async()=>false});
 await recovering.prepare(save,saved);assert.equal(await recovering.confirmStopped(),true);
 await recovering.finish(save,{restoreEnabled:false});
 assert.equal(f.state.enabled,'disabled');assert.equal(f.state.commands.some(x=>['enable','start'].includes(x[0])),false);assert.equal(fs.existsSync(f.dropFile),false);
});
