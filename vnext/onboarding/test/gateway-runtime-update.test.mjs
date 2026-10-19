import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {createDeployment} from '../core.mjs';
import {buildGatewayRuntimeRelease,prepareGatewayRuntime,readGatewayRuntime} from '../gateway-runtime.mjs';
import {planGatewayRuntimeChange,applyGatewayRuntimeChange,recoverGatewayRuntimeChange,observeGatewayRuntimeQuiescence,readGatewayRuntimeChange} from '../gateway-runtime-update.mjs';

const quiet={observeQuiescence:()=>({service:'not_installed',processes:'none'})};
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-runtime-change-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const key=generateKeyPairSync('ed25519'),privateKeyFile=path.join(root,'private.pem'),publisherKeyFile=path.join(root,'publisher.pem');
 fs.writeFileSync(privateKeyFile,key.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});fs.writeFileSync(publisherKeyFile,key.publicKey.export({format:'pem',type:'spki'}),{mode:0o600});
 const nodeBinary=path.join(root,'node-source'),nodeLicenseFile=path.join(root,'LICENSE');fs.writeFileSync(nodeLicenseFile,'Fixture\n');
 const build=version=>{fs.writeFileSync(nodeBinary,'signed fixture '+version+'\n');const destination=path.join(root,'bundle-'+version);const result=buildGatewayRuntimeRelease({destination,version,privateKeyFile,nodeBinary,nodeLicenseFile});return {bundle:destination,...result};};
 const first=build('1.0.0'),second=build('2.0.0'),third=build('3.0.0');
 const runtime={bundle:first.bundle,publisherKeyFile,publisherSha256:first.publisherSha256,baseDir:path.join(root,'runtime')};prepareGatewayRuntime(runtime);
 const input=path.join(root,'input.json'),stateDir=path.join(root,'deployment'),config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:18795',openssl:process.execPath,runtime}};
 fs.writeFileSync(input,JSON.stringify(config),{mode:0o600});createDeployment(input,{stateDir});
 const stateFile=path.join(stateDir,'state.json'),state=JSON.parse(fs.readFileSync(stateFile,'utf8'));for(const step of state.steps)step.status='succeeded';fs.writeFileSync(stateFile,JSON.stringify(state),{mode:0o600});
 const gateway=path.join(stateDir,'gateway');fs.mkdirSync(gateway,{mode:0o700});
 const sentinels=['certificate.pem','private-key.pem','model.token','admin.token','devices.json','identity.json'].map(name=>{const file=path.join(gateway,name);fs.writeFileSync(file,'existing '+name+'\n',{mode:0o600});return {file,sha256:hash(file)};});
 const journal=()=>JSON.parse(fs.readFileSync(path.join(runtime.baseDir,'runtime-change.json'),'utf8'));
 const preserved=()=>{for(const value of sentinels)assert.equal(hash(value.file),value.sha256);};
 return {root,runtime,stateDir,first,second,third,journal,preserved};
}
test('review-bound offline update then signed rollback preserve identity, credentials and configuration',t=>{
 const f=fixture(t),cfgHash=hash(path.join(f.stateDir,'deployment.json'));
 assert.equal(readGatewayRuntimeChange({stateDir:f.stateDir}).status,'none');
 const plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle});assert.equal(plan.current.version,'1.0.0');assert.equal(plan.target.version,'2.0.0');
 assert.equal(fs.existsSync(path.join(f.runtime.baseDir,'runtime-change.json')),false);
 const updated=applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},quiet);assert.equal(updated.status,'completed');assert.equal(readGatewayRuntime(f.runtime).version,'2.0.0');
 assert.equal(f.journal().status,'completed');assert.equal(fs.existsSync(f.journal().backupNode),false);
 assert.equal(readGatewayRuntimeChange({stateDir:f.stateDir}).status,'completed');
 const rollback=planGatewayRuntimeChange({stateDir:f.stateDir,rollback:true});assert.equal(rollback.target.version,'1.0.0');
 assert.equal(applyGatewayRuntimeChange({stateDir:f.stateDir,plan:rollback,authorize:true},quiet).version,'1.0.0');
 assert.equal(readGatewayRuntime(f.runtime).version,'1.0.0');assert.equal(hash(path.join(f.stateDir,'deployment.json')),cfgHash);f.preserved();
 assert.equal(fs.readdirSync(path.join(f.runtime.baseDir,'runtime-changes')).length,2);
});
test('authorization, review edits, configuration changes and shared lock block before mutation',t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle});
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan},quiet),/authorization_required/);
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan:{...plan,reviewSha256:'0'.repeat(64)},authorize:true},quiet),/review_stale/);
 fs.writeFileSync(path.join(f.stateDir,'advance.lock'),'other operation',{mode:0o600});assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},quiet),/busy_or_interrupted_lock/);fs.unlinkSync(path.join(f.stateDir,'advance.lock'));
 const configFile=path.join(f.stateDir,'deployment.json'),bytes=fs.readFileSync(configFile);fs.appendFileSync(configFile,'\n');
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},quiet),/invalid_onboarding_state/);fs.writeFileSync(configFile,bytes);
 assert.equal(fs.existsSync(path.join(f.runtime.baseDir,'runtime-change.json')),false);assert.equal(readGatewayRuntime(f.runtime).version,'1.0.0');f.preserved();
});
test('installed definition, running processes, unknown observations and uncertain Core actions refuse changes',t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle});
 for(const result of [{service:'installed',processes:'none'},{service:'not_installed',processes:'running'},{service:'unknown',processes:'none'}])assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},{observeQuiescence:()=>result}),/quiescence_not_confirmed/);
 const stateFile=path.join(f.stateDir,'state.json'),state=JSON.parse(fs.readFileSync(stateFile,'utf8'));state.gatewayMaintenance=[{status:'uncertain'}];fs.writeFileSync(stateFile,JSON.stringify(state));
 assert.throws(()=>planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle}),/uncertain_deployment_action/);
 assert.equal(fs.existsSync(path.join(f.runtime.baseDir,'runtime-change.json')),false);f.preserved();
});
for(const boundary of ['prepared','staged','node_switched','pointer_switched'])test('interruption at '+boundary+' requires explicit verified recovery and preserves Gateway state',t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle}),old=readGatewayRuntime(f.runtime);
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},{...quiet,afterCheckpoint(stage){if(stage===boundary)throw Error('simulated_interruption');}}),/simulated_interruption/);
 const pending=f.journal();assert.ok(['prepared','staged','committing'].includes(pending.status));
 assert.equal(readGatewayRuntimeChange({stateDir:f.stateDir}).transactionId,pending.id);
 assert.throws(()=>planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.third.bundle}),/unfinished_runtime_change_requires_recovery/);
 assert.throws(()=>recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:pending.id}),/authorization_required/);
 assert.equal(recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:pending.id,authorize:true},quiet).status,'recovered');
 assert.equal(readGatewayRuntime(f.runtime).manifestSha256,old.manifestSha256);assert.equal(f.journal().status,'recovered');f.preserved();
 assert.equal(applyGatewayRuntimeChange({stateDir:f.stateDir,plan:planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.third.bundle}),authorize:true},quiet).version,'3.0.0');
});
test('actual installer process death leaves an exact recoverable transaction lock',t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle}),input=path.join(f.root,'change-input.json'),child=path.join(f.root,'interrupted-update.mjs');
 fs.writeFileSync(input,JSON.stringify({stateDir:f.stateDir,plan,authorize:true}),{mode:0o600});
 fs.writeFileSync(child,`import fs from 'node:fs';\nimport {applyGatewayRuntimeChange} from ${JSON.stringify(new URL('../gateway-runtime-update.mjs',import.meta.url).href)};\napplyGatewayRuntimeChange(JSON.parse(fs.readFileSync(process.argv[2],'utf8')),{observeQuiescence:()=>({service:'not_installed',processes:'none'}),afterCheckpoint(stage){if(stage==='node_switched')process.exit(77)}});\n`,{mode:0o600});
 const result=spawnSync(process.execPath,[child,input],{encoding:'utf8',timeout:10000});assert.equal(result.error,undefined);assert.equal(result.status,77,result.stderr);
 const record=readGatewayRuntimeChange({stateDir:f.stateDir});assert.equal(record.status,'recovery_required');
 const lock=path.join(f.stateDir,'advance.lock');assert.equal(JSON.parse(fs.readFileSync(lock,'utf8')).transactionId,record.transactionId);
 assert.equal(recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:record.transactionId,authorize:true},quiet).version,'1.0.0');assert.equal(fs.existsSync(lock),false);f.preserved();
});
test('changed rollback backup or publisher pin prevents recovery before runtime mutation',t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle});
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},{...quiet,afterCheckpoint(stage){if(stage==='node_switched')throw Error('crash');}}),/crash/);
 const record=f.journal(),activeNode=path.join(f.runtime.baseDir,'install',process.platform==='win32'?'node.exe':'node'),before=hash(activeNode),backupBytes=fs.readFileSync(record.backupNode);
 fs.appendFileSync(record.backupNode,'unsigned');assert.throws(()=>recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:record.id,authorize:true},quiet),/backup_changed/);assert.equal(hash(activeNode),before);
 fs.writeFileSync(record.backupNode,backupBytes);fs.writeFileSync(path.join(f.runtime.baseDir,'publisher.pem'),generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'}));
 assert.throws(()=>recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:record.id,authorize:true},quiet),/publisher_fingerprint_mismatch/);assert.equal(hash(activeNode),before);f.preserved();
});
test('Linux offline observation rejects loaded unit even without an on-disk definition',{skip:process.platform!=='linux'},t=>{
 const f=fixture(t),scope={stateDir:f.stateDir,installRoot:path.join(f.runtime.baseDir,'install')},home=path.join(f.root,'home');fs.mkdirSync(home,{mode:0o700});
 assert.throws(()=>observeGatewayRuntimeQuiescence(scope,{home,run(){return 'LoadState=loaded\nActiveState=inactive\nMainPID=0\n';}}),/definition_must_be_uninstalled/);
 assert.throws(()=>observeGatewayRuntimeQuiescence(scope,{home,run(){throw Error('no bus');}}),/service_quiescence_unknown/);
 try{const observed=observeGatewayRuntimeQuiescence(scope,{home,run(){return 'LoadState=not-found\nActiveState=inactive\nMainPID=0\n';}});assert.equal(observed.processes,'none');}
 catch(e){assert.equal(e.message,'gateway_process_quiescence_unknown');t.diagnostic('Host restricts inspection of another current-user process; observer correctly refuses an offline claim.');}
});

function interruptedFixture(t){
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle});
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},{...quiet,afterCheckpoint(stage){if(stage==='node_switched')throw Error('interrupted');}}),/interrupted/);
 return {...f,transactionId:f.journal().id};
}
async function until(predicate){
 const deadline=Date.now()+7000;
 while(!predicate()){if(Date.now()>=deadline)throw Error('isolated recovery worker did not reach barrier');await new Promise(resolve=>setTimeout(resolve,5));}
}
test('actual concurrent recoverers cannot adopt or release the other live transaction lock',{timeout:15000},async t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle}),input=path.join(f.root,'input-change.json'),installer=path.join(f.root,'crash-installer.mjs');
 const moduleURL=new URL('../gateway-runtime-update.mjs',import.meta.url).href;
 fs.writeFileSync(input,JSON.stringify({stateDir:f.stateDir,plan,authorize:true}),{mode:0o600});
 fs.writeFileSync(installer,`import fs from 'node:fs';import {applyGatewayRuntimeChange} from ${JSON.stringify(moduleURL)};applyGatewayRuntimeChange(JSON.parse(fs.readFileSync(process.argv[2],'utf8')),{observeQuiescence:()=>({service:'not_installed',processes:'none'}),afterCheckpoint(stage){if(stage==='node_switched')process.exit(77)}});`,{mode:0o600});
 const crashed=spawnSync(process.execPath,[installer,input],{encoding:'utf8',timeout:7000});assert.equal(crashed.error,undefined);assert.equal(crashed.status,77,crashed.stderr);
 const transactionId=f.journal().id,worker=path.join(f.root,'recovery-worker.mjs'),go=path.join(f.root,'go'),finish=path.join(f.root,'finish');
 fs.writeFileSync(worker,`import fs from 'node:fs';import path from 'node:path';import {recoverGatewayRuntimeChange} from ${JSON.stringify(moduleURL)};
const root=process.argv[2],stateDir=process.argv[3],transactionId=process.argv[4];fs.writeFileSync(path.join(root,'ready-'+process.pid),'ready');
while(!fs.existsSync(path.join(root,'go')))await new Promise(resolve=>setTimeout(resolve,2));
try{const result=recoverGatewayRuntimeChange({stateDir,transactionId,authorize:true},{observeQuiescence(){fs.writeFileSync(path.join(root,'entered-'+process.pid),'owned');const deadline=Date.now()+7000;while(!fs.existsSync(path.join(root,'finish'))){if(Date.now()>deadline)throw Error('worker release timeout');Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5);}return {service:'not_installed',processes:'none'}}});console.log(JSON.stringify(result));}catch(error){console.log(JSON.stringify({error:error.message}));process.exitCode=2;}`,{mode:0o600});
 const completed=[],children=[];
 const launch=()=>{
  const child=spawn(process.execPath,[worker,f.root,f.stateDir,transactionId],{stdio:['ignore','pipe','pipe']});children.push(child);
  let stdout='',stderr='';child.stdout.on('data',chunk=>{stdout+=chunk});child.stderr.on('data',chunk=>{stderr+=chunk});
  return new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>{const result={code,stdout,stderr};completed.push(result);resolve(result)});});
 };
 t.after(()=>{for(const child of children)if(child.exitCode===null)child.kill('SIGKILL')});
 const runs=[launch(),launch()];await until(()=>fs.readdirSync(f.root).filter(name=>name.startsWith('ready-')).length===2);fs.writeFileSync(go,'start');
 await until(()=>fs.readdirSync(f.root).some(name=>name.startsWith('entered-'))&&completed.length===1);
 const entrants=fs.readdirSync(f.root).filter(name=>name.startsWith('entered-'));assert.equal(entrants.length,1);
 const advance=path.join(f.stateDir,'advance.lock'),guard=path.join(f.stateDir,'gateway-runtime-recovery.lock');
 const advanceBytes=fs.readFileSync(advance,'utf8'),guardBytes=fs.readFileSync(guard,'utf8'),owner=JSON.parse(advanceBytes);
 assert.equal(owner.pid,Number(entrants[0].slice('entered-'.length)));assert.match(owner.token,/^[a-f0-9]{64}$/);
 assert.throws(()=>recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId,authorize:true},quiet),/busy_or_interrupted_lock/);
 assert.equal(fs.readFileSync(advance,'utf8'),advanceBytes);assert.equal(fs.readFileSync(guard,'utf8'),guardBytes);
 assert.equal(readGatewayRuntimeChange({stateDir:f.stateDir}).status,'recovery_required');
 fs.writeFileSync(finish,'release');const results=await Promise.all(runs);
 assert.deepEqual(results.map(result=>result.code).sort(),[0,2],JSON.stringify(results));
 assert.match(results.find(result=>result.code===2).stdout,/busy_or_interrupted_lock/);
 assert.equal(JSON.parse(results.find(result=>result.code===0).stdout).status,'recovered');
 assert.equal(fs.existsSync(advance),false);assert.equal(fs.existsSync(guard),false);assert.equal(readGatewayRuntime(f.runtime).version,'1.0.0');f.preserved();
});
test('foreign or interrupted recovery guard is preserved and exposed after recovery completion',t=>{
 const f=interruptedFixture(t),guard=path.join(f.stateDir,'gateway-runtime-recovery.lock');
 fs.writeFileSync(guard,'foreign or interrupted owner\n',{mode:0o600});
 assert.throws(()=>recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:f.transactionId,authorize:true},quiet),/busy_or_interrupted_lock/);
 assert.equal(fs.readFileSync(guard,'utf8'),'foreign or interrupted owner\n');assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),false);
 assert.equal(readGatewayRuntimeChange({stateDir:f.stateDir}).recoveryGuard,'present_requires_owner_inspection');
 fs.unlinkSync(guard);recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:f.transactionId,authorize:true},quiet);
 fs.writeFileSync(guard,'interrupted cleanup\n',{mode:0o600});assert.equal(readGatewayRuntimeChange({stateDir:f.stateDir}).status,'recovery_required');
});
for(const target of ['advance.lock','gateway-runtime-recovery.lock'])test('recovery release preserves replaced '+target,t=>{
 const f=interruptedFixture(t),file=path.join(f.stateDir,target);let replaced=false;
 assert.throws(()=>recoverGatewayRuntimeChange({stateDir:f.stateDir,transactionId:f.transactionId,authorize:true},{observeQuiescence(){
  if(!replaced){replaced=true;const replacement=file+'.replacement';fs.writeFileSync(replacement,fs.readFileSync(file),{mode:0o600});fs.renameSync(replacement,file);}
  return {service:'not_installed',processes:'none'};
 }}),/lock_ownership_changed/);
 assert.equal(fs.existsSync(file),true);assert.match(JSON.parse(fs.readFileSync(file,'utf8')).token,/^[a-f0-9]{64}$/);f.preserved();
});
test('update release preserves a foreign replacement instead of unlinking another owner lock',t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle}),file=path.join(f.stateDir,'advance.lock');
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},{...quiet,afterCheckpoint(stage){if(stage==='prepared'){
  fs.unlinkSync(file);fs.writeFileSync(file,'foreign owner\n',{mode:0o600});throw Error('stop fixture');
 }}}),/lock_ownership_changed/);
 assert.equal(fs.readFileSync(file,'utf8'),'foreign owner\n');f.preserved();
});

test('an unexplained recovery guard without any journal never projects clean state or permits a fresh update',t=>{
 const f=fixture(t),plan=planGatewayRuntimeChange({stateDir:f.stateDir,bundle:f.second.bundle}),guard=path.join(f.stateDir,'gateway-runtime-recovery.lock');
 fs.writeFileSync(guard,'unknown owner\n',{mode:0o600});
 const status=readGatewayRuntimeChange({stateDir:f.stateDir});assert.equal(status.status,'recovery_required');assert.equal(status.recoveryGuard,'present_requires_owner_inspection');
 assert.throws(()=>applyGatewayRuntimeChange({stateDir:f.stateDir,plan,authorize:true},quiet),/busy_or_interrupted_lock/);
 assert.equal(fs.readFileSync(guard,'utf8'),'unknown owner\n');assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),false);
 assert.equal(readGatewayRuntime(f.runtime).version,'1.0.0');f.preserved();
});
