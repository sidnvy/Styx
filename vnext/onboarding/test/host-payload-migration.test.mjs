import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {stageSignedRelease,activateRelease,refreshVerifiedBootstrap,activeRelease} from '../../host/installer.mjs';
import {planHostPayloadMigration,applyHostPayloadMigration,rollbackHostPayloadMigration,readHostPayloadMigration} from '../host-payload-migration.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const key=()=>generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const pin=k=>sha(k.publicKey.export({type:'spki',format:'der'}));
const put=(p,data,mode=0o600)=>{fs.mkdirSync(path.dirname(p),{recursive:true,mode:0o700});fs.writeFileSync(p,typeof data==='object'&&!Buffer.isBuffer(data)?JSON.stringify(data,null,2)+'\n':data,{mode});};
const json=p=>JSON.parse(fs.readFileSync(p));
const opts={platform:'darwin',arch:process.arch};
function fixture(t,{cross=false}={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-payload-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const stateDir=path.join(dir,'deployment'),base=path.join(dir,'host'),root=path.join(base,'install'),app=path.join(dir,'Styx.app'),oldKey=key(),nextKey=cross?key():oldKey;
 function bundle(directory,version,k){
  const names=['private-storage','installer','launch','connect','enroll','setup-native','doctor','macos-launchagent','macos-native-launcher'].map(n=>'host/'+n+'.mjs').concat(['bin/node','bin/codex','bin/cua-driver']);
  const files=names.map(name=>{const content=Buffer.from(version+' '+name+'\n');put(path.join(directory,name),content,name.startsWith('bin/')?0o700:0o600);return {path:name,sha256:sha(content),size:content.length,executable:name.startsWith('bin/')};});
  const raw=Buffer.from(JSON.stringify({schema:1,version,platform:'darwin',arch:process.arch,files})+'\n');put(path.join(directory,'manifest.json'),raw);put(path.join(directory,'manifest.sig'),sign(null,raw,k.privateKey).toString('base64url')+'\n');return directory;
 }
 const old=bundle(path.join(dir,'old'),'0.1.0-old',oldKey),candidate=bundle(cross?path.join(app,'Contents/Resources/host-bundle'):path.join(dir,'candidate'),'0.2.0-next',nextKey);
 fs.mkdirSync(base,{mode:0o700});stageSignedRelease({sourceDir:old,installRoot:root,publicKeyPem:pem(oldKey),...opts});activateRelease(root,'0.1.0-old',pem(oldKey),opts);refreshVerifiedBootstrap(root,pem(oldKey),'0.1.0-old',opts);
 const registration={path:app,cdhash:'a'.repeat(40),certificateSha1:'b'.repeat(40),certificateSha256:'c'.repeat(64)};
 put(path.join(app,'Contents/Resources/artifact-defaults.json'),{bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256:pin(nextKey)});put(path.join(app,'Contents/Resources/publisher.pem'),pem(nextKey));
 const config={schema:1,mode:'join-existing',gateway:{url:'https://gateway.example'},host:{bundle:old,publisherKeyFile:path.join(base,'publisher.pem'),publisherSha256:pin(oldKey),baseDir:base,label:'Test Mac',computer:false,macPreviewApp:registration}};
 const service={installRoot:root,hostConfigFile:path.join(base,'device/host.json'),trustPublicKeyFile:path.join(base,'publisher.pem'),nodeBinary:path.join(root,'releases/0.1.0-old/bin/node'),label:'app.styx.connector',logDir:path.join(base,'logs')};
 const receipt={schema:1,status:'prepared_not_paired',version:'0.1.0-old',publisher_sha256:pin(oldKey),node:service.nodeBinary,release_root:path.join(root,'releases/0.1.0-old'),enrollment_config:path.join(base,'enrollment.json'),service_config:path.join(base,'service.json'),pairing:'NOT RUN',service_install:'NOT RUN',native_permissions:'NOT RUN'};
 put(path.join(stateDir,'deployment.json'),config);put(path.join(base,'service.json'),service);put(path.join(base,'setup-receipt.json'),receipt);put(path.join(base,'publisher.pem'),pem(oldKey));
 const identity=key();put(path.join(base,'device/identity.pem'),identity.privateKey.export({type:'pkcs8',format:'pem'}));put(path.join(base,'device/identity.json'),{version:1,device_id:'styx-test',fingerprint:pin(identity)});put(path.join(base,'device/host.token'),'PRIVATE_TEST_TOKEN');put(path.join(base,'device/host.json'),{host_id:'styx-test',gateway_ws_url:'wss://gateway.example/',token_file:path.join(base,'device/host.token'),exec:{binary:path.join(root,'releases/0.1.0-old/bin/codex'),cwd:base}});
 put(path.join(base,'enrollment.json'),{gateway_url:config.gateway.url,storage_dir:path.join(base,'device')});put(path.join(base,'setup-state.json'),{schema:1,status:'preparing',version:'0.1.0-old'});
 const configSha256=sha(fs.readFileSync(path.join(stateDir,'deployment.json'))),evidenceFile=p=>({path:p,sha256:sha(fs.readFileSync(p))});
 put(path.join(stateDir,'state.json'),{schema:1,mode:config.mode,configSha256,steps:[{id:'host.prepare',status:'succeeded',evidence:{...receipt,receipt:evidenceFile(path.join(base,'setup-receipt.json')),serviceConfiguration:evidenceFile(path.join(base,'service.json'))}},{id:'host.claim',status:'succeeded',evidence:{hostConfiguration:evidenceFile(service.hostConfigFile)}},{id:'host.doctor',status:'succeeded',evidence:{healthy:true}},{id:'host.service.install',status:'pending'}],onboardingDecisions:{background:{configSha256}}});
 put(path.join(stateDir,'background.json'),{schema:1,configSha256,status:'disabled'});put(path.join(stateDir,'capabilities.json'),{schema:1,configSha256,status:'applied'});
 const adapters={platform:'darwin',observeAbsence:async()=>({status:'absent'}),verifyApp:value=>({...value,cdhash:'d'.repeat(40),trust:'local_certificate_preview_not_notarized'})};
 return {dir,stateDir,base,root,app,config,candidate,oldKey,nextKey,adapters,bundle};
}
async function reviewed(f){const plan=await planHostPayloadMigration({stateDir:f.stateDir,bundle:f.candidate},f.adapters);const before=new Map([...plan.changes,...plan.preserved].map(x=>[x.path,fs.readFileSync(x.path)]));return {plan,before};}
function unchanged(before){for(const [p,b]of before)assert.deepEqual(fs.readFileSync(p),b,p);}
async function rollback(f,id){return rollbackHostPayloadMigration({stateDir:f.stateDir,transactionId:id,authorize:true},f.adapters);}
for(const cross of [false,true])test(`${cross?'registered certificate publisher transition':'same publisher'} apply and explicit rollback retain exact identity/config bytes`,async t=>{
 const f=fixture(t,{cross}),{plan,before}=await reviewed(f);assert.equal(plan.status,'offline_reviewable');assert.equal(plan.publisherChange,cross);assert.doesNotMatch(JSON.stringify(plan),/PRIVATE_TEST_TOKEN|PRIVATE KEY/);
 const result=await applyHostPayloadMigration({stateDir:f.stateDir,plan,authorize:true},f.adapters);assert.equal(result.status,'applied_stopped');assert.equal(result.nativeHealth,'NOT RUN');assert.equal(activeRelease(f.root,pem(f.nextKey),opts).version,'0.2.0-next');
 const config=json(path.join(f.stateDir,'deployment.json')),state=json(path.join(f.stateDir,'state.json'));assert.equal(config.host.publisherSha256,pin(f.nextKey));assert.equal(state.steps[0].evidence.publisher_sha256,pin(f.nextKey));assert.equal(state.configSha256,sha(fs.readFileSync(path.join(f.stateDir,'deployment.json'))));assert.equal(json(path.join(f.base,'service.json')).nodeBinary,path.join(f.root,'node'));assert.equal(state.steps.find(s=>s.id==='host.doctor').status,'pending');assert.equal(state.steps[0].evidence.serviceConfiguration.sha256,sha(fs.readFileSync(path.join(f.base,'service.json'))));assert.equal(fs.readFileSync(path.join(f.base,'device/host.token'),'utf8'),'PRIVATE_TEST_TOKEN');assert.equal(json(path.join(f.root,'active.json')).previous,null);
 const publicStatus=readHostPayloadMigration({stateDir:f.stateDir});assert.equal(publicStatus.status,'applied');assert.equal(publicStatus.files,undefined);assert.equal(publicStatus.plan,undefined);
 assert.equal((await rollback(f,result.transactionId)).status,'rolled_back_stopped');unchanged(before);assert.equal(activeRelease(f.root,pem(f.oldKey),opts).version,'0.1.0-old');
});
test('cross publisher requires registered same certificate and exact sealed App resource',async t=>{
 const f=fixture(t,{cross:true});const other=f.bundle(path.join(f.dir,'other'),'0.3.0-other',f.nextKey);
 await assert.rejects(planHostPayloadMigration({stateDir:f.stateDir,bundle:other},f.adapters),/registered_app_resource/);
 await assert.rejects(planHostPayloadMigration({stateDir:f.stateDir,bundle:f.candidate},{...f.adapters,verifyApp:v=>({...v,certificateSha256:'e'.repeat(64),trust:'local_certificate_preview_not_notarized'})}),/registered_certificate_changed/);
 await assert.rejects(planHostPayloadMigration({stateDir:f.stateDir,bundle:f.candidate},{...f.adapters,verifyApp:()=>{throw Error('signature_invalid')}}),/signature_invalid/);
 assert.equal(readHostPayloadMigration({stateDir:f.stateDir}).status,'not_started');
});
test('unknown native state, foreground owner, stale review and absent authorization refuse mutation',async t=>{
 const f=fixture(t),{plan,before}=await reviewed(f);
 await assert.rejects(applyHostPayloadMigration({stateDir:f.stateDir,plan},f.adapters),/authorization_required/);
 await assert.rejects(planHostPayloadMigration({stateDir:f.stateDir,bundle:f.candidate},{...f.adapters,observeAbsence:async()=>({status:'blocked'})}),/native_absence_required/);
 put(path.join(f.stateDir,'foreground.lock'),{});await assert.rejects(planHostPayloadMigration({stateDir:f.stateDir,bundle:f.candidate},f.adapters),/active_or_uncertain_owner/);fs.unlinkSync(path.join(f.stateDir,'foreground.lock'));
 const stale={...plan,planId:'0'.repeat(64)};await assert.rejects(applyHostPayloadMigration({stateDir:f.stateDir,plan:stale,authorize:true},f.adapters),/review_stale/);unchanged(before);
});
for(const phase of ['prepared','written_deployment','written_publisher','written_pointer','written_bootstrap_node','written_state'])test(`interruption at ${phase} retains recovery ownership and rolls back`,async t=>{
 const f=fixture(t,{cross:true}),{plan,before}=await reviewed(f);
 await assert.rejects(applyHostPayloadMigration({stateDir:f.stateDir,plan,authorize:true},{...f.adapters,onPhase:p=>{if(p===phase)throw Error('injected')}}),/explicit_rollback_required/);
 const j=readHostPayloadMigration({stateDir:f.stateDir});assert.equal(j.status,'uncertain');assert.ok(fs.existsSync(path.join(f.stateDir,'advance.lock')));await assert.rejects(planHostPayloadMigration({stateDir:f.stateDir,bundle:f.candidate},f.adapters),/management_busy/);
 await rollback(f,j.transactionId);unchanged(before);assert.ok(!fs.existsSync(path.join(f.stateDir,'advance.lock')));
});
test('actual updater process exit in write leaves durable journal and recoverable dead-owner locks',async t=>{
 const f=fixture(t,{cross:true}),{plan,before}=await reviewed(f),module=fileURLToPath(new URL('../host-payload-migration.mjs',import.meta.url));
 const script=`import {applyHostPayloadMigration} from ${JSON.stringify(module)};const input=JSON.parse(process.env.STYX_TEST_MIGRATION);await applyHostPayloadMigration(input,{platform:'darwin',observeAbsence:async()=>({status:'absent'}),verifyApp:v=>({...v,cdhash:'d'.repeat(40),trust:'local_certificate_preview_not_notarized'}),onPhase:p=>{if(p==='written_publisher')process.exit(73)}});`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',env:{...process.env,STYX_TEST_MIGRATION:JSON.stringify({stateDir:f.stateDir,plan,authorize:true})}});assert.equal(child.status,73,child.stderr);
 const j=readHostPayloadMigration({stateDir:f.stateDir});assert.equal(j.status,'writing');await rollback(f,j.transactionId);unchanged(before);
});
test('rollback refuses foreign changes and changed credentials rather than overwriting them',async t=>{
 const f=fixture(t),{plan}=await reviewed(f);const result=await applyHostPayloadMigration({stateDir:f.stateDir,plan,authorize:true},f.adapters);
 const file=path.join(f.base,'service.json'),original=fs.readFileSync(file);put(file,{foreign:true});await assert.rejects(rollback(f,result.transactionId),/rollback_scope_changed/);assert.deepEqual(json(file),{foreign:true});put(file,original);
 put(path.join(f.base,'device/host.token'),'CHANGED');await assert.rejects(rollback(f,result.transactionId),/preserved_state_changed/);assert.equal(fs.readFileSync(path.join(f.base,'device/host.token'),'utf8'),'CHANGED');
});
test('failed recovery preflight retains advance lock for old launchers and permits later explicit recovery',async t=>{
 const f=fixture(t),{plan,before}=await reviewed(f);
 await assert.rejects(applyHostPayloadMigration({stateDir:f.stateDir,plan,authorize:true},{...f.adapters,onPhase:p=>{if(p==='written_pointer')throw Error('interrupt')}}),/explicit_rollback/);
 const j=readHostPayloadMigration({stateDir:f.stateDir}),token=path.join(f.base,'device/host.token'),original=fs.readFileSync(token);put(token,'changed');
 await assert.rejects(rollback(f,j.transactionId),/rollback_interrupted/);assert.ok(fs.existsSync(path.join(f.stateDir,'advance.lock')));assert.equal(readHostPayloadMigration({stateDir:f.stateDir}).status,'uncertain');put(token,original);
 await rollback(f,j.transactionId);unchanged(before);
});

for(const phase of ['locked','snapshot_bootstrap_node'])test(`real process exit at ${phase} before journal is explicitly recoverable even after a previous transaction`,async t=>{
 const f=fixture(t,{cross:true}),first=await reviewed(f);
 const applied=await applyHostPayloadMigration({stateDir:f.stateDir,plan:first.plan,authorize:true},f.adapters);await rollback(f,applied.transactionId);
 const {plan,before}=await reviewed(f),module=fileURLToPath(new URL('../host-payload-migration.mjs',import.meta.url));
 const script=`import {applyHostPayloadMigration} from ${JSON.stringify(module)};await applyHostPayloadMigration(JSON.parse(process.env.STYX_TEST_MIGRATION),{platform:'darwin',observeAbsence:async()=>({status:'absent'}),verifyApp:v=>({...v,cdhash:'d'.repeat(40),trust:'local_certificate_preview_not_notarized'}),onPhase:p=>{if(p===${JSON.stringify(phase)})process.exit(74)}});`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',env:{...process.env,STYX_TEST_MIGRATION:JSON.stringify({stateDir:f.stateDir,plan,authorize:true})}});assert.equal(child.status,74,child.stderr);
 const current=readHostPayloadMigration({stateDir:f.stateDir});assert.equal(current.status,'capturing');assert.notEqual(current.transactionId,applied.transactionId);assert.ok(fs.existsSync(path.join(f.stateDir,'advance.lock')));unchanged(before);
 await rollback(f,current.transactionId);unchanged(before);assert.ok(!fs.existsSync(path.join(f.stateDir,'advance.lock')));
});
