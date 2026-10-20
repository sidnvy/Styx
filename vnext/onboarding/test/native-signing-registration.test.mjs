import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {ensurePrivateDirectory,writePrivateFile,requirePrivateFile} from '../../host/private-storage.mjs';
import {createDeployment,readDeployment,setDeploymentOnboardingPreference,readDeploymentOnboardingPreference,
 planDeploymentMacSigningRegistration as plan,applyDeploymentMacSigningRegistration as apply,
 rollbackDeploymentMacSigningRegistration as rollback} from '../core.mjs';
import {main} from '../cli.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const oldApp={path:'/Applications/Styx.app',cdhash:'a'.repeat(40)};
const app={path:oldApp.path,cdhash:'b'.repeat(40),certificateSha1:'c'.repeat(40),certificateSha256:'d'.repeat(64)};
const verifyApp=value=>({...value,trust:'local_certificate_preview_not_notarized'});
const read=file=>JSON.parse(fs.readFileSync(file));
const save=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{mode:0o600});
function fixture(t,{registered=oldApp,auxiliary=true}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-signing-registration-'));ensurePrivateDirectory(root);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const input=path.join(root,'input.json'),d=path.join(root,'deployment');
 writePrivateFile(input,JSON.stringify({schema:1,mode:'join-existing',gateway:{url:'https://gateway.example.invalid'},host:{bundle:path.join(root,'bundle'),publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'e'.repeat(64),baseDir:path.join(root,'host'),label:'Existing enrolled device',computer:false,macPreviewApp:registered}}));
 createDeployment(input,{stateDir:d});setDeploymentOnboardingPreference(d,{background:'foreground',authorize:true});
 // Real Core-created deployment, preserved runtime records are inert fixtures.
 const device=path.join(root,'host/device');ensurePrivateDirectory(path.dirname(device));ensurePrivateDirectory(device);
 const preserved=[['identity.json','{"device_id":"existing","fingerprint":"preserved"}'],['identity.pem','fixture-private-identity'],['host.token','fixture-private-token'],['host.json','{"host_id":"existing","computer":{"enabled":false}}']].map(([name,data])=>{const file=path.join(device,name);writePrivateFile(file,data);return [file,fs.readFileSync(file)];});
 if(auxiliary)for(const name of ['background','capabilities'])writePrivateFile(path.join(d,name+'.json'),JSON.stringify({schema:1,configSha256:read(path.join(d,'state.json')).configSha256,status:'not_configured',operations:[],retainedEvidence:'historical_not_current'}));
 const files=['deployment','state',...(auxiliary?['background','capabilities']:[])].map(name=>path.join(d,name+'.json'));
 return {root,d,preserved,files,before:files.map(file=>fs.readFileSync(file))};
}
function assertPreserved(f){for(const [file,bytes]of f.preserved)assert.deepEqual(fs.readFileSync(file),bytes);}

test('real Core registration plan is read-only; authorized apply preserves roles, identity and background choice; rollback restores exact bytes',t=>{
 const f=fixture(t);const stateFile=path.join(f.d,'state.json');
 // Noncanonical input formatting must still be restored byte-for-byte.
 fs.writeFileSync(stateFile,JSON.stringify(read(stateFile))+'  \n',{mode:0o600});f.before=f.files.map(file=>fs.readFileSync(file));
 const roles=readDeployment(f.d).roles;let verified=0;
 const adapters={verifyApp(value){verified++;return verifyApp(value)}};
 const p=plan(f.d,{app},adapters);assert.equal(verified,1);assert.equal(p.status,'reviewable');assert.equal(p.previousRegistration.cdhash,oldApp.cdhash);
 assert.equal(fs.existsSync(path.join(f.d,'mac-signing-registration.json')),false);
 f.files.forEach((file,i)=>assert.deepEqual(fs.readFileSync(file),f.before[i]));
 assert.throws(()=>apply(f.d,{plan:p},adapters),/explicit_mac_signing/);
 const result=apply(f.d,{plan:p,authorize:true},adapters);assert.equal(verified,2);assert.equal(result.status,'applied');
 const config=read(f.files[0]),state=read(f.files[1]);assert.deepEqual(config.host.macPreviewApp,app);
 assert.equal(state.configSha256,sha(fs.readFileSync(f.files[0])));assert.deepEqual(readDeployment(f.d).roles,roles);
 const expectedConfig=JSON.parse(f.before[0]);expectedConfig.host.macPreviewApp=app;assert.deepEqual(config,expectedConfig);
 const expectedState=JSON.parse(f.before[1]);expectedState.configSha256=state.configSha256;expectedState.onboardingDecisions.background.configSha256=state.configSha256;assert.deepEqual(state,expectedState);
 assert.deepEqual(readDeploymentOnboardingPreference(f.d),{background:'foreground',configurationBound:true});
 for(const file of f.files.slice(2))assert.equal(read(file).configSha256,state.configSha256);
 const journal=read(path.join(f.d,'mac-signing-registration.json'));assert.equal(journal.status,'applied');assert.equal(journal.phases[0].phase,'prepared');assert.equal(journal.phases.at(-1).phase,'applied');requirePrivateFile(path.join(f.d,'mac-signing-registration.json'));
 assert.equal(JSON.stringify(p).includes('fixture-private'),false);assertPreserved(f);
 assert.throws(()=>rollback(f.d,{}),/explicit_mac_signing/);assert.equal(rollback(f.d,{authorize:true}).status,'rolled_back');
 f.files.forEach((file,i)=>assert.deepEqual(fs.readFileSync(file),f.before[i]));assertPreserved(f);
 assert.deepEqual(readDeploymentOnboardingPreference(f.d),{background:'foreground',configurationBound:true});
 assert.throws(()=>rollback(f.d,{authorize:true}),/rollback_not_available/);
});

test('registration permits same-certificate refresh and refuses certificate change, removal, alternate app path or failed verification',t=>{
 const f=fixture(t,{registered:app});
 const refreshed={...app,cdhash:'f'.repeat(40)},p=plan(f.d,{app:refreshed},{verifyApp});apply(f.d,{authorize:true,plan:p},{verifyApp});
 assert.equal(read(f.files[0]).host.macPreviewApp.cdhash,refreshed.cdhash);
 for(const change of [{certificateSha1:'1'.repeat(40)},{certificateSha256:'2'.repeat(64)},{certificateSha1:undefined},{certificateSha256:undefined},{path:'/tmp/Styx.app'}])assert.throws(()=>plan(f.d,{app:{...refreshed,...change}},{verifyApp}));
 assert.throws(()=>plan(f.d,{app:refreshed},{verifyApp(){throw Error('native_signature_invalid')}}),/native_signature_invalid/);
 assert.throws(()=>plan(f.d,{app:refreshed},{verifyApp:v=>({...verifyApp(v),cdhash:'3'.repeat(40)})}),/verification_changed/);
 assert.throws(()=>plan(f.d,{app:{...refreshed,trust:'model_claim'}},{verifyApp}),/invalid_configuration_fields/);
 assertPreserved(f);
});

test('stale or edited plans and concurrent management locks refuse before registration writes',t=>{
 const f=fixture(t),p=plan(f.d,{app},{verifyApp});
 for(const bad of [{...p,app:{...app,certificateSha1:'f'.repeat(40)}},{...p,configSha256:'f'.repeat(64)},{...p,scope:'all_roles'}])assert.throws(()=>apply(f.d,{authorize:true,plan:bad},{verifyApp}),/plan_changed/);
 fs.appendFileSync(f.files[1],' ');assert.throws(()=>apply(f.d,{authorize:true,plan:p},{verifyApp}),/plan_changed/);
 assert.equal(fs.existsSync(path.join(f.d,'mac-signing-registration.json')),false);
 const p2=plan(f.d,{app},{verifyApp});writePrivateFile(path.join(f.d,'capabilities.lock'),'foreign lock');
 assert.throws(()=>apply(f.d,{authorize:true,plan:p2},{verifyApp}),/management_busy/);fs.unlinkSync(path.join(f.d,'capabilities.lock'));
 writePrivateFile(path.join(f.d,'advance.lock'),'foreign lock');assert.throws(()=>apply(f.d,{authorize:true,plan:p2},{verifyApp}),/busy_or_interrupted/);
 assert.equal(fs.existsSync(path.join(f.d,'mac-signing-registration.json')),false);assertPreserved(f);
});

for(const phase of ['prepared','written_deployment','written_state','written_background'])test('interruption at '+phase+' fails closed and explicit rollback restores every original file',t=>{
 const f=fixture(t),p=plan(f.d,{app},{verifyApp});
 assert.throws(()=>apply(f.d,{authorize:true,plan:p},{verifyApp,onPhase(value){if(value===phase)throw Error('simulated_interruption')}}),/simulated_interruption/);
 assert.equal(fs.existsSync(path.join(f.d,'advance.lock')),true);assert.throws(()=>readDeployment(f.d),/requires_rollback/);
 assert.throws(()=>plan(f.d,{app},{verifyApp}),/busy_or_interrupted/);
 assert.throws(()=>apply(f.d,{authorize:true,plan:p},{verifyApp}),/busy_or_interrupted/);
 assert.equal(rollback(f.d,{authorize:true}).status,'rolled_back');
 assert.equal(fs.existsSync(path.join(f.d,'advance.lock')),false);f.files.forEach((file,i)=>assert.deepEqual(fs.readFileSync(file),f.before[i]));assertPreserved(f);readDeployment(f.d);
});

test('rollback refuses unrelated drift or a foreign/unknown recovery owner',t=>{
 const f=fixture(t),p=plan(f.d,{app},{verifyApp});apply(f.d,{authorize:true,plan:p},{verifyApp});
 const appliedState=fs.readFileSync(f.files[1]);fs.appendFileSync(f.files[1],' ');assert.throws(()=>rollback(f.d,{authorize:true}),/rollback_scope_changed/);
 assert.equal(read(path.join(f.d,'mac-signing-registration.json')).status,'applied');fs.writeFileSync(f.files[1],appliedState);
 writePrivateFile(path.join(f.d,'advance.lock'),JSON.stringify({kind:'foreign',token:'unknown'}));assert.throws(()=>rollback(f.d,{authorize:true}),/foreign_lock/);fs.unlinkSync(path.join(f.d,'advance.lock'));
 const journal=read(path.join(f.d,'mac-signing-registration.json'));writePrivateFile(path.join(f.d,'advance.lock'),JSON.stringify({...journal.owner}));
 assert.throws(()=>rollback(f.d,{authorize:true}),/owner_still_running/);assertPreserved(f);
});

test('a real child process exit between configuration and state writes requires explicit dead-owner rollback',{skip:process.platform==='win32'},t=>{
 const f=fixture(t),p=plan(f.d,{app},{verifyApp}),planFile=path.join(f.root,'reviewed-plan.json');writePrivateFile(planFile,JSON.stringify(p));
 const script=`import fs from 'node:fs';import {applyDeploymentMacSigningRegistration as apply} from ${JSON.stringify(new URL('../core.mjs',import.meta.url).href)};apply(${JSON.stringify(f.d)},{authorize:true,plan:JSON.parse(fs.readFileSync(${JSON.stringify(planFile)}))},{verifyApp:a=>({...a,trust:'local_certificate_preview_not_notarized'}),onPhase:p=>{if(p==='written_deployment')process.exit(77)}});`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',script],{encoding:'utf8',timeout:10000});assert.equal(child.status,77,child.stderr);
 assert.throws(()=>readDeployment(f.d),/requires_rollback/);assert.equal(rollback(f.d,{authorize:true}).status,'rolled_back');
 f.files.forEach((file,i)=>assert.deepEqual(fs.readFileSync(file),f.before[i]));assertPreserved(f);
});

test('CLI exposes only fixed explicit registration verbs and default native verification remains enabled',async t=>{
 const f=fixture(t),appFile=path.join(f.root,'app.json');writePrivateFile(appFile,JSON.stringify(app));
 assert.ok((await main(['help'])).commands.includes('mac-signing-plan STATE PRIVATE_APP_JSON'));
 await assert.rejects(main(['mac-signing-apply',f.d,appFile]),/usage_/);await assert.rejects(main(['mac-signing-rollback',f.d]),/usage_/);
 if(process.platform!=='darwin')await assert.rejects(main(['mac-signing-plan',f.d,appFile]),/invalid_adhoc_preview_trust/);
 const p=plan(f.d,{app},{verifyApp});apply(f.d,{authorize:true,plan:p},{verifyApp});assert.equal((await main(['mac-signing-rollback',f.d,'--authorize'])).status,'rolled_back');
 assertPreserved(f);
});
