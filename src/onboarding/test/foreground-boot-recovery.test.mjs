import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {ensurePrivateDirectory,writePrivateFile} from '../../host/private-storage.mjs';
import {deploymentConnectionHash} from '../../shared/deployment-scope.mjs';
import {recordForegroundOwner,recoverForegroundAfterBoot,planLegacyForegroundRecovery,applyLegacyForegroundRecovery,currentForegroundBoot} from '../foreground-boot-recovery.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(t,{legacy=false,appOwned=true}={}){
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'styx-boot-'));fs.chmodSync(d,0o700);t.after(()=>fs.rmSync(d,{recursive:true,force:true}));
 const base=path.join(d,'host');ensurePrivateDirectory(base);ensurePrivateDirectory(path.join(base,'device'));
 writePrivateFile(path.join(base,'device/identity.json'),JSON.stringify({device_id:'test-device',fingerprint:'unchanged'}));
 writePrivateFile(path.join(base,'device/host.token'),'preserve-token');
 writePrivateFile(path.join(d,'deployment.json'),JSON.stringify({mode:'join-existing',gateway:{url:'https://localhost:1234'},host:{baseDir:base}}));
 const configurationHash=deploymentConnectionHash(fs.readFileSync(path.join(d,'deployment.json'))),token='a'.repeat(64);
 writePrivateFile(path.join(d,'foreground.lock'),token);
 const oldBoot={platform:'fixture',id:'old',startedAt:Date.now()-100000},newBoot={platform:'fixture',id:'new',startedAt:Date.now()+5000};
 if(!legacy)recordForegroundOwner(d,{configurationHash,appOwned,bootProof:oldBoot});
 writePrivateFile(path.join(d,'foreground-observer.json'),JSON.stringify({schema:1,pid:process.pid,configurationHash,lock:{ino:32932572275745908,dev:2853196016,sha256:sha(token)}}));
 const identity=fs.readFileSync(path.join(base,'device/identity.json')),credentials=fs.readFileSync(path.join(base,'device/host.token'));
 return {d,base,configurationHash,oldBoot,newBoot,options:{configurationHash,appOwned:true,bootProof:newBoot,isAlive:()=>false},preserved(){assert.deepEqual(fs.readFileSync(path.join(base,'device/identity.json')),identity);assert.deepEqual(fs.readFileSync(path.join(base,'device/host.token')),credentials)}};
}
test('different boot retires only exact App-owned files; retains unknown outcome and identity',t=>{
 const f=fixture(t),result=recoverForegroundAfterBoot(f.d,f.options);assert.equal(result.status,'retired_previous_boot_owner');f.preserved();
 const archive=path.join(f.d,'foreground-recovery',result.transactionId),receipt=JSON.parse(fs.readFileSync(path.join(archive,'receipt.json')));
 assert.equal(receipt.previousWorkOutcome,'unknown_not_replayed');assert.equal(receipt.status,'retired');
 for(const name of ['foreground.lock','foreground-owner.json','foreground-observer.json']){assert.equal(fs.existsSync(path.join(f.d,name)),false);assert.deepEqual(fs.readFileSync(path.join(archive,name+'.before')),fs.readFileSync(path.join(archive,name+'.retired')))}
 assert.equal(fs.existsSync(path.join(f.d,'foreground-recovery.lock')),false);
});
for(const kind of ['same_boot','alive','independent','changed_lock','missing_boot','newer_file'])test('automatic recovery rejects '+kind,t=>{
 const f=fixture(t,{appOwned:kind!=='independent'});let opts={...f.options};
 if(kind==='same_boot')opts.bootProof=f.oldBoot;
 if(kind==='alive')opts.isAlive=()=>true;
 if(kind==='changed_lock')fs.writeFileSync(path.join(f.d,'foreground.lock'),'b'.repeat(64));
 if(kind==='missing_boot')opts.bootProof=null;
 if(kind==='newer_file')fs.utimesSync(path.join(f.d,'foreground.lock'),new Date(f.newBoot.startedAt+1000),new Date(f.newBoot.startedAt+1000));
 assert.throws(()=>recoverForegroundAfterBoot(f.d,opts),/owned_or_interrupted/);assert.equal(fs.existsSync(path.join(f.d,'foreground.lock')),true);f.preserved();
});
test('legacy unsafe file ID is never automatic; explicit exact plan archives original bytes',t=>{
 const f=fixture(t,{legacy:true});assert.throws(()=>recoverForegroundAfterBoot(f.d,f.options),/legacy_owner_requires_authorized_maintenance/);
 const observations={bootProof:f.newBoot,isAlive:()=>false},plan=planLegacyForegroundRecovery(f.d,observations);
 assert.equal(typeof plan.files[0].ino,'string');assert.equal(plan.requiresExplicitAuthorization,true);
 assert.throws(()=>applyLegacyForegroundRecovery(f.d,{plan},observations),/authorization_required/);
 const done=applyLegacyForegroundRecovery(f.d,{authorize:true,plan},observations);assert.equal(done.status,'retired_previous_boot_owner');f.preserved();
});
for(const changed of ['lock','identity','boot','alive'])test('legacy approved plan rejects changed '+changed,t=>{
 const f=fixture(t,{legacy:true}),observations={bootProof:f.newBoot,isAlive:()=>false},plan=planLegacyForegroundRecovery(f.d,observations);
 if(changed==='lock')fs.writeFileSync(path.join(f.d,'foreground.lock'),'c'.repeat(64));
 if(changed==='identity')fs.writeFileSync(path.join(f.base,'device/identity.json'),JSON.stringify({device_id:'replacement'}));
 if(changed==='boot')observations.bootProof={...f.newBoot,id:'another'};
 if(changed==='alive')observations.isAlive=()=>true;
 assert.throws(()=>applyLegacyForegroundRecovery(f.d,{authorize:true,plan},observations),/plan_changed|evidence_insufficient/);assert.equal(fs.existsSync(path.join(f.d,'foreground.lock')),true);
});
test('interrupted recovery guard is retained and blocks further ownership changes',t=>{
 const f=fixture(t);writePrivateFile(path.join(f.d,'foreground-recovery.lock'),'interrupted');
 assert.throws(()=>recoverForegroundAfterBoot(f.d,f.options),/requires_review/);f.preserved();
});
test('native boot observation is a bounded stable read',()=>{const value=currentForegroundBoot();assert.ok(value);assert.equal(value.platform,process.platform);assert.ok(value.startedAt<=Date.now());assert.equal(currentForegroundBoot(),value)});
test('lock changes during final owner check stop retirement and preserve review guard',t=>{
 const f=fixture(t);let calls=0;
 assert.throws(()=>recoverForegroundAfterBoot(f.d,{...f.options,isAlive(){if(++calls===2)fs.writeFileSync(path.join(f.d,'foreground.lock'),'changed');return false}}),/file_changed/);
 assert.equal(fs.existsSync(path.join(f.d,'foreground-recovery.lock')),true);assert.equal(fs.readFileSync(path.join(f.d,'foreground.lock'),'utf8'),'changed');f.preserved();
});
