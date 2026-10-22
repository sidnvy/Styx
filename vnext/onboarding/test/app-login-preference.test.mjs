import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createDeployment,readDeploymentAppLoginPreference,changeDeploymentAppLoginPreference,reconcileDeploymentAppLoginPreference} from '../core.mjs';
import {readDeploymentAppLifecycle,controlDeploymentAppLifecycle} from '../app-lifecycle.mjs';
import {writePrivateFile} from '../../host/private-storage.mjs';

function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-app-login-'));fs.chmodSync(root,0o700);
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const input=path.join(root,'input.json'),stateDir=path.join(root,'deployment');
 const config={schema:1,mode:'join-existing',gateway:{url:'https://gateway.test:8443'},invitationFile:path.join(root,'invitation.json'),host:{bundle:path.join(root,'bundle'),publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'host'),label:'Test',computer:false}};
 writePrivateFile(input,JSON.stringify(config));createDeployment(input,{stateDir});
 const original=fs.readFileSync(path.join(stateDir,'deployment.json'));
 return {root,stateDir,original};
}
test('App and CLI lifecycle facade share one preference, keeping OS registration separate from readiness',async t=>{
 const f=fixture(t);let present=false,mutations=0;
 const registration={schema:1,kind:'windows-startup-shortcut',stateDir:f.stateDir};
 const windowsAdapter={
  readWindowsAppLogin:async({registration:stored,trustedApp})=>{
   if(stored)assert.deepEqual(stored,registration);
   return {schema:1,status:present?'registered_unverified':'not_registered',systemApproval:'unknown',registration:{present,owned:present,targetMatches:present},reconciledRegistration:registration};
  },
  planWindowsAppLogin:async({enabled})=>({action:enabled?'create':'remove',registration}),
  controlWindowsAppLogin:async plan=>{
   mutations++;assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),true);
   const intent=readDeploymentAppLoginPreference(f.stateDir);assert.equal(intent.lastOperation.status,'running');
   present=plan.action==='create';return windowsAdapter.readWindowsAppLogin({registration});
  }
 };
 const trusted={trustedWindowsApp:{resourceRoot:f.root,authority:{source:'current_windows_native_app'}},operations:{platform:'win32',windowsAdapter}};
 const result=await controlDeploymentAppLifecycle(f.stateDir,{action:'login',authorize:true,enabled:true},trusted);
 assert.equal(result.desiredEnabled,true);assert.equal(result.systemApproval,'unknown');assert.equal(result.status,'registered_unverified');
 assert.equal('reconciledRegistration' in result,false);
 const cli=await readDeploymentAppLifecycle(f.stateDir,{operations:trusted.operations});
 assert.deepEqual(cli,result);assert.equal(mutations,1);
 // Deleting the OS entry is observed; a desired preference does not recreate it.
 present=false;
 const deleted=await readDeploymentAppLifecycle(f.stateDir,trusted);
 assert.equal(deleted.desiredEnabled,true);assert.equal(deleted.status,'not_registered');assert.equal(mutations,1);
 await controlDeploymentAppLifecycle(f.stateDir,{action:'quit',authorize:true},trusted);
 assert.equal(mutations,1);assert.equal(readDeploymentAppLoginPreference(f.stateDir).desiredEnabled,true);
 assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'deployment.json')),f.original);
});
test('failed OS write retains intent without read-time replay; an explicit retry re-observes the plan',async t=>{
 const f=fixture(t);let attempts=0,plans=0;
 const ops={plan:previous=>{plans++;return {action:'create',registration:{schema:1}}},apply:()=>{attempts++;throw Error('native_write_unconfirmed')}};
 await assert.rejects(changeDeploymentAppLoginPreference(f.stateDir,{authorize:true,enabled:true},ops),/native_write_unconfirmed/);
 assert.equal(readDeploymentAppLoginPreference(f.stateDir).lastOperation.status,'needs_attention');
 const observed=await readDeploymentAppLifecycle(f.stateDir,{operations:{platform:'win32',windowsAdapter:{readWindowsAppLogin:async()=>({status:'registered_unverified',registration:{present:true,owned:true,targetMatches:true}})}}});
 assert.equal(observed.status,'needs_attention');assert.equal(observed.registration.present,true);
 assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),false);assert.equal(attempts,1);
 ops.apply=()=>{attempts++;return {status:'registered_unverified'}};
 const result=await changeDeploymentAppLoginPreference(f.stateDir,{authorize:true,enabled:true},ops);
 assert.equal(result.preference.lastOperation.status,'succeeded');assert.equal(attempts,2);assert.equal(plans,2);
 assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'deployment.json')),f.original);
});
test('a concurrent management operation or request-supplied adapter cannot write login preferences',async t=>{
 const f=fixture(t);const before=fs.readFileSync(path.join(f.stateDir,'state.json'));let calls=0;
 const ops={plan:()=>{calls++;return {action:'none',registration:null}},apply:()=>({})};
 await assert.rejects(changeDeploymentAppLoginPreference(f.stateDir,{authorize:true,enabled:true,registration:{}},ops),/invalid_configuration_fields/);
 writePrivateFile(path.join(f.stateDir,'advance.lock'),'foreign operation');
 await assert.rejects(changeDeploymentAppLoginPreference(f.stateDir,{authorize:true,enabled:true},ops),/busy_or_interrupted_lock/);
 assert.equal(calls,0);assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'state.json')),before);
});
test('native upgrade reconciliation preserves the desired choice and never retries an uncertain operation',async t=>{
 const f=fixture(t),old={schema:1,packageSha256:'a'.repeat(64)},current={schema:1,packageSha256:'b'.repeat(64)};
 await changeDeploymentAppLoginPreference(f.stateDir,{authorize:true,enabled:false},{plan:()=>({action:'none',registration:old}),apply:()=>({status:'not_registered'})});
 let reads=0;
 const result=await reconcileDeploymentAppLoginPreference(f.stateDir,previous=>{
  reads++;assert.equal(previous.desiredEnabled,false);assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),true);return current;
 });
 assert.equal(result.status,'reconciled');
 assert.equal(readDeploymentAppLoginPreference(f.stateDir).desiredEnabled,false);
 assert.deepEqual(readDeploymentAppLoginPreference(f.stateDir).registration,current);
 await assert.rejects(changeDeploymentAppLoginPreference(f.stateDir,{authorize:true,enabled:true},{plan:()=>({action:'create',registration:current}),apply:()=>{throw Error('unconfirmed')}}),/unconfirmed/);
 assert.equal((await reconcileDeploymentAppLoginPreference(f.stateDir,()=>{reads++;return old})).status,'needs_attention');
 assert.equal(reads,1);assert.deepEqual(readDeploymentAppLoginPreference(f.stateDir).registration,current);
 assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'deployment.json')),f.original);
});
