import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {nativeHostStartupDecision} from '../native-host-startup.mjs';
import {createOnboardingServer} from '../server.mjs';

test('an interrupted, cancelled or rolled-back Host update is never replayed by App reopen',async()=>{
 const artifacts={bundle:'/test/bundle'},hash='a'.repeat(64);
 for(const status of ['preparing','awaiting_exit','blocked','needs_recovery','cancelled','rolled_back','unknown']){
  const decision=await nativeHostStartupDecision('/test/state',{artifacts,core:{readDeployment:()=>({steps:[{id:'host.claim',status:'succeeded'}]}),readDeploymentComponents:()=>({host:{status:'update_available',bundled:{manifestSha256:hash}}}),readHostPayloadHandoff:()=>({status})}});
  assert.equal(decision.automaticUpdate,false);assert.equal(decision.reason,'host_payload_requires_review');
 }
 const core={readDeployment:()=>({steps:[{id:'host.claim',status:'succeeded'}]}),readDeploymentComponents:()=>({host:{status:'update_available',bundled:{manifestSha256:hash}}}),readHostPayloadHandoff:()=>({status:'applied_stopped',target:{manifestSha256:hash}})};
 assert.equal((await nativeHostStartupDecision('/test/state',{artifacts,core})).automaticUpdate,false);
 core.readHostPayloadHandoff=()=>({status:'applied_stopped',target:{manifestSha256:'b'.repeat(64)}});
 assert.equal((await nativeHostStartupDecision('/test/state',{artifacts,core})).automaticUpdate,true);
 for(const status of ['publisher_changed','same_version_conflict','candidate_unverified','unavailable']){
  core.readDeploymentComponents=()=>({host:{status}});
  assert.equal((await nativeHostStartupDecision('/test/state',{artifacts,core})).automaticUpdate,false);
 }
});

test('native startup gates old Host execution and reconnect HTTP until bundle reconciliation, while quit remains available',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-startup-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const stateDir=path.join(root,'deployment');fs.mkdirSync(stateDir,{mode:0o700});fs.writeFileSync(path.join(stateDir,'deployment.json'),'{}',{mode:0o600});
 const artifactDefaultsFile=path.join(root,'artifacts.json');fs.writeFileSync(artifactDefaultsFile,JSON.stringify({bundle:path.join(root,'bundle'),publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64)}),{mode:0o600});
 let starts=0,prepares=0,component='update_available';
 const core={
  readDeployment:()=>({schema:1,mode:'join-existing',roles:{browser:'disabled'},steps:[{id:'host.prepare',status:'succeeded'},{id:'host.claim',status:'succeeded'},{id:'host.doctor',status:'succeeded'}]}),
  planDeployment:()=>({steps:[]}),
  readDeploymentComponents:()=>({host:{status:component,bundled:{manifestSha256:'a'.repeat(64)}}}),
  readHostPayloadHandoff:()=>({status:'not_started'}),
  prepareHostPayloadHandoff:()=>{prepares++;throw Error('must_not_install_during_observation');},
  startDeploymentForeground:()=>{starts++;},
  prepareDeploymentWorkAdmission:()=>({status:'ready',ticketId:'test-admission'}),
  commitDeploymentWorkAdmission:()=>({status:'ready'}),cancelDeploymentWorkAdmission:()=>{},
 };
 async function launch(){
  const instance=await createOnboardingServer({stateDir,artifactDefaultsFile,core,nativeAppAuthority:()=>({source:'current_windows_native_app'})});
  const token=new URL(instance.url).hash.slice('#session='.length),headers={Authorization:'Bearer '+token,Origin:instance.origin};
  const session=await(await fetch(instance.origin+'/api/session',{headers})).json();
  const post=route=>fetch(instance.origin+'/api/'+route,{method:'POST',headers:{...headers,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json'},body:JSON.stringify({authorize:true})});
  return{instance,post,read:route=>fetch(instance.origin+'/api/'+route,{headers})};
 }
 const pending=await launch();try{
  assert.equal(starts,0);assert.equal(prepares,0);
  const status=await(await pending.read('status')).json();assert.equal(status.nativeStartup.automaticUpdate,true);
  assert.equal(status.nativeStartup.reason,'host_payload_update_required');
  const reconnect=await pending.post('foreground');assert.equal(reconnect.status,409);assert.equal((await reconnect.json()).error,'host_payload_update_required');
  const quit=await pending.post('app/quit-admission');assert.equal(quit.status,200);
 }finally{await pending.instance.close();}
 // Once the installed signed generation agrees, the same launch path resumes
 // the prepared Host rather than sending the user through another setup step.
 component='aligned';const ready=await launch();try{assert.equal(starts,1);assert.equal(prepares,0);}finally{await ready.instance.close();}
});


test('enrollment precedes migration; a terminal preflight ticket permits joining but never auto replays',async()=>{
 const artifacts={bundle:'/test/bundle'};let status='uncertain',previous={status:'not_started'},components=0;
 const core={readDeployment:()=>({mode:'join-existing',steps:[{id:'host.prepare',status:'succeeded'},{id:'host.claim',status}]}),readHostPayloadHandoff:()=>previous,readDeploymentComponents:()=>{components++;return {host:{status:'update_available',bundled:{manifestSha256:'c'.repeat(64)}}};}};
 for(status of ['pending','awaiting_approval','blocked','uncertain']){
  for(previous of [{status:'not_started'},{status:'cancelled',phase:'preflight_only'}])
   assert.deepEqual(await nativeHostStartupDecision('/test/state',{artifacts,core}),{status:'continue',phase:'enrollment_incomplete'});
 }
 assert.equal(components,0);
 for(previous of [{status:'preparing',phase:'preflight_only'},{status:'cancelled',phase:'candidate_bound'},{status:'needs_recovery',phase:'preflight_only'}])
  assert.equal((await nativeHostStartupDecision('/test/state',{artifacts,core})).reason,'host_payload_requires_review');
 status='succeeded';previous={status:'not_started'};
 assert.equal((await nativeHostStartupDecision('/test/state',{artifacts,core})).automaticUpdate,true);
 previous={status:'cancelled',phase:'preflight_only'};
 assert.equal((await nativeHostStartupDecision('/test/state',{artifacts,core})).automaticUpdate,false);
});


test('a native server refreshes the runtime barrier after claim and releases ownership even when close fails',async t=>{
 const {assertDeploymentRuntimeReady}=await import('../runtime-guard.mjs');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-enrollment-order-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const stateDir=path.join(root,'deployment');fs.mkdirSync(stateDir,{mode:0o700});fs.writeFileSync(path.join(stateDir,'deployment.json'),'{}',{mode:0o600});
 const artifacts=path.join(root,'artifacts.json');fs.writeFileSync(artifacts,JSON.stringify({bundle:path.join(root,'bundle'),publisherKeyFile:path.join(root,'publisher'),publisherSha256:'a'.repeat(64)}),{mode:0o600});
 let claimed=false,prepared=0;
 const core={readDeployment:()=>({mode:'join-existing',steps:[{id:'host.prepare',status:'succeeded'},{id:'host.request',status:'succeeded'},{id:'host.claim',status:claimed?'succeeded':'pending'},{id:'host.doctor',status:'pending'}]}),planDeployment:()=>({steps:[]}),readDeploymentComponents:()=>({host:{status:'update_available',bundled:{manifestSha256:'b'.repeat(64)}}}),readHostPayloadHandoff:()=>({status:'cancelled',phase:'preflight_only'}),startDeploymentForeground:()=>{throw Error('must_not_connect')},stopDeploymentForeground:()=>{throw Error('cleanup_failed')},advanceDeployment:(_d,{authorize})=>{assert.deepEqual(authorize,['host.claim']);claimed=true},prepareHostPayloadHandoff:()=>{prepared++;},prepareDeploymentWorkAdmission:()=>{throw Error('must_not_admit_incomplete_claim')}};
 const server=await createOnboardingServer({stateDir,artifactDefaultsFile:artifacts,core,nativeAppAuthority:()=>({source:'current_windows_native_app'})});
 const headers={Authorization:'Bearer '+new URL(server.url).hash.slice(9),Origin:server.origin};const session=await(await fetch(server.origin+'/api/session',{headers})).json();
 const post=(route,body)=>fetch(server.origin+'/api/'+route,{method:'POST',headers:{...headers,'Content-Type':'application/json','X-Styx-CSRF':session.csrf},body:JSON.stringify(body)});
 try{
  await assert.rejects(assertDeploymentRuntimeReady(stateDir,{action:'foreground.start'}),/foreground_prepared_paired_host_doctor_required/);
  assert.equal((await post('host-payload/handoff/prepare',{authorize:true})).status,409);assert.equal(prepared,0);
  assert.equal((await post('advance',{authorize:['host.claim']})).status,200);
  const status=await(await fetch(server.origin+'/api/status',{headers})).json();
  assert.equal(status.nativeStartup.reason,'host_payload_requires_review');assert.equal(status.nativeStartup.automaticUpdate,false);
  assert.equal(status.deployment.steps.at(-1).status,'pending');
  await assert.rejects(assertDeploymentRuntimeReady(stateDir,{action:'advance',stepId:'host.doctor'}),/host_payload_requires_review/);
 }finally{await assert.rejects(server.close(),/cleanup_failed/);}
 await assertDeploymentRuntimeReady(stateDir,{action:'foreground.start'});
});
