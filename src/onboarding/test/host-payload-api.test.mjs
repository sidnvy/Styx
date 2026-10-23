import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createOnboardingServer} from '../server.mjs';
import {main} from '../cli.mjs';
import {WorkAdmission} from '../../shared/work-admission.mjs';
import {prepareHostUpdateAdmission,commitHostUpdateAdmission,cancelHostUpdateAdmission} from '../host-update-admission.mjs';

test('native update API authenticates mutations and cannot substitute a payload, publisher, state directory or admission token',async t=>{
 const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-handoff-api-'));t.after(()=>fs.rmSync(stateDir,{recursive:true,force:true}));
 const artifacts={bundle:path.join(stateDir,'registered-bundle'),publisherKeyFile:path.join(stateDir,'publisher.pem'),publisherSha256:'a'.repeat(64)},defaults=path.join(stateDir,'artifacts.json');fs.writeFileSync(defaults,JSON.stringify(artifacts),{mode:0o600});
 const calls=[],core={prepareDeploymentWorkAdmission:async()=>({status:'ready',ticketId:'c'.repeat(32)}),commitDeploymentWorkAdmission:async()=>({status:'ready'}),cancelDeploymentWorkAdmission:async()=>({status:'cancelled'}),prepareHostPayloadHandoff:async args=>{calls.push(args);return{status:'awaiting_exit',ticketId:'b'.repeat(32)}}};
 const app=await createOnboardingServer({stateDir,artifactDefaultsFile:defaults,core});t.after(()=>app.close());
 const headers={Authorization:'Bearer '+new URLSearchParams(new URL(app.url).hash.slice(1)).get('session')};
 const session=await(await fetch(app.origin+'/api/session',{headers})).json();
 const post=(data,extra={})=>fetch(app.origin+'/api/host-payload/handoff/prepare',{method:'POST',headers:{...headers,Origin:app.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json',...extra},body:JSON.stringify(data)});
 assert.equal((await post({authorize:true},{Authorization:''})).status,401);
 assert.equal((await post({authorize:true},{'X-Styx-CSRF':''})).status,403);
 assert.equal((await post({authorize:true},{Origin:'https://untrusted.example'})).status,403);
 for(const data of [{authorize:false},{authorize:true,bundle:'/foreign'},{authorize:true,publisherSha256:'c'.repeat(64)},{authorize:true,stateDir:'/foreign'},{authorize:true,token:'secret'}])assert.equal((await post(data)).status,409);
 assert.equal(calls.length,0);const response=await post({authorize:true});assert.equal(response.status,200);assert.deepEqual(calls,[{stateDir,bundle:artifacts.bundle,authorize:true}]);
 assert.equal((await response.json()).handoff.status,'awaiting_exit');
 assert.deepEqual(await main(['host-payload-handoff-status',stateDir]),{schema:1,status:'not_started'});
});

for(const outcome of ['response_returns','response_stays_pending','peer_changes'])test('update admission holds its fence while a triggering click settles: '+outcome,async t=>{
 const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-click-update-'));t.after(()=>fs.rmSync(stateDir,{recursive:true,force:true}));
 const defaults=path.join(stateDir,'artifacts.json');fs.writeFileSync(defaults,JSON.stringify({bundle:path.join(stateDir,'bundle'),publisherKeyFile:path.join(stateDir,'publisher.pem'),publisherSha256:'a'.repeat(64)}),{mode:0o600});
 let identity='original',ticketId,staged=0,first=true,signal;
 const begun=new Promise(resolve=>{signal=resolve}),controller=new WorkAdmission({observe:()=>({identity,retained:0,unknown:false})}),finish=controller.enter('local','computer');
 const core={
  prepareDeploymentWorkAdmission:async(d,{purpose})=>{const value=prepareHostUpdateAdmission({stateDir:d,purpose},{gateway:controller,ownsGateway:true,requiresLocalHost:false});ticketId=value.ticketId;if(first){first=false;signal()}return value;},
  commitDeploymentWorkAdmission:async(d,{ticketId})=>commitHostUpdateAdmission({stateDir:d,ticketId}),
  cancelDeploymentWorkAdmission:async(d,{ticketId})=>cancelHostUpdateAdmission({stateDir:d,ticketId}),
  prepareHostPayloadHandoff:async()=>{staged++;return{status:'awaiting_exit'}}
 };
 const app=await createOnboardingServer({stateDir,core,artifactDefaultsFile:defaults});t.after(async()=>{await app.close();finish();try{cancelHostUpdateAdmission({stateDir,ticketId})}catch{}});
 const headers={Authorization:'Bearer '+new URLSearchParams(new URL(app.url).hash.slice(1)).get('session')},session=await(await fetch(app.origin+'/api/session',{headers})).json();
 const response=fetch(app.origin+'/api/host-payload/handoff/prepare',{method:'POST',headers:{...headers,Origin:app.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json'},body:JSON.stringify({authorize:true})});
 await begun;assert.throws(()=>controller.enter('another','exec'),/device_in_maintenance/);
 if(outcome==='peer_changes')identity='replacement';
 if(outcome!=='response_stays_pending')finish();
 const result=await response;
 if(outcome==='response_returns'){assert.equal(result.status,200);assert.equal(staged,1);assert.throws(()=>controller.enter('another','exec'),/device_in_maintenance/);}
 else{assert.equal(result.status,409);assert.equal((await result.json()).error,outcome==='peer_changes'?'work_state_unknown':'work_in_progress');assert.equal(staged,0);controller.enter('another','exec')();if(outcome==='response_stays_pending')assert.equal(controller.active.size,1);}
});

test('an active or unobserved task blocks update and quit without leaving the App in maintenance',async t=>{
 const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-work-api-'));t.after(()=>fs.rmSync(stateDir,{recursive:true,force:true}));
 const artifacts={bundle:path.join(stateDir,'bundle'),publisherKeyFile:path.join(stateDir,'publisher.pem'),publisherSha256:'a'.repeat(64)},defaults=path.join(stateDir,'artifacts.json');fs.writeFileSync(defaults,JSON.stringify(artifacts),{mode:0o600});
 let status='waiting',staged=0,cancelled=0,committed=0;
 const core={prepareDeploymentWorkAdmission:async()=>({status,ticketId:'a'.repeat(32)}),commitDeploymentWorkAdmission:async()=>{committed++;return{status:'ready'}},cancelDeploymentWorkAdmission:async()=>{cancelled++;return{status:'cancelled'}},prepareHostPayloadHandoff:async()=>{staged++;return{status:'awaiting_exit'}}};
 const app=await createOnboardingServer({stateDir,core,artifactDefaultsFile:defaults});t.after(()=>app.close());
 const headers={Authorization:'Bearer '+new URLSearchParams(new URL(app.url).hash.slice(1)).get('session')},session=await(await fetch(app.origin+'/api/session',{headers})).json();
 const post=route=>fetch(app.origin+route,{method:'POST',headers:{...headers,Origin:app.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json'},body:JSON.stringify({authorize:true})});
 for(const value of ['waiting','unknown']){status=value;for(const route of ['/api/host-payload/handoff/prepare','/api/app/quit-admission']){const response=await post(route);assert.equal(response.status,409);assert.equal((await response.json()).error,value==='waiting'?'work_in_progress':'work_state_unknown');}}
 assert.equal(staged,0);assert.equal(committed,0);assert.equal(cancelled,4);
 status='ready';const ready=await post('/api/app/quit-admission');assert.equal(ready.status,200);assert.deepEqual((await ready.json()).quit,{status:'ready_to_quit',ticketId:'a'.repeat(32)});assert.equal(committed,1);assert.equal(cancelled,4);
});
