// Run against an already compiled, resource-bearing STYX_TESTING app.
// Real private HTTP server and native client; synthetic deployment observations.
// No user configuration, tunnel credentials, TCC, account or live network success.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createOnboardingServer} from '../../../onboarding/server.mjs';

test('native slow observation leaves reconnect interactive and retains drafts', {timeout:30000}, async t => {
 const binary=process.env.STYX_NATIVE_TEST_BINARY;
 assert.ok(binary, 'Set STYX_NATIVE_TEST_BINARY to the resource-bearing testing executable');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-observation-'));
 let reads=0;
 const core={
  async readDeployment(){reads++; await new Promise(resolve=>setTimeout(resolve,350)); return {mode:'create-local',roles:{host:'local',gateway:'local',exec:'enabled',computer:'disabled',browser:'disabled'},steps:[{id:'host.doctor',status:'succeeded'}]};},
  planDeployment(){return {steps:[]};},
  readDeploymentForeground(){return {status:'connected',observation:'authenticated_foreground_owner',host:'foreground',gateway:'foreground'};},
  readDeploymentAcceptance(){return {status:'not_started',complete:false};},
  readDeploymentConnectionHandoff(){return {status:'unavailable'};},
  readDeploymentPlugin(){return {required:true,profileSaved:false,contextChanged:false,presentation:{displayName:'Styx'},selection:{mode:'create'}};}
 };
 const instance=await createOnboardingServer({stateDir:path.join(root,'deployment'),core,backgroundRead:()=>null});
 t.after(async()=>{await instance.close();fs.rmSync(root,{recursive:true,force:true});});
 const writes=[];instance.server.on('request',req=>{if(req.method==='POST')writes.push(req.url);});
 const file=path.join(root,'session.url');fs.writeFileSync(file,instance.url,{mode:0o600});
 const {stdout}=await promisify(execFile)(binary,['--observation-self-test',file],{timeout:25000});
 assert.match(stdout,/PASS: isolated Core HTTP/);
 // bootstrap + one overlapped refresh + two subsequent observations. A second
 // simultaneous refresh must not reach Core and failed writes are not replayed.
 assert.equal(reads,4);
 assert.deepEqual(writes,['/api/tunnel/start']);
 console.log(stdout.trim());
});

test('native welcome renders against fresh real Core without creating a deployment', {timeout:20000}, async t => {
 const binary=process.env.STYX_NATIVE_TEST_BINARY;
 assert.ok(binary);
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-real-core-'));
 const stateDir=path.join(root,'deployment');
 const instance=await createOnboardingServer({stateDir});
 t.after(async()=>{await instance.close();fs.rmSync(root,{recursive:true,force:true});});
 const file=path.join(root,'session.url');fs.writeFileSync(file,instance.url,{mode:0o600});
 const image=process.env.STYX_NATIVE_SMOKE_IMAGE??path.join(root,'welcome.png');
 const {stdout}=await promisify(execFile)(binary,['--product-window-fixture',file,image],{timeout:15000});
 assert.match(stdout,/PASS: native welcome window rendered through authenticated Core reads/);
 assert.ok(fs.statSync(image).size>1000);
 assert.equal(fs.existsSync(stateDir),false,'Opening the native app must not create a deployment');
 console.log(stdout.trim());
});
