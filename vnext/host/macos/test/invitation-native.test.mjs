import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createOnboardingServer} from '../../../onboarding/server.mjs';

for(const mode of ['retry','rollback']) test(`native invitation: multiple interfaces, interrupted preparation and ${mode}`, {skip:process.platform!=='darwin',timeout:30000}, async t=>{
 const binary=process.env.STYX_NATIVE_TEST_BINARY;
 assert.ok(binary,'Set STYX_NATIVE_TEST_BINARY to the resource-bearing testing executable');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-invitation-'));
 let setup={status:'not_started'},prepares=0,creates=0,approvals=0,closes=0;
 const request={request_id:'a'.repeat(32),fingerprint:'b'.repeat(64),label:'Isolated joining computer',comparison_code:'ABCD-0123-EF45-6789',computer_requested:false,browser_requested:true};
 const core={
  readDeployment:()=>({mode:'create-local',steps:[]}),planDeployment:()=>({steps:[]}),
  readDeploymentForeground:()=>({status:'not_running',observation:'current_process'}),
  readDeploymentAcceptance:()=>({status:'not_started',complete:false}),readDeploymentConnectionHandoff:()=>({status:'unavailable'}),
  readDeploymentPlugin:()=>({required:true,profileSaved:false,contextChanged:false,presentation:{displayName:'Styx'},selection:{mode:'create'}}),
  readDeploymentDeviceIngressSetup:()=>setup,
  planDeviceIngress:()=>({gateway:'local',candidates:['192.0.2.10','198.51.100.10'],requiresInterfaceChoice:setup.status!=='applied',blockers:setup.status==='needs_reconciliation'?['device_ingress_recovery_required']:[],nextAction:setup.status==='applied'?'open_pairing_window':'prepare_additional_entry'}),
  prepareDeploymentDeviceIngress(d,options){assert.deepEqual(options,{authorize:true,listenHost:'192.0.2.10'});prepares++;setup={status:'needs_reconciliation',phase:'configuring'};throw Error('isolated_interrupted_prepare');},
  recoverDeploymentDeviceIngress(d,options){assert.deepEqual(options,{authorize:true,action:mode});assert.equal(prepares,1);setup={status:mode==='retry'?'applied':'rolled_back'};return setup;},
  createDeploymentPairingLink(d,options){assert.deepEqual(options,{authorize:true});assert.equal(setup.status,'applied');creates++;return {link:'https://preview.invalid/not-real',origin:'https://192.0.2.10:443',expiresAt:Date.now()+600000};},
  listDeploymentPending:()=>approvals?[]:[request],
  approveDeploymentPending(d,options){assert.deepEqual(options,{authorize:true,requestId:request.request_id,fingerprint:request.fingerprint});approvals++;return {status:'approved'};},
  closeDeploymentPairingWindow(d,options){assert.deepEqual(options,{authorize:true});closes++;if(closes===1)throw Error('isolated_close_failure');return {pairing:{status:'closed'}};}
 };
 const instance=await createOnboardingServer({stateDir:path.join(root,'deployment'),core,backgroundRead:()=>null});
 t.after(async()=>{await instance.close();fs.rmSync(root,{recursive:true,force:true});});
 const posts=[];instance.server.on('request',req=>{if(req.method==='POST'&&req.url==='/api/pending/approve'){let body='';req.on('data',c=>body+=c);req.on('end',()=>posts.push(JSON.parse(body)));}});
 const file=path.join(root,'session.url');fs.writeFileSync(file,instance.url,{mode:0o600});
 const {stdout}=await promisify(execFile)(binary,['--invitation-self-test',file,mode],{timeout:25000});
 assert.match(stdout,/PASS: native/);assert.equal(prepares,1);
 assert.equal(creates,mode==='retry'?1:0);assert.equal(closes,mode==='retry'?2:0);assert.equal(approvals,mode==='retry'?1:0);
 assert.deepEqual(posts,mode==='retry'?[{authorize:true,requestId:request.request_id,comparisonCodeConfirmation:request.comparison_code,enableComputer:false,enableBrowser:true}]:[]);
 console.log(stdout.trim());
});
