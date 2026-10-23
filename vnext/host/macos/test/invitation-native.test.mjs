import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import http from 'node:http';
import {createOnboardingServer} from '../../../onboarding/server.mjs';

for(const mode of ['retry','rollback','lost-create']) test(`native invitation: multiple interfaces, interrupted preparation and ${mode}`, {skip:process.platform!=='darwin',timeout:30000}, async t=>{
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
  recoverDeploymentDeviceIngress(d,options){assert.deepEqual(options,{authorize:true,action:mode==='rollback'?'rollback':'retry'});assert.equal(prepares,1);setup={status:mode==='rollback'?'rolled_back':'applied'};return setup;},
  createDeploymentPairingLink(d,options){assert.deepEqual(options,{authorize:true});assert.equal(setup.status,'applied');creates++;if(mode==='lost-create')throw Error('isolated_lost_create_response');return {link:'https://preview.invalid/not-real',origin:'https://192.0.2.10:443',expiresAt:Date.now()+600000};},
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
 assert.equal(creates,mode==='rollback'?0:1);assert.equal(closes,mode==='rollback'?0:2);assert.equal(approvals,mode==='retry'?1:0);
 assert.deepEqual(posts,mode==='retry'?[{authorize:true,requestId:request.request_id,comparisonCodeConfirmation:request.comparison_code,enableComputer:false,enableBrowser:true}]:[]);
 console.log(stdout.trim());
});

// Native model/client transport contract; Core's recovery transaction is tested
// independently. This loopback fixture is not physical pairing acceptance.
for (const mode of ['join-recover','join-denied','join-rollback']) test(`native existing join recovery: ${mode}`, {skip:process.platform!=='darwin',timeout:30000}, async t=>{
 const binary=process.env.STYX_NATIVE_TEST_BINARY;assert.ok(binary);
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-join-recovery-'));
 const token='a'.repeat(43),csrf='b'.repeat(43),posts=[];let recovered=false,continued=false,rolledBack=false;
 const snapshot=()=>({status:{joinRecovery:{canRecover:!recovered,reason:recovered?'request_pending':'request_uncertain',rollbackRequired:false},deployment:{mode:'join-existing',roles:{computer:'disabled',browser:'disabled'},steps:[{id:'host.prepare',status:'succeeded'},{id:'host.request',status:continued?'succeeded':recovered?'pending':'uncertain'},{id:'host.claim',status:continued?'awaiting_approval':'pending'}]}},journey:{},acceptance:{},plugin:{}});
 let origin;
 const server=http.createServer((req,res)=>{let body='';req.on('data',b=>body+=b);req.on('end',()=>{
  try{
   assert.equal(req.headers.authorization,'Bearer '+token);assert.equal(req.headers.origin,origin);
   let result;
   if(req.method==='GET'&&req.url==='/api/session')result={csrf,joinRecoverySupported:true,defaults:{label:'Retained Mac'}};
   else if(req.method==='GET'&&req.url==='/api/snapshot'){if(mode==='join-rollback'&&!rolledBack){res.writeHead(409,{'Content-Type':'application/json'});res.end('{}');return;}result=snapshot();}
   else if(req.method==='GET'&&req.url==='/api/join/recovery')result={recovery:{canRecover:false,rollbackRequired:true,transactionId:'interrupted'}};
   else if(req.method==='POST'){
    assert.equal(req.headers['x-styx-csrf'],csrf);const input=JSON.parse(body);posts.push({route:req.url,input});
    if(req.url==='/api/pairing-link/inspect'){assert.deepEqual(input,{link:'isolated-invitation'});result={inspectionId:'inspection',preview:{origin:'https://192.0.2.10:443',caSha256:'c'.repeat(64)}};}
    else if(req.url==='/api/pairing-link/accept'){assert.deepEqual(input,{inspectionId:'inspection',approvedGatewayOrigin:'https://192.0.2.10:443',approvedCaSha256:'c'.repeat(64)});result={joinLinkId:'accepted',origin:'https://192.0.2.10:443'};}
    else if(req.url==='/api/join/rollback'){assert.deepEqual(input,{authorize:true,transactionId:'interrupted'});rolledBack=true;result={recovery:{status:'rolled_back'}};}
    else if(req.url==='/api/join/recover'){assert.deepEqual(input,{authorize:true,joinLinkId:'accepted'});recovered=true;result={recovery:{status:'recovered',transactionId:'transaction',nextStep:'host.request',previousRequestOutcome:'unknown'}};}
    else if(req.url==='/api/advance'){assert.ok(recovered);if(input.authorize[0]==='host.request'){continued=true;}else assert.deepEqual(input,{authorize:['host.claim']});result={};}
    else assert.fail('Unexpected native mutation '+req.url);
   }else assert.fail('Unexpected native request '+req.url);
   res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(result));
  }catch(error){res.writeHead(500,{'Content-Type':'application/json'});res.end('{}');server.emit('testFailure',error);}
 });});
 const failures=[];server.on('testFailure',e=>failures.push(e));await new Promise(r=>server.listen(0,'127.0.0.1',r));origin='http://127.0.0.1:'+server.address().port;
 t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true});});
 const file=path.join(root,'session.url');fs.writeFileSync(file,origin+'/#session='+token,{mode:0o600});
 const {stdout}=await promisify(execFile)(binary,['--invitation-self-test',file,mode],{timeout:25000});
 assert.match(stdout,/PASS: native joined recovery/);assert.deepEqual(failures,[]);
 assert.deepEqual(posts.map(p=>p.route),mode==='join-rollback'?['/api/join/rollback']:mode==='join-denied'?['/api/pairing-link/inspect']:['/api/pairing-link/inspect','/api/pairing-link/accept','/api/join/recover','/api/advance','/api/advance']);
 assert.equal(posts.some(p=>p.route==='/api/create'),false);
});
