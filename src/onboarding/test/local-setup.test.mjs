import test from 'node:test';
import assert from 'node:assert/strict';
import {completeLocalSetup} from '../local-setup.mjs';
const scope={gatewayUrl:'https://127.0.0.1:8795',label:'My Mac',enableComputer:true};
const approval={approve:true,...scope};
function fixture(){
 const state={mode:'create-local',steps:['gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.doctor','host.service.install'].map(id=>({id,status:'pending'}))};
 const calls=[];
 const api={planDeployment:()=>({ownerPairingScope:scope}),readDeployment:()=>structuredClone(state),advanceDeployment:(_d,args)=>{calls.push(args);state.steps.find(s=>s.id===args.authorize[0]).status='succeeded'}};
 return {state,calls,api};
}
test('one exact approval prepares and pairs local device without starting background or account',async()=>{
 const f=fixture(),r=await completeLocalSetup(f.api,'unused',approval);
 assert.equal(r.status,'local_preparation_complete');assert.equal(f.calls.length,6);
 assert.deepEqual(f.calls[4].ownerApproval,approval);assert.equal(f.state.steps[6].status,'pending');
 await completeLocalSetup(f.api,'unused',approval);assert.equal(f.calls.length,6);
});
test('wrong scope or remote enrollment cannot be silently approved',async()=>{
 for(const change of [{enableComputer:false},{label:'Other'},{gatewayUrl:'https://remote.invalid'},{approve:false},{arbitrary:true}]){
  const f=fixture();await assert.rejects(completeLocalSetup(f.api,'unused',{...approval,...change}));assert.equal(f.calls.length,0);
 }
 const f=fixture();f.state.mode='join-existing';await assert.rejects(completeLocalSetup(f.api,'unused',approval));assert.equal(f.calls.length,0);
});
test('failure or interrupted journal halts without replay or further mutations',async()=>{
 for(const status of ['uncertain','blocked','failed','running']){
  const f=fixture();f.state.steps[0].status=status;assert.equal((await completeLocalSetup(f.api,'unused',approval)).status,'needs_attention');assert.equal(f.calls.length,0);
 }
 const f=fixture();f.api.advanceDeployment=(_d,args)=>{f.calls.push(args);f.state.steps[0].status='uncertain'};
 assert.equal((await completeLocalSetup(f.api,'unused',approval)).status,'needs_attention');assert.equal(f.calls.length,1);
});
test('reopen resumes same prepared Gateway without replaying identity creation',async()=>{
 const f=fixture();for(const step of f.state.steps.slice(0,3))step.status='succeeded';
 let restarted=0;f.api.startDeploymentGateway=()=>{restarted++;f.state.gatewayRuntime={status:'running'}};
 assert.equal((await completeLocalSetup(f.api,'unused',approval)).status,'local_preparation_complete');
 assert.equal(restarted,1);assert.equal(f.calls.length,3);assert.equal(f.calls[0].authorize[0],'host.prepare');
});


test('aggregate local setup cannot omit or change its requested Browser approval',async()=>{
 const f=fixture();f.api.planDeployment=()=>({ownerPairingScope:{...scope,enableBrowser:true}});
 for(const change of [{},{enableBrowser:false},{enableBrowser:'yes'}])await assert.rejects(completeLocalSetup(f.api,'unused',{...approval,...change}),/local_setup_scope_changed/);
 assert.equal(f.calls.length,0);
 assert.equal((await completeLocalSetup(f.api,'unused',{...approval,enableBrowser:true})).status,'local_preparation_complete');
 assert.equal(f.calls[4].ownerApproval.enableBrowser,true);
});

test('explicit continue retries only a blocked read-only doctor after successful pairing',async()=>{
 const f=fixture();for(const s of f.state.steps.slice(0,5))s.status='succeeded';f.state.steps[5].status='blocked';
 f.state.gatewayRuntime={status:'running'};
 let defaults=0;f.api.setLocalDeploymentDefault=()=>{defaults++};
 const r=await completeLocalSetup(f.api,'unused',approval);
 assert.equal(r.status,'local_preparation_complete');assert.deepEqual(f.calls,[{authorize:['host.doctor']}]);assert.equal(defaults,1);
 assert.equal(f.state.steps[6].status,'pending');
});
test('a repeated blocked doctor remains honest and does not loop or start background work',async()=>{
 const f=fixture();for(const s of f.state.steps.slice(0,5))s.status='succeeded';f.state.steps[5].status='blocked';f.state.gatewayRuntime={status:'running'};
 f.api.advanceDeployment=(_d,args)=>{f.calls.push(args)};
 assert.deepEqual(await completeLocalSetup(f.api,'unused',approval),{status:'needs_attention',step:'host.doctor'});
 assert.deepEqual(f.calls,[{authorize:['host.doctor']}]);assert.equal(f.state.steps[6].status,'pending');
});
test('a reopened App starts the same prepared Gateway before explicitly rechecking a blocked doctor',async()=>{
 const f=fixture();for(const s of f.state.steps.slice(0,5))s.status='succeeded';f.state.steps[5].status='blocked';
 let started=0;f.api.startDeploymentGateway=()=>{started++;f.state.gatewayRuntime={status:'running'}};
 assert.equal((await completeLocalSetup(f.api,'unused',approval)).status,'local_preparation_complete');assert.equal(started,1);assert.deepEqual(f.calls,[{authorize:['host.doctor']}]);
});
test('a retryable doctor cannot bypass an earlier uncertain mutation or replay an uncertain doctor',async()=>{
 for(const id of ['gateway.prepare','host.prepare','host.pair','host.doctor']){
  const f=fixture();for(const s of f.state.steps.slice(0,5))s.status='succeeded';f.state.steps[5].status='blocked';f.state.steps.find(s=>s.id===id).status='uncertain';
  assert.deepEqual(await completeLocalSetup(f.api,'unused',approval),{status:'needs_attention',step:id});assert.equal(f.calls.length,0);
 }
});
