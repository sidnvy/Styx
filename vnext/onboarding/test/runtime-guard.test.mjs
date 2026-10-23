import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import {registerDeploymentRuntimeGuard,assertDeploymentRuntimeReady} from '../runtime-guard.mjs';
test('trusted runtime guard rechecks every step and cannot be replaced or released by a stale owner',async()=>{
 const d=path.join(os.tmpdir(),'styx-runtime-guard-scope');let aligned=false,calls=0;
 const guard=async()=>{calls++;if(!aligned)throw Error('host_payload_update_required')};
 const dispose=registerDeploymentRuntimeGuard(d,guard);
 try{
  assert.throws(()=>registerDeploymentRuntimeGuard(d,async()=>{}),/already_owned/);
  await assert.rejects(assertDeploymentRuntimeReady(d,{stepId:'host.doctor'}),/host_payload_update_required/);
  aligned=true;await assertDeploymentRuntimeReady(d,{stepId:'host.doctor'});
  aligned=false;await assert.rejects(assertDeploymentRuntimeReady(d,{stepId:'host.service.start'}),/host_payload_update_required/);
  assert.equal(calls,3);
 }finally{dispose()}
 const next=registerDeploymentRuntimeGuard(d,guard);dispose();
 try{await assert.rejects(assertDeploymentRuntimeReady(d,{}),/host_payload_update_required/)}finally{next()}
 await assertDeploymentRuntimeReady(d,{});
});
test('in-flight readiness cannot survive guard disposal',async()=>{
 const d=path.join(os.tmpdir(),'styx-runtime-guard-disposal');let release;
 const dispose=registerDeploymentRuntimeGuard(d,()=>new Promise(r=>{release=r}));
 const pending=assertDeploymentRuntimeReady(d,{});dispose();release();
 await assert.rejects(pending,/owner_changed/);
});

test('capability uncertainty blocks fresh CLI starts and foreground fastpath readiness, not explicit recovery/read',async t=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'styx-capability-guard-'));fs.chmodSync(d,0o700);t.after(()=>fs.rmSync(d,{recursive:true,force:true}));
 const file=path.join(d,'capabilities.json');
 for(const status of ['running','uncertain']){
  fs.writeFileSync(file,JSON.stringify({schema:1,status}),{mode:0o600});
  for(const action of [{action:'foreground'},{action:'host-service',stepId:'host.service.start'},{action:'host-service',stepId:'host.service.install'},{action:'advance',stepId:'host.doctor'}])await assert.rejects(assertDeploymentRuntimeReady(d,action),/foreground_capability_state_uncertain/);
  for(const action of ['status','rollback','recovery'])await assertDeploymentRuntimeReady(d,{action});
 }
 fs.writeFileSync(file,JSON.stringify({schema:1,status:'updated'}));await assertDeploymentRuntimeReady(d,{action:'foreground'});
 fs.writeFileSync(path.join(d,'capabilities.lock'),'owned transaction',{mode:0o600});await assert.rejects(assertDeploymentRuntimeReady(d,{action:'foreground'}),/foreground_capability_state_uncertain/);assert.equal(fs.readFileSync(path.join(d,'capabilities.lock'),'utf8'),'owned transaction');
});
test('capability transaction beginning during native guard await cannot authorize runtime start',async t=>{
 const d=fs.mkdtempSync(path.join(os.tmpdir(),'styx-capability-guard-race-'));fs.chmodSync(d,0o700);t.after(()=>fs.rmSync(d,{recursive:true,force:true}));let ready;
 const dispose=registerDeploymentRuntimeGuard(d,()=>new Promise(resolve=>{ready=resolve}));t.after(dispose);
 const result=assertDeploymentRuntimeReady(d,{action:'foreground'});fs.writeFileSync(path.join(d,'capabilities.json'),JSON.stringify({schema:1,status:'uncertain'}),{mode:0o600});ready();
 await assert.rejects(result,/foreground_capability_state_uncertain/);
});
