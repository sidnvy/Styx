import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
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
