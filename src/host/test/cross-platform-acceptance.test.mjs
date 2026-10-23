import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {crossScope,observedCrossReference,requireCrossGates,saveCrossReceipt,crossOperationSuccess} from '../cross-platform-acceptance.mjs';
test('cross-machine actors require explicit opt-in, native roles and exact network scope',()=>{
 const original=process.env.STYX_RUN_CROSS_PLATFORM_ACCEPTANCE;
 try{
  delete process.env.STYX_RUN_CROSS_PLATFORM_ACCEPTANCE;
  assert.throws(()=>crossScope({},'gateway','linux'),/explicit_cross_platform_acceptance_required/);
  process.env.STYX_RUN_CROSS_PLATFORM_ACCEPTANCE='1';
  const options={directory:path.join(os.tmpdir(),'cross-owned'),listenHost:'10.0.2.19',authorizeExactInterface:true};
  assert.deepEqual(crossScope(options,'gateway','linux'),options);
  for(const listenHost of ['0.0.0.0','127.0.0.1','localhost'])assert.throws(()=>crossScope({...options,listenHost},'gateway','linux'),/explicit_exact_cross_interface_required/);
  assert.throws(()=>crossScope({...options,authorizeExactInterface:false},'gateway','linux'),/explicit_exact_cross_interface_required/);
  assert.throws(()=>crossScope(options,'host','linux'),/cross_native_role_platform_required/);
  assert.throws(()=>crossScope({...options,directory:'relative'},'gateway','linux'),/absolute_cross_scope_required/);
 }finally{if(original===undefined)delete process.env.STYX_RUN_CROSS_PLATFORM_ACCEPTANCE;else process.env.STYX_RUN_CROSS_PLATFORM_ACCEPTANCE=original;}
});
test('cross-machine Browser test acts only on observed opaque refs',()=>{
 const snapshot={content:[{type:'text',text:'- button "Store" [ref=styx-abcdef012345]'}]};
 assert.equal(observedCrossReference(snapshot,'Store'),'styx-abcdef012345');
 assert.throws(()=>observedCrossReference(snapshot,'Delete'),/cross_owned_observed_reference_missing/);
});
test('native completion refuses missing gates instead of promoting stop to acceptance',()=>{
 const receipt={gates:{prepared:{status:'PASS'}}};
 assert.throws(()=>requireCrossGates(receipt,['prepared','joined','reconnected']),/cross_required_gates_incomplete/);
 assert.deepEqual(receipt.missingRequiredGates,['joined','reconnected']);
 receipt.gates.joined={status:'PASS'};receipt.gates.reconnected={status:'PASS'};
 assert.doesNotThrow(()=>requireCrossGates(receipt,['prepared','joined','reconnected']));
 assert.deepEqual(receipt.missingRequiredGates,[]);
});
test('progress receipt safely replaces its own earlier file and leaves no temporary members',{skip:process.platform==='win32'},t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-cross-receipt-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const file=path.join(root,'receipt.json');saveCrossReceipt(file,{status:'RUNNING'});saveCrossReceipt(file,{status:'PASS'});
 assert.deepEqual(JSON.parse(fs.readFileSync(file)),{status:'PASS'});assert.equal(fs.statSync(file).mode&0o777,0o600);assert.deepEqual(fs.readdirSync(root),['receipt.json']);
});

test('successful enrollment reports pending domain state without making the actor operation fail',()=>{
 assert.deepEqual(crossOperationSuccess({status:'pending',request_id:'own-request'}),{status:'PASS',resultStatus:'pending',request_id:'own-request'});
});
