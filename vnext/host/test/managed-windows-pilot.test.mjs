import test from 'node:test';
import assert from 'node:assert/strict';
import {runManagedWindowsPilot,reconcileAttemptedWindowsTask} from '../managed-windows-pilot.mjs';
test('Windows native pilot never starts without explicit opt-in',async()=>{
 const before=process.env.STYX_RUN_MANAGED_WINDOWS_PILOT;delete process.env.STYX_RUN_MANAGED_WINDOWS_PILOT;
 try{await assert.rejects(runManagedWindowsPilot(),/explicit_native_pilot_opt_in_required/)}
 finally{if(before===undefined)delete process.env.STYX_RUN_MANAGED_WINDOWS_PILOT;else process.env.STYX_RUN_MANAGED_WINDOWS_PILOT=before}
});
test('Windows native pilot rejects simulated foreign platform before filesystem/service work',{skip:process.platform==='win32'},async()=>{
 const before=process.env.STYX_RUN_MANAGED_WINDOWS_PILOT;process.env.STYX_RUN_MANAGED_WINDOWS_PILOT='1';
 try{await assert.rejects(runManagedWindowsPilot(),/native_windows_x64_required/)}
 finally{if(before===undefined)delete process.env.STYX_RUN_MANAGED_WINDOWS_PILOT;else process.env.STYX_RUN_MANAGED_WINDOWS_PILOT=before}
});

test('uncertain registration reconciles exact task before permitting state cleanup',async()=>{
 let present=true;const calls=[];
 await reconcileAttemptedWindowsTask({status:()=>{calls.push('status');return {status:present?'Running':'not_installed'}},uninstall:()=>{calls.push('uninstall');present=false},quiescent:async()=>{calls.push('quiescent')}});
 assert.deepEqual(calls,['status','uninstall','quiescent','status']);
});
test('unknown or foreign task state refuses cleanup without uninstalling',async()=>{
 for(const status of [()=>({status:'Unknown'}),()=>{throw Error('task_owner_mismatch')}]){
  let destructive=false;
  await assert.rejects(reconcileAttemptedWindowsTask({status,uninstall:()=>{destructive=true},quiescent:async()=>{destructive=true}}));assert.equal(destructive,false);
 }
});
test('uncertain uninstall or remaining processes cannot authorize state cleanup',async()=>{
 for(const failure of ['uninstall','quiescent','still_registered']){
  let calls=0;await assert.rejects(reconcileAttemptedWindowsTask({status:()=>({status:++calls===1?'Running':'Ready'}),uninstall:()=>{if(failure==='uninstall')throw Error('timeout')},quiescent:async()=>{if(failure==='quiescent')throw Error('owned_process_cleanup_failed')}}));
 }
});
