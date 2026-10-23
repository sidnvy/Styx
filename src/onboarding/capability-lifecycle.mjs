import {setTimeout as delay} from 'node:timers/promises';
import {changeDeploymentCapabilitiesOffline,validateDeploymentCapabilityOptions} from './capabilities.mjs';
import {readDeploymentForeground,stopOwnedDeploymentForeground,startDeploymentForeground} from './foreground.mjs';

// App, CLI and onboarding share this entry. The offline transaction remains
// usable by an already-stopped Host; a live connector is suspended only by its
// actual Core owner, after both dispatch boundaries have admitted maintenance.
export async function changeManagedDeploymentCapabilities(stateDir,options={},operations={}){
 const selection=validateDeploymentCapabilityOptions(options);
 const {lifecycle={},...transactionOperations}=operations;
 const core=await import('./core.mjs');
 const control={read:readDeploymentForeground,stop:stopOwnedDeploymentForeground,start:startDeploymentForeground,
  prepare:core.prepareDeploymentWorkAdmission,commit:core.commitDeploymentWorkAdmission,cancel:core.cancelDeploymentWorkAdmission,
  change:changeDeploymentCapabilitiesOffline,...lifecycle};
 const before=await control.read(stateDir);
 if(before.status==='not_running')return control.change(stateDir,selection,transactionOperations);
 if(before.observation!=='current_process'||before.host!=='foreground'||!['started','connected'].includes(before.status))throw Error('foreground_not_owned_or_unsafe_for_capability_change');
 let ticket;
 try{
  let admission=await control.prepare(stateDir,{authorize:true,purpose:'host-update'});ticket=admission.ticketId;
  const deadline=performance.now()+2000;
  // A Cua click may still be returning its own response. Continuations can
  // drain it through the fence; retained Exec work and unknown outcomes never
  // qualify for this grace period.
  while(admission.status==='waiting'&&admission.retained===0&&admission.active>0&&performance.now()<deadline){
   await delay(25);admission=await control.prepare(stateDir,{authorize:true,purpose:'host-update'});
   if(admission.ticketId!==ticket)throw Error('work_state_unknown');
  }
  if(admission.status!=='ready')throw Error(admission.status==='waiting'?'work_in_progress':'work_state_unknown');
  const committed=await control.commit(stateDir,{authorize:true,ticketId:ticket});
  if(committed.status!=='ready')throw Error(committed.status==='waiting'?'work_in_progress':'work_state_unknown');
  const stopped=await control.stop(stateDir,{authorize:true});
  if(!['stopped','not_running'].includes(stopped.status))throw Error('foreground_stop_unconfirmed');
  const result=await control.change(stateDir,selection,transactionOperations);
  if(result?.status!=='updated')throw Error('capability_uncertain_requires_reconciliation');
  // Release the old owner's fences before starting the new configuration.
  // An uncertain transaction throws above and is deliberately left stopped.
  await control.cancel(stateDir,{authorize:true,ticketId:ticket});ticket=null;
  const resumed=await control.start(stateDir,{authorize:true});
  if(!['started','connected'].includes(resumed.status)||resumed.host!=='foreground')throw Error('capability_changed_reconnect_requires_review');
  return {...result,foregroundRestartRequired:false,foregroundResumed:true};
 }finally{
  if(ticket)await control.cancel(stateDir,{authorize:true,ticketId:ticket});
 }
}
