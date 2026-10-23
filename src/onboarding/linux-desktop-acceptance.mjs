// CLI-owned temporary window, not a Linux App or a caller-supplied PID proof.
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {resolveLinuxDesktopSession} from '../host/linux-desktop.mjs';
import {acceptanceBinding,currentAcceptanceEvidence} from '../shared/onboarding-evidence.mjs';
import {beginDeploymentAcceptance,recordDeploymentDesktopReadback,readDeploymentAcceptance} from './account-acceptance.mjs';

export async function runLinuxDesktopAcceptance(stateDir,options={}, {
 resolveSession=resolveLinuxDesktopSession,spawnWindow=spawn,timeoutMs=600000,
 onChallenge=()=>{},signal,platform=process.platform,pollMs=2000
}={}){
 if(options.authorize!==true||Object.keys(options).some(k=>k!=='authorize'))throw Error('explicit_linux_acceptance_authorization_required');
 if(platform!=='linux')throw Error('linux_acceptance_only');
 // This binding resolves only the deployment's own locally prepared Host
 // identity. Gateway-only and arbitrary selected remote targets cannot enter.
 const {host,target}=acceptanceBinding(stateDir);
 if(target.platform!=='linux'||host.host_id!==target.id)throw Error('linux_acceptance_requires_local_host');
 if(target.computer?.enabled!==true)return beginDeploymentAcceptance(stateDir,options);
 let session;try{session=resolveSession()}catch{return {schema:1,status:'blocked',reason:'session_probe_failed',desktop:'not_verified'}}
 if(!session.available)return {schema:1,status:'blocked',reason:session.reason,desktop:'not_verified'};
 if(session.type!=='wayland'||!session.env.HYPRLAND_INSTANCE_SIGNATURE)return {schema:1,status:'blocked',reason:'hyprland_session_required',desktop:'not_verified'};
 if(signal?.aborted)return {schema:1,status:'cancelled',desktop:'not_verified'};
 const generation=randomBytes(16).toString('hex');
 const child=spawnWindow('/usr/bin/zenity',['--entry','--title=Styx desktop acceptance',
  '--text=Use Styx Computer Use to enter the challenge, observe it again, then confirm.',
  '--ok-label=Confirm','--cancel-label=Cancel','--width=520','--timeout=600'],
 {env:{...process.env,...session.env,GDK_BACKEND:'wayland'},stdio:['ignore','pipe','ignore']});
 let output='',closed=false,spawnError=false,cancelReason,killTimer,timer,sessionTimer,challenge,submission;
 const done=new Promise(resolve=>{
  child.once('error',()=>{spawnError=true;});
  child.once('close',(code,terminationSignal)=>{closed=true;resolve({code,signal:terminationSignal});});
 });
 const stop=reason=>{
  cancelReason??=reason;
  if(!closed){child.kill('SIGTERM');killTimer??=setTimeout(()=>{if(!closed)child.kill('SIGKILL');},1000);}
 };
 const cancel=()=>stop('cancelled');
 child.stdout.on('data',chunk=>{
  if(Buffer.byteLength(output)+chunk.length>256){stop('native_readback_too_large');return;}
  output+=chunk.toString('utf8');
 });
 const nativeDesktopApp=()=>{
  if(!Number.isSafeInteger(child.pid)||spawnError||cancelReason||closed&&!submission)throw Error('owned_window_unavailable');
  return {source:'current_linux_acceptance_window',nativeAppPid:child.pid,nativeAppGeneration:generation,...submission};
 };
 process.once('SIGINT',cancel);process.once('SIGTERM',cancel);signal?.addEventListener('abort',cancel,{once:true});
 try{
  await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',()=>reject(Error('linux_acceptance_window_unavailable')));});
  if(signal?.aborted)cancel();
  if(cancelReason){await done;return {schema:1,status:cancelReason,desktop:'not_verified'};}
  challenge=beginDeploymentAcceptance(stateDir,options,{nativeDesktopApp});
  timer=setTimeout(()=>stop('timed_out'),timeoutMs);
  sessionTimer=setInterval(()=>{
   try{
    const {record}=currentAcceptanceEvidence(stateDir);
    if(record.id!==challenge.challenge.id){stop('challenge_replaced');return;}
    const current=resolveSession();
    if(!current.available||current.key!==session.key)stop('desktop_session_changed');
   }catch{stop('acceptance_context_or_session_unavailable');}
  },pollMs);
  await onChallenge(challenge);
  const terminal=await done;
  if(cancelReason||terminal.code!==0||terminal.signal)return {schema:1,status:cancelReason??'cancelled',desktop:'not_verified',challengeId:challenge.challenge.id};
  // Zenity produces its actual field contents only on successful submission.
  // Never pass the expected marker to the process, or use an MCP value as the
  // independent readback. The original observed window is bound to this child.
  const value=output.endsWith('\n')?output.slice(0,-1):output;
  const {record}=currentAcceptanceEvidence(stateDir);
  if(record.id!==challenge.challenge.id)throw Error('linux_acceptance_challenge_changed');
  if(value!==record.desktopValue)throw Error('linux_acceptance_readback_mismatch');
  if(record.desktop?.after!==true||record.desktop.actionVerified!==true||record.desktop.actionAttempt?.pid!==child.pid||!Number.isSafeInteger(record.desktop.actionAttempt?.window))throw Error('actual_desktop_action_evidence_required');
  submission={submitted:true,readbackValue:value,challengeId:record.id,windowId:record.desktop.actionAttempt.window};
  recordDeploymentDesktopReadback(stateDir,{authorize:true,challengeId:record.id,value,pid:child.pid,windowId:submission.windowId},{nativeDesktopApp});
  return readDeploymentAcceptance(stateDir);
 }finally{
  clearTimeout(timer);clearInterval(sessionTimer);
  process.off('SIGINT',cancel);process.off('SIGTERM',cancel);signal?.removeEventListener('abort',cancel);
  if(!closed){stop('cancelled');await done;}
  clearTimeout(killTimer);
 }
}
