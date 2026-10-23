// Windows desktop availability is a live property of the caller's own session.
// Reuse the existing session-scoped cancellation/retry loop; never launch a
// privileged desktop service or move a process into another user's session.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execFileAsync=promisify(execFile);
import {runLinuxDesktopLifecycle as runObservedDesktopLifecycle} from './linux-desktop.mjs';
const unavailable=reason=>({available:false,reason});
export async function resolveWindowsDesktopSession(probe,{run=execFileAsync,platform=process.platform}={}){
 if(platform!=='win32')return unavailable('windows_only');
 if(!probe)return unavailable('windows_session_probe_missing');
 try{
  if(Object.keys(probe).sort().join(',')!=='binary,sha256'||typeof probe.binary!=='string'||!path.isAbsolute(probe.binary)||!/^[a-f0-9]{64}$/.test(probe.sha256??''))return unavailable('windows_session_probe_invalid');
  const stat=fs.lstatSync(probe.binary);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.size>2*1024*1024||fs.realpathSync(probe.binary).toLowerCase()!==path.resolve(probe.binary).toLowerCase()||createHash('sha256').update(fs.readFileSync(probe.binary)).digest('hex')!==probe.sha256)return unavailable('windows_session_probe_changed');
  const env={};for(const key of ['SystemRoot','WINDIR'])if(process.env[key])env[key]=process.env[key];
  const output=await run(probe.binary,[],{cwd:path.dirname(probe.binary),env,encoding:'utf8',timeout:1500,maxBuffer:4096,windowsHide:true,stdio:['ignore','pipe','pipe']});
  const value=JSON.parse(String(typeof output==='string'?output:output.stdout));
  if(value?.schema!==1||value.status!=='available'||value.interactive!==true||!Number.isSafeInteger(value.sessionId)||value.sessionId<1||value.windowStation!=='WinSta0'||value.inputDesktop!=='Default')return unavailable('windows_interactive_desktop_unavailable');
  return {available:true,key:'windows:'+value.sessionId,id:String(value.sessionId)};
 }catch{return unavailable('windows_session_probe_unavailable')}
}
export async function runWindowsDesktopLifecycle({probe,connect,signal,onReady,onStatus,resolveSession=()=>resolveWindowsDesktopSession(probe),pollMs=2000,once=false}={}){
 if(typeof connect!=='function')throw Error('desktop_connector_required');
 return runObservedDesktopLifecycle({signal,onStatus,resolveSession,pollMs,once,
  connect:(session,{signal:sessionSignal})=>{
   const abort=new AbortController(),cancel=()=>abort.abort();sessionSignal.addEventListener('abort',cancel,{once:true});if(sessionSignal.aborted)cancel();
   const ready=async info=>{
    let current;try{current=await resolveSession()}catch{}
    if(abort.signal.aborted)return;
    if(!current?.available||current.key!==session.key){abort.abort();onStatus?.('unavailable',{lane:'computer',reason:current?.reason??'windows_session_probe_unavailable'});return;}
    onReady?.(info);
   };
   return Promise.resolve().then(()=>connect({signal:abort.signal,onReady:ready})).finally(()=>{abort.abort();sessionSignal.removeEventListener('abort',cancel)});
  }
 });
}
