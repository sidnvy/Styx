import {readFileSync} from 'node:fs';
import {localDesktopExec,powershellCommand} from '../../src/desktop/exec.mjs';
const probe=new URL('../windows-session-probe.ps1',import.meta.url);
// Accept only the complete native evidence conjunction, never truthy/partial status.
export function sessionFromEvidence(value){
 const valid=e=>e?.supported===true&&e.same_user===true&&e.input_receiving===true&&e.thread_receiving===true&&
  Number.isInteger(e.process_session)&&e.process_session>0&&e.process_session<0xffffffff&&
  e.process_session===e.console_session&&e.process_session===e.reported_session&&e.state===0&&e.flags===1&&
  e.station==='WinSta0'&&e.input_desktop==='Default'&&e.thread_desktop==='Default'&&
  typeof e.generation==='string'&&/^[a-f0-9]{64}$/.test(e.generation);
 if(!Array.isArray(value)||value.length!==2||!value.every(valid)||value[0].generation!==value[1].generation||
  value[0].process_session!==value[1].process_session)return {ready:false};
 return {ready:true,session_id:value[1].generation};
}
export function createWindowsSessionProbe(run=localDesktopExec,{platform=process.platform}={}){
 return async()=>{
  if(platform!=='win32')return {ready:false};
  try{return sessionFromEvidence(JSON.parse(await run('powershell.exe',powershellCommand(readFileSync(probe,'utf8')),{timeout_ms:10000})));}
  catch{return {ready:false};}
 };
}
export const windowsSessionProbe=createWindowsSessionProbe();
