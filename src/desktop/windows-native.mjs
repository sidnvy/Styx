import {powershellCommand} from './exec.mjs';
import {createHash} from 'node:crypto';
import {DesktopError} from './primitives.mjs';
const script=__STYX_WINDOWS_NATIVE_SCRIPT__;
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export function sessionFromEvidence(value){
 const valid=e=>e?.supported===true&&e.same_user===true&&e.input_receiving===true&&e.thread_receiving===true&&
  Number.isInteger(e.process_session)&&e.process_session>0&&e.process_session<0xffffffff&&
  e.process_session===e.console_session&&e.process_session===e.reported_session&&e.state===0&&e.flags===1&&
  e.station==='WinSta0'&&e.input_desktop==='Default'&&e.thread_desktop==='Default'&&
  typeof e.generation==='string'&&/^[a-f0-9]{64}$/.test(e.generation);
 if(!Array.isArray(value)||value.length!==2||!value.every(valid)||value[0].generation!==value[1].generation||value[0].process_session!==value[1].process_session)return {ready:false};
 return {ready:true,session_id:value[1].generation};
}
export function createWindowsNativeProbe(run){
 async function query(operation,hwnd=''){
  if(process.platform!=='win32')throw new DesktopError('driver_unavailable','Windows required');
  if(!['session','window','capture'].includes(operation)||(operation!=='session'&&!/^[1-9][0-9]{0,18}$/.test(hwnd)))throw new DesktopError('invalid_window','Invalid HWND');
  try{
   const raw=JSON.parse(await run('powershell.exe',powershellCommand(script,[operation,hwnd])));
   const session=sessionFromEvidence(raw?.sessions);
   if(!session.ready)throw new DesktopError('no_interactive_desktop','Session unavailable');
   if(operation==='session')return session;
   if(!raw.before||hash(raw.before)!==hash(raw.after)||raw.before.session_id!==raw.sessions[0].process_session)throw new DesktopError('stale_target','Native identity changed');
   raw.before.session_generation=session.session_id;
   if(operation==='window')return raw.before;
   const p=raw.before;
   return {identity:{hwnd:p.hwnd,pid:p.pid,start_time:p.start_time,session_id:p.session_id,session_generation:session.session_id,user_sid:p.user_sid,thread_desktop:p.thread_desktop,thread_receiving:p.thread_receiving,title_digest:hash(p.title)},image:{mimeType:'image/png',data:raw.png}};
  }catch(e){throw new DesktopError(e instanceof DesktopError?e.code:'stale_target','Native evidence unavailable');}
 }
 return {session:()=>query('session'),window:hwnd=>query('window',hwnd),capture:hwnd=>query('capture',hwnd)};
}
