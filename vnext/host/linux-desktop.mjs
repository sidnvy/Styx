// Linux desktop is a live capability of the owning user's logind session.
// Gateway/Exec/Browser lifetimes and enrollment are deliberately outside this module.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

const GUI_KEYS=['DISPLAY','WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS',
  'XAUTHORITY','HYPRLAND_INSTANCE_SIGNATURE','XDG_CURRENT_DESKTOP','XDG_SESSION_TYPE','XDG_SESSION_ID'];
const props=['Id','User','Type','Class','Active','State','Remote','Leader','LockedHint'];
const fields=text=>Object.fromEntries(String(text).split('\n').filter(x=>x.includes('='))
  .map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)]}));
function guiEnvironment(raw){
  const result={};
  for(const key of GUI_KEYS){
    let value=raw[key];
    if(typeof value!=='string'||value.length>4096||/[\0\r\n]/.test(value))continue;
    // systemctl quotes values requiring shell escaping. Never evaluate shell text.
    if(value.startsWith('"')){try{value=JSON.parse(value)}catch{continue}}
    else if(value.startsWith("'")&&value.endsWith("'"))value=value.slice(1,-1);
    if(typeof value==='string')result[key]=value;
  }
  return result;
}
const unavailable=reason=>({available:false,reason});
export function resolveLinuxDesktopSession({env=process.env,uid=process.getuid?.(),
  run=execFileSync,stat=fs.statSync,platform=process.platform}={}){
  if(platform!=='linux')return unavailable('linux_only');
  const call=(binary,args)=>String(run(binary,args,{encoding:'utf8',timeout:1500,
    maxBuffer:128*1024,stdio:['ignore','pipe','pipe']}));
  let sessions;
  try{
    const ids=call('/usr/bin/loginctl',['list-sessions','--no-legend','--no-pager'])
      .trim().split('\n').filter(Boolean).map(line=>line.trim().split(/\s+/))
      .filter(parts=>parts[1]===String(uid)).map(parts=>parts[0]);
    sessions=ids.filter(id=>/^[A-Za-z0-9_-]{1,64}$/.test(id)).map(id=>fields(call(
      '/usr/bin/loginctl',['show-session',id,...props.flatMap(p=>['-p',p]),'--no-pager'])))
      .filter(s=>s.User===String(uid)&&s.Remote==='no'&&s.Class==='user'&&
        s.Active==='yes'&&s.State==='active'&&['wayland','x11'].includes(s.Type));
  }catch{return unavailable('session_manager_unavailable')}
  if(!sessions.length)return unavailable('no_active_graphical_session');
  let managed={};
  try{managed=guiEnvironment(fields(call('/usr/bin/systemctl',['--user','show-environment'])))}catch{}
  const sources=[guiEnvironment(env),managed];
  let locked=false;
  for(const candidate of sources){
    const matching=candidate.XDG_SESSION_ID?sessions.filter(s=>s.Id===candidate.XDG_SESSION_ID):sessions;
    if(matching.length!==1)continue;
    const session=matching[0];
    // Unknown lock state is unavailable, rather than assuming an unlocked desktop.
    if(session.LockedHint!=='no'){locked=true;continue}
    try{
      const runtime=candidate.XDG_RUNTIME_DIR;
      if(!runtime||!path.isAbsolute(runtime))continue;
      const dir=stat(runtime);
      if(!dir.isDirectory()||dir.uid!==uid||(dir.mode&0o077)!==0)continue;
      let displaySocket;
      if(session.Type==='wayland'){
        const display=candidate.WAYLAND_DISPLAY;
        if(!display||!/^[A-Za-z0-9_.-]+$/.test(display))continue;
        displaySocket=path.join(runtime,display);
      }else{
        const match=/^:([0-9]+)(?:\.[0-9]+)?$/.exec(candidate.DISPLAY??'');
        if(!match)continue;
        displaySocket='/tmp/.X11-unix/X'+match[1];
      }
      const socket=stat(displaySocket);
      if(!socket.isSocket()||socket.uid!==uid)continue;
      const selected={...candidate,XDG_SESSION_ID:session.Id,XDG_SESSION_TYPE:session.Type};
      // Remove the other backend's stale display rather than passing both to Cua.
      selected[session.Type==='wayland'?'DISPLAY':'WAYLAND_DISPLAY']='';
      if(session.Type==='wayland')selected.CUA_DRIVER_RS_ENABLE_WAYLAND='1';
      return {available:true,id:session.Id,type:session.Type,
        key:[session.Id,session.Leader,session.Type,displaySocket,socket.ino].join(':'),env:selected};
    }catch{/* A removed runtime/socket is a normal logout race. */}
  }
  return unavailable(locked?'desktop_locked':'graphical_session_environment_unavailable');
}
function wait(ms,signal){return new Promise(resolve=>{
  if(signal?.aborted)return resolve();
  const finish=()=>{clearTimeout(timer);signal?.removeEventListener('abort',finish);resolve()};
  const timer=setTimeout(finish,ms);signal?.addEventListener('abort',finish,{once:true});
})}
// connect receives only a live session and a session-scoped AbortSignal. A logout,
// lock or replacement cancels and drains that Computer connector before resuming.
export async function runLinuxDesktopLifecycle({connect,signal,onStatus,
  resolveSession=resolveLinuxDesktopSession,pollMs=2000,once=false}={}){
  if(typeof connect!=='function')throw Error('desktop_connector_required');
  if(!Number.isInteger(pollMs)||pollMs<10||pollMs>60000)throw Error('invalid_desktop_poll');
  let active,lastStatus;
  const report=(state,reason)=>{const key=state+':'+(reason??'');if(lastStatus!==key){
    lastStatus=key;onStatus?.(state,{lane:'computer',...(reason?{reason}:{})});
  }};
  const stop=async()=>{if(active){active.abort.abort();await active.done;active=undefined}};
  try{
    do{
      let session;
      try{session=await resolveSession()}catch{session=unavailable('session_probe_failed')}
      if(active&&(!session.available||session.key!==active.key||active.finished))await stop();
      if(!session.available)report('unavailable',session.reason);
      else if(!active&&!signal?.aborted){
        const abort=new AbortController();
        const cancel=()=>abort.abort();signal?.addEventListener('abort',cancel,{once:true});
        active={key:session.key,abort,finished:false};
        const current=active;
        current.done=Promise.resolve().then(()=>connect(session,{signal:abort.signal}))
          .catch(()=>report('connection_failed'))
          .finally(()=>{current.finished=true;signal?.removeEventListener('abort',cancel)});
        report('session_available');
      }
      if(once){if(active)await active.done;return}
      await wait(pollMs,signal);
    }while(!signal?.aborted);
  }finally{await stop()}
}
