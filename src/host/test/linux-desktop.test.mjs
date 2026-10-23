import test from 'node:test';
import assert from 'node:assert/strict';
import {resolveLinuxDesktopSession,runLinuxDesktopLifecycle} from '../linux-desktop.mjs';
const env={WAYLAND_DISPLAY:'wayland-1',XDG_RUNTIME_DIR:'/run/user/1000',DBUS_SESSION_BUS_ADDRESS:'unix:path=/run/user/1000/bus'};
function fixture({sessions,manager=env,socket=true,owner=1000,mode=0o700}={}){
  sessions??=[{Id:'1',User:'1000',Type:'wayland',Class:'user',Active:'yes',State:'active',Remote:'no',Leader:'99',LockedHint:'no'}];
  const calls=[];
  return {calls,options:{platform:'linux',uid:1000,env:{},run(binary,args){
    calls.push([binary,...args]);
    if(args[0]==='list-sessions')return sessions.map(s=>`${s.Id} ${s.User} user seat0`).join('\n');
    if(args[0]==='show-session')return Object.entries(sessions.find(s=>s.Id===args[1])).map(([k,v])=>`${k}=${v}`).join('\n');
    return Object.entries(manager).map(([k,v])=>`${k}=${v}`).join('\n');
  },stat(file){return {uid:owner,mode,ino:123,isDirectory:()=>file==='/run/user/1000',isSocket:()=>socket&&file!=='/run/user/1000'}}}};
}
test('DISPLAY, explicit socket and headless manager environment do not prove a session',()=>{
  const f=fixture({sessions:[]});
  assert.deepEqual(resolveLinuxDesktopSession({...f.options,env:{DISPLAY:':0'}}),{available:false,reason:'no_active_graphical_session'});
});
test('active owned logind session plus owned socket yields fixed GUI environment only',()=>{
  const f=fixture({manager:{...env,SECRET_TOKEN:'must-not-forward',DISPLAY:':4'}});
  const state=resolveLinuxDesktopSession(f.options);
  assert.equal(state.available,true);assert.equal(state.id,'1');assert.equal(state.env.SECRET_TOKEN,undefined);
  assert.equal(state.env.DISPLAY,'');assert.equal(state.env.CUA_DRIVER_RS_ENABLE_WAYLAND,'1');
  assert.equal(state.env.XDG_SESSION_ID,'1');
  assert.ok(f.calls.some(call=>call.includes('-p')&&call.includes('LockedHint')));
});
test('lock, remote, inactive, nongraphical, other uid, and unknown lock never attach',()=>{
  for(const change of [{LockedHint:'yes'},{LockedHint:''},{Remote:'yes'},{Active:'no'},{State:'closing'},{Type:'tty'},{User:'1001'},{Class:'manager'}]){
    const base=fixture().options;
    const read=base.run('/usr/bin/loginctl',['show-session','1']);
    const session=Object.fromEntries(read.split('\n').map(x=>x.split('=')));
    assert.equal(resolveLinuxDesktopSession(fixture({sessions:[{...session,...change}]}).options).available,false,JSON.stringify(change));
  }
});
test('runtime directory permissions and display socket ownership are required',()=>{
  for(const options of [{socket:false},{owner:1001},{mode:0o755}])assert.equal(resolveLinuxDesktopSession(fixture(options).options).available,false);
  assert.equal(resolveLinuxDesktopSession({...fixture().options,env:{...env,WAYLAND_DISPLAY:'../../other'}}).available,true,'invalid caller env falls back to verified manager');
  assert.equal(resolveLinuxDesktopSession(fixture({manager:{...env,WAYLAND_DISPLAY:'../../other'}}).options).available,false);
});
test('multiple active sessions require an explicit matching session id',()=>{
  const base=fixture().options.run('', ['show-session','1']);const one=Object.fromEntries(base.split('\n').map(x=>x.split('=')));
  const f=fixture({sessions:[one,{...one,Id:'3'}]});
  assert.equal(resolveLinuxDesktopSession(f.options).available,false);
  assert.equal(resolveLinuxDesktopSession({...f.options,env:{...env,XDG_SESSION_ID:'3'}}).id,'3');
});
test('missing logind fails closed without executing arbitrary binaries',()=>{
  assert.equal(resolveLinuxDesktopSession({...fixture().options,run(){throw Error('offline')}}).reason,'session_manager_unavailable');
});
test('X11 requires a local display and owned X11 socket',()=>{
  const f=fixture();const base=Object.fromEntries(f.options.run('', ['show-session','1']).split('\n').map(x=>x.split('=')));
  const options=fixture({sessions:[{...base,Type:'x11'}],manager:{...env,DISPLAY:':0'}}).options;
  const state=resolveLinuxDesktopSession(options);assert.equal(state.type,'x11');assert.equal(state.env.WAYLAND_DISPLAY,'');
  assert.equal(resolveLinuxDesktopSession({...options,env:{},run:(bin,args)=>args[1]==='show-environment'?'DISPLAY=remote:0':options.run(bin,args)}).available,false);
});
test('lifecycle drains Computer on logout and resumes on new login without touching other lanes',async()=>{
  const abort=new AbortController(),events=[],states=[];
  const live=id=>({available:true,id,key:id,env});
  let session={available:false,reason:'no_active_graphical_session'},current;
  let startResolve;const start=()=>new Promise(resolve=>{startResolve=resolve});let started=start();
  const done=runLinuxDesktopLifecycle({signal:abort.signal,pollMs:10,resolveSession:()=>session,onStatus:(state,meta)=>states.push([state,meta.reason]),
    connect(s,{signal}){events.push('start:'+s.id);current=s.id;startResolve();return new Promise(resolve=>signal.addEventListener('abort',()=>{
      setTimeout(()=>{events.push('stop:'+s.id);current=undefined;resolve()},5);
    },{once:true}));}});
  await new Promise(r=>setTimeout(r,20));assert.equal(current,undefined);
  session=live('1');await started;assert.equal(current,'1');
  session={available:false,reason:'desktop_locked'};await new Promise(r=>setTimeout(r,40));assert.equal(current,undefined);
  started=start();session=live('2');await started;
  started=start();session=live('3');await started;
  abort.abort();await done;
  assert.deepEqual(events,['start:1','stop:1','start:2','stop:2','start:3','stop:3']);
  assert.ok(states.some(([s,r])=>s==='unavailable'&&r==='desktop_locked'));
});
test('probe failure affects Computer only and waits for future recovery',async()=>{
  const abort=new AbortController();let count=0,connected=0;
  await runLinuxDesktopLifecycle({pollMs:10,signal:abort.signal,resolveSession(){if(++count===1)throw Error('logind restarted');return {available:true,key:'recovered',env}},connect(){connected++;abort.abort()}});
  assert.equal(connected,1);
});
