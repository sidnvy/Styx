#!/usr/bin/env node
// Bounded user-owned scratch-window test. Never target other applications.
const {spawn}=require('node:child_process');
const {randomBytes}=require('node:crypto');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const readline=require('node:readline');

const binary=process.argv[2],fixtureFile=process.argv[3];
if(!binary){console.error('usage: native-cua-gui.cjs cua-driver [scratch-winforms.ps1]');process.exit(2)}
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'styx-cua-gui-'));
const state=path.join(temp,'readback.txt');
let fixture,driver,finished=false,next=0,stderr='';
const pending=new Map();
function status(phase,extra={},code=2) {
  if(finished)return;finished=true;clearTimeout(watchdog);
  for(const promise of pending.values()){clearTimeout(promise.timer);promise.reject(Error('cleanup'))}
  pending.clear();
  try{driver?.stdin.end();driver?.kill()}catch{}
  try{if(fixture && fixture.exitCode===null)fixture.kill()}catch{}
  try{fs.rmSync(temp,{recursive:true,force:true})}catch{}
  console.log(JSON.stringify({pilot:'styx-cua-owned-gui',os:process.platform,
    phase,result:code===0?'PASS':'BLOCKED',...extra}));
  process.exitCode=code;
}
const watchdog=setTimeout(()=>status('global_timeout'),47000);
async function sleep(t){return new Promise(resolve=>setTimeout(resolve,t))}
function rpc(method,params={},timeoutMs=10000) {
  return new Promise((resolve,reject)=>{
    const id=++next;
    const timer=setTimeout(()=>{pending.delete(id);reject(Error(method+'_timeout'))},timeoutMs);
    pending.set(id,{resolve,reject,timer});
    driver.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');
  });
}
function notify(method){driver.stdin.write(JSON.stringify({jsonrpc:'2.0',method,params:{}})+'\n')}
function extractWindows(response){
  const data=response?.structuredContent??{};
  if(Array.isArray(data.windows))return data.windows;
  if(Array.isArray(data.data?.windows))return data.data.windows;
  return [];
}
(async()=>{
  if(process.platform==='win32'){
    if(!fixtureFile || !fs.existsSync(fixtureFile))throw Error('scratch_fixture_missing');
    const psh=process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    fixture=spawn(psh,['-NoProfile','-STA','-File',fixtureFile,'-StateFile',state],
      {windowsHide:false,stdio:'ignore'});
  } else if(process.platform==='linux'){
    fixture=spawn('/usr/bin/zenity',['--question',
      '--title=Styx Cua Owned Scratch 20261017',
      '--text=Only this scratch dialog is an automation test target',
      '--ok-label=Styx Increment','--cancel-label=Cancel'],
      {env:{...process.env,GDK_BACKEND:process.env.STYX_GUI_BACKEND||'x11'},
        stdio:'ignore'});
  }else throw Error('scratch_fixture_not_configured');
  const fixtureExited=new Promise(resolve=>fixture.once('exit',(code)=>resolve(code)));
  driver=spawn(binary,['mcp'],{windowsHide:true,
    env:{...process.env,DO_NOT_TRACK:'1',CUA_DRIVER_RS_TELEMETRY_ENABLED:'false',
      ...(process.platform==='linux'?{CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}:{})},
    stdio:['pipe','pipe','pipe']});
  driver.stderr.on('data',b=>{stderr+=b.toString().slice(0,150)});
  driver.on('error',e=>{stderr='driver_spawn_'+e.code});
  const rl=readline.createInterface({input:driver.stdout});
  rl.on('line',line=>{
    try {
      const obj=JSON.parse(line),p=pending.get(obj.id);
      if(!p)return;clearTimeout(p.timer);pending.delete(obj.id);
      obj.error?p.reject(Error('rpc_'+obj.error.code)):p.resolve(obj.result);
    }catch{}
  });
  await rpc('initialize',{protocolVersion:'2025-06-18',capabilities:{},
    clientInfo:{name:'styx-owned-gui-pilot',version:'0.1.0'}});
  notify('notifications/initialized');
  let found;
  for(let n=0;n<18;n++){
    await sleep(300);
    const r=await rpc('tools/call',{name:'list_windows',arguments:{pid:fixture.pid,
      on_screen_only:false}});
    const windows=extractWindows(r);
    found=windows.find(w=>String(w.title||'').includes('Styx Cua Owned Scratch'));
    if(found)break;
    if(fixture.exitCode!==null)break;
  }
  if(!found)return status('scratch_window_not_discovered',{
    fixturePid:fixture.pid,backend:process.platform==='linux'?(process.env.STYX_GUI_BACKEND||'x11'):null});
  const winId=found.window_id??found.windowId;
  if(!Number.isSafeInteger(Number(winId))||Number(winId)<1)return status('invalid_window_id');
  const snapshot=await rpc('tools/call',{name:'get_window_state',arguments:{
    pid:fixture.pid,window_id:Number(winId),tree_format:'elements',
    include_screenshot:true,max_elements:100}});
  const data=snapshot?.structuredContent??{};
  if(snapshot.isError)return status('snapshot_refused',{error:'native_refusal'});
  const elements=Array.isArray(data.elements)?data.elements:[];
  const button=elements.find(e=>String(e.label||e.name||'').includes('Styx Increment'));
  if(!button?.element_token)return status('button_not_in_accessibility_tree',{
    elementCount:elements.length,hasScreenshot:(snapshot.content||[]).some(x=>x.type==='image')});
  const result=await rpc('tools/call',{name:'click',arguments:{
    target:{kind:'window',pid:fixture.pid,window_id:Number(winId)},
    element_token:button.element_token}},12000);
  let readback=false,exitCode=null;
  for(let n=0;n<12;n++){
    if(process.platform==='win32' && fs.existsSync(state) &&
      fs.readFileSync(state,'utf8')==='clicked'){readback=true;break}
    if(process.platform==='linux' && fixture.exitCode===0){readback=true;exitCode=0;break}
    await sleep(250);
  }
  if(!readback && process.platform==='linux' && fixture.exitCode===null){
    exitCode=await Promise.race([fixtureExited,new Promise(r=>setTimeout(()=>r(null),500))]);
    readback=exitCode===0;
  }
  return status(readback?'action_independently_verified':'action_unverified',{
    fixturePid:fixture.pid,windowId:Number(winId),
    elementCount:elements.length,hasScreenshot:(snapshot.content||[]).some(x=>x.type==='image'),
    nativeIsError:result.isError===true,verified:readback,
    backend:process.platform==='linux'?(process.env.STYX_GUI_BACKEND||'x11'):null
  },readback?0:2);
})().catch(e=>status('pilot_error',{error:String(e.message).slice(0,130)}));
