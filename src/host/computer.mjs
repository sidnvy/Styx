import {spawn} from 'node:child_process';
import {StringDecoder} from 'node:string_decoder';
import {randomInt} from 'node:crypto';
import path from 'node:path';
import WebSocket from 'ws';
import {hostAuthentication,normalizeConnector} from './connect.mjs';

const MAX_COMPUTER_FRAME=8*1024*1024;
const delay=(ms,signal)=>new Promise(resolve=>{
  if(signal?.aborted)return resolve();
  const timer=setTimeout(()=>{signal?.removeEventListener('abort',stop);resolve()},ms);
  const stop=()=>{clearTimeout(timer);resolve()};
  signal?.addEventListener('abort',stop,{once:true});
});

export function computerConfig(config) {
  const c=normalizeConnector(config);
  const driver=c.computer;
  if(!driver || driver.enabled!==true)return null;
  if(typeof driver.binary!=='string' || !path.isAbsolute(driver.binary))
    throw Error('invalid_cua_binary');
  if(driver.socket!==undefined && (typeof driver.socket!=='string' ||
    !path.isAbsolute(driver.socket))) throw Error('invalid_cua_socket');
  // On macOS, the GUI permission-bearing Styx.app must already own the
  // embedded daemon. Never auto-start a standalone Cua runtime from SSH.
  if(process.platform==='darwin' && !driver.socket)
    throw Error('macos_requires_embedded_cua_socket');
  if(driver.env!==undefined && (!driver.env || typeof driver.env!=='object' ||
    Array.isArray(driver.env) ||
    Object.values(driver.env).some(value=>typeof value!=='string')))
    throw Error('invalid_cua_environment');
  const connections=driver.connections??1;
  if(!Number.isInteger(connections)||connections<1||connections>8)
    throw Error('invalid_cua_connections');
  const endpoint=new URL(c.endpoint);
  endpoint.pathname=endpoint.pathname.replace(/\/exec$/,'/computer');
  return {...c,computer:{...driver,connections},computerEndpoint:endpoint.href};
}


// Documented Cua v0.36.0 launch shapes:
// - Windows/Linux: bare mcp owns runtime unless a daemon socket is used.
// - macOS Embedded: mcp --embedded --socket <app-owned-private-socket>
//   attaches to a daemon spawned by the signed GUI application.
export function computerMcpArgs(driver,{platform=process.platform}={}) {
  if(platform==='darwin') {
    if(!driver.socket)throw Error('macos_requires_embedded_cua_socket');
    return ['mcp','--embedded','--socket',driver.socket];
  }
  return ['mcp',...(driver.socket?['--socket',driver.socket]:[])];
}

export async function connectComputerOnce(config,{signal,onReady,workAdmission}={}) {
  const c=computerConfig(config);
  if(!c)throw Error('computer_not_configured');
  if(signal?.aborted)throw Error('connector_cancelled');
  const auth=hostAuthentication(c);
  let ws,child,childClosed,cleanup;const workPeer=workAdmission?.openPeer('computer');
  let childExited=false;
  let closed=false;
  const stop=()=>{
    if(cleanup)return cleanup;
    closed=true;
    try{ws?.terminate()}catch{}
    try{child?.stdin.end()}catch{}
    // Only this ChildProcess is ours. An attached App-owned embedded daemon is
    // outside this lifetime. Wait for actual exit, escalating only this child.
    cleanup=(async()=>{
      if(!child||childExited)return;
      try{child.kill('SIGTERM')}catch{}
      let timer;
      await Promise.race([childClosed,new Promise(resolve=>{timer=setTimeout(resolve,2000)})]);
      clearTimeout(timer);
      if(!childExited){try{child.kill('SIGKILL')}catch{}await childClosed;}
    })();
    return cleanup;
  };
  const abort=()=>stop();
  signal?.addEventListener('abort',abort,{once:true});
  try {
    const args=computerMcpArgs(c.computer);
    child=spawn(c.computer.binary,args,{
      cwd:c.exec.cwd,windowsHide:true,
      env:{...process.env,DO_NOT_TRACK:'1',CUA_DRIVER_RS_TELEMETRY_ENABLED:'false',
        ...(process.platform==='darwin'?{CUA_DRIVER_EMBEDDED:'1'}:{}),
        ...(c.computer.env??{})},
      stdio:['pipe','pipe','pipe']
    });
    childClosed=new Promise(resolve=>child.once('close',()=>{childExited=true;resolve()}));
    child.stderr.resume();
    child.on('error',stop);
    child.on('close',stop);
    child.stdin.on('error',stop);

    ws=new WebSocket(c.computerEndpoint,{
      ...auth,maxPayload:MAX_COMPUTER_FRAME,handshakeTimeout:5000,
      followRedirects:false,perMessageDeflate:false
    });
    // Attach readers before handshake: a GUI reply must not be lost even if
    // initialization starts immediately after the gateway claims this socket.
    const decoder=new StringDecoder('utf8');
    let buffer='';
    child.stdout.on('data',bytes=>{
      if(closed)return;
      buffer+=decoder.write(bytes);
      if(Buffer.byteLength(buffer)>MAX_COMPUTER_FRAME){stop();return}
      let pos;
      while((pos=buffer.indexOf('\n'))>=0) {
        const line=buffer.slice(0,pos);buffer=buffer.slice(pos+1);
        if(!line.trim())continue;
        if(Buffer.byteLength(line)>MAX_COMPUTER_FRAME){stop();return}
        try {
          const obj=JSON.parse(line);
          if(!obj || typeof obj!=='object' || Array.isArray(obj))throw Error();
          workPeer?.response(obj);
        }catch{stop();return}
        if(ws.readyState!==WebSocket.OPEN){stop();return}
        if(ws.bufferedAmount>2*MAX_COMPUTER_FRAME){stop();return}
        ws.send(line,{binary:false},err=>{if(err)stop()});
      }
    });
    ws.on('message',(payload,isBinary)=>{
      if(closed)return;
      if(isBinary || payload.length>MAX_COMPUTER_FRAME ||
        !child.stdin.writable || child.stdin.writableLength>2*MAX_COMPUTER_FRAME) {
        stop();return;
      }
      try {
        const msg=JSON.parse(String(payload));
        if(!msg || typeof msg!=='object' || Array.isArray(msg))throw Error();
        try{workPeer?.request(msg)}catch(error){if(error.message==='device_in_maintenance'){ws.send(JSON.stringify({jsonrpc:'2.0',id:msg.id,error:{code:-32001,message:'device_in_maintenance'}}));return}throw error}
        child.stdin.write(JSON.stringify(msg)+'\n');
      }catch{stop()}
    });
    const connected=await new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>reject(Error('computer_connect_timeout')),7000);
      const done=(fn,value)=>{
        clearTimeout(timer);
        ws.off('open',open);ws.off('error',fail);ws.off('close',close);
        fn(value);
      };
      const open=()=>done(resolve);
      const fail=()=>done(reject,Error('computer_websocket_unavailable'));
      const close=()=>done(reject,Error('computer_socket_closed'));
      ws.once('open',open);ws.once('error',fail);ws.once('close',close);
      if(ws.readyState===WebSocket.OPEN) open();
    });
    if(closed || signal?.aborted)throw Error('computer_connector_closed');
    onReady?.({host_id:c.host_id,lane:'computer'},{isCurrent:()=>!closed&&!childExited&&!signal?.aborted&&ws.readyState===WebSocket.OPEN});
    await new Promise(resolve=>{
      const complete=()=>resolve();
      ws.once('close',complete);
      ws.once('error',complete);
      child.once('close',complete);
      if(closed) resolve();
    });
  }finally{
    workPeer?.close();await stop();
    signal?.removeEventListener('abort',abort);
    // Termination of a tool server does not establish that an in-flight GUI
    // click was rolled back. Gateway presents unknown mutation outcome.
  }
}

export async function runComputerConnectors(config,{signal,once=false,
  retryMinMs=500,retryMaxMs=15000,onReady,onStatus,workAdmission}={}) {
  const c=computerConfig(config);
  if(!c)return;
  if(process.platform==='win32'){
    const {runWindowsDesktopLifecycle}=await import('./windows-session.mjs');
    return runWindowsDesktopLifecycle({probe:c.computer.sessionProbe,signal,onReady,onStatus,once,
      connect:session=>runComputerLanes(c,{signal:session.signal,once,retryMinMs,retryMaxMs,onReady:session.onReady,onStatus,workAdmission})});
  }
  return runComputerLanes(c,{signal,once,retryMinMs,retryMaxMs,onReady,onStatus,workAdmission});
}
async function runComputerLanes(c,{signal,once,retryMinMs,retryMaxMs,onReady,onStatus,workAdmission}){
  const one=async slot=>{
    let failed=0;
    while(!signal?.aborted) {
      try{
        await connectComputerOnce(c,{signal,onReady,workAdmission});
        failed=0;onStatus?.('disconnected',{slot,lane:'computer'});
      }catch{
        failed++;
        onStatus?.('connection_failed',{slot,lane:'computer'});
      }
      if(once)return;
      const interval=Math.min(retryMaxMs,retryMinMs*(2**Math.min(8,failed)))+
        randomInt(0,Math.max(1,Math.floor(retryMinMs)));
      await delay(interval,signal);
    }
  };
  await Promise.all(Array.from({length:c.computer.connections},(_,slot)=>one(slot)));
}
