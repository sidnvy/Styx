import fs from 'node:fs';
import {requirePrivateFile} from '../shared/private-file.mjs';
import path from 'node:path';
import {randomInt} from 'node:crypto';
import WebSocket from 'ws';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {stdioClient} from '../packages/styx-exec-adapter/rpc.mjs';
import {runComputerConnectors} from './computer.mjs';

function tokenFrom(filename) {
  requirePrivateFile(filename);
  const value=fs.readFileSync(filename,'utf8').trim();
  if (!/^[A-Za-z0-9_-]{32,}$/.test(value)) throw Error('invalid_host_token');
  return value;
}

export function normalizeConnector(config) {
  if (!config || typeof config!=='object' || Array.isArray(config)) throw Error('invalid_host_config');
  if (typeof config.host_id!=='string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(config.host_id)) throw Error('invalid_host_id');
  const url=new URL(config.gateway_ws_url);
  if (!['ws:','wss:'].includes(url.protocol) || url.username || url.password ||
      url.search || url.hash || (url.protocol==='ws:' &&
        !['localhost','127.0.0.1','[::1]'].includes(url.hostname))) {
    throw Error('gateway_requires_tls');
  }
  if (url.pathname!=='/' && url.pathname!=='') throw Error('gateway_url_must_be_origin');
  url.pathname='/styx/hosts/'+encodeURIComponent(config.host_id)+'/exec';
  const hasBearer=typeof config.token_file==='string' &&
    path.isAbsolute(config.token_file);
  const hasMtls=typeof config.client_cert_file==='string' &&
    path.isAbsolute(config.client_cert_file) &&
    typeof config.client_key_file==='string' &&
    path.isAbsolute(config.client_key_file);
  if(hasBearer===hasMtls || (config.token_file!==undefined && !hasBearer) ||
    (config.client_cert_file!==undefined && !hasMtls) ||
    (config.client_key_file!==undefined && !hasMtls))
    throw Error('exactly_one_host_auth_required');
  if(hasMtls && url.protocol!=='wss:') throw Error('mtls_requires_wss');
  if(config.gateway_ca_file!==undefined &&
    (typeof config.gateway_ca_file!=='string' || !path.isAbsolute(config.gateway_ca_file)))
    throw Error('invalid_gateway_ca_file');
  const e=config.exec;
  if(!e || typeof e!=='object' || typeof e.binary!=='string' ||
    !path.isAbsolute(e.binary) || typeof e.cwd!=='string' || !path.isAbsolute(e.cwd))
    throw Error('invalid_local_executor');
  if (e.env!==undefined && (typeof e.env!=='object' || Array.isArray(e.env) ||
      Object.values(e.env).some(x=>typeof x!=='string'))) throw Error('invalid_executor_environment');
  return {...config, endpoint:url.href, exec:{...e}};
}

// No local listening socket. One host outbound WebSocket transports unmodified
// Codex Exec JSON-RPC frames from a locally supervised stdio child.
export function hostAuthentication(config){
  const c=normalizeConnector(config);
  const token=c.token_file ? tokenFrom(c.token_file) : undefined;
  let clientCert,clientKey,gatewayCa;
  if(c.client_cert_file){
    clientCert=fs.readFileSync(c.client_cert_file);
    requirePrivateFile(c.client_key_file);
    clientKey=fs.readFileSync(c.client_key_file);
  }
  if(c.gateway_ca_file) gatewayCa=fs.readFileSync(c.gateway_ca_file);
  return {
    ...(token?{headers:{Authorization:'Bearer '+token}}:{}),
    ...(clientCert?{cert:clientCert,key:clientKey}:{}),
    ...(gatewayCa?{ca:gatewayCa}:{})
  };
}

export async function connectHostOnce(config, {signal,onReady,workAdmission}={}) {
  const c=normalizeConnector(config);
  const auth=hostAuthentication(c);
  if (signal?.aborted) throw Error('connector_cancelled');
  let client,ws;const workPeer=workAdmission?.openPeer('exec');
  try {
    client=await stdioClient({
      binary:c.exec.binary,cwd:c.exec.cwd,
      env:{...process.env,...(c.exec.env??{})},timeoutMs:c.exec.timeout_ms??35000
    });
    ws=new WebSocket(c.endpoint,{maxPayload:2*1024*1024,
      handshakeTimeout:5000,followRedirects:false,perMessageDeflate:false,
      ...auth});
    await Promise.race([
      once(ws,'open'),
      new Promise((_,reject)=>signal?.addEventListener('abort',
        ()=>reject(Error('connector_cancelled')),{once:true}))
    ]);
    if (signal?.aborted) throw Error('connector_cancelled');
    const channel=client.channel;
    let settled=false;
    return await new Promise(resolve=>{
      const finish=()=>{if(settled)return;settled=true;resolve()};
      const cancel=()=>{ws.terminate();finish()};
      signal?.addEventListener('abort',cancel,{once:true});
      ws.on('error',finish);
      ws.on('close',finish);
      channel.on('closed',()=>{ws.terminate();finish()});
      ws.on('message',(data,isBinary)=>{
        if (isBinary || data.length>2*1024*1024) {ws.terminate();return}
        try {const message=JSON.parse(String(data));workPeer?.request(message);channel.send(String(data))}
        catch(error){if(error.message==='device_in_maintenance'){const message=JSON.parse(String(data));ws.send(JSON.stringify({jsonrpc:'2.0',id:message.id,error:{code:-32001,message:'device_in_maintenance'}}));return}ws.terminate()}
      });
      channel.on('message', data=>{
        if (ws.readyState!==WebSocket.OPEN) return;
        if (Buffer.byteLength(data)>2*1024*1024) {ws.terminate();return}
        ws.send(String(data),{binary:false},err=>{if(err){workAdmission?.markUnknown();ws.terminate()}else{try{workPeer?.response(JSON.parse(String(data)))}catch{workAdmission?.markUnknown()}}});
      });
      workPeer?.ready();onReady?.({host_id:c.host_id});
    });
  } finally {
    workPeer?.close();ws?.terminate();
    await client?.close().catch(()=>{});
  }
}
export async function runHostConnector(config,{signal,once:runOnce=false,
  retryMinMs=500,retryMaxMs=15000,onReady,onStatus,workAdmission}={}) {
  let failures=0;
  while(!signal?.aborted) {
    try {
      await connectHostOnce(config,{signal,onReady,workAdmission});
      failures=0;onStatus?.('disconnected');
    } catch {
      failures++;
      onStatus?.('connection_failed');
    }
    if(runOnce) return;
    const delay=Math.min(retryMaxMs,retryMinMs*Math.pow(2,Math.min(8,failures)))+
      randomInt(0, Math.max(1,Math.floor(retryMinMs)));
    await new Promise(resolve=>{
      const timer=setTimeout(resolve,delay);
      if(signal) signal.addEventListener('abort',()=>{clearTimeout(timer);resolve()},{once:true});
    });
  }
}
async function runCommandLine() {
  const filename=process.argv[2];
  if (!filename) {process.stderr.write('Usage: node host/connect.mjs /private/host.json or --stdin-config\n');process.exit(2)}
  let config;
  try {
    // The signed stable launcher passes a verified, generation-specific
    // configuration over a one-shot local stdin pipe. No secret-bearing
    // temporary config file is created. Ordinary direct Host CLI remains.
    if(filename!=='--stdin-config')requirePrivateFile(filename);
    const raw=filename==='--stdin-config' ? fs.readFileSync(0,'utf8')
      :fs.readFileSync(filename,'utf8');
    if(raw.length>65536)throw Error('host_config_too_large');
    config=JSON.parse(raw);
    normalizeConnector(config);
    if(config.token_file) tokenFrom(config.token_file);
    if(config.client_cert_file) {
      fs.readFileSync(config.client_cert_file);
      requirePrivateFile(config.client_key_file);
    }
  } catch {
    process.stderr.write('Styx Host configuration invalid.\n');process.exit(2);
  }
  const abort=new AbortController();
  process.once('SIGINT',()=>abort.abort());
  process.once('SIGTERM',()=>abort.abort());
  const status=(state,{lane='exec',slot}={})=>
    process.stdout.write(JSON.stringify({host:config.host_id,lane,
      ...(slot!==undefined?{slot}:{}),status:state})+'\n');
  try { await Promise.all([
    runHostConnector(config,{signal:abort.signal,
      onStatus:state=>status(state),
      onReady:info=>status('connected',{lane:'exec'})}),
    ...(config.browser?.enabled?[import('./browser.mjs').then(({runBrowserConnector})=>runBrowserConnector(config,{signal:abort.signal,onStatus:(state,meta)=>status(state,meta),onReady:()=>status('connected',{lane:'browser'})}))]:[]),
    ...(config.computer?.enabled?[process.platform==='linux'
      ? import('./linux-desktop.mjs').then(({runLinuxDesktopLifecycle,resolveLinuxDesktopSession})=>runLinuxDesktopLifecycle({
        signal:abort.signal,onStatus:(state,meta)=>status(state,meta),
        resolveSession:()=>resolveLinuxDesktopSession({env:{...process.env,...config.computer.env}}),
        connect:(session,{signal})=>runComputerConnectors({...config,computer:{...config.computer,
          env:{...config.computer.env,DISPLAY:'',WAYLAND_DISPLAY:'',...session.env}}},{signal,
          onStatus:(state,meta)=>status(state,meta),onReady:()=>status('connected',{lane:'computer'})})}))
      :runComputerConnectors(config,{signal:abort.signal,onStatus:(state,meta)=>status(state,meta),
        onReady:()=>status('connected',{lane:'computer'})})]:[])
  ]); } finally { abort.abort(); }
}
// Finish evaluating this module before optional Browser imports it for shared
// authentication. Awaiting the CLI lanes at module scope deadlocks that cycle.
// Keep Browser lazy: Exec-only signed bundles do not contain its provider.
if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  void runCommandLine().catch(()=>{
    process.stderr.write('Styx Host startup failed.\n');
    process.exitCode=1;
  });
}
