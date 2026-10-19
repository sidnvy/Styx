// App-owned Secure MCP Tunnel adapter. CLI contract: official tunnel-client
// 0.0.16 run --help; https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {ensurePrivateDirectory,requirePrivateFile,openPrivateFile,writePrivateFile} from '../host/private-storage.mjs';
import {readDeployment} from './core.mjs';
const fail=code=>{throw Error(code)};
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function read(file){requirePrivateFile(file);if(fs.statSync(file).size>65536)fail('tunnel_state_too_large');return fs.readFileSync(file,'utf8');}
function write(file,value){const tmp=file+'.'+randomBytes(8).toString('hex');try{writePrivateFile(tmp,value);fs.renameSync(tmp,file);}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp);}}
function locations(stateDir){readDeployment(stateDir);const root=path.join(stateDir,'tunnel');ensurePrivateDirectory(root);return {root,config:path.join(root,'connection.json'),lock:path.join(root,'owner.lock'),header:path.join(root,'gateway-header'),health:path.join(root,'health.url')};}
function configAt(p){if(!fs.existsSync(p.config))return null;const c=JSON.parse(read(p.config));if(c.schema!==1||typeof c.autoStart!=='boolean'||!/^tunnel_[A-Za-z0-9_-]{8,128}$/.test(c.tunnelId)||!/^key-[a-f0-9]{32}$/.test(c.keyFile))fail('invalid_tunnel_configuration');read(path.join(p.root,c.keyFile));return c;}
function acquireOwnerLock(p){
 let fd;try{fd=openPrivateFile(p.lock,0o600)}catch{fail('tunnel_running_or_interrupted')}
 const token=randomBytes(24).toString('hex');
 try{fs.writeFileSync(fd,token)}catch(error){fs.closeSync(fd);fs.unlinkSync(p.lock);throw error}
 fs.closeSync(fd);return token;
}
function releaseOwnerLock(p,token){try{if(read(p.lock)===token)fs.unlinkSync(p.lock)}catch{}}
function gatewayAt(stateDir){
 const root=path.join(stateDir,'gateway'),r=JSON.parse(read(path.join(root,'runtime.json')));
 const expected=path.join(root,'model.token'),certificate=path.join(root,'certificate.pem');
 const url=new URL(r.url);
 if(r.schema!==1||r.modelTokenFile!==expected||r.tlsCertificateFile!==certificate||r.listenHost!=='127.0.0.1'||url.protocol!=='https:'||url.hostname!=='127.0.0.1'||!url.port||url.username||url.password||url.pathname!=='/'||url.search||url.hash)fail('tunnel_owned_loopback_gateway_required');
 const token=read(expected).trim();if(!/^[A-Za-z0-9_-]{32,256}$/.test(token))fail('invalid_gateway_model_credential');read(certificate);
 return {url:new URL('/mcp',url).href,certificate,header:'Bearer '+token};
}
export function configureTunnel(stateDir,{tunnelId,apiKey,autoStart=false,authorize=false}={}){
 if(authorize!==true)fail('explicit_tunnel_authorization_required');
 if(typeof autoStart!=='boolean')fail('invalid_tunnel_autostart');
 if(!/^tunnel_[A-Za-z0-9_-]{8,128}$/.test(tunnelId??''))fail('invalid_tunnel_id');
 if(typeof apiKey!=='string'||!/^sk-[A-Za-z0-9_-]{16,512}$/.test(apiKey))fail('invalid_tunnel_runtime_key');
 const p=locations(stateDir);gatewayAt(stateDir);
 const lockToken=acquireOwnerLock(p);
 try{
  // Configuration and process startup share the same cross-process lock. Read
  // after acquisition so key rotation cannot delete a starting client's key.
  const old=configAt(p),keyFile='key-'+randomBytes(16).toString('hex');
  writePrivateFile(path.join(p.root,keyFile),apiKey);
  try{write(p.config,JSON.stringify({schema:1,tunnelId,keyFile,autoStart})+'\n');}catch(e){fs.unlinkSync(path.join(p.root,keyFile));throw e;}
  if(old)fs.unlinkSync(path.join(p.root,old.keyFile));
  return {status:'configured',tunnelId,autoStart,accountAcceptance:'NOT RUN'};
 }finally{releaseOwnerLock(p,lockToken)}
}
// Only publisher/server configuration may supply this pin, never HTTP input.
export class TunnelRuntime {
 #retry=null;#wanted=false;#child=null;#pending=null;#ownedLock=false;#lockToken=null;#exit=null;#spawn;#binary;#sha;#stateDir;
 constructor({stateDir,binary,sha256,spawnProcess=spawn}){
  this.#stateDir=stateDir;this.#binary=binary;this.#sha=sha256;this.#spawn=spawnProcess;
 }
 status(){
  const p=locations(this.#stateDir),c=configAt(p);
  return {status:this.#child?'running':fs.existsSync(p.lock)?'interrupted':c?'configured':'not_configured',available:typeof this.#binary==='string'&&/^[a-f0-9]{64}$/.test(this.#sha??''),tunnelId:c?.tunnelId??null,autoStart:c?.autoStart??false,ownership:this.#child?'current_app':'none',lastExit:this.#exit,accountAcceptance:'NOT RUN'};
 }
 async resume(){
  const c=configAt(locations(this.#stateDir));
  return c?.autoStart===true?this.start({authorize:true}):this.status();
 }
 async health(){
  const status=this.status();if(!this.#child)return {...status,transport:'not_running'};
  const p=locations(this.#stateDir);
  try{
   const st=fs.lstatSync(p.health);
   if(!st.isFile()||st.isSymbolicLink()||st.size>2048)fail('invalid_health_url');
   const url=new URL(fs.readFileSync(p.health,'utf8').trim());
   if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||!url.port||url.username||url.password||!['/','/healthz','/readyz'].includes(url.pathname)||url.search||url.hash)fail('invalid_health_url');
   const codes=await Promise.all(['/healthz','/readyz'].map(async route=>{
    const response=await fetch(new URL(route,url),{redirect:'error',signal:AbortSignal.timeout(1500)});
    await response.body?.cancel();return response.status;
   }));
   return {...status,transport:codes[0]===200&&codes[1]===200?'ready':codes[0]===200?'starting':'unavailable'};
  }catch{return {...status,transport:'unavailable'};}
 }
 async start({authorize=false}={}){
  if(authorize!==true)fail('explicit_tunnel_authorization_required');
  this.#wanted=true;
  if(this.#retry){clearTimeout(this.#retry);this.#retry=null;}
  if(this.#pending) return this.#pending;
  if(this.#child)return this.status();
  this.#pending=this.#start();try{return await this.#pending;}catch(e){this.#schedule();throw e;}finally{this.#pending=null;}
 }
 async #start(){
  const p=locations(this.#stateDir);
  if(typeof this.#binary!=='string'||!path.isAbsolute(this.#binary)||! /^[a-f0-9]{64}$/.test(this.#sha??''))fail('pinned_tunnel_client_required');
  const st=fs.lstatSync(this.#binary);if(!st.isFile()||st.isSymbolicLink()||hash(this.#binary)!==this.#sha)fail('tunnel_client_integrity_failed');
  fs.accessSync(this.#binary,fs.constants.X_OK);const g=gatewayAt(this.#stateDir);
  this.#lockToken=acquireOwnerLock(p);this.#ownedLock=true;
  try{
   const c=configAt(p);if(!c)fail('tunnel_configuration_required');
   write(p.header,g.header);if(fs.existsSync(p.health)){const st=fs.lstatSync(p.health);if(!st.isFile()||st.isSymbolicLink())fail('invalid_health_url');fs.unlinkSync(p.health);}
   const args=['run','--control-plane.tunnel-id',c.tunnelId,'--control-plane.api-key','file:'+path.join(p.root,c.keyFile),'--mcp.server-url',g.url,'--ca-bundle',g.certificate,'--mcp.extra-headers','Authorization: file:'+p.header,'--mcp.discovery-extra-headers','Authorization: file:'+p.header,'--health.listen-addr','127.0.0.1:0','--health.url-file',p.health,'--log.level','warn'];
   // No inherited proxy, profile, NODE_OPTIONS or credential environment; no raw logs.
   const child=this.#spawn(process.execPath,[fileURLToPath(new URL('./tunnel-runner.mjs',import.meta.url)),this.#binary,this.#sha,JSON.stringify(args),this.#lockToken],{cwd:p.root,env:{PATH:'/usr/bin:/bin',HOME:p.root,XDG_CONFIG_HOME:p.root},stdio:['pipe','ignore','ignore'],windowsHide:true});
   this.#child=child;this.#exit=null;
   child.once('exit',(code,signal)=>{if(this.#child===child){this.#child=null;this.#exit={code,signal};this.#release(p);this.#schedule();}});
   await new Promise((resolve,reject)=>{child.once('spawn',resolve);child.once('error',()=>reject(Error('tunnel_client_start_failed')));});
   return this.status();
  }catch(e){this.#child=null;this.#release(p);throw e;}
 }
 #release(p){if(this.#ownedLock){this.#ownedLock=false;releaseOwnerLock(p,this.#lockToken);this.#lockToken=null;}}
 #schedule(){
  if(!this.#wanted||this.#retry)return;
  // Retry connection startup, never replay an MCP request. Network/Gateway may
  // become ready after login; stop() explicitly cancels this desired runtime.
  this.#retry=setTimeout(()=>{this.#retry=null;if(this.#wanted)void this.start({authorize:true}).catch(()=>{});},15000);
  this.#retry.unref?.();
 }
 async stop(){
  this.#wanted=false;if(this.#retry){clearTimeout(this.#retry);this.#retry=null;}
  if(this.#pending)await this.#pending.catch(()=>{});
  const child=this.#child;if(!child)return this.status();
  // Never kill a persisted PID: only this App's ChildProcess object is authority.
  await new Promise(resolve=>{let timer;const done=()=>{clearTimeout(timer);resolve();};child.once('exit',done);child.stdin?.end();child.kill('SIGTERM');timer=setTimeout(()=>{child.kill('SIGKILL');},4000);});
  return this.status();
 }
}
