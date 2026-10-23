// Foreground Linux/operator entry for the existing Tunnel configuration/runtime.
// A private descriptor supplies a verified executable pin, never a command or PID.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {configureTunnel,TunnelRuntime} from './tunnel-runtime.mjs';
const fail=code=>{throw Error(code)};
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
function exact(value,keys){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!keys.includes(key)))fail('invalid_tunnel_cli_input')}
function privateJson(file){
 if(!absolute(file))fail('private_tunnel_cli_file_required');
 requirePrivateDirectory(path.dirname(file));if(requirePrivateFile(file).size>65536)fail('tunnel_cli_input_too_large');
 try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch{fail('invalid_tunnel_cli_json')}
}
// Fixed installed-package location only. This manifest is public derived
// release data; no state directory, environment variable or CWD selects it.
export function packagedCliTunnelClient(){
 const manifest=fileURLToPath(new URL('../../runtime/tunnel-client.json',import.meta.url));
 try{
  const root=path.dirname(manifest),dir=fs.lstatSync(root),entry=fs.lstatSync(manifest);
  if(!dir.isDirectory()||dir.isSymbolicLink()||!entry.isFile()||entry.isSymbolicLink()||entry.size>8192)fail('packaged_tunnel_client_invalid');
  const value=JSON.parse(fs.readFileSync(manifest,'utf8'));
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!['schema','path','sha256','version'].includes(key))||
   value.schema!==1||value.path!=='tunnel-client'||typeof value.sha256!=='string'||! /^[a-f0-9]{64}$/.test(value.sha256)||
   typeof value.version!=='string'||value.version.length>64||! /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value.version))fail('packaged_tunnel_client_invalid');
  const binary=path.join(root,'tunnel-client'),stat=fs.lstatSync(binary);
  if(!stat.isFile()||stat.isSymbolicLink()||createHash('sha256').update(fs.readFileSync(binary)).digest('hex')!==value.sha256)fail('packaged_tunnel_client_invalid');
  fs.accessSync(binary,fs.constants.X_OK);
  return {binary,sha256:value.sha256,version:value.version};
 }catch(error){fail(error.code==='ENOENT'?'packaged_tunnel_client_unavailable':'packaged_tunnel_client_invalid')}
}
function packagedStatus(){
 try{const client=packagedCliTunnelClient();return {available:true,status:'available',version:client.version}}
 catch(error){return {available:false,status:error.message==='packaged_tunnel_client_unavailable'?'unavailable':'invalid',reason:error.message}}
}
function scope(stateDir){if(!absolute(stateDir))fail('absolute_tunnel_state_directory_required')}
function authorized(options){exact(options,['authorize']);if(options.authorize!==true)fail('explicit_tunnel_cli_authorization_required')}
function projection(value,{owned=false}={}){
 const locked=value.status==='interrupted';
 return {schema:1,status:locked?'owner_unobserved':value.status,
  tunnelId:value.tunnelId??null,autoStart:value.autoStart===true,
  ownership:owned&&value.ownership==='current_app'?'current_process':locked?'not_observed':'none',
  transport:'not_observed',accountAcceptance:'NOT RUN',
  ...(locked?{reason:'owner_lock_present_process_not_observed'}:{})};
}
export function configureCliTunnel(stateDir,inputFile,options={}){
 authorized(options);scope(stateDir);const input=privateJson(inputFile);exact(input,['tunnelId','apiKey','autoStart']);
 return projection(configureTunnel(stateDir,{...input,authorize:true}));
}
export function readCliTunnel(stateDir){
 scope(stateDir);return {...projection(new TunnelRuntime({stateDir}).status()),packagedClient:packagedStatus()};
}
export async function runCliTunnel(stateDir,clientFile,options={},operations={}){
 authorized(options);scope(stateDir);
 const selected=clientFile===undefined?packagedCliTunnelClient():privateJson(clientFile);
 if(clientFile!==undefined)exact(selected,['binary','sha256']);
 const client={binary:selected.binary,sha256:selected.sha256};
 if(!absolute(client.binary)||typeof client.sha256!=='string'||! /^[a-f0-9]{64}$/.test(client.sha256))fail('pinned_tunnel_cli_client_required');
 const runtime=(operations.createRuntime??(value=>new TunnelRuntime(value)))({stateDir,...client});
 const signals=operations.signals??process;
 const started=operations.onStarted??(()=>process.stderr.write('Styx Tunnel foreground owner started. Keep this terminal open; Ctrl-C stops only this process-owned tunnel. Cloud readiness and account acceptance are not verified.\n'));
 let finish,requested=false;
 const done=new Promise(resolve=>{finish=resolve}),stop=()=>{requested=true;finish()};
 const keepAlive=setInterval(()=>{},5000);
 signals.once('SIGINT',stop);signals.once('SIGTERM',stop);
 let final;
 try{
  const value=await runtime.start({authorize:true});started(projection(value,{owned:true}));
  if(!requested)await done;
 }finally{
  clearInterval(keepAlive);signals.off('SIGINT',stop);signals.off('SIGTERM',stop);
  // Runtime owns its ChildProcess and supervisor lifetime pipe. No persisted
  // PID is read, no foreign process is killed, and no MCP request is replayed.
  final=await runtime.stop();
 }
 const result=projection(final);
 return {...result,status:['configured','not_configured'].includes(final.status)?'stopped':'needs_attention',
  serviceMutation:'NOT RUN',identityMutation:'NOT RUN'};
}
