// Explicit local-owner acceptance only. Never imported by ordinary tests.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync,spawn} from 'node:child_process';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {ensurePrivateDirectory,requirePrivateDirectory} from './private-storage.mjs';
import {buildHostRelease} from './build-host-release.mjs';
import {stageSignedRelease,activateRelease,refreshVerifiedBootstrap,activeRelease} from './installer.mjs';
import {createStyxGateway} from '../gateway/index.mjs';
import {createGatewayHttp} from '../gateway/http.mjs';
const root=path.dirname(fileURLToPath(import.meta.url));
const literal=s=>"'"+s.replaceAll("'","''")+"'";
const sha=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const assert=(v,m)=>{if(!v)throw Error(m)};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const ps=command=>execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from("$ErrorActionPreference='Stop';"+command,'utf16le').toString('base64')],{encoding:'utf8',timeout:45000,windowsHide:true,stdio:['ignore','pipe','pipe']}).trim();
async function until(fn,reason,ms=30000){const end=Date.now()+ms;while(Date.now()<end){if(await fn())return;await sleep(250)}throw Error(reason)}
// Trusted local callbacks only; this is cleanup orchestration, never a model tool.
export async function reconcileAttemptedWindowsTask({status,uninstall,quiescent}){
 const current=status();
 assert(['not_installed','Running','Ready','Disabled','Queued'].includes(current?.status),'owned_task_status_uncertain');
 if(current.status!=='not_installed')uninstall();
 await quiescent();
 assert(status()?.status==='not_installed','owned_task_cleanup_failed');
}
export async function runManagedWindowsPilot({directory,nodeBinary,codexBinary,cuaBinary}={}){
 assert(process.env.STYX_RUN_MANAGED_WINDOWS_PILOT==='1','explicit_native_pilot_opt_in_required');
 assert(process.platform==='win32'&&process.arch==='x64','native_windows_x64_required');
 assert(path.isAbsolute(directory)&&!fs.existsSync(directory),'fresh_absolute_pilot_directory_required');
 requirePrivateDirectory(path.dirname(directory));
 // Retain this exclusive receipt even after failure: uncertain bootstrap is never replayed.
 const ownerLock=fs.openSync(directory+'.driver-lock','wx',0o600);fs.writeFileSync(ownerLock,String(process.pid));fs.closeSync(ownerLock);
 for(const p of [directory,nodeBinary,codexBinary,cuaBinary])assert(/^[A-Za-z]:\\[A-Za-z0-9_. +@\\-]+$/.test(p),'safe_native_path_required');
 const taskName='StyxPilot-RC20261019-'+randomBytes(4).toString('hex');
 assert(ps('(Get-Process -Id $PID).SessionId')!=='0','interactive_native_session_required');
 assert(ps('if(Get-ScheduledTask -TaskName '+literal(taskName)+' -ErrorAction SilentlyContinue){"exists"}else{"absent"}')==='absent','fresh_task_required');
 for(const [p,h] of [[nodeBinary,'9c9245166b4a8e182e0b797da9c20136117ff24368eaff1fec8343a123c8db0e'],[codexBinary,'2692c8c7bb2cf8b0aefe638741fc90236f4b824c59578ce84994f9de58200993'],[cuaBinary,'99291d8d6a4851d9df96da5813a1ef2761f2c9d3a59d2a7036c0bf4d09652f4f']])assert(sha(p)===h,'pinned_public_binary_mismatch');
 ensurePrivateDirectory(directory);const state=path.join(directory,'private');ensurePrivateDirectory(state);
 const receipt={schema:1,kind:'windows-owned-native-host-pilot',status:'NOT RUN',task:taskName,node:process.version,started_at:new Date().toISOString(),source_sha256:{orchestrator:sha(fileURLToPath(import.meta.url)),gui:sha(path.join(root,'physical-cua-windows.mjs'))},binary_sha256:{node:sha(nodeBinary),codex:sha(codexBinary),cua:sha(cuaBinary)},evidence:{},boundaries:{service:'fresh Interactive/Limited owner task only',gateway:'fresh loopback HTTP/WS only; no external controller for product operations',publisher:'ephemeral pilot key, no distribution trust claim',gui:'exact owned pid/title self-expiring WinForms; no screenshots persisted',runtime_upgrade:'NOT RUN'}};
 const save=()=>{fs.writeFileSync(path.join(directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n')};
 const note=n=>{receipt.evidence[n]='PASS';save()};save();
 let gateway,server,client,transport,installAttempted=false,phase='signed_build';
 const installRoot=path.join(state,'installed');
 const helper=path.join(root,'windows-task.ps1');
 const helperHash=sha(helper);
 // Execute these exact reviewed helper bytes without changing PowerShell's
 // script-file execution policy. User data remains separately encoded data.
 const control=(action,cfg)=>{
  assert(['install','start','stop','status','uninstall'].includes(action),'invalid_pilot_task_action');
  assert(sha(helper)===helperHash,'pilot_task_helper_changed');
  const source=fs.readFileSync(helper).toString('base64');
  const params=Buffer.from(JSON.stringify({Action:action,TaskName:taskName,...(cfg?{ConfigPath:cfg}:{})})).toString('base64');
  return ps('$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('+literal(source)+'));$values=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('+literal(params)+'))|ConvertFrom-Json;$params=@{};$values.PSObject.Properties|ForEach-Object {$params[$_.Name]=$_.Value};& ([ScriptBlock]::Create($source)) @params');
 };
 const ownPids=()=>JSON.parse(ps('@(Get-CimInstance Win32_Process -Filter "Name=\'node.exe\'" | Where-Object {$_.ExecutablePath -eq '+literal(path.join(installRoot,'node.exe'))+'} | Select-Object -ExpandProperty ProcessId) | ConvertTo-Json -Compress')||'[]');
 const pids=()=>{const v=ownPids();return Array.isArray(v)?v:[v]};
 async function closeClient(){if(transport)await transport.terminateSession().catch(()=>{});await client?.close().catch(()=>{});client=null;transport=null}
 try{
  const publisher=generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  const privateKeyFile=path.join(state,'publisher-private.pem'),publicKeyFile=path.join(state,'publisher-public.pem');
  fs.writeFileSync(privateKeyFile,publisher.privateKey);fs.writeFileSync(publicKeyFile,publisher.publicKey);
  const version='0.1.0-winrc20261019',sourceDir=path.join(state,'release');
  buildHostRelease({destination:sourceDir,version,privateKeyFile,nodeBinary,codexBinary,cuaBinary});
  stageSignedRelease({sourceDir,installRoot,publicKeyPem:publisher.publicKey});activateRelease(installRoot,version,publisher.publicKey);refreshVerifiedBootstrap(installRoot,publisher.publicKey,version);note('signed_native_build_install');
  // Always execute bundled signed copies; source binaries are only build inputs.
  const release=activeRelease(installRoot,publisher.publicKey);assert(release.version===version,'signed_release_mismatch');
  const target='windows-owned-native',token=randomBytes(32).toString('hex'),modelToken=randomBytes(32).toString('hex');
  const tokenFile=path.join(state,'host.token'),modelTokenFile=path.join(state,'model.token');fs.writeFileSync(tokenFile,token);fs.writeFileSync(modelTokenFile,modelToken);
  const nativeEnv=Object.fromEntries(['SystemRoot','WINDIR','COMSPEC','PATH','PATHEXT','TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA'].filter(k=>process.env[k]!==undefined).map(k=>[k,process.env[k]]));
  const scratch=path.join(state,'scratch'),codexHome=path.join(state,'codex-home');ensurePrivateDirectory(scratch);ensurePrivateDirectory(codexHome);
  const shell=path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
  gateway=createStyxGateway({catalog:{version:1,default_environment_id:target,targets:[{id:target,kind:'host',platform:'win32',generation:'owned-winrc-g1',allowed:true,cwd:scratch,shell,shells:[shell],exec:{transport:'outbound',token_file:tokenFile},computer:{enabled:true,transport:'outbound',max_connections:1}}]}});
  const allowedHosts=[];server=await createGatewayHttp(gateway,{token:modelToken,port:0,allowedHosts});const origin='http://127.0.0.1:'+server.address.port;allowedHosts.push('127.0.0.1:'+server.address.port);
  const configFile=path.join(state,'host.json');fs.writeFileSync(configFile,JSON.stringify({host_id:target,gateway_ws_url:origin.replace('http:','ws:'),token_file:tokenFile,exec:{binary:path.join(installRoot,'releases',version,'bin','codex.exe'),cwd:scratch,env:{...nativeEnv,CODEX_HOME:codexHome}},computer:{enabled:true,binary:path.join(installRoot,'releases',version,'bin','cua-driver.exe'),connections:1,env:{...nativeEnv}}}));
  const taskConfig=path.join(state,'task.json');fs.writeFileSync(taskConfig,JSON.stringify({task_name:taskName,install_root:installRoot,host_config_file:configFile,publisher_key_file:publicKeyFile,node_binary:path.join(installRoot,'node.exe')}));
  phase='managed_start';installAttempted=true;control('install',taskConfig);control('start');
  async function ready(){await until(()=>gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===1&&pids().length>0,'owned_native_host_readiness_timeout',60000);
   await closeClient();transport=new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+modelToken}}});client=new Client({name:'styx-owned-windows-native',version:'0.1.0'});await client.connect(transport);
   const r=await client.callTool({name:'exec_command',arguments:{environment_id:target,cmd:"[Console]::Write('STYX_WINDOWS_NATIVE_OK')",login:false,yield_time_ms:1000}},undefined,{timeout:15000});let out=r.structuredContent?.output??'',last=r;const end=Date.now()+15000;while(last.structuredContent?.session_id&&Date.now()<end){last=await client.callTool({name:'write_stdin',arguments:{session_id:last.structuredContent.session_id,chars:'',yield_time_ms:250}},undefined,{timeout:15000});out+=last.structuredContent?.output??''}assert(!last.isError&&last.structuredContent?.exit_code===0&&out==='STYX_WINDOWS_NATIVE_OK','native_exec_readback_failed');}
  await ready();note('interactive_task_start_native_exec');
  phase='owned_gui';
  const gui=await new Promise((resolve,reject)=>{const child=spawn(nodeBinary,[path.join(root,'physical-cua-windows.mjs')],{env:{...process.env,STYX_PILOT_MCP_URL:origin+'/mcp',STYX_PILOT_MCP_TOKEN_FILE:modelTokenFile,STYX_PILOT_ENVIRONMENT_ID:target,STYX_PILOT_SCRATCH_DIR:scratch},windowsHide:true,stdio:['ignore','pipe','ignore']});let out='';const timer=setTimeout(()=>{child.kill();reject(Error('owned_gui_deadline'))},75000);child.stdout.on('data',d=>{if(out.length<10000)out+=d});child.on('error',reject);child.on('exit',code=>{clearTimeout(timer);if(code!==0)return reject(Error('owned_gui_native_refusal'));try{resolve(JSON.parse(out.trim().split('\n').at(-1)))}catch{reject(Error('owned_gui_receipt_invalid'))}})});
  assert(gui.result==='PASS','owned_gui_not_passed');receipt.gui=gui;note('owned_gui_screenshot_ax_click_independent_readback');
  phase='managed_stop_start';await closeClient();control('stop');await until(()=>!gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===0&&pids().length===0,'owned_stop_not_quiescent');
  assert(JSON.parse(control('status')).status==='Disabled','owned_stop_not_disabled');
  const stoppedAt=Date.now();while(Date.now()-stoppedAt<65000){assert(JSON.parse(control('status')).status==='Disabled'&&pids().length===0&&!gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===0,'explicit_stop_restarted_unexpectedly');await sleep(1000)}receipt.stopped_recovery_observation_ms=Date.now()-stoppedAt;control('start');await ready();note('managed_stop_start');
  phase='managed_crash_recovery';await closeClient();const before=pids();assert(before.length===1,'unique_owned_launcher_required');execFileSync('taskkill.exe',['/PID',String(before[0]),'/T','/F'],{stdio:'ignore',timeout:10000});await until(()=>!gateway.relay.connected(target),'owned_kill_not_disconnected');await until(()=>pids().some(p=>!before.includes(p)),'owned_task_recovery_timeout',100000);await ready();note('managed_crash_recovery');receipt.status='PASS';
 }catch{receipt.status='BLOCKED';receipt.failed_phase=phase;receipt.reason='native_pilot_operation_failed';}
 finally{
  await closeClient();let clean=!installAttempted;
  // Registration may have succeeded before a timeout/refusal became visible.
  // Reconcile only this exact task through the owner-checking helper. Unknown
  // or foreign state retains the private fixture for explicit owner recovery.
  if(installAttempted){try{await reconcileAttemptedWindowsTask({status:()=>JSON.parse(control('status')),uninstall:()=>control('uninstall'),quiescent:()=>until(()=>pids().length===0,'owned_process_cleanup_failed')});clean=true;note('owned_task_uninstall')}catch{receipt.status='BLOCKED';receipt.cleanup='owned_task_cleanup_requires_attention'}}
  await server?.close().catch(()=>{});
  if(clean){fs.rmSync(state,{recursive:true,force:true});note('secret_and_signed_fixture_cleanup')}
  receipt.completed_at=new Date().toISOString();save();
 }
 return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const receipt=await runManagedWindowsPilot(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));console.log(JSON.stringify(receipt));process.exitCode=receipt.status==='PASS'?0:2}catch{console.log(JSON.stringify({status:'BLOCKED',reason:'native_pilot_setup_failed'}));process.exitCode=2}
}
