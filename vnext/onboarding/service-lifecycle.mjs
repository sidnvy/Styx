// Trusted owner API only: fixed Host adapters, never a model command runner.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requirePrivateFile,requirePrivateDirectory,ensurePrivateDirectory} from '../host/private-storage.mjs';
import {activeRelease,verifySignedRelease,verifiedServiceNode} from '../host/installer.mjs';
import {linuxUserUnit,knownLinuxUserUnit,installLinuxService,systemdUser,statusUserService} from '../host/linux-service.mjs';
import {macHostExecutionIdentity} from '../host/macos-native-launcher.mjs';
import {macLaunchAgent,writeMacLaunchAgent,controlMacLaunchAgent,statusMacLaunchAgent} from '../host/macos-launchagent.mjs';
const assert=(v,c)=>{if(!v)throw Error(c)};
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const absolute=p=>typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p;
const managers={linux:'systemd-user',darwin:'launchd-user',win32:'windows-interactive-task'};
export const serviceIds=Object.freeze({linux:'styx-host.service',darwin:'app.styx.connector',win32:'Styx-Host'});
function readConfig(file){assert(absolute(file),'invalid_service_config');requirePrivateFile(file);assert(fs.statSync(file).size<=32768,'invalid_service_config');return JSON.parse(fs.readFileSync(file,'utf8'))}
function descriptor(raw){
 assert(raw&&typeof raw==='object'&&!Array.isArray(raw),'invalid_service_config');
 const windows=process.platform==='win32';
 const allowed=windows?['task_name','install_root','host_config_file','publisher_key_file','node_binary']:['unitName','label','installRoot','hostConfigFile','trustPublicKeyFile','nodeBinary','logDir','restartSec','nativeApp'];
 assert(!Object.keys(raw).some(k=>!allowed.includes(k)),'invalid_service_config');
 return windows?{id:raw.task_name,installRoot:raw.install_root,hostConfigFile:raw.host_config_file,trustPublicKeyFile:raw.publisher_key_file,nodeBinary:raw.node_binary}:{id:process.platform==='darwin'?raw.label:raw.unitName,installRoot:raw.installRoot,hostConfigFile:raw.hostConfigFile,trustPublicKeyFile:raw.trustPublicKeyFile,nodeBinary:raw.nodeBinary,...(raw.logDir!==undefined?{logDir:raw.logDir}:{}),...(raw.restartSec!==undefined?{restartSec:raw.restartSec}:{}),...(raw.nativeApp!==undefined?{nativeApp:raw.nativeApp}:{})};
}
function verified(d){
 for(const key of ['installRoot','hostConfigFile','trustPublicKeyFile','nodeBinary'])assert(absolute(d[key]),'invalid_service_path');
 requirePrivateDirectory(d.installRoot);requirePrivateFile(d.hostConfigFile);requirePrivateFile(d.trustPublicKeyFile);
 const cfg=readConfig(d.hostConfigFile);assert(typeof cfg.host_id==='string'&&cfg.exec&&typeof cfg.exec==='object','invalid_host_config');
 requirePrivateFile(cfg.token_file);
 const pub=fs.readFileSync(d.trustPublicKeyFile,'utf8');
 const selected=activeRelease(d.installRoot,pub);assert(selected,'no_active_release');
 const release=verifySignedRelease(selected.release_root,pub);
 // New installations only: no unsigned stable shims or external Node fallback.
 for(const name of ['host/installer.mjs','host/launch.mjs','host/private-storage.mjs','bin/'+(process.platform==='win32'?'node.exe':'node')]){
  const entry=release.manifest.files.find(e=>e.path===name);assert(entry,'incomplete_signed_service_release');
  const file=path.join(d.installRoot,path.basename(name));requirePrivateFile(file);assert(hash(file)===entry.sha256,'stable_service_bootstrap_changed');
 }
 assert(verifiedServiceNode({installRoot:d.installRoot,publicKeyPem:pub,nodeBinary:d.nodeBinary})===d.nodeBinary,'signed_service_runtime_required');
 return release;
}
const windowsInspect=`$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $env:STYX_SERVICE_NAME -ErrorAction Stop;@{execute=[string]$t.Actions.Execute;arguments=[string]$t.Actions.Arguments;working=[string]$t.Actions.WorkingDirectory}|ConvertTo-Json -Compress`;
function fixedWindows(run,d,release,action,configFile){
 const helper=path.join(release.folder??release.sourceDir??path.join(d.installRoot,'releases',release.manifest.version),'host','windows-task.ps1');
 assert(release.manifest.files.some(e=>e.path==='host/windows-task.ps1'),'signed_windows_task_helper_missing');
 return runVerifiedWindowsTask({helper,expectedSha256:release.manifest.files.find(e=>e.path==='host/windows-task.ps1').sha256,action,taskName:d.id,configFile},run);
}
// Fixed signed helper only. Execute the exact hash-checked bytes as a command,
// so read-only status does not require changing the user's script-file policy.
// Paths and actions are data, never interpolated into PowerShell source.
export function runVerifiedWindowsTask({helper,expectedSha256,action,taskName,configFile},run=execFileSync){
 assert(['install','status','start','stop'].includes(action),'unsupported_service_action');
 assert(taskName==='Styx-Host'||/^StyxPilot-[A-Za-z0-9-]{1,30}$/.test(taskName),'invalid_service_identity');
 const info=fs.lstatSync(helper);assert(info.isFile()&&!info.isSymbolicLink()&&info.size<=32768,'signed_windows_task_helper_invalid');
 const bytes=fs.readFileSync(helper);assert(createHash('sha256').update(bytes).digest('hex')===expectedSha256,'signed_windows_task_helper_changed');
 const script=`$ErrorActionPreference='Stop'
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:STYX_FIXED_TASK_SOURCE))
$params=@{Action=$env:STYX_FIXED_TASK_ACTION;TaskName=$env:STYX_FIXED_TASK_NAME}
if($env:STYX_FIXED_TASK_CONFIG){$params.ConfigPath=$env:STYX_FIXED_TASK_CONFIG}
& ([ScriptBlock]::Create($source)) @params`;
 const env={...process.env,STYX_FIXED_TASK_SOURCE:bytes.toString('base64'),STYX_FIXED_TASK_ACTION:action,STYX_FIXED_TASK_NAME:taskName,STYX_FIXED_TASK_CONFIG:configFile??''};
 assert(env.STYX_FIXED_TASK_SOURCE.length<=30000,'signed_windows_task_helper_too_large');
 return JSON.parse(String(run('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{env,encoding:'utf8',timeout:45000,windowsHide:true,stdio:['ignore','pipe','pipe']})).trim());
}
function sanitized(platform,native){
 if(platform==='linux')return native.status!=='reported'?{state:'unknown',persistence:'unknown'}:{state:native.load==='not-found'?'not_installed':native.active==='active'&&native.pid>0?'running':['inactive','failed'].includes(native.active)&&native.pid===0?'stopped':'transitioning',persistence:native.enabled==='enabled'?'enabled':native.enabled==='disabled'?'disabled':'unknown'};
 if(platform==='darwin')return {state:native.status==='unavailable'?'unknown':native.loaded&&native.state==='running'&&native.pid>0?'running':native.loaded?'loaded':'stopped',persistence:'unknown'};
 return {state:native.status==='not_installed'?'not_installed':native.status==='Running'?'running':['Ready','Disabled'].includes(native.status)?'stopped':'unknown',persistence:native.status==='Disabled'?'disabled':native.status==='not_installed'?'none':'unknown'};
}
export async function hostServiceAction({action,role='host',serviceConfigFile,authorization}={}, {home=os.homedir(),run=execFileSync}={}){
 let d,attempted=false;const platform=process.platform;
 try{
  assert(['install','status','start','stop'].includes(action),'unsupported_service_action');
  assert(authorization?.approved===true&&authorization.action===action&&authorization.role===role,'explicit_scoped_service_authorization_required');
  if(role==='gateway')return {status:'not_implemented',role,action,reason:'persistent_gateway_service_not_implemented'};
  assert(role==='host'&&managers[platform],'unsupported_service_role_or_platform');
  assert(authorization.serviceConfigFile===serviceConfigFile&&absolute(serviceConfigFile),'service_authorization_scope_mismatch');
  d=descriptor(readConfig(serviceConfigFile));assert(typeof d.id==='string'&&d.id.length>0,'invalid_service_identity');assert(d.id===authorization.serviceId,'service_authorization_scope_mismatch');
  for(const key of ['installRoot','hostConfigFile','trustPublicKeyFile','nodeBinary','logDir','restartSec'])assert(d[key]===authorization[key],'service_authorization_scope_mismatch');
  assert(JSON.stringify(d.nativeApp??null)===JSON.stringify(authorization.nativeApp??null),'service_authorization_scope_mismatch');
  if(platform==='darwin'){assert(absolute(d.logDir),'invalid_service_log_directory');if(fs.existsSync(d.logDir))requirePrivateDirectory(d.logDir);else requirePrivateDirectory(path.dirname(d.logDir))}
  const release=verified(d),options={...d,unitName:d.id,label:d.id};delete options.id;
  let file,expected,observe,control;
  if(platform==='linux'){
   expected=linuxUserUnit(options);file=path.join(home,'.config/systemd/user',d.id);
   observe=()=>statusUserService(d.id,{run});control=verb=>systemdUser(d.id,verb,{run});
  }else if(platform==='darwin'){
   expected=macLaunchAgent(options);file=path.join(home,'Library/LaunchAgents',d.id+'.plist');
   observe=()=>statusMacLaunchAgent(d.id,{run});control=verb=>controlMacLaunchAgent(verb,d.id,{home,run});
  }else{
   observe=()=>fixedWindows(run,d,release,'status');control=verb=>fixedWindows(run,d,release,verb);
  }
  const binding=()=>{if(file){requirePrivateFile(file);assert(platform==='linux'?knownLinuxUserUnit(fs.readFileSync(file,'utf8'),options):fs.readFileSync(file,'utf8')===expected,'service_definition_scope_mismatch')}else{const state=observe();if(state.status==='not_installed')return;const native=JSON.parse(String(run('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(windowsInspect,'utf16le').toString('base64')],{env:{...process.env,STYX_SERVICE_NAME:d.id},encoding:'utf8',timeout:15000,windowsHide:true,stdio:['ignore','pipe','pipe']})));assert(native.execute===d.nodeBinary&&native.working===d.installRoot&&native.arguments===['launch.mjs','',d.hostConfigFile,d.trustPublicKeyFile].map((p,i)=>'"'+(i===0?path.join(d.installRoot,p):i===1?d.installRoot:p)+'"').join(' '),'service_definition_scope_mismatch')}};
  if(action==='install'){
   assert(!file||!fs.existsSync(file),'service_already_installed');
   attempted=true;
   if(platform==='linux')installLinuxService(options,{home,run});else if(platform==='darwin'){ensurePrivateDirectory(d.logDir);writeMacLaunchAgent(options,{home});control('disable')}else{fixedWindows(run,d,release,'install',serviceConfigFile);control('stop')}
  }else if(action!=='status'){
   binding();attempted=true;
   if(action==='start'){if(platform==='linux')control('enable');control('start')}
   else{if(platform!=='win32')control('disable');if(platform!=='darwin'||observe().loaded)control('stop')}
  }else if(file&&fs.existsSync(file))binding();else if(!file)binding();
  let native=observe(),state=sanitized(platform,native);
  const installed=file?fs.existsSync(file):state.state!=='not_installed';
  // An active job without our exact on-disk definition is not ours to adopt.
  if(!installed&&((platform==='darwin'&&native.loaded)||state.state==='running'))throw Error('service_definition_missing');
  if(['start','stop'].includes(action)){
   const deadline=Date.now()+10000;while(Date.now()<deadline&&state.state!==(action==='start'?'running':'stopped')){if(platform==='darwin'&&state.state==='unknown')break;await new Promise(r=>setTimeout(r,100));native=observe();state=sanitized(platform,native)}
  }
  return {status:['start','stop'].includes(action)&&state.state!==(action==='start'?'running':'stopped')?'needs_attention':'reported',role,action,manager:managers[platform],serviceId:d.id,installed,...state,health:'not_checked',...(platform==='darwin'?{executionIdentity:macHostExecutionIdentity(d)}:{})};
 }catch{return {status:attempted?'uncertain':'blocked',role:role==='host'?'host':'unknown',action:['install','status','start','stop'].includes(action)?action:'unsupported',reason:'service_scope_or_native_operation_refused'}}
}

// Read-only fixed descriptor inspection for UI refresh; no maintenance journal writes.
export async function observeHostService({serviceConfigFile}={},options={}){
 try{
  const d=descriptor(readConfig(serviceConfigFile));
  return await hostServiceAction({action:'status',role:'host',serviceConfigFile,authorization:{
   approved:true,action:'status',role:'host',serviceConfigFile,serviceId:d.id,
   installRoot:d.installRoot,hostConfigFile:d.hostConfigFile,trustPublicKeyFile:d.trustPublicKeyFile,
   nodeBinary:d.nodeBinary,...(d.logDir!==undefined?{logDir:d.logDir}:{}),
   ...(d.restartSec!==undefined?{restartSec:d.restartSec}:{}),...(d.nativeApp!==undefined?{nativeApp:d.nativeApp}:{})
  }},options);
 }catch{return {status:'blocked',action:'status',role:'host',reason:'service_scope_or_native_operation_refused'}}
}
