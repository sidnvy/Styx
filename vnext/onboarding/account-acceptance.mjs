import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {requirePrivateFile} from '../host/private-storage.mjs';
import {readDeploymentPermissions} from './permissions.mjs';
import {browserAcceptanceChallenge,browserAcceptanceVerified,acceptanceBinding,acceptanceFile,currentAcceptanceEvidence,writeAcceptanceEvidence,withAcceptanceLock,privateEvidenceRead} from '../shared/onboarding-evidence.mjs';
const fail=code=>{throw Error(code)};
const exact=(value,names)=>{if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!names.includes(key)))fail('invalid_acceptance_options')};
function authorized(value,names){exact(value,names);if(value.authorize!==true)fail('explicit_acceptance_authorization_required')}
const desktopVerified=record=>!record.desktopRequired||record.desktop?.after===true&&record.desktop?.readback===true&&record.desktop?.actionVerified===true&&!!record.desktop.actionOwner&&record.desktop.readbackPid===record.desktopAppPid&&record.desktop.readbackWindow===record.desktop.actionAttempt?.window&&(record.desktopAppGeneration===undefined||record.desktop.readbackGeneration===record.desktopAppGeneration);
// Runtime-only dependency: HTTP/CLI input cannot supply a native App authority.
function windowsNativeApp(provider,code){
 let value;try{value=typeof provider==='function'?provider():null}catch{fail(code)}
 if(value?.source!=='current_windows_native_app'||!Number.isSafeInteger(value.nativeAppPid)||value.nativeAppPid<1||typeof value.nativeAppGeneration!=='string'||!(/^[1-9][0-9]{0,18}$/).test(value.nativeAppGeneration))fail(code);
 return value;
}
function projection(record){
 const proof=record.requestProof?.status==='verified',desktop=desktopVerified(record),browser=browserAcceptanceVerified(record),confirmed=record.targetChatConfirmation?.status==='user_confirmed';
 return {schema:1,status:proof&&desktop&&browser&&confirmed?'user_confirmed_with_mcp_evidence':proof||record.browserRequired&&browser?'request_observed':'awaiting_chat_request',
  challenge:{id:record.id,expiresAt:record.expiresAt,prompt:record.prompt,command:record.command,environmentId:record.environmentId,...(record.desktopRequired?{desktopValue:record.desktopValue}:{}),...(record.browserRequired?{browser:{url:record.browserUrl,marker:record.browserMarker}}:{})},
  requestProof:{status:proof?'verified':'pending',...(proof?{observedAt:record.requestProof.at,source:'authenticated_mcp_exec_result'}:{})},
  targetChatConfirmation:{status:confirmed?'user_confirmed':'pending',providerIdentity:'not_verified',source:confirmed?'user_attested':'not_recorded'},
  desktop:{status:!record.desktopRequired?'not_required':desktop?'verified':'pending'},
  browser:{status:!record.browserRequired?'not_required':browser?'verified':'pending',required:record.browserRequired===true,source:record.browserRequired&&browser?'authenticated_mcp_browser_result':'not_observed',...(record.browserRequired&&browser?{observedAt:record.browser.observedAt}:{})},complete:proof&&desktop&&browser&&confirmed};
}
export function readDeploymentAcceptance(stateDir){
 try{return projection(currentAcceptanceEvidence(stateDir).record)}catch(error){return {schema:1,status:['acceptance_expired','acceptance_context_changed'].includes(error.message)?error.message:'not_started',challenge:null,requestProof:{status:'pending'},targetChatConfirmation:{status:'pending',providerIdentity:'not_verified'},desktop:{status:'pending'},browser:{status:'pending',required:'not_observed',source:'not_observed'},complete:false};}
}
export function beginDeploymentAcceptance(stateDir,options={},{nativeDesktopApp}={}){
 authorized(options,['authorize']);return withAcceptanceLock(stateDir,()=>{
  const {target,binding}=acceptanceBinding(stateDir),nonce=randomBytes(16).toString('hex'),id=randomBytes(16).toString('hex');
  const marker='STYX_EXEC_'+nonce,desktopValue='STYX_GUI_'+nonce;
  const command=target.platform==='win32'?"Write-Output '"+marker+"'":"printf '%s\\n' '"+marker+"'";
  const desktopRequired=target.computer?.enabled===true,browserRequired=target.browser?.enabled===true;
  const browser=browserRequired?browserAcceptanceChallenge(nonce):null;
  const windowsDesktop=desktopRequired&&target.platform==='win32';
  const native=windowsDesktop?windowsNativeApp(nativeDesktopApp,'windows_native_app_binding_required'):desktopRequired?readDeploymentPermissions(stateDir):null;
  const appPid=['current_native_app_preflight','current_windows_native_app'].includes(native?.source)?native.nativeAppPid:null;
  const prompt='请通过当前 Styx 插件验收设备 '+target.id+'。先用 exec_command 执行 '+JSON.stringify({cmd:command,environment_id:target.id,login:false,yield_time_ms:1000})+'，若返回 session_id，仅用 write_stdin 空输入轮询到退出，核对输出标记及退出码0。'+(browserRequired?'然后使用 browser_navigate '+JSON.stringify({url:browser.url,environment_id:target.id})+' 打开一次性验收页面，再单独调用 browser_snapshot '+JSON.stringify({environment_id:target.id})+'，在实际网页快照正文中读到标题 '+browser.marker+'。导航返回、URL包含标记、Browser已启用或进程就绪均不算读回证据；若原生工具拒绝data URL请报告具体错误，不换用脚本或模拟结果。':'')+(desktopRequired?'然后仅使用 Styx Cua 桌面工具，用 get_window_state 观察 Styx 原生设置窗口'+(appPid?'（pid '+appPid+'）':'')+'，找到“桌面验收输入框”，通过该快照的 element_token 或同一 pid/window_id 输入 '+desktopValue+'，再次用 get_window_state 观察同一窗口核对读回值；禁止用终端、JavaScript、AppleScript 或系统脚本替代桌面操作。':'')+'不要请求、读取或输出任何密钥。完成后告诉我实际结果；若失败请说明具体环节，不要宣称通过。';
  const record={schema:1,id,nonce,binding,environmentId:target.id,createdAt:Date.now(),expiresAt:Date.now()+30*60*1000,marker,command,prompt,browserRequired,...(browser?{browserUrl:browser.url,browserMarker:browser.marker}:{}),desktopRequired,desktopValue,desktopAppPid:appPid,...(windowsDesktop?{desktopAppGeneration:native.nativeAppGeneration}:{}),requestProof:{status:'pending'},targetChatConfirmation:{status:'pending'}};
  writeAcceptanceEvidence(stateDir,record);return projection(record);
 });
}
export function recordDeploymentDesktopReadback(stateDir,options={},{nativeDesktopApp}={}){
 authorized(options,['authorize','challengeId','value','pid','windowId']);return withAcceptanceLock(stateDir,()=>{
  const {ctx,record}=currentAcceptanceEvidence(stateDir);
  if(record.id!==options.challengeId||!record.desktopRequired||typeof options.value!=='string'||options.value.length>256||!Number.isSafeInteger(options.pid)||options.pid!==record.desktopAppPid||!Number.isSafeInteger(options.windowId)||options.windowId<1)fail('desktop_acceptance_scope_mismatch');
  let native;
  if(ctx.target.platform==='win32'){
   native=windowsNativeApp(nativeDesktopApp,'desktop_acceptance_native_app_changed');
   if(native.nativeAppPid!==record.desktopAppPid||native.nativeAppGeneration!==record.desktopAppGeneration)fail('desktop_acceptance_native_app_changed');
  }
  record.desktop={...record.desktop,readback:options.value===record.desktopValue,readbackPid:options.pid,readbackWindow:options.windowId,...(native?{readbackGeneration:native.nativeAppGeneration}:{})};writeAcceptanceEvidence(stateDir,record);return projection(record);
 });
}
export function confirmDeploymentAcceptance(stateDir,options={}){
 authorized(options,['authorize','challengeId','observedInTargetChat']);return withAcceptanceLock(stateDir,()=>{
  const {record}=currentAcceptanceEvidence(stateDir);
  if(record.id!==options.challengeId||options.observedInTargetChat!==true)fail('target_chat_confirmation_required');
  if(record.requestProof?.status!=='verified'||!desktopVerified(record)||!browserAcceptanceVerified(record))fail('actual_mcp_acceptance_evidence_required');
  record.targetChatConfirmation={status:'user_confirmed',at:Date.now(),source:'user_attested'};writeAcceptanceEvidence(stateDir,record);return projection(record);
 });
}
function modelCredential(stateDir){
 const file=path.join(stateDir,'gateway/model.token');if(requirePrivateFile(file).size>65536)fail('invalid_model_credential');const value=fs.readFileSync(file,'utf8').trim();if(value.length<32||/\s/.test(value))fail('invalid_model_credential');
 const admin=path.join(stateDir,'gateway/admin.token');if(requirePrivateFile(admin).size>65536||value===fs.readFileSync(admin,'utf8').trim())fail('model_credential_separation_required');
 return value;
}
export function readDeploymentConnectionHandoff(stateDir){
 try{acceptanceBinding(stateDir);modelCredential(stateDir);const tunnelFile=path.join(stateDir,'tunnel/connection.json');const tunnel=fs.existsSync(tunnelFile)?privateEvidenceRead(tunnelFile):null;
  const available=tunnel?.schema===1&&/^tunnel_[A-Za-z0-9_-]{8,128}$/.test(tunnel.tunnelId??'');
  return {status:available?'available':'unavailable',authentication:'bearer',credentialAvailable:true,requiresTargetAccountAction:true,connection:available?{tunnelId:tunnel.tunnelId}:null,reason:available?null:'configure_tunnel_or_verified_external_entry_first'};
 }catch{return {status:'unavailable',authentication:'bearer',credentialAvailable:false,requiresTargetAccountAction:true,connection:null,reason:'owned_gateway_and_approved_host_required'}}
}
export function prepareDeploymentConnectionHandoff(stateDir,options={}){
 authorized(options,['authorize']);const value=modelCredential(stateDir),status=readDeploymentConnectionHandoff(stateDir);if(status.status!=='available')fail('connection_handoff_not_ready');
 return {status:'prepared',connection:status.connection,authentication:{type:'bearer',modelCredential:value},expiresAt:Date.now()+60000,credentialValidity:'existing_gateway_credential_not_rotated; expiresAt_is_display_only',targetAccountAuthorization:'required'};
}
