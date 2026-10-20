// Account presentation and handoff receipts only. Roles and connection authority
// continue to come from deployment.json and the owned Gateway runtime.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
import {normalizePresentation,connection} from '../plugin/package.mjs';
import {buildPackageArchive} from '../plugin/archive.mjs';
const fail=code=>{throw Error(code)};
const exact=(x,names)=>{if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).some(k=>!names.includes(k)))fail('invalid_plugin_options')};
const hash=value=>createHash('sha256').update(value).digest('hex');
function read(file){if(requirePrivateFile(file).size>512*1024)fail('plugin_state_too_large');return JSON.parse(fs.readFileSync(file,'utf8'))}
function context(stateDir){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir)||path.normalize(stateDir)!==stateDir)fail('absolute_state_directory_required');
 requirePrivateDirectory(stateDir);
 const config=read(path.join(stateDir,'deployment.json'));
 if(!['create-local','join-existing'].includes(config.mode))fail('invalid_deployment');
 if(config.mode==='join-existing')return {required:false};
 // The profile and user attestation can be entered before local setup finishes.
 // Neither asserts local readiness or account acceptance; export requires verification.
 let target=null;
 const tunnel=path.join(stateDir,'tunnel','connection.json');
 if(fs.existsSync(tunnel)){requirePrivateDirectory(path.dirname(tunnel));target=connection({tunnelId:read(tunnel).tunnelId})}
 const cert=path.join(stateDir,'gateway','certificate.pem'),runtime=path.join(stateDir,'gateway','runtime.json');
 let identity=null;
 if(fs.existsSync(cert)&&fs.existsSync(runtime)){
  requirePrivateDirectory(path.dirname(cert));requirePrivateFile(cert);
  const r=read(runtime),u=new URL(config.gateway.url);
  if(r.schema!==1||r.url!==config.gateway.url||r.listenHost!=='127.0.0.1'||u.protocol!=='https:'||u.hostname!=='127.0.0.1'||r.tlsCertificateFile!==cert)fail('plugin_owned_loopback_gateway_required');
  identity=hash(fs.readFileSync(cert));
 }
 return {required:true,target,identity,binding:hash(JSON.stringify({target,identity,gateway:config.gateway.url})),endpoint:new URL('/mcp',config.gateway.url).href};
}
function selection(value){
 exact(value,['mode','accountLabel','pluginUrl']);
 if(!['create','reuse'].includes(value.mode)||typeof value.accountLabel!=='string'||[...value.accountLabel.trim()].length>160||/[\u0000-\u001f\u007f]/.test(value.accountLabel))fail('invalid_plugin_selection');
 const url=optionalPluginUrl(value.pluginUrl);
 return {mode:value.mode,accountLabel:value.accountLabel.trim(),pluginUrl:url};
}
const optionalPluginUrl=value=>value===undefined||value===''?'':pluginUrl(value);
export function pluginUrl(value){
 let u;try{u=new URL(value)}catch{fail('invalid_plugin_url')}
 if(typeof value!=='string'||value.length>2048||u.protocol!=='https:'||u.hostname!=='chatgpt.com'||u.port||u.username||u.password||u.search||u.hash||!u.pathname.startsWith('/plugins/')||u.pathname==='/plugins/')fail('specific_chatgpt_plugin_url_required');
 return u.href;
}
function load(stateDir){
 const file=path.join(stateDir,'onboarding-plugin.json');
 if(!fs.existsSync(file))return null;
 const value=read(file);exact(value,['schema','binding','presentation','selection','export','accountActions']);
 if(value.schema!==1||typeof value.binding!=='string')fail('invalid_plugin_state');
 value.presentation=normalizePresentation(value.presentation);value.selection=selection(value.selection);
 exact(value.export,['sha256','binding','profileHash','filename','verificationSource','at']);
 if(value.export.sha256!==undefined&&(!/^[a-f0-9]{64}$/.test(value.export.sha256)||value.export.filename!=='styx-native.zip'||value.export.verificationSource!=='authenticated_local_gateway_discovery'))fail('invalid_plugin_export_receipt');
 exact(value.accountActions,['upload','installation']);
 for(const [stage,record] of Object.entries(value.accountActions)){
  exact(record,['at','binding','profileHash','pluginUrl','source','method']);
  if(record.source!=='user_attested'||!Number.isSafeInteger(record.at)||record.at<0||typeof record.binding!=='string'||typeof record.profileHash!=='string')fail('invalid_plugin_account_receipt');
  if(record.method!==undefined&&!['official_page','archive_upload'].includes(record.method)||stage==='upload'&&record.method==='official_page')fail('invalid_plugin_account_receipt');
  // Schema 1 archive receipts remain valid. Only the direct official path can
  // omit a management URL, which is never treated as provider identity proof.
  if(record.method==='official_page')optionalPluginUrl(record.pluginUrl);else pluginUrl(record.pluginUrl);
 }
 return value;
}
const profileHash=value=>hash(JSON.stringify({presentation:value.presentation,selection:value.selection}));
function write(stateDir,value){
 const file=path.join(stateDir,'onboarding-plugin.json'),tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp);
 try{fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 try{fs.renameSync(tmp,file);if(process.platform!=='win32'){const dir=fs.openSync(stateDir,'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}
}
async function locked(stateDir,fn){
 requirePrivateDirectory(stateDir);const file=path.join(stateDir,'onboarding-plugin.lock');let fd;
 try{fd=openPrivateFile(file)}catch{fail('plugin_change_busy_or_interrupted')}
 const nonce=randomBytes(32).toString('hex'),identity=fs.fstatSync(fd);let initialized=false;
 try{fs.writeFileSync(fd,nonce);fs.fsyncSync(fd);initialized=true;return await fn()}
 finally{try{if(initialized){const current=requirePrivateFile(file);if(current.ino!==identity.ino||current.dev!==identity.dev||fs.readFileSync(file,'utf8')!==nonce)fail('plugin_lock_changed');fs.unlinkSync(file)}}finally{fs.closeSync(fd)}}
}
export function readDeploymentPlugin(stateDir){
 const ctx=context(stateDir),value=ctx.required?load(stateDir):null;
 const presentation=value?.presentation??normalizePresentation(),chosen=value?.selection??{mode:'create',accountLabel:'',pluginUrl:''};
 const current=record=>!!value&&record?.binding===ctx.binding&&record?.profileHash===profileHash(value);
 return {schema:1,required:ctx.required,presentation,selection:chosen,profileSaved:!!value,
  contextChanged:!!value&&value.binding!==ctx.binding,
  export:{status:!value?.export?.sha256?'not_exported':current(value.export)?'exported':'stale',...(value?.export?.sha256?{sha256:value.export.sha256,filename:value.export.filename,verificationSource:value.export.verificationSource}:{})},
  accountActions:{upload:current(value?.accountActions?.upload)?'user_confirmed':'not_observed',installation:current(value?.accountActions?.installation)?'user_confirmed':'not_observed',connection:'not_verified',providerIdentity:'not_verified'},
  requiresAccountAction:ctx.required,externalDiscovery:'not_performed',authentication:{declared:'bearer',tunnelWithoutManualCredential:'not_verified'}};
}
export async function setDeploymentPluginProfile(stateDir,options={}){
 exact(options,['authorize','presentation','selection']);if(options.authorize!==true)fail('explicit_plugin_authorization_required');
 const presentation=normalizePresentation(options.presentation),chosen=selection(options.selection);
 return locked(stateDir,()=>{
  const ctx=context(stateDir);if(!ctx.required)fail('plugin_managed_by_gateway_owner');
  const old=load(stateDir),value={schema:1,binding:ctx.binding,presentation,selection:chosen,export:{},accountActions:{}};
  if(old?.binding===ctx.binding&&profileHash(old)===profileHash(value)){value.export=old.export;value.accountActions=old.accountActions}
  write(stateDir,value);return readDeploymentPlugin(stateDir);
 });
}
export async function exportDeploymentPlugin(stateDir,options={}){
 exact(options,['authorize']);if(options.authorize!==true)fail('explicit_plugin_authorization_required');
 return locked(stateDir,async()=>{
  const ctx=context(stateDir),value=load(stateDir);
  if(!ctx.required)fail('plugin_managed_by_gateway_owner');
  if(!value||value.selection.mode!=='create')fail('new_plugin_profile_required');
  if(value.binding!==ctx.binding)fail('plugin_context_changed');
  if(!ctx.target||!ctx.identity)fail('configured_owned_gateway_and_tunnel_required');
  const before=profileHash(value),{verifyDeploymentGateway}=await import('./core.mjs');
  const verified=await verifyDeploymentGateway(stateDir),r=verified?.receipt;
  if(verified?.status!=='gateway_verified'||r?.connection?.url!==ctx.endpoint||r?.method!=='authenticated-mcp-discovery-and-readonly-call'||r.toolCall?.status!=='PASS')fail('plugin_local_discovery_required');
  const receipt={version:1,connection:ctx.target,independentStyx:r.independentStyx,freshConnection:r.freshConnection,verifiedAt:r.verifiedAt,serverName:r.serverName,tools:r.tools,method:'authenticated-local-mcp-discovery'};
  const result=buildPackageArchive({connection:ctx.target,presentation:value.presentation},receipt);
  if(context(stateDir).binding!==ctx.binding||profileHash(load(stateDir))!==before)fail('plugin_context_changed_during_export');
  const sha256=hash(result.archive),sameArchive=value.export.sha256===sha256&&value.export.binding===ctx.binding&&value.export.profileHash===before;
  value.binding=ctx.binding;value.export={sha256,binding:ctx.binding,profileHash:before,filename:'styx-native.zip',verificationSource:'authenticated_local_gateway_discovery',at:Date.now()};
  if(!sameArchive){
   // Replacing an optional archive invalidates only archive-specific receipts.
   // Direct official-page confirmation is bound to the profile and connection.
   const direct=value.accountActions.installation?.method==='official_page'?value.accountActions.installation:null;
   value.accountActions=direct?{installation:direct}:{};
  }
  write(stateDir,value);
  return {...result,sha256:value.export.sha256,verificationSource:value.export.verificationSource,accountUpload:'NOT RUN',accountInstallation:'NOT RUN',accountConnection:'NOT RUN'};
 });
}
export async function recordDeploymentPluginAction(stateDir,options={}){
 exact(options,['authorize','stage','pluginUrl']);if(options.authorize!==true)fail('explicit_plugin_authorization_required');
 if(!['upload','installation'].includes(options.stage))fail('invalid_plugin_account_stage');
 const suppliedUrl=optionalPluginUrl(options.pluginUrl);
 return locked(stateDir,()=>{
  const ctx=context(stateDir),value=load(stateDir);if(!ctx.required)fail('plugin_managed_by_gateway_owner');if(!value)fail('plugin_profile_required');
  if(value.binding!==ctx.binding)fail('plugin_context_changed');
  const url=suppliedUrl||value.selection.pluginUrl;
  if(value.selection.pluginUrl&&value.selection.pluginUrl!==url)fail('plugin_url_mismatch');
  if(options.stage==='upload'){
   if(value.selection.mode!=='create')fail('existing_plugin_does_not_require_upload');
   if(!value.export.sha256||value.export.binding!==ctx.binding||value.export.profileHash!==profileHash(value))fail('current_plugin_export_required');
   pluginUrl(url);
  }
  // URL receipt updates the selection and consistently rebinds earlier receipts.
  value.selection.pluginUrl=url;const ph=profileHash(value);if(value.export.sha256)value.export.profileHash=ph;
  for(const entry of Object.values(value.accountActions))entry.profileHash=ph;
  value.accountActions[options.stage]={at:Date.now(),binding:ctx.binding,profileHash:ph,pluginUrl:url,source:'user_attested',method:options.stage==='upload'?'archive_upload':'official_page'};
  write(stateDir,value);return readDeploymentPlugin(stateDir);
 });
}
