// App lifecycle is independent of deployment roles. This facade never stops
// Host/Gateway services, the chat tunnel, or another process's foreground Core.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {verifyMacPreviewApp} from '../host/macos-preview-trust.mjs';
import {controlMacLoginRecovery,macLoginRecoveryPlan} from './macos-login-recovery.mjs';

const label='app.styx.desktop-login';
const fail=code=>{throw Error(code)};
function absolute(value,code){
 if(typeof value!=='string'||!path.isAbsolute(value)||path.normalize(value)!==value||/[\x00-\x1f\x7f]/.test(value))fail(code);
 return value;
}
function existing(file){try{fs.lstatSync(file);return true}catch(error){if(error.code==='ENOENT')return false;throw error}}
function context(stateDir,{trustedAppPath,operations={}}={}){
 absolute(stateDir,'app_lifecycle_absolute_state_directory_required');
 const ops={platform:process.platform,home:os.homedir(),uid:process.getuid?.(),run:execFileSync,verifyApp:verifyMacPreviewApp,...operations};
 if(existing(stateDir))requirePrivateDirectory(stateDir);
 const file=path.join(stateDir,'deployment.json');let registered;
 if(existing(file)){
  if(requirePrivateFile(file).size>1024*1024)fail('app_lifecycle_configuration_too_large');
  const config=JSON.parse(fs.readFileSync(file,'utf8'));
  if(!config||typeof config!=='object'||Array.isArray(config))fail('app_lifecycle_configuration_invalid');
  registered=config.host?.macPreviewApp;
  if(registered!==undefined&&(!registered||typeof registered!=='object'||Array.isArray(registered)||typeof registered.path!=='string'||!/^[a-f0-9]{40}$/.test(registered.cdhash??'')))fail('app_lifecycle_registered_identity_invalid');
 }
 let appPath,source='unconfigured';
 if(trustedAppPath!==undefined){
  // Only the native launch backend may supply this option after verifying its
  // bundle. It must never be copied from an HTTP body or CLI flag. An upgraded
  // trusted native launch may have a newer CDHash than the previous deployment.
  appPath=absolute(trustedAppPath,'app_lifecycle_trusted_app_invalid');
  if(path.basename(appPath)!=='Styx.app')fail('app_lifecycle_trusted_app_invalid');
  if(registered&&registered.path!==appPath)fail('app_lifecycle_registered_path_changed');
  source='verified_native_launch';
 }else if(registered){
  // CLI uses authoritative registration plus a fresh native signature/hash
  // verification. A path in configuration is not evidence of App ownership.
  appPath=ops.verifyApp(registered).path;source='verified_deployment_identity';
 }
 return {stateDir,appPath,source,ops,config:appPath?{appPath,logDir:path.join(stateDir,'login-recovery-logs')}:null};
}
function ctl(ctx,...args){return String(ctx.ops.run('/bin/launchctl',args,{encoding:'utf8',timeout:20000,stdio:['ignore','pipe','pipe']}))}
function domain(ctx){if(ctx.ops.platform!=='darwin'||!(ctx.ops.uid>0))fail('app_lifecycle_graphical_user_required');return 'gui/'+ctx.ops.uid}
function loadedDefinition(ctx){
 const gui=domain(ctx);ctl(ctx,'print',gui);
 try{return ctl(ctx,'print',gui+'/'+label)}catch(error){
  if(/Could not find (?:specified )?service/.test(String(error.stderr??'')))return null;
  fail('app_lifecycle_observation_unknown');
 }
}
function assertLoadedOwnership(ctx,text){
 if(text===null)return;
 if(!ctx.config)fail('app_lifecycle_loaded_app_not_owned');
 const expected=macLoginRecoveryPlan(ctx.config)[0];
 const file=path.join(ctx.ops.home,'Library','LaunchAgents',label+'.plist');
 const args=/^\s*arguments = \{\n([\s\S]*?)^\s*\}/m.exec(text)?.[1]?.split('\n').map(x=>x.trim()).filter(Boolean);
 if(/^\s*path = (.+)$/m.exec(text)?.[1]!==file||!Array.isArray(args)||args.length!==expected.args.length||!args.every((arg,i)=>arg===expected.args[i]))fail('app_lifecycle_loaded_app_not_owned');
}
function preference(ctx,installed){
 if(!installed)return 'not_installed';
 try{
  const text=ctl(ctx,'print-disabled',domain(ctx));
  if(!/^\s*disabled services = \{\s*$/m.test(text)||!/^\s*}\s*$/m.test(text))return 'unknown';
  const override=/^\s*"app\.styx\.desktop-login"\s*=>\s*(true|false)\s*$/m.exec(text);
  // No override means the exact checked plist's default: RunAtLoad, no Disabled.
  // A matching malformed entry is not silently interpreted as enabled.
  if(!override&&text.includes('"'+label+'"'))return 'unknown';
  return override?.[1]==='true'?'disabled':'enabled';
 }catch{return 'unknown'}
}
function observe(ctx){
 if(ctx.ops.platform!=='darwin')return {schema:1,status:'not_applicable',source:ctx.source,loginAtStartup:'unknown',installed:false,loaded:false,running:false,accountAcceptance:'NOT RUN'};
 const text=loadedDefinition(ctx);assertLoadedOwnership(ctx,text);
 if(!ctx.config)return {schema:1,status:'not_configured',source:ctx.source,loginAtStartup:'unknown',installed:null,loaded:false,running:false,accountAcceptance:'NOT RUN'};
 const result=controlMacLoginRecovery(ctx.config,{...ctx.ops,action:'status'});
 const {installed,loaded,running}=result.services[0];
 return {schema:1,status:running?'running':installed?'stopped':'not_installed',source:ctx.source,loginAtStartup:preference(ctx,installed),installed,loaded,running,accountAcceptance:'NOT RUN'};
}
export function readDeploymentAppLifecycle(stateDir,options={}){return observe(context(stateDir,options))}
export function controlDeploymentAppLifecycle(stateDir,options={},trusted={}){
 if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(key=>!['authorize','action','enabled'].includes(key))||options.authorize!==true)fail('app_lifecycle_authorization_required');
 if(!['quit','login'].includes(options.action)||options.action==='login'&&typeof options.enabled!=='boolean'||options.action==='quit'&&options.enabled!==undefined)fail('app_lifecycle_action_invalid');
 const ctx=context(stateDir,trusted);domain(ctx);
 // Inspect before any mutation, including fresh installs and explicit startup
 // changes. Existing private files and loaded launchd definitions must agree.
 const before=observe(ctx);
 if(!ctx.config){
  if(options.action==='quit')return {...before,status:'not_running',currentSessionRecovery:'absent',loginPreference:'unchanged'};
  fail('app_lifecycle_verified_app_required');
 }
 const action=options.action==='quit'?'suspend':options.enabled?'install':'stop';
 const result=controlMacLoginRecovery(ctx.config,{...ctx.ops,action,authorize:true});
 return {...observe(ctx),...(options.action==='quit'?{currentSessionRecovery:result.currentSessionRecovery,loginPreference:'unchanged'}:{})};
}
