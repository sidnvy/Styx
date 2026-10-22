// Explicit Linux user service for the existing foreground Tunnel owner. Package
// paths and the client pin are fixed; this adds no role or credential authority.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {requirePrivateFile} from '../host/private-storage.mjs';
import {packagedCliTunnelClient,readCliTunnel} from './cli-tunnel.mjs';
const fail=code=>{throw Error(code)};
const sha=value=>createHash('sha256').update(value).digest('hex');
const reason=(error,fallback)=>typeof error?.message==='string'&&error.message.startsWith('linux_tunnel_')?error.message:fallback;
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value&&!/[\x00-\x1f\x7f]/.test(value);
const present=file=>{try{fs.lstatSync(file);return true}catch(error){if(error.code==='ENOENT')return false;throw error}};
const regular=file=>{const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink())fail('linux_tunnel_package_not_regular');return stat};
const quote=value=>'"'+value.replaceAll('\\','\\\\').replaceAll('"','\\"').replaceAll('%','%%')+'"';
const properties='Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,NeedDaemonReload';
export function linuxTunnelServicePlan(stateDir,{home=os.homedir()}={}){
 if(process.platform!=='linux')fail('linux_tunnel_user_service_only');
 if(!absolute(stateDir)||!absolute(home))fail('absolute_linux_tunnel_service_paths_required');
 const identity=sha(stateDir),name='styx-tunnel-'+identity.slice(0,12)+'.service';
 const nodeBinary=fileURLToPath(new URL('../../runtime/node',import.meta.url)),cli=fileURLToPath(new URL('./cli.mjs',import.meta.url));
 // systemd rejects quotes, backslashes and glob characters in the executable
 // itself even when quoted. Refuse an unusable package location before writes.
 if(/["'\\*?\[\]{}]/.test(nodeBinary))fail('linux_tunnel_package_path_not_supported');
 const directory=path.join(home,'.config/systemd/user'),unitFile=path.join(directory,name);
 const unit=['# Styx owned CLI Tunnel '+identity,'[Unit]','Description=Styx private Secure MCP Tunnel','After=network.target',
  '[Service]','Type=simple',
  // ':' disables systemd environment expansion, including dollar signs in a
  // user's state path. Percent specifiers still need the ordinary %% escape.
  'ExecStart=:'+quote(nodeBinary)+' '+quote(cli)+' tunnel-run '+quote(stateDir)+' --authorize',
  'UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH',
  'Restart=on-failure','RestartSec=5','TimeoutStopSec=15','KillMode=control-group','UMask=0077','NoNewPrivileges=true',
  '[Install]','WantedBy=default.target',''].join('\n');
 return {name,stateDir,nodeBinary,cli,directory,unitFile,unit};
}
function unitDirectory(home,{create=false}={}){
 for(const file of [home,path.join(home,'.config'),path.join(home,'.config/systemd'),path.join(home,'.config/systemd/user')]){
  if(!present(file)){if(!create||file===home)return false;fs.mkdirSync(file,{mode:0o700});}
  const stat=fs.lstatSync(file);if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid())fail('linux_tunnel_service_directory_not_owned');
 }
 return true;
}
function definition(plan,expected){
 const stat=requirePrivateFile(plan.unitFile);
 if(fs.readFileSync(plan.unitFile,'utf8')!==plan.unit||expected&&(stat.ino!==expected.ino||stat.dev!==expected.dev))fail('linux_tunnel_service_definition_changed');
 return stat;
}
function packageReady(plan){
 const runtime=path.dirname(plan.nodeBinary),dir=fs.lstatSync(runtime);
 if(!dir.isDirectory()||dir.isSymbolicLink())fail('linux_tunnel_package_not_regular');
 regular(plan.nodeBinary);regular(plan.cli);
 const file=path.join(runtime,'node-provenance.json');if(regular(file).size>8192)fail('linux_tunnel_packaged_node_invalid');
 let provenance;try{provenance=JSON.parse(fs.readFileSync(file,'utf8'))}catch{fail('linux_tunnel_packaged_node_invalid')}
 if(provenance.schema!==1||provenance.component!=='node'||provenance.platform!=='linux'||provenance.arch!=='x64'||provenance.binary_sha256!==sha(fs.readFileSync(plan.nodeBinary)))fail('linux_tunnel_packaged_node_invalid');
 fs.accessSync(plan.nodeBinary,fs.constants.X_OK);return packagedCliTunnelClient();
}
function show(plan,run){
 const output=String(run('/usr/bin/systemctl',['--user','show',plan.name,'--property='+properties],{encoding:'utf8',timeout:10000,maxBuffer:8192,stdio:['ignore','pipe','ignore']}));
 const values={};for(const line of output.trim().split('\n')){const index=line.indexOf('=');if(index<1||Object.hasOwn(values,line.slice(0,index)))fail('linux_tunnel_service_status_unknown');values[line.slice(0,index)]=line.slice(index+1);}
 if(properties.split(',').some(key=>typeof values[key]!=='string')||values.Id!==plan.name||! /^(0|[1-9][0-9]*)$/.test(values.MainPID)||!Number.isSafeInteger(Number(values.MainPID))||
  !['loaded','not-found'].includes(values.LoadState)||!['yes','no'].includes(values.NeedDaemonReload)||
  ![values.ActiveState,values.SubState,values.UnitFileState].every(value=>/^[A-Za-z0-9_-]*$/.test(value)))fail('linux_tunnel_service_status_unknown');
 if(values.FragmentPath&&values.FragmentPath!==plan.unitFile)fail('linux_tunnel_service_manager_definition_not_owned');
 return {load:values.LoadState,active:values.ActiveState,substate:values.SubState,enabled:values.UnitFileState,pid:Number(values.MainPID)||null,fragment:values.FragmentPath,reloadRequired:values.NeedDaemonReload==='yes'};
}
function snapshot(plan,observed,extra={}){
 const status=observed.load==='not-found'?'not_installed':observed.active==='active'&&observed.pid?'running':observed.active==='inactive'&&!observed.pid?'stopped':'needs_reconciliation';
 return {schema:1,status,name:plan.name,scope:'user_systemd_unit',active:observed.active,substate:observed.substate,enabled:observed.enabled,pid:observed.pid,
  transport:'not_observed',accountAcceptance:'NOT RUN',systemBootWithoutLogin:'NOT CONFIGURED',...extra};
}
function writeDefinition(plan){
 const fd=fs.openSync(plan.unitFile,'wx',0o600);try{fs.writeFileSync(fd,plan.unit);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
}
export function controlLinuxTunnelService(stateDir,options={}, {run=execFileSync,home=os.homedir()}={}){
 if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(key=>!['action','authorize'].includes(key))||!['install','status','start','stop','uninstall'].includes(options.action))fail('invalid_linux_tunnel_service_action');
 const {action,authorize=false}=options;if(action!=='status'&&authorize!==true)fail('explicit_linux_tunnel_service_authorization_required');
 const plan=linuxTunnelServicePlan(stateDir,{home});unitDirectory(home);const exists=present(plan.unitFile);
 let owned=exists?definition(plan):null,observed;
 try{observed=show(plan,run)}catch(error){return {schema:1,status:'needs_reconciliation',name:plan.name,reason:reason(error,'linux_tunnel_service_status_unknown'),systemBootWithoutLogin:'NOT CONFIGURED',transport:'not_observed',accountAcceptance:'NOT RUN'}}
 if(!exists&&observed.load!=='not-found')fail('linux_tunnel_service_manager_definition_not_owned');
 if(exists&&observed.load==='loaded'&&observed.fragment!==plan.unitFile)fail('linux_tunnel_service_manager_definition_not_owned');
 if(action==='status')return snapshot(plan,observed,{...(exists&&observed.load==='not-found'||observed.reloadRequired?{status:'needs_reconciliation',reason:'linux_tunnel_service_reload_required'}:{})});
 if(action!=='install'&&!exists)fail('linux_tunnel_service_not_installed');
 // Only install/start may execute or authorize execution of package material.
 // Stop/uninstall remain usable if an installed client's bytes need attention.
 if(['install','start'].includes(action)){
  packageReady(plan);const tunnel=readCliTunnel(stateDir);
  if(tunnel.status==='not_configured')fail('linux_tunnel_configuration_required');
  if(action==='start'&&tunnel.status==='owner_unobserved'&&!(observed.active==='active'&&observed.pid))return snapshot(plan,observed,{status:'needs_reconciliation',reason:'linux_tunnel_owner_unobserved'});
 }
 let removed=false;
 const assertOwned=()=>definition(plan,owned);
 const control=operation=>{assertOwned();return run('/usr/bin/systemctl',['--user',operation,plan.name],{stdio:'ignore',timeout:20000})};
 const reload=()=>run('/usr/bin/systemctl',['--user','daemon-reload'],{stdio:'ignore',timeout:20000});
 try{
  if(action==='install'){
   if(!exists){unitDirectory(home,{create:true});writeDefinition(plan);owned=definition(plan);}
   assertOwned();reload();observed=show(plan,run);
   if(observed.load!=='loaded'||observed.fragment!==plan.unitFile||observed.reloadRequired)fail('linux_tunnel_service_install_unconfirmed');
   return snapshot(plan,observed,{...(observed.active==='inactive'&&!observed.pid?{status:'installed_not_started'}:{}),activation:'not_requested'});
  }
  if(action==='start'){
   assertOwned();reload();observed=show(plan,run);
   if(observed.load!=='loaded'||observed.fragment!==plan.unitFile||observed.reloadRequired)fail('linux_tunnel_service_reload_required');
   control('enable');control('start');observed=show(plan,run);
   if(observed.active!=='active'||!observed.pid||!['enabled','enabled-runtime'].includes(observed.enabled))fail('linux_tunnel_service_start_unconfirmed');
   return snapshot(plan,observed);
  }
  control('disable');control('stop');observed=show(plan,run);
  if(observed.active!=='inactive'||observed.pid||['enabled','enabled-runtime'].includes(observed.enabled))fail('linux_tunnel_service_stop_unconfirmed');
  if(action==='stop')return snapshot(plan,observed);
  assertOwned();fs.unlinkSync(plan.unitFile);removed=true;reload();
  observed=show(plan,run);if(observed.load!=='not-found'||observed.pid)fail('linux_tunnel_service_uninstall_unconfirmed');
  return snapshot(plan,observed,{status:'uninstalled_state_preserved',configuration:'preserved',profiles:'preserved'});
 }catch(error){
  // Keep an unconfirmed uninstall reviewable. An exclusive restore never
  // replaces a file another actor created after our deletion.
  if(removed&&!present(plan.unitFile)){try{writeDefinition(plan)}catch{}}
  return snapshot(plan,observed,{status:'needs_reconciliation',operation:action,reason:reason(error,'linux_tunnel_service_operation_failed'),definition:present(plan.unitFile)?'retained':'absent_requires_inspection'});
 }
}
