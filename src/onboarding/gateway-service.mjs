// Persistent local Gateway service in the owning user session; no system/root changes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {activeRelease,verifySignedRelease,verifiedServiceNode} from '../host/installer.mjs';
import {readGatewayRuntime} from './gateway-runtime.mjs';
import {readDeployment} from './core.mjs';
import {platformGatewayService,platformGatewayPlan} from './gateway-platform-services.mjs';

const runner=fileURLToPath(new URL('./gateway-runner.mjs',import.meta.url));
const fail=code=>{throw Error(code)};
const digest=s=>createHash('sha256').update(s).digest('hex');
const quote=s=>{if(typeof s!=='string'||!path.isAbsolute(s)||/[\r\n\0]/.test(s))fail('unsafe_service_path');return '"'+s.replaceAll('\\','\\\\').replaceAll('"','\\"').replaceAll('%','%%')+'"'};
export function gatewayServiceIdentity(stateDir){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir)||path.normalize(stateDir)!==stateDir)fail('absolute_state_directory_required');
 return 'styx-gateway-'+digest(stateDir).slice(0,12)+'.service';
}
export function gatewayServicePlan(stateDir){
 const status=readDeployment(stateDir);
 if(status.mode!=='create-local')fail('local_gateway_required');
 requirePrivateFile(path.join(stateDir,'deployment.json'));
 const cfg=JSON.parse(fs.readFileSync(path.join(stateDir,'deployment.json'),'utf8'));
 if(!status.steps.some(s=>s.id==='gateway.prepare'&&s.status==='succeeded'))fail('gateway_preparation_required');
 let node,runtimeSource,serviceRunner=runner,application='source_checkout_preview';
 if(cfg.gateway.runtime){
  if(!status.steps.some(s=>s.id==='gateway.runtime.prepare'&&s.status==='succeeded'))fail('gateway_runtime_preparation_required');
  const runtime=readGatewayRuntime(cfg.gateway.runtime);node=runtime.nodeBinary;runtimeSource='gateway';application=runtime.application;serviceRunner=runtime.runnerBinary??runner;
 }else{
  // Existing installs keep their signed Host-owned runtime until an explicit
  // migration. No Host config, Exec/Cua or permission is needed on the new path.
  if(!cfg.host||!status.steps.some(s=>s.id==='host.prepare'&&s.status==='succeeded'))fail('gateway_or_legacy_signed_host_runtime_required');
  const root=path.join(cfg.host.baseDir,'install'),pub=path.join(cfg.host.baseDir,'publisher.pem');requirePrivateFile(pub);
  const pem=fs.readFileSync(pub,'utf8'),active=activeRelease(root,pem);
  if(!active||!verifySignedRelease(active.release_root,pem).manifest.files.some(f=>f.path==='bin/'+(process.platform==='win32'?'node.exe':'node')&&f.executable))fail('signed_gateway_node_required');
  node=verifiedServiceNode({installRoot:root,publicKeyPem:pem});runtimeSource='legacy_host';
 }
 const name=gatewayServiceIdentity(stateDir),marker='# Styx owned Gateway '+digest(stateDir);
 const unit=[marker,'[Unit]','Description=Styx private Gateway','After=network.target','[Service]','Type=simple',
 'ExecStart='+quote(node)+' '+quote(serviceRunner)+' '+quote(stateDir),'Restart=on-failure','RestartSec=3','TimeoutStopSec=15','UMask=0077','NoNewPrivileges=true','[Install]','WantedBy=default.target',''].join('\n');
 const descriptor={stateDir,nodeBinary:node,runner:serviceRunner,identityHash:digest(stateDir)};
 const native=process.platform==='linux'?{}:platformGatewayPlan(descriptor);
 return {name,marker,unit,...descriptor,...native,runtimeSource,application,platform:process.platform,supported:['linux','darwin','win32'].includes(process.platform),startup:native.startup??'user_login',
  requirement:application==='signed_application'?'verified_signed_gateway_application_and_Core_deployment':'stable_trusted_source_checkout_and_signed_Node',systemBootWithoutLogin:'NOT CONFIGURED'};
}
function unitDirectory(home){
 const dir=path.join(home,'.config','systemd','user');
 for(const part of [path.join(home,'.config'),path.join(home,'.config','systemd'),dir]){
  if(fs.existsSync(part)){const st=fs.lstatSync(part);if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid())fail('unsafe_user_service_directory');}
  else fs.mkdirSync(part,{mode:0o700});
 }
 return dir;
}
export function verifyGatewayServiceDefinition(file,{marker,unit}){
 requirePrivateFile(file);const text=fs.readFileSync(file,'utf8');
 if(text.split('\n')[0]!==marker)fail('gateway_service_not_owned');
 if(text!==unit)fail('gateway_service_definition_changed');
}
function control(action,name,run){
 const args=['--user',action,name];
 try{return run('/usr/bin/systemctl',args,{encoding:'utf8',timeout:20000,maxBuffer:128*1024,stdio:['ignore','pipe','pipe']})}
 catch{fail('gateway_service_operation_failed')}
}
export function controlGatewayService(stateDir,{action,authorize=false}={}, {run=execFileSync,home=os.homedir()}={}){
 if(!['install','status','start','stop','enable','disable','uninstall'].includes(action))fail('invalid_gateway_service_action');
 if(!['linux','darwin','win32'].includes(process.platform))fail('persistent_gateway_service_platform_not_supported');
 if(action!=='status'&&authorize!==true)fail('gateway_service_authorization_required');
 const plan=gatewayServicePlan(stateDir);
 if(action==='start'&&readDeployment(stateDir).gatewayRuntime.status==='running')fail('stop_foreground_gateway_before_service_start');
 if(process.platform!=='linux')return platformGatewayService({action,authorize,descriptor:{stateDir:plan.stateDir,nodeBinary:plan.nodeBinary,runner:plan.runner,identityHash:plan.identityHash}},{run,home});
 // Read-only status must not create directories or write units.
 const file=path.join(home,'.config/systemd/user',plan.name);
 if(action==='status'&&!fs.existsSync(file))return {status:'not_installed',name:plan.name};
 if(action==='install'){
  if(fs.existsSync(file)){verifyGatewayServiceDefinition(file,plan);}
  else{unitDirectory(home);fs.writeFileSync(file,plan.unit,{mode:0o600,flag:'wx'});}
  requirePrivateFile(file);
  try{run('/usr/bin/systemctl',['--user','daemon-reload'],{stdio:'ignore',timeout:20000})}catch{fail('gateway_service_reload_failed_preserve_unit')}
  return {status:'installed_not_started',name:plan.name};
 }
 verifyGatewayServiceDefinition(file,plan);
 if(action==='uninstall'){
  control('disable',plan.name,run);control('stop',plan.name,run);fs.unlinkSync(file);
  try{run('/usr/bin/systemctl',['--user','daemon-reload'],{stdio:'ignore',timeout:20000})}catch{fail('gateway_service_reload_failed')}
  return {status:'uninstalled_state_preserved',name:plan.name};
 }
 // Match Host/macOS/Windows semantics: stop is durable across the next login;
 // start restores persistence. Each command can fail independently; Core logs
 // an uncertain transaction and never silently replays a partial mutation.
 if(action==='start')control('enable',plan.name,run);
 if(action==='stop')control('disable',plan.name,run);
 if(action!=='status')control(action,plan.name,run);
 let data;try{data=run('/usr/bin/systemctl',['--user','show',plan.name,'--property=ActiveState,SubState,UnitFileState,MainPID'],{encoding:'utf8',timeout:10000,maxBuffer:8192,stdio:['ignore','pipe','pipe']})}catch{fail('gateway_service_status_failed')}
 const values=Object.fromEntries(data.trim().split('\n').map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)]}));
 return {name:plan.name,active:values.ActiveState,substate:values.SubState,enabled:values.UnitFileState,pid:Number(values.MainPID)||null};
}
