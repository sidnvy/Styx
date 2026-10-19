// Persistent local Gateway service in the owning user session; no system/root changes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {verifiedServiceNode} from '../host/installer.mjs';
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
 if(!status.steps.some(s=>s.id==='gateway.prepare'&&s.status==='succeeded')||!status.steps.some(s=>s.id==='host.prepare'&&s.status==='succeeded'))fail('gateway_and_signed_host_preparation_required');
 const root=path.join(cfg.host.baseDir,'install'),pub=path.join(cfg.host.baseDir,'publisher.pem');requirePrivateFile(pub);
 const node=verifiedServiceNode({installRoot:root,publicKeyPem:fs.readFileSync(pub,'utf8')});
 const name=gatewayServiceIdentity(stateDir),marker='# Styx owned Gateway '+digest(stateDir);
 const unit=[marker,'[Unit]','Description=Styx private Gateway','After=network.target','[Service]','Type=simple',
 'ExecStart='+quote(node)+' '+quote(runner)+' '+quote(stateDir),'Restart=on-failure','RestartSec=3','TimeoutStopSec=15','UMask=0077','NoNewPrivileges=true','[Install]','WantedBy=default.target',''].join('\n');
 const descriptor={stateDir,nodeBinary:node,runner,identityHash:digest(stateDir)};
 const native=process.platform==='linux'?{}:platformGatewayPlan(descriptor);
 return {name,marker,unit,...descriptor,...native,platform:process.platform,supported:['linux','darwin','win32'].includes(process.platform),startup:native.startup??'user_login',
  requirement:'stable_trusted_source_checkout_and_signed_Node',systemBootWithoutLogin:'NOT CONFIGURED'};
}
function unitDirectory(){
 const dir=path.join(os.homedir(),'.config','systemd','user');
 for(const part of [path.join(os.homedir(),'.config'),path.join(os.homedir(),'.config','systemd'),dir]){
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
function control(action,name){
 const args=['--user',action,name];
 try{return execFileSync('/usr/bin/systemctl',args,{encoding:'utf8',timeout:20000,maxBuffer:128*1024,stdio:['ignore','pipe','pipe']})}
 catch{fail('gateway_service_operation_failed')}
}
export function controlGatewayService(stateDir,{action,authorize=false}={}){
 if(!['install','status','start','stop','enable','disable','uninstall'].includes(action))fail('invalid_gateway_service_action');
 if(!['linux','darwin','win32'].includes(process.platform))fail('persistent_gateway_service_platform_not_supported');
 if(action!=='status'&&authorize!==true)fail('gateway_service_authorization_required');
 const plan=gatewayServicePlan(stateDir);
 if(action==='start'&&readDeployment(stateDir).gatewayRuntime.status==='running')fail('stop_foreground_gateway_before_service_start');
 if(process.platform!=='linux')return platformGatewayService({action,authorize,descriptor:{stateDir:plan.stateDir,nodeBinary:plan.nodeBinary,runner:plan.runner,identityHash:plan.identityHash}});
 // Read-only status must not create directories or write units.
 const file=path.join(os.homedir(),'.config/systemd/user',plan.name);
 if(action==='status'&&!fs.existsSync(file))return {status:'not_installed',name:plan.name};
 if(action==='install'){
  if(fs.existsSync(file)){verifyGatewayServiceDefinition(file,plan);}
  else{unitDirectory();fs.writeFileSync(file,plan.unit,{mode:0o600,flag:'wx'});}
  requirePrivateFile(file);
  try{execFileSync('/usr/bin/systemctl',['--user','daemon-reload'],{stdio:'ignore',timeout:20000})}catch{fail('gateway_service_reload_failed_preserve_unit')}
  return {status:'installed_not_started',name:plan.name};
 }
 verifyGatewayServiceDefinition(file,plan);
 if(action==='uninstall'){
  control('stop',plan.name);control('disable',plan.name);fs.unlinkSync(file);
  try{execFileSync('/usr/bin/systemctl',['--user','daemon-reload'],{stdio:'ignore',timeout:20000})}catch{fail('gateway_service_reload_failed')}
  return {status:'uninstalled_state_preserved',name:plan.name};
 }
 if(action!=='status')control(action,plan.name);
 let data;try{data=execFileSync('/usr/bin/systemctl',['--user','show',plan.name,'--property=ActiveState,SubState,UnitFileState,MainPID'],{encoding:'utf8',timeout:10000,maxBuffer:8192,stdio:['ignore','pipe','pipe']})}catch{fail('gateway_service_status_failed')}
 const values=Object.fromEntries(data.trim().split('\n').map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)]}));
 return {name:plan.name,active:values.ActiveState,substate:values.SubState,enabled:values.UnitFileState,pid:Number(values.MainPID)||null};
}
