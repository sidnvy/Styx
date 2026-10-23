// A stopped, disabled user unit participates in the existing payload transaction.
// This module never starts/stops services or creates a separate migration journal.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {knownLinuxUserUnit} from '../host/linux-service.mjs';
import {requirePrivateFile} from '../host/private-storage.mjs';
import {gatewayServiceIdentity,gatewayServicePlan} from './gateway-service.mjs';
import {readGatewayRuntime} from './gateway-runtime.mjs';
import {fileURLToPath} from 'node:url';
const fail=code=>{throw Error(code)};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fields=text=>Object.fromEntries(String(text).trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)]}));
export function linuxHostPayloadUnitPath(service,{home=os.homedir()}={}){
 const name=service.id??service.unitName;
 if(!/^styx-(?:vnext-)?[a-z0-9][a-z0-9-]{0,48}\.service$/.test(name??'')||!path.isAbsolute(home)||path.normalize(home)!==home)fail('host_payload_linux_unit_scope_invalid');
 return path.join(home,'.config/systemd/user',name);
}
function observe(service,{home=os.homedir(),run=execFileSync}={}){
 const unit=service.id??service.unitName,file=linuxHostPayloadUnitPath(service,{home});
 const row=fields(run('/usr/bin/systemctl',['--user','show',unit,'--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,DropInPaths,Restart,Type','--no-pager'],{encoding:'utf8',timeout:10000,maxBuffer:32768,stdio:['ignore','pipe','pipe']}));
 if(row.LoadState!=='loaded'||!['inactive','failed'].includes(row.ActiveState)||!['dead','failed'].includes(row.SubState)||row.UnitFileState!=='disabled'||row.MainPID!=='0'||row.FragmentPath!==file||row.DropInPaths!==''||row.Restart!=='on-failure'||!['exec','simple'].includes(row.Type))fail('host_payload_linux_unit_not_stopped_disabled');
 return row;
}
export function inspectLinuxHostPayloadUnit(service,options={}){
 const file=linuxHostPayloadUnitPath(service,options);
 if(!fs.existsSync(file))return null;
 for(let parent=path.dirname(file);parent!==path.dirname(options.home??os.homedir());parent=path.dirname(parent))if(fs.lstatSync(parent).isSymbolicLink())fail('host_payload_linux_unit_redirected');
 if(requirePrivateFile(file).size>32768)fail('host_payload_linux_unit_too_large');const before=fs.readFileSync(file),unitName=service.id??service.unitName;
 if(!knownLinuxUserUnit(before.toString(),{...service,unitName}))fail('host_payload_linux_unit_definition_changed');
 const prior='ExecStart='+service.nodeBinary+' ',replacement='ExecStart='+path.join(service.installRoot,'node')+' ';
 if(!before.toString().includes('\n'+prior))fail('host_payload_linux_unit_definition_changed');
 const after=Buffer.from(before.toString().replace('\n'+prior,'\n'+replacement)),observation=observe(service,options);
 return {name:'linuxHostUnit',path:file,before,after,mode:fs.statSync(file).mode&0o777,afterMode:0o600,binding:{schema:1,unitName,path:file,beforeSha256:sha(before),afterSha256:sha(after),observation}};
}
export function observeLinuxHostPayloadUnit(service,binding,options={}){
 const file=linuxHostPayloadUnitPath(service,options);
 if(binding?.schema!==1||binding.path!==file||binding.unitName!==(service.id??service.unitName)||!['beforeSha256','afterSha256'].every(key=>/^[a-f0-9]{64}$/.test(binding[key]??'')))fail('host_payload_linux_unit_binding_invalid');
 requirePrivateFile(file);if(![binding.beforeSha256,binding.afterSha256].includes(sha(fs.readFileSync(file))))fail('host_payload_linux_unit_definition_changed');
 const state=observe(service,options);
 if(JSON.stringify(state)!==JSON.stringify(binding.observation))fail('host_payload_linux_unit_observation_changed');
 return true;
}
export function reconcileLinuxHostPayloadUnit(service,binding,options={}){
 observeLinuxHostPayloadUnit(service,binding,options);
 (options.run??execFileSync)('/usr/bin/systemctl',['--user','daemon-reload'],{encoding:'utf8',timeout:10000,maxBuffer:32768,stdio:['ignore','pipe','pipe']});
 observeLinuxHostPayloadUnit(service,binding,options);return true;
}

export function writeLinuxHostPayloadUnit(service,binding,data,{expectedSha256,mode=0o600,...options}={}){
 if(!Number.isInteger(mode)||mode<0||mode>0o700||(mode&0o077)!==0)fail('host_payload_linux_unit_mode_invalid');
 const file=linuxHostPayloadUnitPath(service,options),home=options.home??os.homedir();
 if(binding?.path!==file||![binding.beforeSha256,binding.afterSha256].includes(sha(data)))fail('host_payload_linux_unit_binding_invalid');
 const parents=[home,path.join(home,'.config'),path.join(home,'.config/systemd'),path.dirname(file)];
 const observed=parents.map(parent=>{const st=fs.lstatSync(parent);if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o022)!==0)fail('host_payload_linux_unit_directory_unsafe');return {path:parent,ino:st.ino,dev:st.dev}});
 observeLinuxHostPayloadUnit(service,binding,options);const prior=requirePrivateFile(file);
 if(sha(fs.readFileSync(file))!==expectedSha256)fail('host_payload_linux_unit_definition_changed');
 const temp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,mode);
 try{fs.writeFileSync(fd,data);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 try{
  for(const parent of observed){const st=fs.lstatSync(parent.path);if(st.ino!==parent.ino||st.dev!==parent.dev||st.isSymbolicLink()||(st.mode&0o022)!==0)fail('host_payload_linux_unit_directory_changed')}
  const now=requirePrivateFile(file);if(now.ino!==prior.ino||now.dev!==prior.dev||sha(fs.readFileSync(file))!==expectedSha256)fail('host_payload_linux_unit_definition_changed');
  fs.renameSync(temp,file);const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}
 }finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}
}

// The Gateway is not updated here. Preserve its exact known definition and
// stopped/disabled observation across the existing Host transaction.
function gatewayPath(stateDir,options={}){
 return linuxHostPayloadUnitPath({id:gatewayServiceIdentity(stateDir)},options);
}
function gatewayRuntimeBinding(config,hostRoot){
 const root=fs.realpathSync(hostRoot),fallback=fileURLToPath(new URL('./gateway-runner.mjs',import.meta.url));
 if(!config.gateway.runtime)return {source:'legacy_host',nodeBinary:path.join(hostRoot,'node'),runner:fallback};
 const runtime=readGatewayRuntime(config.gateway.runtime),gatewayRoot=fs.realpathSync(runtime.installRoot);
 if(root===gatewayRoot||root.startsWith(gatewayRoot+path.sep)||gatewayRoot.startsWith(root+path.sep))fail('host_payload_gateway_runtime_overlaps_host');
 if(runtime.application!=='signed_application'||!runtime.runnerBinary)fail('host_payload_gateway_signed_application_required');
 return {source:'gateway',installRoot:runtime.installRoot,nodeBinary:runtime.nodeBinary,runner:runtime.runnerBinary,version:runtime.version,manifestSha256:runtime.manifestSha256,publisherSha256:runtime.publisherSha256};
}
function runnerHash(file){
 const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||fs.realpathSync(file)!==file||st.size>2*1024*1024)fail('host_payload_gateway_runner_changed');
 return sha(fs.readFileSync(file));
}
export function inspectLinuxPayloadGatewayUnit(stateDir,config,hostRoot,options={}){
 if(config.mode!=='create-local')return null;
 const file=gatewayPath(stateDir,options);if(!fs.existsSync(file))return null;
 const plan=gatewayServicePlan(stateDir),runtime=gatewayRuntimeBinding(config,hostRoot);
 if(requirePrivateFile(file).size>32768)fail('host_payload_gateway_unit_too_large');
 const unit=fs.readFileSync(file,'utf8');
 // A legacy source-checkout runner at another path is intentionally not guessed.
 if(unit!==plan.unit||plan.nodeBinary!==runtime.nodeBinary||plan.runner!==runtime.runner)fail('host_payload_gateway_unit_definition_changed');
 const binding={schema:1,unitName:plan.name,path:file,unit,sha256:sha(unit),runtime,runnerSha256:runnerHash(runtime.runner),observation:observe({id:plan.name},options)};
 observeLinuxPayloadGatewayUnit(stateDir,config,hostRoot,binding,options);return binding;
}
export function observeLinuxPayloadGatewayUnit(stateDir,config,hostRoot,binding,options={}){
 const file=gatewayPath(stateDir,options),name=gatewayServiceIdentity(stateDir);
 if(config.mode!=='create-local'||binding?.schema!==1||binding.path!==file||binding.unitName!==name||typeof binding.unit!=='string'||sha(binding.unit)!==binding.sha256)fail('host_payload_gateway_unit_binding_invalid');
 for(let parent=path.dirname(file);parent!==path.dirname(options.home??os.homedir());parent=path.dirname(parent))if(fs.lstatSync(parent).isSymbolicLink())fail('host_payload_gateway_unit_redirected');
 requirePrivateFile(file);if(fs.readFileSync(file,'utf8')!==binding.unit)fail('host_payload_gateway_unit_definition_changed');
 const runtime=gatewayRuntimeBinding(config,hostRoot);
 if(JSON.stringify(runtime)!==JSON.stringify(binding.runtime)||runnerHash(runtime.runner)!==binding.runnerSha256)fail('host_payload_gateway_runtime_changed');
 if(JSON.stringify(observe({id:name},options))!==JSON.stringify(binding.observation))fail('host_payload_gateway_unit_observation_changed');
 return true;
}
