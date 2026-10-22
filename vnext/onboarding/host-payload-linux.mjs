// Read-only Linux offline boundary for the shared Host payload transaction.
// Service stop/update/restart remains the existing service-update workflow.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {observeLinuxHostPayloadUnit} from './host-payload-linux-service.mjs';
import {observeLinuxGatewayProcesses} from '../host/linux-gateway-quiescence.mjs';
const absolute=p=>typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p&&p!=='/'&&!/[\x00-\x1f\x7f]/.test(p);
const unit=p=>/^styx-(?:vnext-)?[a-z0-9][a-z0-9-]{0,48}\.service$/.test(p??'');
const sha=b=>createHash('sha256').update(b).digest('hex');
const fields=text=>Object.fromEntries(String(text).split('\n').filter(x=>x.includes('=')).map(x=>{const i=x.indexOf('=');return [x.slice(0,i),x.slice(i+1)]}));
export function observeLinuxHostPayloadAbsence({stateDir,installRoot,hostConfigFile,hostServiceUnitName,gatewayServiceUnitName,hostServiceBinding}={},
 {platform=process.platform,home=os.homedir(),run=execFileSync,observeProcesses=observeLinuxGatewayProcesses}={}){
 const result=(status,reason,extra={})=>({schema:1,status,observation:'native_offline_boundary',mutation:'NONE',...(reason?{reason}:{}),...extra});
 if(platform!=='linux')return result('blocked','linux_native_observation_required');
 if(![stateDir,installRoot,hostConfigFile,home].every(absolute)||!unit(hostServiceUnitName)||hostConfigFile!==path.join(path.dirname(installRoot),'device/host.json'))return result('blocked','native_scope_invalid');
 const gateway='styx-gateway-'+sha(stateDir).slice(0,12)+'.service';
 if(gatewayServiceUnitName!==undefined&&gatewayServiceUnitName!==gateway)return result('blocked','gateway_service_name_mismatch');
 try{
  requirePrivateDirectory(stateDir);requirePrivateDirectory(installRoot);requirePrivateFile(hostConfigFile);
  const file=path.join(stateDir,'deployment.json');requirePrivateFile(file);
  if(fs.statSync(file).size>1024*1024)return result('blocked','native_scope_invalid');
  const config=JSON.parse(fs.readFileSync(file));
  if(config.host?.baseDir!==path.dirname(installRoot))return result('blocked','native_scope_invalid');
  const roots=[installRoot];
  if(config.mode==='create-local'&&config.gateway?.runtime){
   if(!absolute(config.gateway.runtime.baseDir))return result('blocked','native_scope_invalid');
   roots.push(path.join(config.gateway.runtime.baseDir,'install'));
  }
  if(hostServiceBinding)observeLinuxHostPayloadUnit({id:hostServiceUnitName},hostServiceBinding,{home,run});
  const labels=[hostServiceUnitName,...(config.mode==='create-local'?[gateway]:[])];
  for(const name of labels)for(const user of [true,false]){
   if(hostServiceBinding&&name===hostServiceUnitName&&user)continue;
   const text=run('/usr/bin/systemctl',[...(user?['--user']:[]),'show',name,'--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath','--no-pager'],{encoding:'utf8',timeout:10000,maxBuffer:32768,stdio:['ignore','pipe','pipe']});
   const value=fields(text);
   if(value.LoadState!=='not-found'||value.ActiveState!=='inactive'||value.SubState!=='dead'||value.MainPID!=='0'||value.FragmentPath||value.UnitFileState)return result('blocked','native_service_definition_present',{serviceName:name});
  }
  // Query fresh unit search paths too: a file installed since the manager's
  // last reload must not turn a stale not-found observation into absence.
  for(const user of [true,false]){
   const directories=String(run('/usr/bin/systemd-analyze',[...(user?['--user']:[]),'unit-paths'],{encoding:'utf8',timeout:10000,maxBuffer:32768,stdio:['ignore','pipe','pipe']})).trim().split('\n');
   if(!directories.length||directories.some(p=>!absolute(p)))return result('blocked','native_service_observation_unknown');
   for(const directory of directories)for(const name of labels){
    if(hostServiceBinding&&name===hostServiceUnitName&&user&&path.join(directory,name)===hostServiceBinding.path)continue;
    try{fs.lstatSync(path.join(directory,name));return result('blocked','native_service_definition_present',{serviceName:name})}catch(error){if(error.code!=='ENOENT')throw error}
   }
  }
  for(const root of roots)observeProcesses({stateDir,installRoot:root});
  return result('absent',null,{services:hostServiceBinding?'exact_host_unit_stopped_disabled_other_services_absent':'not_installed_or_loaded',processes:'kernel_executable_exclusion_and_complete_current_user_argv',pointInTime:true});
 }catch(error){
  return result('blocked',error.message==='gateway_runtime_process_still_running'?'native_owned_process_present':'native_observation_unavailable');
 }
}
