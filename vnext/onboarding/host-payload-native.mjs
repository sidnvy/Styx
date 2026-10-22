// Offline payload changes need observed absence, not a request to stop. This
// adapter never stops a process, unloads a job, reads credentials or loads Core.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';

const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value&&value!=='/'&&!/[\x00-\x1f\x7f]/.test(value);
const label=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/.test(value);
const sha=value=>createHash('sha256').update(value).digest('hex');
const options={encoding:'utf8',timeout:10000,maxBuffer:8*1024*1024,stdio:['ignore','pipe','pipe']};

export function observeMacHostPayloadAbsence({installRoot,hostConfigFile,hostServiceLabel,gatewayServiceLabel,stateDir,appPath='/Applications/Styx.app'}={},
  {home=os.homedir(),uid=process.getuid?.(),run=execFileSync,platform=process.platform,pid=process.pid,execPath=process.execPath}={}){
 const result=(status,reason,extra={})=>({schema:1,status,observation:'native_offline_boundary',mutation:'NONE',...(reason?{reason}:{}),...extra});
 if(platform!=='darwin')return result('blocked','macos_native_observation_required');
 if(![installRoot,hostConfigFile,stateDir,home,appPath,execPath].every(absolute)||!Number.isSafeInteger(uid)||uid<1||!Number.isSafeInteger(pid)||pid<1||!label(hostServiceLabel))return result('blocked','native_scope_invalid');
 const gatewayLabel='app.styx.gateway.'+sha(stateDir).slice(0,12);
 if(gatewayServiceLabel!==undefined&&gatewayServiceLabel!==gatewayLabel)return result('blocked','gateway_service_label_mismatch');
 const labels=[...new Set([hostServiceLabel,gatewayLabel,'app.styx.desktop-login'])];
 try{
  const st=fs.lstatSync(home);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==uid||st.mode&0o022||fs.realpathSync(home)!==home)return result('blocked','native_home_untrusted');
  // A disabled, unloaded plist can still be enabled at next login. The first
  // migration boundary requires absence rather than inferring durable inhibit.
  for(const folder of [path.join(home,'Library/LaunchAgents'),'/Library/LaunchAgents','/Library/LaunchDaemons','/System/Library/LaunchAgents','/System/Library/LaunchDaemons']){
   let info;try{info=fs.lstatSync(folder)}catch(error){if(error.code==='ENOENT')continue;throw error}
   if(!info.isDirectory()||info.isSymbolicLink())return result('blocked','native_service_directory_untrusted');
   for(const name of labels){
    try{fs.lstatSync(path.join(folder,name+'.plist'));return result('blocked','native_service_definition_present',{serviceLabel:name});}
    catch(error){if(error.code!=='ENOENT')throw error}
   }
  }
  for(const domain of ['gui/'+uid,'user/'+uid,'system'])for(const name of labels){
   try{run('/bin/launchctl',['print',domain+'/'+name],options);return result('blocked','native_service_loaded',{serviceLabel:name});}
   catch(error){
    // A missing domain, denied read, timeout or generic nonzero is unknown.
    if(error.status!==113||!/Could not find (?:specified )?service/i.test(String(error.stderr??'')))return result('blocked','native_service_observation_unknown',{serviceLabel:name});
   }
  }
  const table=String(run('/bin/ps',['-ww','-axo','uid=,pid=,ppid=,command='],options));
  const lines=table.trim().split('\n');if(!table.trim())return result('blocked','native_process_observation_unknown');
  const needles=[installRoot,path.dirname(installRoot),hostConfigFile,stateDir,appPath];let observed=0;const pids=[];
  for(const line of lines){
   const row=/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/.exec(line);
   if(!row||![row[1],row[2],row[3]].every(value=>Number.isSafeInteger(Number(value))))return result('blocked','native_process_observation_unknown');
   if(Number(row[1])!==uid)continue;observed++;
   // Preserve arguments internally to catch wrappers, legacy Gateway runtimes,
   // orphaned Exec/Cua children and a Core which references this state directory.
   // Never return commands: they may contain credentials or unrelated user data.
   if(needles.some(needle=>row[4].includes(needle))){
    if(Number(row[2])===pid){
     // CLI arguments necessarily name the deployment and candidate. Only this
     // exact updater may be ignored, and only after native executable identity
     // confirms it runs outside the Host tree that the transaction will change.
     const executable=fs.realpathSync(execPath),root=fs.realpathSync(installRoot);
     if(executable===root||executable.startsWith(root+path.sep))return result('blocked','independent_updater_runtime_required');
     const identity=String(run('/bin/ps',['-ww','-p',String(pid),'-o','uid=,comm='],options)).trim();
     const current=/^(\d+)\s+(.+)$/.exec(identity);
     if(!current||Number(current[1])!==uid||fs.realpathSync(current[2])!==executable)return result('blocked','native_updater_identity_unverified');
     continue;
    }
    pids.push(Number(row[2]));
   }
  }
  if(!observed)return result('blocked','native_process_observation_unknown');
  if(pids.length)return result('blocked','native_owned_process_present',{processCount:pids.length,pids});
  return result('absent',null,{services:'not_installed_or_loaded',processes:'no_matching_current_user_process',pointInTime:true});
 }catch{return result('blocked','native_observation_unavailable')}
}
