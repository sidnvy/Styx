// The App polls Apple's read-only APIs. Its fresh private descriptor reports
// those grants only; neither a grant nor a socket proves GUI execution or TCC
// responsibility for Exec descendants. This module never requests a grant.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
const unknown=()=>({source:'not_observed',accessibility:'not_observed',screenRecording:'not_observed',automation:'not_required',tccResponsibility:'NOT RUN'});
export function observeMacAppPermissions({appPath,descriptorFile,uid,now=Date.now(),run=spawnSync,runtimeRoot='/tmp/styx-cua-'+uid}){
 try{
  if(!Number.isSafeInteger(uid)||uid<1||appPath!=='/Applications/Styx.app'||!Number.isSafeInteger(now))return unknown();
  const root=runtimeRoot;if(!path.isAbsolute(root)||path.normalize(root)!==root)return unknown();
  if(descriptorFile!==path.join(root,'connection.json'))return unknown();
  requirePrivateDirectory(root);const info=requirePrivateFile(descriptorFile);
  if(info.size>8192||now-info.mtimeMs>5000||info.mtimeMs-now>1000)return unknown();
  const bytes=fs.readFileSync(descriptorFile),d=JSON.parse(bytes);
  if(d.schema!==1||d.bundle_id!=='app.styx.host'||d.transport!=='socket_accepting'||d.socket!==path.join(root,'cua.sock')||typeof d.generation!=='string'||!/^[A-Fa-f0-9-]{36}$/.test(d.generation)||!Number.isSafeInteger(d.owner_pid)||d.owner_pid<1||typeof d.host_accessibility!=='boolean'||typeof d.host_screen_recording!=='boolean')return unknown();
  const ps=run('/bin/ps',['-p',String(d.owner_pid),'-o','uid=','-o','comm='],{encoding:'utf8',timeout:3000,maxBuffer:8192,stdio:['ignore','pipe','ignore']});
  const identity=String(ps.stdout??'').trim().match(/^(\d+)\s+(.+)$/);
  if(ps.error||ps.status!==0||!identity||Number(identity[1])!==uid||identity[2]!==appPath+'/Contents/MacOS/Styx')return unknown();
  const current=requirePrivateFile(descriptorFile);
  // Native App refreshes atomically every 200 ms; a newer descriptor is valid
  // only when it still names this same owner and Cua generation.
  const fresh=JSON.parse(fs.readFileSync(descriptorFile,'utf8'));
  if(current.size>8192||current.dev!==info.dev||fresh.owner_pid!==d.owner_pid||fresh.generation!==d.generation||fresh.bundle_id!==d.bundle_id||fresh.socket!==d.socket||fresh.transport!==d.transport||fresh.host_accessibility!==d.host_accessibility||fresh.host_screen_recording!==d.host_screen_recording)return unknown();
  return {source:'current_native_app_preflight',nativeAppPid:d.owner_pid,nativeAppGeneration:d.generation,accessibility:d.host_accessibility?'granted':'denied',screenRecording:d.host_screen_recording?'granted':'denied',automation:'not_required',observedAt:new Date(current.mtimeMs).toISOString(),tccResponsibility:'NOT RUN'};
 }catch{return unknown()}
}
export function readDeploymentPermissions(stateDir){
 try{
  requirePrivateDirectory(stateDir);const file=path.join(stateDir,'deployment.json');if(requirePrivateFile(file).size>1024*1024)return unknown();
  const config=JSON.parse(fs.readFileSync(file,'utf8'));
  let desktop=config.host?.computer===true;
  if(config.host){const current=path.join(config.host.baseDir??'','device/host.json');if(path.isAbsolute(current)&&fs.existsSync(current)){if(requirePrivateFile(current).size>65536)return unknown();desktop=JSON.parse(fs.readFileSync(current,'utf8')).computer?.enabled===true}}
  if(!config.host||!desktop)return {...unknown(),source:'not_requested',accessibility:'not_required',screenRecording:'not_required'};
  if(process.platform!=='darwin')return unknown();
  const uid=process.getuid();
  return observeMacAppPermissions({appPath:config.host.macPreviewApp?.path,descriptorFile:'/tmp/styx-cua-'+uid+'/connection.json',uid});
 }catch{return unknown()}
}
