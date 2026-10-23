// A trusted native management entry binds its bundled target to this Core
// process. This is not persisted configuration and cannot be registered by HTTP.
import path from 'node:path';
import fs from 'node:fs';
import {requirePrivateFile} from '../host/private-storage.mjs';
const guards=new Map();
const valid=d=>typeof d==='string'&&path.isAbsolute(d)&&path.normalize(d)===d;
export function hasDeploymentRuntimeGuard(d){return valid(d)&&guards.has(d);}
export function registerDeploymentRuntimeGuard(d,guard){
 if(!valid(d)||typeof guard!=='function')throw Error('invalid_runtime_guard');
 if(guards.has(d))throw Error('runtime_guard_already_owned');
 const owner={guard};guards.set(d,owner);
 return()=>{if(guards.get(d)===owner)guards.delete(d)};
}
function assertCapabilityRuntimeSettled(d,action){
 if(['status','rollback','recovery'].includes(action?.action))return;
 const starts=action?.action==='foreground'||['host.doctor','host.service.install','host.service.start'].includes(action?.stepId);
 if(!starts)return;
 for(const name of ['capabilities.lock','capabilities.json']){
  const file=path.join(d,name);let info;
  try{info=fs.lstatSync(file)}catch(error){if(error.code==='ENOENT')continue;throw error}
  if(name==='capabilities.lock')throw Error('foreground_capability_state_uncertain');
  try{
   requirePrivateFile(file);
   if(info.size>1048576)throw Error('invalid_capability_journal');
   const journal=JSON.parse(fs.readFileSync(file,'utf8'));
   if(journal.schema!==1||!['updated','rolled_back'].includes(journal.status))throw Error('unsettled_capability_journal');
  }catch{throw Error('foreground_capability_state_uncertain')}
 }
}
export async function assertDeploymentRuntimeReady(d,action){
 if(!valid(d))throw Error('invalid_runtime_guard');
 assertCapabilityRuntimeSettled(d,action);
 const owner=guards.get(d);
 if(!owner)return; // Independent CLI uses its existing configured runtime.
 await owner.guard(action);
 assertCapabilityRuntimeSettled(d,action);
 if(guards.get(d)!==owner)throw Error('runtime_guard_owner_changed');
}
