// A trusted native management entry binds its bundled target to this Core
// process. This is not persisted configuration and cannot be registered by HTTP.
import path from 'node:path';
const guards=new Map();
const valid=d=>typeof d==='string'&&path.isAbsolute(d)&&path.normalize(d)===d;
export function registerDeploymentRuntimeGuard(d,guard){
 if(!valid(d)||typeof guard!=='function')throw Error('invalid_runtime_guard');
 if(guards.has(d))throw Error('runtime_guard_already_owned');
 const owner={guard};guards.set(d,owner);
 return()=>{if(guards.get(d)===owner)guards.delete(d)};
}
export async function assertDeploymentRuntimeReady(d,action){
 if(!valid(d))throw Error('invalid_runtime_guard');
 const owner=guards.get(d);
 if(!owner)return; // Independent CLI uses its existing configured runtime.
 await owner.guard(action);
 if(guards.get(d)!==owner)throw Error('runtime_guard_owner_changed');
}
