// Preflight is a point-in-time budget, not a reservation or a cleanup policy.
import fs from 'node:fs';
import path from 'node:path';
function number(value){const n=Number(value);if(!Number.isSafeInteger(n)||n<0)throw Error('host_payload_space_observation_failed');return n}
function ancestor(file){let p=path.resolve(file);for(;;){try{const s=fs.statSync(p);if(!s.isDirectory())p=path.dirname(p);else return p;}catch(e){if(e.code!=='ENOENT')throw e;const parent=path.dirname(p);if(parent===p)throw e;p=parent;}}}
export function inspectHostPayloadSpace(items,{observeVolume}={}){
 const groups=new Map(),ancestors=new Map(),volumesByAncestor=new Map();
 for(const item of items){
  if(!path.isAbsolute(item.path)||!Number.isSafeInteger(item.bytes)||item.bytes<0)throw Error('host_payload_space_observation_failed');
  const directory=path.dirname(item.path);let existing=ancestors.get(directory);if(!existing){existing=ancestor(directory);ancestors.set(directory,existing)}
  let volume=volumesByAncestor.get(existing);if(!volume){volume=observeVolume?observeVolume(existing):(()=>{const s=fs.statSync(existing,{bigint:true}),v=fs.statfsSync(existing,{bigint:true});return{volumeId:String(s.dev),blockSize:number(v.bsize),availableBytes:number(v.bavail*v.bsize)}})();volumesByAncestor.set(existing,volume);}
  const {volumeId}=volume,blockSize=number(volume.blockSize),availableBytes=number(volume.availableBytes);if(typeof volumeId!=='string'||!blockSize)throw Error('host_payload_space_observation_failed');
  let group=groups.get(volumeId);if(!group){group={volumeId,requiredBytes:0,availableBytes,items:[],directories:new Set()};groups.set(volumeId,group)}group.availableBytes=Math.min(group.availableBytes,availableBytes);
  const allocatedBytes=Math.ceil(item.bytes/blockSize)*blockSize;group.requiredBytes=number(group.requiredBytes+allocatedBytes);let category=group.items.find(x=>x.kind===item.kind);if(!category){category={kind:item.kind,bytes:0,allocatedBytes:0,fileCount:0};group.items.push(category)}category.bytes=number(category.bytes+item.bytes);category.allocatedBytes=number(category.allocatedBytes+allocatedBytes);category.fileCount++;
  for(let p=path.dirname(item.path);p!==existing;p=path.dirname(p)){if(group.directories.has(p))break;group.directories.add(p);group.requiredBytes=number(group.requiredBytes+blockSize);}
 }
 const volumes=[...groups.values()].map(({directories,...g})=>({...g,directoryCount:directories.size,shortfallBytes:Math.max(0,g.requiredBytes-g.availableBytes)}));
 const budget={schema:1,checkedAt:new Date().toISOString(),volumes};
 if(volumes.some(v=>v.shortfallBytes)){const error=Error('host_payload_insufficient_space');error.code=error.message;error.budget=budget;throw error}return budget;
}
