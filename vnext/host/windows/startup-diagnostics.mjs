// Last completed native startup only. No paths, input, errors, or remote upload.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,writePrivateFile} from '../private-storage.mjs';
const invalid=()=>{throw Error('invalid_native_startup_diagnostics');};
const keys=(value,names)=>{if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!==[...names].sort().join(','))invalid();};
const time=value=>{if(typeof value!=='number'||!Number.isFinite(value)||value<0||value>86400000)invalid();};
export function validateStartupDiagnostics(value){
 keys(value,['schema','verification','startup']);if(value.schema!==1)invalid();
 const v=value.verification,s=value.startup;
 keys(v,['nodeReadyMilliseconds','childStartedMilliseconds','childExitedMilliseconds','progress']);
 keys(s,['verificationStartedMilliseconds','verifiedMilliseconds','readyMilliseconds']);
 for(const name of Object.keys(s))time(s[name]);
 if(s.verifiedMilliseconds<s.verificationStartedMilliseconds||s.readyMilliseconds<s.verifiedMilliseconds)invalid();
 for(const name of ['nodeReadyMilliseconds','childStartedMilliseconds','childExitedMilliseconds'])time(v[name]);
 if(v.childStartedMilliseconds<v.nodeReadyMilliseconds||v.childExitedMilliseconds<v.childStartedMilliseconds||!Array.isArray(v.progress)||v.progress.length<2||v.progress.length>160)invalid();
 let last=v.childStartedMilliseconds,fileTotal,completed=-1,signed=false;
 for(const row of v.progress){
  keys(row,['phase','completed','total','elapsedMilliseconds']);time(row.elapsedMilliseconds);
  if(row.elapsedMilliseconds<last||row.elapsedMilliseconds>v.childExitedMilliseconds||!Number.isSafeInteger(row.completed)||!Number.isSafeInteger(row.total)||row.completed<0||row.total<1||row.total>=20000||row.completed>row.total)invalid();
  last=row.elapsedMilliseconds;
  if(row.phase==='files'){
   if(signed||fileTotal!==undefined&&fileTotal!==row.total||row.completed<completed)invalid();
   fileTotal=row.total;completed=row.completed;
  }else if(row.phase==='signed_host'){
   if(completed!==fileTotal||row.total!==1)invalid();signed=true;
  }else invalid();
 }
 if(completed!==fileTotal)invalid();
 return value;
}
export function writeStartupDiagnostics(stateRoot,value){
 validateStartupDiagnostics(value);requirePrivateDirectory(stateRoot);
 const target=path.join(stateRoot,'native-startup.json'),temp=path.join(stateRoot,'.native-startup-'+randomUUID()+'.json');
 if(fs.existsSync(target))requirePrivateFile(target);
 try{writePrivateFile(temp,JSON.stringify(value)+'\n');fs.renameSync(temp,target);}
 finally{if(fs.existsSync(temp))fs.unlinkSync(temp);}
 return {status:'recorded_locally'};
}
