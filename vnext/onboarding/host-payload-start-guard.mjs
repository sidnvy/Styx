// An interrupted multi-file Host migration must not start either local role,
// even if a process crash or an operator removed the ordinary management lock.
import fs from 'node:fs';
import path from 'node:path';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
const fail=()=>{throw Error('host_payload_migration_requires_recovery')};
function present(file){try{fs.lstatSync(file);return true}catch(error){if(error.code==='ENOENT')return false;fail()}}
export function assertHostPayloadMigrationSettled(stateDir){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir)||path.normalize(stateDir)!==stateDir)fail();
 requirePrivateDirectory(stateDir);
 if(present(path.join(stateDir,'host-payload-migration-recovery.lock')))fail();
 // Admission precedes journal creation; an interrupted capture still needs
 // recovery even when the previous transaction has a terminal journal.
 const admission=path.join(stateDir,'advance.lock');
 if(present(admission)){
  let record;try{if(requirePrivateFile(admission).size<=2*1024*1024)record=JSON.parse(fs.readFileSync(admission,'utf8'))}catch{}
  if(record?.kind==='host-payload-migration-v1')fail();
 }
 const file=path.join(stateDir,'host-payload-migration.json');if(!present(file))return;
 try{
  if(requirePrivateFile(file).size>1024*1024)fail();
  const record=JSON.parse(fs.readFileSync(file,'utf8'));
  if(record.schema!==1||record.kind!=='host-payload-migration-v1'||!/^[a-f0-9]{32}$/.test(record.transactionId??'')||!['applied','rolled_back'].includes(record.status)||record.plan?.stateDir!==stateDir)fail();
 }catch{fail()}
}
