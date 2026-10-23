import {assertHostPayloadMigrationSettled} from './host-payload-start-guard.mjs';
// Shared read-only startup interlock. The update journal and Core lock remain
// authoritative; this module never creates, adopts or removes either.
import fs from 'node:fs';
import path from 'node:path';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
const fail=()=>{throw Error('gateway_runtime_start_requires_reconciliation')};
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
function present(file){try{fs.lstatSync(file);return true}catch(error){if(error.code==='ENOENT')return false;fail()}}
export function assertGatewayRuntimeStartAllowed({stateDir,baseDir,ownsAdvance=false}={}){
 if(!absolute(stateDir)||baseDir!==undefined&&!absolute(baseDir))fail();
 requirePrivateDirectory(stateDir);
 assertHostPayloadMigrationSettled(stateDir);
 if(present(path.join(stateDir,'gateway-runtime-recovery.lock')))fail();
 const advance=path.join(stateDir,'advance.lock');
 if(present(advance)){
  if(ownsAdvance!==true)fail();
  // Core's current in-process advance may own an empty lock. It must never
  // exempt an update, a foreign record, or an uninspectable lock from refusal.
  try{requirePrivateFile(advance);if(fs.readFileSync(advance,'utf8')!=='')fail()}catch{fail()}
 }
 if(baseDir===undefined)return;
 requirePrivateDirectory(baseDir);
 const journal=path.join(baseDir,'runtime-change.json');
 if(!present(journal))return;
 try{
  requirePrivateFile(journal);if(fs.statSync(journal).size>1024*1024)fail();
  const record=JSON.parse(fs.readFileSync(journal,'utf8'));
  if(record.schema!==1||!['completed','recovered'].includes(record.status)||!/^[a-f0-9]{32}$/.test(record.id??'')||record.plan?.stateDir!==stateDir||record.plan?.installRoot!==path.join(baseDir,'install'))fail();
 }catch{fail()}
}
