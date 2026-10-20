// Only explicit recovery may reclaim a same-transaction guard whose owner is
// proven dead. Older/unknown records and inaccessible or live PIDs stay intact.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {openPrivateFile,requirePrivateFile} from '../host/private-storage.mjs';
const ownerToken=randomBytes(32).toString('hex');
const fail=code=>{throw Error(code)};
const nonce=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
function snapshot(file){
 const info=requirePrivateFile(file);if(info.size>4096)fail('recovery_guard_owner_unknown');
 const bytes=fs.readFileSync(file),after=requirePrivateFile(file);
 if(info.ino!==after.ino||info.dev!==after.dev||info.size!==after.size)fail('recovery_guard_identity_changed');
 return {info,bytes};
}
function unchanged(file,expected){
 const actual=snapshot(file);
 if(actual.info.ino!==expected.info.ino||actual.info.dev!==expected.info.dev||!actual.bytes.equals(expected.bytes))fail('recovery_guard_identity_changed');
}
function syncParent(file){if(process.platform!=='win32'){const fd=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}}
export function acquireRecoveryGuard(file,{kind,transactionId},{probePid=pid=>process.kill(pid,0)}={}){
 if(fs.existsSync(file)){
  const previous=snapshot(file);let record;try{record=JSON.parse(previous.bytes)}catch{fail('recovery_guard_owner_unknown')}
  if(record?.schema!==1||record.kind!==kind||record.transactionId!==transactionId||!Number.isSafeInteger(record.pid)||record.pid<1||!nonce(record.ownerToken)||!nonce(record.token)||Object.keys(record).some(key=>!['schema','kind','transactionId','pid','ownerToken','token'].includes(key)))fail('recovery_guard_owner_unknown');
  let dead=false;try{probePid(record.pid)}catch(error){dead=error.code==='ESRCH'}
  if(!dead)fail('recovery_guard_owner_alive_or_unknown');
  unchanged(file,previous);fs.unlinkSync(file);syncParent(file);
 }
 let fd;try{fd=openPrivateFile(file)}catch{fail('recovery_guard_busy_or_unknown')}
 const info=fs.fstatSync(fd),bytes=Buffer.from(JSON.stringify({schema:1,kind,transactionId,pid:process.pid,ownerToken,token:randomBytes(32).toString('hex')})+'\n');
 try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);syncParent(file)}catch(error){fs.closeSync(fd);throw error}
 const expected={info,bytes};let closed=false;
 return {
  assertOwned(){if(closed)fail('recovery_guard_already_released');unchanged(file,expected)},
  close(){if(closed)return;try{unchanged(file,expected);fs.unlinkSync(file);syncParent(file)}finally{closed=true;fs.closeSync(fd)}}
 };
}
