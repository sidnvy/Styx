// Ephemeral ownership evidence, never deployment identity or work outcome.
// A reboot ends process lifetimes, not the uncertainty of previously sent work.
import fs from 'node:fs';
import path from 'node:path';
import {deploymentConnectionHash} from '../shared/deployment-scope.mjs';
import {execFileSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,writePrivateFile,ensurePrivateDirectory,openPrivateFile} from '../host/private-storage.mjs';
const fail=code=>{throw Error(code)};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const ownerFile=d=>path.join(d,'foreground-owner.json');
const recoveryLock=d=>path.join(d,'foreground-recovery.lock');
function syncDirectory(d){if(process.platform!=='win32'){const fd=fs.openSync(d,'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}}
let boot;
export function currentForegroundBoot(){
 if(boot!==undefined)return boot;
 try{
  let id,startedAt;
  if(process.platform==='linux'){
   id=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim();
   startedAt=Number(/^btime (\d+)$/m.exec(fs.readFileSync('/proc/stat','utf8'))?.[1])*1000;
  }else if(process.platform==='darwin'){
   const value=execFileSync('/usr/sbin/sysctl',['-n','kern.boottime'],{encoding:'utf8',timeout:5000});
   const parts=/sec = (\d+), usec = (\d+)/.exec(value);id=parts?.[0];startedAt=Number(parts?.[1])*1000+Number(parts?.[2])/1000;
  }else if(process.platform==='win32'){
   const script="$ErrorActionPreference='Stop'; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')";
   id=execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:15000,windowsHide:true}).trim();startedAt=Date.parse(id);
  }
  if(typeof id!=='string'||!id||!Number.isFinite(startedAt)||startedAt<=0||startedAt>Date.now())throw Error();
  boot=Object.freeze({platform:process.platform,id,startedAt});
 }catch{boot=null}
 return boot;
}
function snapshot(file){
 requirePrivateFile(file);const a=fs.lstatSync(file,{bigint:true});
 if(!a.isFile()||a.isSymbolicLink()||a.size>32768n||a.nlink!==1n)fail('foreground_recovery_private_file_invalid');
 const bytes=fs.readFileSync(file),b=fs.lstatSync(file,{bigint:true});
 if(a.ino!==b.ino||a.dev!==b.dev||a.mtimeNs!==b.mtimeNs||a.size!==b.size)fail('foreground_recovery_file_changed');
 return {bytes,identity:{ino:b.ino.toString(),dev:b.dev.toString(),sha256:hash(bytes)},modifiedAt:Number(b.mtimeMs)};
}
const same=(a,b)=>a.ino===b.ino&&a.dev===b.dev&&a.sha256===b.sha256;
const unchanged=(file,saved)=>same(snapshot(file).identity,saved.identity);
export function recordForegroundOwner(d,{configurationHash,appOwned,bootProof=currentForegroundBoot()}={}){
 requirePrivateDirectory(d);if(fs.existsSync(recoveryLock(d)))fail('foreground_recovery_requires_review');
 const lock=snapshot(path.join(d,'foreground.lock'));
 const value={schema:1,kind:appOwned===true?'native_app':'independent',pid:process.pid,configurationHash,boot:bootProof,createdAt:Date.now(),lock:lock.identity};
 const file=ownerFile(d),fd=openPrivateFile(file);
 try{fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 syncDirectory(d);const saved=snapshot(file);
 return ()=>{if(!unchanged(file,saved))fail('foreground_owner_receipt_changed');fs.unlinkSync(file)};
}
const alive=pid=>{try{process.kill(pid,0);return true}catch(error){return error.code!=='ESRCH'}};
// Test adapters supply observations, never HTTP options. Production always uses
// the OS boot identity and the process table; an absent PID alone is not proof.
export function recoverForegroundAfterBoot(d,{configurationHash,appOwned,bootProof=currentForegroundBoot(),isAlive=alive}={}){
 requirePrivateDirectory(d);
 if(fs.existsSync(recoveryLock(d)))fail('foreground_recovery_requires_review');
 const configUnchanged=()=>deploymentConnectionHash(snapshot(path.join(d,'deployment.json')).bytes)===configurationHash;
 if(!configUnchanged())fail('foreground_scope_changed');
 const lockPath=path.join(d,'foreground.lock');
 if(!fs.existsSync(lockPath))return {status:'not_required'};
 if(!appOwned)fail('foreground_owned_or_interrupted_do_not_take_over');
 let saved,value,lock;
 try{saved=snapshot(ownerFile(d));value=JSON.parse(saved.bytes);lock=snapshot(lockPath)}catch{fail('foreground_legacy_owner_requires_authorized_maintenance')}
 if(value.schema!==1||value.kind!=='native_app'||value.configurationHash!==configurationHash||!Number.isSafeInteger(value.pid)||value.pid<1||!same(lock.identity,value.lock??{}))fail('foreground_owned_or_interrupted_do_not_take_over');
 const previous=value.boot;
 if(!previous||!bootProof||previous.platform!==bootProof.platform||previous.id===bootProof.id||!Number.isFinite(previous.startedAt)||!Number.isFinite(bootProof.startedAt)||previous.startedAt>=bootProof.startedAt||!Number.isFinite(value.createdAt)||value.createdAt<previous.startedAt||value.createdAt>=bootProof.startedAt||saved.modifiedAt>=bootProof.startedAt||lock.modifiedAt>=bootProof.startedAt||isAlive(value.pid))fail('foreground_owned_or_interrupted_do_not_take_over');
 const files=[{file:lockPath,saved:lock},{file:ownerFile(d),saved}];
 const observer=path.join(d,'foreground-observer.json');
 if(fs.existsSync(observer)){
  const receipt=snapshot(observer),data=JSON.parse(receipt.bytes);
  // Older observation receipts can contain lossy NTFS IDs. Never use them as
  // identity evidence: the new owner proof binds the actual lock instead.
  if(data.pid!==value.pid||data.configurationHash!==configurationHash||data.lock?.sha256!==lock.identity.sha256||receipt.modifiedAt>=bootProof.startedAt)fail('foreground_owned_or_interrupted_do_not_take_over');
  files.push({file:observer,saved:receipt});
 }
 return retire(d,files,{previousBoot:previous,currentBoot:bootProof,previousOwnerPid:value.pid,configurationHash},()=>!isAlive(value.pid)&&configUnchanged());
}
function retire(d,files,context,stillSafe){
 const guard=openPrivateFile(recoveryLock(d)),guardIdentity=fs.fstatSync(guard,{bigint:true});
 fs.fsyncSync(guard);syncDirectory(d);let completed=false;
 try{
  const transactionId=randomUUID(),archive=path.join(d,'foreground-recovery',transactionId);
  ensurePrivateDirectory(path.dirname(archive));ensurePrivateDirectory(archive,{exclusive:true});
  const journal={schema:1,transactionId,status:'prepared',...context,files:files.map(x=>({name:path.basename(x.file),...x.saved.identity})),previousWorkOutcome:'unknown_not_replayed',identityMutation:'none'};
  writePrivateFile(path.join(archive,'prepared.json'),JSON.stringify(journal)+'\n');
  // Save evidence before mutating any live pathname. If interrupted, the guard
  // persists and the next start requires review instead of continuing blindly.
  for(const x of files)writePrivateFile(path.join(archive,path.basename(x.file)+'.before'),x.saved.bytes);
  syncDirectory(archive);syncDirectory(path.dirname(archive));
  if(files.some(x=>!unchanged(x.file,x.saved))||!stillSafe())fail('foreground_recovery_file_changed');
  for(const x of files){if(!unchanged(x.file,x.saved))fail('foreground_recovery_file_changed');fs.renameSync(x.file,path.join(archive,path.basename(x.file)+'.retired'))}
  syncDirectory(archive);syncDirectory(d);
  writePrivateFile(path.join(archive,'receipt.json'),JSON.stringify({...journal,status:'retired'})+'\n');
  syncDirectory(archive);completed=true;return {status:'retired_previous_boot_owner',transactionId,previousWorkOutcome:'unknown_not_replayed'};
 }finally{fs.closeSync(guard);if(completed){requirePrivateFile(recoveryLock(d));const current=fs.lstatSync(recoveryLock(d),{bigint:true});if(current.ino!==guardIdentity.ino||current.dev!==guardIdentity.dev||current.size!==0n)fail('foreground_recovery_guard_changed');fs.unlinkSync(recoveryLock(d));syncDirectory(d)}}
}

// Explicit maintenance for pre-boot-proof releases. This is never called by
// normal startup. The reviewer receives exact file hashes and acknowledges
// that historical work outcomes remain unknown, rather than erasing history.
export function planLegacyForegroundRecovery(d,observations={}){return legacyPlan(d,observations,false)}
function legacyPlan(d,{bootProof=currentForegroundBoot(),isAlive=alive}={},retiring=false){
 requirePrivateDirectory(d);
 if((!retiring&&fs.existsSync(recoveryLock(d)))||fs.existsSync(ownerFile(d)))fail('foreground_recovery_requires_review');
 const config=snapshot(path.join(d,'deployment.json')),configurationHash=deploymentConnectionHash(config.bytes),deployment=JSON.parse(config.bytes);
 if(!deployment.host?.baseDir)fail('foreground_recovery_host_required');
 const identityFile=path.join(deployment.host.baseDir,'device','identity.json'),identity=snapshot(identityFile),device=JSON.parse(identity.bytes);
 const files=['foreground.lock','foreground-observer.json'].map(name=>({file:path.join(d,name),saved:snapshot(path.join(d,name))}));
 const observer=JSON.parse(files[1].saved.bytes),lock=files[0].saved;
 if(!bootProof||!Number.isFinite(bootProof.startedAt)||!Number.isSafeInteger(observer.pid)||observer.pid<1||observer.configurationHash!==configurationHash||observer.lock?.sha256!==lock.identity.sha256||files.some(x=>x.saved.modifiedAt>=bootProof.startedAt)||isAlive(observer.pid)||typeof device.device_id!=='string')fail('foreground_legacy_recovery_evidence_insufficient');
 const body={schema:1,action:'retire_legacy_foreground_owner',stateDir:d,deviceId:device.device_id,identitySha256:identity.identity.sha256,configurationHash,currentBoot:bootProof,previousOwnerPid:observer.pid,files:files.map(x=>({name:path.basename(x.file),...x.saved.identity,modifiedAt:x.saved.modifiedAt})),previousWorkOutcome:'unknown_not_replayed',identityMutation:'none',requiresExplicitAuthorization:true};
 return {...body,planSha256:hash(JSON.stringify(body))};
}
export function applyLegacyForegroundRecovery(d,{authorize,plan}={},observations={}){
 if(authorize!==true||!plan)fail('explicit_legacy_foreground_recovery_authorization_required');
 const current=planLegacyForegroundRecovery(d,observations);
 if(JSON.stringify(plan)!==JSON.stringify(current))fail('foreground_recovery_plan_changed');
 const files=current.files.map(x=>({file:path.join(d,x.name),saved:snapshot(path.join(d,x.name))}));
 return retire(d,files,{currentBoot:current.currentBoot,previousOwnerPid:current.previousOwnerPid,configurationHash:current.configurationHash,authorizationPlan:current,legacy:true},()=>{
  try{return JSON.stringify(legacyPlan(d,observations,true))===JSON.stringify(current)}catch{return false}
 });
}