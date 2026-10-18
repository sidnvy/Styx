// Trusted local owner API. No model-visible administration or automatic resume.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {requirePrivateDirectory,ensurePrivateDirectory,requirePrivateFile} from './private-storage.mjs';
import {verifySignedRelease,activeRelease} from './installer.mjs';

const assert=(ok,code)=>{if(!ok)throw Error(code)};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const versionPattern=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const idPattern=/^[a-f0-9]{32}$/;
const terminal=new Set(['activated','rolled_back','recovered_stopped']);
function syncDirectory(folder){
  // Windows does not expose a portable directory-fsync handle through Node.
  if(process.platform==='win32')return;
  const fd=fs.openSync(folder,'r');
  try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
}
function atomic(file,bytes,mode=0o600){
  const temp=file+'.transaction-'+randomBytes(8).toString('hex');
  const fd=fs.openSync(temp,'wx',mode);
  try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  try{fs.renameSync(temp,file);syncDirectory(path.dirname(file))}
  catch(e){try{fs.unlinkSync(temp)}catch{};throw e}
}
function snapshot(file){requirePrivateFile(file);return fs.readFileSync(file,'utf8')}
function roots(installRoot){
  requirePrivateDirectory(installRoot);
  const realRoot=fs.realpathSync(installRoot),runtime=fs.realpathSync(process.execPath);
  assert(runtime!==realRoot&&!runtime.startsWith(realRoot+path.sep),'independent_updater_runtime_required');
  return {lock:path.join(installRoot,'.health-update-lock'),
    records:path.join(installRoot,'update-transactions'),pointer:path.join(installRoot,'active.json')};
}
function receiptFile(records,id){assert(idPattern.test(id??''),'invalid_transaction_id');return path.join(records,id+'.json')}
function save(ctx,phase,extra={}){
  ctx.record={...ctx.record,...extra,phase,updatedAt:new Date().toISOString()};
  atomic(receiptFile(ctx.records,ctx.record.transactionId),JSON.stringify(ctx.record,null,2)+'\n');
}
function ownership(ctx){
  requirePrivateDirectory(ctx.lock);
  assert(snapshot(path.join(ctx.lock,'owner'))===ctx.record.transactionId,'update_ownership_changed');
}
function pointerOwned(ctx){
  ownership(ctx);
  const current=snapshot(ctx.pointer);
  assert((ctx.recoveryPointers??[ctx.record.expectedPointer]).includes(current),
    'active_pointer_changed_during_update');
}
function checked(installRoot,version,publicKeyPem,options,expected){
  assert(versionPattern.test(version??''),'invalid_version');
  const folder=path.join(installRoot,'releases',version);
  const result=verifySignedRelease(folder,publicKeyPem,options);
  if(expected)assert(result.sha256===expected,'signed_release_changed');
  const names=['host/private-storage.mjs','host/installer.mjs','host/launch.mjs',
    'bin/'+(options.platform==='win32'?'node.exe':'node')];
  const entries=names.map(name=>{
    const entry=result.manifest.files.find(e=>e.path===name);
    assert(entry,'signed_update_bootstrap_missing');
    if(name.startsWith('bin/'))assert(entry.executable,'signed_node_not_executable');
    return {...entry,destination:path.basename(name)};
  });
  return {...result,folder,entries};
}
function verifyStable(ctx,previous,candidate,{previousOnly=false}={}){
  pointerOwned(ctx);
  for(const entry of previous.entries){
    const file=path.join(ctx.installRoot,entry.destination);
    requirePrivateFile(file);
    const actual=sha(fs.readFileSync(file));
    const other=candidate?.entries.find(e=>e.destination===entry.destination);
    assert(actual===entry.sha256||(!previousOnly&&actual===other?.sha256),
      'stable_bootstrap_changed');
  }
}
function switchFiles(ctx,release){
  pointerOwned(ctx);
  for(const entry of release.entries){
    // Never use unsigned workspace shims or backups. Each rollback byte comes
    // from the independently verified previous signed release.
    const bytes=fs.readFileSync(path.join(release.folder,entry.path));
    assert(bytes.length===entry.size&&sha(bytes)===entry.sha256,'signed_release_changed');
    atomic(path.join(ctx.installRoot,entry.destination),bytes,entry.executable?0o700:0o600);
  }
}
function releaseLock(ctx){
  ownership(ctx);
  fs.unlinkSync(path.join(ctx.lock,'owner'));fs.rmdirSync(ctx.lock);syncDirectory(ctx.installRoot);
}
function result(ctx){const {transactionId,phase,reason}=ctx.record;return {
  status:terminal.has(phase)?phase:'needs_recovery',transactionId,phase,...(reason?{reason}:{})};}
async function callback(ctx,fn,phase,version,timeoutMs){
  save(ctx,phase);ownership(ctx);
  const controller=new AbortController();let timer;const started=performance.now();
  const context=Object.freeze({transactionId:ctx.record.transactionId,version,
    previousVersion:ctx.record.previousVersion,phase,signal:controller.signal,
    restartInhibitionRequired:['stop_intent','rollback_stop_intent','recovery_observe_intent'].includes(phase)});
  try{
    const outcome=await Promise.race([
      Promise.resolve().then(()=>fn(context)).then(value=>({value}),()=>({error:'callback_failed'})),
      new Promise(resolve=>{timer=setTimeout(()=>{controller.abort();resolve({error:'callback_timeout'})},timeoutMs)})
    ]);
    const callbackElapsed=performance.now()-started;
    ownership(ctx);
    if(callbackElapsed>=timeoutMs)throw Error('callback_timeout');
    if(outcome.error)throw Error(outcome.error);
    assert(typeof outcome.value==='boolean','callback_result_invalid');
    return outcome.value;
  }finally{clearTimeout(timer);controller.abort()}
}
function timeout(value){assert(Number.isInteger(value)&&value>=1&&value<=60000,'invalid_update_timeout')}
function failure(ctx,error){
  // Never persist callback output, raw exception text, paths or credentials.
  const reason=['callback_timeout','callback_failed','callback_result_invalid',
    'active_pointer_changed_during_update','update_ownership_changed',
    'stable_bootstrap_changed','signed_release_changed'].includes(error.message)
    ?error.message:'update_failed';
  try{ownership(ctx);save(ctx,ctx.record.phase,{reason})}catch{}
  return {...result(ctx),status:'needs_recovery',reason};
}

export async function updateServiceRelease({installRoot,version,publicKeyPem,
  stopService,startService,checkHealth,timeoutMs=10000,
  platform=process.platform,arch=process.arch}={}){
  for(const fn of [stopService,startService,checkHealth])assert(typeof fn==='function','trusted_service_callbacks_required');
  timeout(timeoutMs);const locations=roots(installRoot),options={platform,arch};
  const originalPointer=snapshot(locations.pointer);
  const current=activeRelease(installRoot,publicKeyPem,options);
  assert(current&&current.version!==version,'distinct_active_release_required');
  const previous=checked(installRoot,current.version,publicKeyPem,options);
  const candidate=checked(installRoot,version,publicKeyPem,options);
  ensurePrivateDirectory(locations.records);
  try{fs.mkdirSync(locations.lock,{mode:0o700})}
  catch(e){if(e.code==='EEXIST')throw Error('health_update_in_progress');throw e}
  const transactionId=randomBytes(16).toString('hex');
  const ctx={...locations,installRoot,record:{schema:1,transactionId,
    previousVersion:previous.version,candidateVersion:version,
    previousManifest:previous.sha256,candidateManifest:candidate.sha256,
    platform,arch,originalPointer,expectedPointer:originalPointer,
    candidateBootstrap:candidate.entries.map(({destination,sha256})=>({destination,sha256})),
    candidatePointer:JSON.stringify({schema:1,version,previous:previous.version,
      manifest_sha256:candidate.sha256,activated_at:new Date().toISOString()},null,2)+'\n'}};
  atomic(path.join(ctx.lock,'owner'),transactionId);syncDirectory(installRoot);
  try{
    save(ctx,'prepared',{restartInhibition:'required_before_switch_and_during_recovery'});verifyStable(ctx,previous,candidate,{previousOnly:true});
    // true must attest both stopped AND durable startup/restart inhibition.
    // Trusted wrappers keep startup inhibited through terminal health; a
    // merely inactive but still enabled service is not safe for this switch.
    assert(await callback(ctx,stopService,'stop_intent',previous.version,timeoutMs),'service_stop_not_confirmed');
    save(ctx,'stopped');pointerOwned(ctx);
    const candidateNow=checked(installRoot,version,publicKeyPem,options,candidate.sha256);
    checked(installRoot,previous.version,publicKeyPem,options,previous.sha256);
    verifyStable(ctx,previous,candidateNow,{previousOnly:true});
    save(ctx,'switch_intent');switchFiles(ctx,candidateNow);atomic(ctx.pointer,ctx.record.candidatePointer);
    save(ctx,'switched',{expectedPointer:ctx.record.candidatePointer});
    const started=await callback(ctx,startService,'start_intent',version,timeoutMs);
    const healthy=started&&await callback(ctx,checkHealth,'health_intent',version,timeoutMs);
    pointerOwned(ctx);
    checked(installRoot,version,publicKeyPem,options,candidate.sha256);
    checked(installRoot,previous.version,publicKeyPem,options,previous.sha256);
    if(healthy){verifyStable(ctx,candidateNow,null,{previousOnly:true});save(ctx,'activated');releaseLock(ctx);return result(ctx)}
    assert(await callback(ctx,stopService,'rollback_stop_intent',version,timeoutMs),'rollback_stop_not_confirmed');
    save(ctx,'rollback_switch_intent');
    const old=checked(installRoot,previous.version,publicKeyPem,options,previous.sha256);
    verifyStable(ctx,old,candidateNow);switchFiles(ctx,old);atomic(ctx.pointer,ctx.record.originalPointer);
    save(ctx,'rollback_switched',{expectedPointer:ctx.record.originalPointer});
    assert(await callback(ctx,startService,'rollback_start_intent',old.version,timeoutMs),'rollback_start_not_confirmed');
    assert(await callback(ctx,checkHealth,'rollback_health_intent',old.version,timeoutMs),'rollback_health_not_confirmed');
    pointerOwned(ctx);checked(installRoot,old.version,publicKeyPem,options,previous.sha256);
    verifyStable(ctx,old,null,{previousOnly:true});save(ctx,'rolled_back');releaseLock(ctx);return result(ctx);
  }catch(error){return failure(ctx,error)}
}

function validateReceipt(record,transactionId){
  const phases=['prepared','stop_intent','stopped','switch_intent','switched',
    'start_intent','health_intent','rollback_stop_intent','rollback_switch_intent',
    'rollback_switched','rollback_start_intent','rollback_health_intent',
    'recovery_observe_intent','recovery_switch_intent',...terminal];
  assert(record&&record.schema===1&&record.transactionId===transactionId&&
    phases.includes(record.phase)&&versionPattern.test(record.previousVersion??'')&&
    versionPattern.test(record.candidateVersion??'')&&record.previousVersion!==record.candidateVersion&&
    /^[a-f0-9]{64}$/.test(record.previousManifest??'')&&
    /^[a-f0-9]{64}$/.test(record.candidateManifest??'')&&
    ['linux','darwin','win32'].includes(record.platform),'invalid_update_receipt');
  let original,candidate;
  try{original=JSON.parse(record.originalPointer);candidate=JSON.parse(record.candidatePointer)}
  catch{throw Error('invalid_update_receipt')}
  assert(original?.schema===1&&original.version===record.previousVersion&&
    original.manifest_sha256===record.previousManifest&&candidate?.schema===1&&
    candidate.version===record.candidateVersion&&candidate.previous===record.previousVersion&&
    candidate.manifest_sha256===record.candidateManifest&&
    [record.originalPointer,record.candidatePointer].includes(record.expectedPointer),
    'invalid_update_receipt');
  const names=['private-storage.mjs','installer.mjs','launch.mjs',record.platform==='win32'?'node.exe':'node'];
  assert(Array.isArray(record.candidateBootstrap)&&record.candidateBootstrap.length===4&&
    names.every(name=>record.candidateBootstrap.filter(entry=>entry.destination===name&&
      /^[a-f0-9]{64}$/.test(entry.sha256??'')).length===1),'invalid_update_receipt');
}

export function inspectServiceUpdate({installRoot,transactionId}={}){
  requirePrivateDirectory(installRoot);
  const records=path.join(installRoot,'update-transactions');requirePrivateDirectory(records);
  const file=receiptFile(records,transactionId);
  requirePrivateFile(file);const record=JSON.parse(fs.readFileSync(file,'utf8'));
  validateReceipt(record,transactionId);
  return record;
}

export async function recoverServiceUpdate({installRoot,publicKeyPem,transactionId,
  confirmStopped,timeoutMs=10000,platform=process.platform,arch=process.arch}={}){
  assert(typeof confirmStopped==='function','trusted_stopped_observer_required');timeout(timeoutMs);
  const locations=roots(installRoot),record=inspectServiceUpdate({installRoot,transactionId});
  assert(!terminal.has(record.phase),'update_already_completed');
  assert(record.platform===platform&&record.arch===arch,'recovery_platform_mismatch');
  const ctx={...locations,installRoot,record};
  if(record.phase==='switch_intent'||record.phase==='rollback_switch_intent'||
      record.phase==='recovery_switch_intent')
    ctx.recoveryPointers=[record.originalPointer,record.candidatePointer];
  ownership(ctx);pointerOwned(ctx);
  ctx.record.expectedPointer=snapshot(ctx.pointer);delete ctx.recoveryPointers;
  const previous=checked(installRoot,record.previousVersion,publicKeyPem,{platform,arch},record.previousManifest);
  // Recovery never replays an uncertain stop/start callback. The operator must
  // independently stop AND durably inhibit startup/restarts, then supply a
  // read-only observer confirming both conditions. Merely inactive is unsafe.
  try{
    assert(await callback(ctx,confirmStopped,'recovery_observe_intent',record.previousVersion,timeoutMs),
      'service_stop_not_confirmed');
    pointerOwned(ctx);
    verifyStable(ctx,previous,{entries:record.candidateBootstrap});
    save(ctx,'recovery_switch_intent');
    switchFiles(ctx,previous);atomic(ctx.pointer,record.originalPointer);
    save(ctx,'recovered_stopped',{expectedPointer:record.originalPointer});releaseLock(ctx);return result(ctx);
  }catch(error){return failure(ctx,error)}
}
