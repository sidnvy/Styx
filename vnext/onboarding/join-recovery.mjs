// Explicit replacement of an uncompleted join attempt, never a network retry.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,randomBytes,X509Certificate} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,ensurePrivateDirectory,openPrivateFile,writePrivateFile} from '../host/private-storage.mjs';
import {validateDeployment} from './deployment-config.mjs';
import {observeHostService} from './service-lifecycle.mjs';
import {acquireRecoveryGuard} from './recovery-guard.mjs';
const kind='uncompleted-join-recovery-v1',sha=b=>createHash('sha256').update(b).digest('hex');
const fail=c=>{throw Error(c)},encode=x=>Buffer.from(JSON.stringify(x,null,2)+'\n');
const exists=f=>{try{fs.lstatSync(f);return true}catch(e){if(e.code==='ENOENT')return false;throw e}};
function bytes(f){if(requirePrivateFile(f).size>2*1024*1024)fail('join_recovery_file_too_large');return fs.readFileSync(f)}
const read=f=>JSON.parse(bytes(f));
function atomic(f,b){const t=f+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(t);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}try{fs.renameSync(t,f);if(process.platform!=='win32'){const d=fs.openSync(path.dirname(f),'r');try{fs.fsyncSync(d)}finally{fs.closeSync(d)}}}finally{if(exists(t))fs.unlinkSync(t)}}
function options(o,allowed){if(!o||o.authorize!==true||Object.keys(o).some(k=>!allowed.includes(k)))fail('join_recovery_explicit_authorization_required')}
function directory(d){if(typeof d!=='string'||!path.isAbsolute(d)||path.normalize(d)!==d)fail('join_recovery_absolute_state_required');requirePrivateDirectory(d)}
const journalFile=d=>path.join(d,'join-recovery.json');
export function assertJoinRecoverySettled(d){if(exists(journalFile(d))&&!['applied','rolled_back'].includes(read(journalFile(d)).status))fail('join_recovery_rollback_required')}
function idle(d,base){
 for(const name of ['background.lock','capabilities.lock','foreground.lock','account-acceptance.lock','onboarding-plugin.lock'])if(exists(path.join(d,name)))fail('join_recovery_management_busy');
 for(const name of ['pending.json','host.token','host.json'])if(exists(path.join(base,'device',name)))fail('join_recovery_existing_enrollment_refused');
 for(const name of ['.health-update-lock','.health-operation-lock','.health-recovery-guard'])if(exists(path.join(base,'install',name)))fail('join_recovery_runtime_busy');
}
async function stopped(base,operations){const r=await (operations.observeHostService??observeHostService)({serviceConfigFile:path.join(base,'service.json')});if(r.status!=='reported'||!['not_installed','stopped'].includes(r.state))fail('join_recovery_service_not_quiescent');return r}
function scope(d){
 directory(d);const config=read(path.join(d,'deployment.json')),state=read(path.join(d,'state.json'));validateDeployment(config,{checkNetwork:false});
 if(config.mode!=='join-existing'||!config.host||state.mode!==config.mode||state.schema!==1||state.configSha256!==sha(bytes(path.join(d,'deployment.json'))))fail('join_recovery_scope_invalid');
 const expected=['host.prepare','host.request','host.claim','host.doctor','host.service.install','host.service.start','host.service.status'];
 if(!Array.isArray(state.steps)||state.steps.length!==expected.length||state.steps.some((s,i)=>s.id!==expected[i])||state.steps[0].status!=='succeeded'||!['uncertain','blocked'].includes(state.steps[1].status)||state.steps.slice(2).some(s=>s.status!=='pending')||(state.maintenance??[]).length||(state.gatewayMaintenance??[]).length)fail('join_recovery_not_uncompleted_request');
 const base=config.host.baseDir;requirePrivateDirectory(base);idle(d,base);
 for(const name of ['background.json','capabilities.json','account-acceptance.json'])if(exists(path.join(d,name)))fail('join_recovery_auxiliary_state_requires_reconciliation');
 const enrollment=read(path.join(base,'enrollment.json'));
 if(enrollment.gateway_url!==config.gateway.url||enrollment.storage_dir!==path.join(base,'device'))fail('join_recovery_enrollment_binding_changed');
 const id=read(path.join(base,'device/identity.json')),key=bytes(path.join(base,'device/identity.pem'));
 if(!/^styx-[a-f0-9]{24}$/.test(id.device_id)||id.fingerprint!==sha(createPublicKey(key).export({type:'spki',format:'der'})))fail('join_recovery_identity_invalid');
 for(const e of Object.values(state.steps[0].evidence??{}))if(e&&typeof e==='object'&&e.path&&e.sha256&&sha(bytes(e.path))!==e.sha256)fail('join_recovery_preparation_evidence_changed');
 const bindings=[path.join(d,'deployment.json'),path.join(d,'state.json'),...['enrollment.json','device/identity.json','device/identity.pem','service.json','setup-receipt.json','setup-state.json','publisher.pem','install/active.json'].map(n=>path.join(base,n))].map(file=>({path:file,sha256:sha(bytes(file))}));
 return {config,state,base,enrollment,id,bindings};
}
function material(file){
 const p=read(file);if(p.schema!==1||!Number.isSafeInteger(p.expiresAt)||p.expiresAt<=Date.now()||p.expiresAt>Date.now()+600000)fail('join_recovery_invitation_expired');
 const u=new URL(p.gatewayOrigin);if(u.protocol!=='https:'||u.origin!==p.gatewayOrigin||u.username||u.password)fail('join_recovery_origin_invalid');
 const invitation=bytes(p.invitationFile);if(!/^[A-Za-z0-9_-]{43}$/.test(invitation.toString().trim()))fail('join_recovery_invitation_invalid');
 let ca;if(p.gatewayCaFile){ca=bytes(p.gatewayCaFile);const c=new X509Certificate(ca);if(sha(c.raw)!==p.caSha256||Date.parse(c.validTo)<=Date.now()||Date.parse(c.validFrom)>Date.now())fail('join_recovery_ca_binding_changed')}else if(p.caSha256)fail('join_recovery_ca_binding_changed');
 return {p,invitation,ca};
}
function unchanged(j){for(const f of j.preserved)if(sha(bytes(f.path))!==f.sha256)fail('join_recovery_preserved_state_changed')}
function result(j,status){return {schema:1,status,transactionId:j.transactionId,nextStep:status==='recovered'?'host.request':null,previousRequestOutcome:'unknown',identityMutation:'NONE',serviceMutation:'NONE'}}
// Before journal publication this transaction cannot have changed authoritative
// files. Reclaim only its proven-dead guard, after rechecking the whole scope;
// leave any orphan private material as evidence. Never adopt another operation.
async function recoverPreJournalGuard(d,operations){
 const file=path.join(d,'advance.lock');if(!exists(file))return;
 const original=bytes(file),owner=JSON.parse(original);
 if(owner.kind!==kind||! /^[a-f0-9]{32}$/.test(owner.transactionId??''))fail('join_recovery_foreign_guard');
 if(exists(journalFile(d))&&read(journalFile(d)).transactionId===owner.transactionId)fail('join_recovery_rollback_required');
 const s=scope(d);await stopped(s.base,operations);scope(d);unchanged({preserved:s.bindings});
 if(!bytes(file).equals(original))fail('join_recovery_guard_changed');
 const guard=acquireRecoveryGuard(file,{kind,transactionId:owner.transactionId});
 guard.close();
}
export async function recoverDeploymentJoin(d,o={},operations={}){
 options(o,['authorize','pairingFile']);directory(d);assertJoinRecoverySettled(d);await recoverPreJournalGuard(d,operations);
 const transactionId=randomBytes(16).toString('hex'),guard=acquireRecoveryGuard(path.join(d,'advance.lock'),{kind,transactionId});let j;
 try{
  const s=scope(d),m=material(o.pairingFile),service=await stopped(s.base,operations);scope(d);unchanged({preserved:s.bindings});guard.assertOwned();if(m.p.expiresAt<=Date.now())fail('join_recovery_invitation_expired');
  const oldInvitation=bytes(s.config.invitationFile).toString().trim();if(oldInvitation===m.invitation.toString().trim())fail('join_recovery_new_invitation_required');
  const root=path.join(d,'join-recovery-history');ensurePrivateDirectory(root);const dir=path.join(root,transactionId);ensurePrivateDirectory(dir,{exclusive:true});
  // Material is copied into this transaction, so a later accepted invitation
  // cannot mutate the active attempt. Previous secret material is retained.
  const invitationFile=path.join(dir,'invitation');writePrivateFile(invitationFile,m.invitation);
  const caFile=m.ca?path.join(dir,'gateway-ca.pem'):null;if(caFile)writePrivateFile(caFile,m.ca);
  const config={...s.config,gateway:{url:m.p.gatewayOrigin,...(caFile?{caFile}:{})},invitationFile};validateDeployment(config,{checkNetwork:false});
  const enrollment={...s.enrollment,gateway_url:m.p.gatewayOrigin};delete enrollment.gateway_ca_file;if(caFile)enrollment.gateway_ca_file=caFile;
  const state=structuredClone(s.state),changes=[];
  const add=(file,after)=>changes.push({path:file,before:bytes(file).toString('base64'),after:after.toString('base64')});
  add(path.join(s.base,'enrollment.json'),encode(enrollment));add(path.join(d,'deployment.json'),encode(config));
  state.joinAttempts=[...(state.joinAttempts??[]),{at:new Date().toISOString(),transactionId,origin:s.config.gateway.url,request:state.steps[1],remoteOutcome:'unknown',reason:'explicit_new_invitation_accepted'}];
  state.steps[1]={id:'host.request',status:'pending'};state.configSha256=sha(encode(config));
  if(state.onboardingDecisions?.background){if(state.onboardingDecisions.background.configSha256!==s.state.configSha256)fail('join_recovery_preference_binding_changed');state.onboardingDecisions.background.configSha256=state.configSha256;}
  state.steps[0].evidence={...state.steps[0].evidence,enrollmentConfiguration:{path:path.join(s.base,'enrollment.json'),sha256:sha(encode(enrollment))}};
  add(path.join(d,'state.json'),encode(state));
  const preserved=['device/identity.json','device/identity.pem','service.json','setup-receipt.json','setup-state.json','publisher.pem','install/active.json'].map(name=>({path:path.join(s.base,name),sha256:sha(bytes(path.join(s.base,name)))}));
  j={schema:1,kind,transactionId,status:'prepared',base:s.base,changes,preserved,serviceObservation:service,previousRequestOutcome:'unknown',phases:[]};
  writePrivateFile(path.join(dir,'journal.json'),encode(j));atomic(journalFile(d),encode(j));
  for(let i=0;i<changes.length;i++){unchanged(j);idle(d,s.base);guard.assertOwned();j.status='writing';j.phases.push({index:i,at:new Date().toISOString()});atomic(journalFile(d),encode(j));operations.beforeWrite?.(i);atomic(changes[i].path,Buffer.from(changes[i].after,'base64'))}
  unchanged(j);j.status='applied';atomic(journalFile(d),encode(j));atomic(path.join(dir,'journal.json'),encode(j));return result(j,'recovered');
 }catch(e){if(j){try{restore(d,j);j.status='rolled_back';atomic(journalFile(d),encode(j));atomic(path.join(d,'join-recovery-history',transactionId,'journal.json'),encode(j))}catch{throw Error('join_recovery_rollback_required')}}throw e}finally{guard.close()}
}
function restore(d,j){
 unchanged(j);idle(d,j.base);
 for(const f of j.changes){const b=bytes(f.path);if(!b.equals(Buffer.from(f.before,'base64'))&&!b.equals(Buffer.from(f.after,'base64')))fail('join_recovery_changed_since_transaction')}
 j.status='rolling_back';atomic(journalFile(d),encode(j));for(const f of [...j.changes].reverse())atomic(f.path,Buffer.from(f.before,'base64'));
}
export async function rollbackDeploymentJoin(d,o={},operations={}){
 options(o,['authorize','transactionId']);directory(d);const j=read(journalFile(d));
 if(j.kind!==kind||j.schema!==1||j.transactionId!==o.transactionId||!/^[a-f0-9]{32}$/.test(j.transactionId)||!['prepared','writing','applied','rolling_back','rolled_back'].includes(j.status)||!Array.isArray(j.changes)||j.changes.length!==3||!Array.isArray(j.preserved))fail('join_recovery_transaction_mismatch');
 const original=JSON.parse(Buffer.from(j.changes[1].before,'base64'));validateDeployment(original,{checkNetwork:false});if(original.mode!=='join-existing'||original.host?.baseDir!==j.base||j.changes.some((f,i)=>f.path!==[path.join(j.base,'enrollment.json'),path.join(d,'deployment.json'),path.join(d,'state.json')][i]))fail('join_recovery_transaction_mismatch');
 const guard=acquireRecoveryGuard(path.join(d,'advance.lock'),{kind,transactionId:j.transactionId});
 try{await stopped(j.base,operations);restore(d,j);j.status='rolled_back';atomic(journalFile(d),encode(j));atomic(path.join(d,'join-recovery-history',j.transactionId,'journal.json'),encode(j));return result(j,'rolled_back')}finally{guard.close()}
}

export async function readDeploymentJoinRecovery(d,operations={}){
 try{
  directory(d);
  if(exists(journalFile(d))){const j=read(journalFile(d));if(!['applied','rolled_back'].includes(j.status))return {schema:1,canRecover:false,reason:'join_recovery_rollback_required',transactionId:j.transactionId,rollbackRequired:true};}
  const s=scope(d);await stopped(s.base,operations);
  return {schema:1,canRecover:true,reason:'new_invitation_requires_explicit_acceptance',previousRequestOutcome:'unknown',rollbackRequired:false};
 }catch(error){return {schema:1,canRecover:false,reason:/^join_recovery_[a-z_]+$/.test(error.message)?error.message:'join_recovery_unavailable',rollbackRequired:false}}
}
