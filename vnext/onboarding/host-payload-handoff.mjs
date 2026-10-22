// A private maintenance ticket joins the native App to an independent updater.
// It authorizes one already registered App payload; it never grants pairing,
// credentials, permissions, a replacement publisher, or arbitrary shell work.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {inspectHostPayloadCandidate,planHostPayloadMigration,applyHostPayloadMigration} from './host-payload-migration.mjs';
import {verifyMacPreviewApp} from '../host/macos-preview-trust.mjs';
import {requirePrivateDirectory,requirePrivateFile,ensurePrivateDirectory,openPrivateFile} from '../host/private-storage.mjs';
import {acquireRecoveryGuard} from './recovery-guard.mjs';
const KIND='host-payload-handoff-v1',FILE='host-payload-handoff.json',TTL=15*60*1000;
const id=x=>/^[a-f0-9]{32}$/.test(x??''),digest=x=>/^[a-f0-9]{64}$/.test(x??''),sha=b=>createHash('sha256').update(b).digest('hex');
const fail=c=>{throw Error(c)},assert=(ok,c)=>{if(!ok)fail(c)},encode=x=>Buffer.from(JSON.stringify(x,null,2)+'\n');
function root(d){assert(typeof d==='string'&&path.isAbsolute(d)&&path.normalize(d)===d,'handoff_absolute_state_required');requirePrivateDirectory(d);return d}
function read(file){const s=requirePrivateFile(file);assert(s.size<=2*1024*1024,'handoff_record_too_large');return JSON.parse(fs.readFileSync(file))}
function syncParent(file){const fd=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
function write(file,value){const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp);try{fs.writeFileSync(fd,encode(value));fs.fsyncSync(fd)}finally{fs.closeSync(fd)}try{fs.renameSync(tmp,file);syncParent(file)}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}}
function ticket(d){const f=path.join(root(d),FILE);if(!fs.existsSync(f))return null;const t=read(f);assert(t.schema===1&&t.kind===KIND&&t.stateDir===d&&id(t.ticketId)&&digest(t.token)&&digest(t.candidateBinding)&&Number.isSafeInteger(t.ownerPid)&&t.ownerPid>0&&Number.isFinite(t.expiresAt),'handoff_invalid_ticket');return t}
function publicTicket(t){return t?{schema:1,ticketId:t.ticketId,status:t.status,...(t.reason?{reason:t.reason}:{}),current:t.candidate.current,target:t.candidate.target,expiresAt:t.expiresAt,...(t.transactionId?{transactionId:t.transactionId}:{}),nativeHealth:t.nativeHealth??'NOT RUN',accountAcceptance:'NOT RUN',...(t.status==='applied_stopped'?{appPath:t.appPath}: {})}:{schema:1,status:'not_started'}}
function admission(t){return{schema:1,kind:KIND,stateDir:t.stateDir,ticketId:t.ticketId,token:t.token,pid:t.ownerPid,candidateBinding:t.candidateBinding}}
function owns(t){const f=path.join(t.stateDir,'advance.lock');assert(JSON.stringify(read(f))===JSON.stringify(admission(t)),'handoff_admission_changed');return f}
function dead(pid){try{process.kill(pid,0);return false}catch(e){return e.code==='ESRCH'}}
function copyTree(source,dest){const s=fs.lstatSync(source);assert(!s.isSymbolicLink(),'handoff_source_redirected');if(s.isDirectory()){fs.mkdirSync(dest,{mode:0o700});for(const n of fs.readdirSync(source).sort())copyTree(path.join(source,n),path.join(dest,n))}else{assert(s.isFile(),'handoff_source_not_regular');const bytes=fs.readFileSync(source);fs.writeFileSync(dest,bytes,{flag:'wx',mode:s.mode&0o111?0o700:0o600});assert(sha(fs.readFileSync(dest))===sha(bytes),'handoff_copy_mismatch')}}
function save(t){write(path.join(t.stateDir,FILE),t)}
export function readHostPayloadHandoff({stateDir}={}){return publicTicket(ticket(stateDir))}
export async function prepareHostPayloadHandoff({stateDir,bundle,authorize=false}={},adapters={}){
 assert(authorize===true,'explicit_handoff_authorization_required');root(stateDir);
 const previous=ticket(stateDir);assert(!previous||['cancelled','applied_stopped'].includes(previous.status),'handoff_requires_recovery');
 const config=read(path.join(stateDir,'deployment.json')),registered=config.host?.macPreviewApp;
 const app=(adapters.verifyApp??verifyMacPreviewApp)(registered),expectedBundle=path.join(app.path,'Contents/Resources/host-bundle');assert(bundle===undefined||bundle===expectedBundle,'handoff_registered_payload_required');
 const inspect=adapters.inspectCandidate??inspectHostPayloadCandidate,candidate=await inspect({stateDir,bundle:expectedBundle});assert(candidate.platform==='darwin'&&digest(candidate.bindingSha256),'handoff_candidate_invalid');
 const now=adapters.now?.()??Date.now(),t={schema:1,kind:KIND,stateDir,ticketId:randomBytes(16).toString('hex'),token:randomBytes(32).toString('hex'),ownerPid:process.pid,candidateBinding:candidate.bindingSha256,candidate,appPath:app.path,createdAt:now,expiresAt:now+TTL,status:'preparing'};
 const lock=path.join(stateDir,'advance.lock');let fd;try{fd=openPrivateFile(lock)}catch{fail('handoff_management_busy')}
 try{fs.writeFileSync(fd,encode(admission(t)));fs.fsyncSync(fd);syncParent(lock);save(t);const next=await inspect({stateDir,bundle:expectedBundle},{handoffAdmission:{ticketId:t.ticketId,token:t.token,ownerPid:t.ownerPid,candidateBinding:t.candidateBinding},allowLivingOwner:true});assert(next.bindingSha256===t.candidateBinding,'handoff_candidate_changed');
  const dir=path.join(stateDir,'host-payload-handoffs');ensurePrivateDirectory(dir);const target=path.join(dir,t.ticketId);ensurePrivateDirectory(target,{exclusive:true});
  const resources=path.join(app.path,'Contents/Resources');
  (adapters.stageUpdater??((destination)=>{copyTree(path.join(app.path,'Contents/MacOS/StyxUpdater'),path.join(destination,'StyxUpdater'));copyTree(path.join(resources,'runtime/node'),path.join(destination,'node'));copyTree(path.join(resources,'onboarding/vnext'),path.join(destination,'vnext'));}))(target);
  (adapters.verifyApp??verifyMacPreviewApp)(registered);owns(t);t.status='awaiting_exit';save(t);return publicTicket(t);
 }catch(error){try{owns(t);t.status='cancelled';t.reason='handoff_preparation_failed';save(t);fs.unlinkSync(lock)}catch{}throw error}finally{fs.closeSync(fd)}
}
export async function executeHostPayloadHandoff({stateDir,ticketId,authorize=false}={},adapters={}){
 assert(authorize===true&&id(ticketId),'explicit_handoff_authorization_required');let t=ticket(stateDir);assert(t?.ticketId===ticketId,'handoff_ticket_changed');
 if(t.status==='applied_stopped')return publicTicket(t);assert(['awaiting_exit','blocked'].includes(t.status),'handoff_requires_recovery');
 owns(t);if(!(adapters.ownerDead??dead)(t.ownerPid))return{...publicTicket(t),status:'waiting_for_exit'};
 assert((adapters.now?.()??Date.now())<=t.expiresAt,'handoff_ticket_expired');
 const guard=acquireRecoveryGuard(path.join(stateDir,'host-payload-handoff-execute.lock'),{kind:KIND,transactionId:t.ticketId});
 try{t=ticket(stateDir);assert(t?.ticketId===ticketId&&['awaiting_exit','blocked'].includes(t.status),'handoff_ticket_changed');owns(t);const handoffAdmission={ticketId:t.ticketId,token:t.token,ownerPid:t.ownerPid,candidateBinding:t.candidateBinding};
  const p=await(adapters.plan??planHostPayloadMigration)({stateDir,bundle:t.candidate.bundle},{handoffAdmission});
  if(p.status!=='offline_reviewable'){t.status='blocked';t.reason=p.reason??'handoff_offline_required';save(t);return publicTicket(t)}
  write(path.join(stateDir,'host-payload-handoffs',t.ticketId,'reviewed-plan.json'),p);
  const result=await(adapters.apply??applyHostPayloadMigration)({stateDir,plan:p,authorize:true},{handoffAdmission});assert(result.status==='applied_stopped','handoff_apply_not_confirmed');
  t.status='applied_stopped';t.transactionId=result.transactionId;delete t.reason;save(t);return publicTicket(t);
 }catch(error){t.status='needs_recovery';t.reason='handoff_execution_requires_review';save(t);throw error}finally{guard.close()}
}
export function cancelHostPayloadHandoff({stateDir,ticketId,authorize=false}={}){
 assert(authorize===true&&id(ticketId),'explicit_handoff_authorization_required');const t=ticket(stateDir);assert(t?.ticketId===ticketId&&['awaiting_exit','blocked'].includes(t.status),'handoff_cancel_not_available');assert(!fs.existsSync(path.join(stateDir,'host-payload-handoff-execute.lock')),'handoff_execution_active');const guard=acquireRecoveryGuard(path.join(stateDir,'host-payload-handoff-execute.lock'),{kind:KIND,transactionId:t.ticketId});try{const current=ticket(stateDir);assert(current?.ticketId===t.ticketId&&['awaiting_exit','blocked'].includes(current.status),'handoff_cancel_not_available');const file=owns(current);current.status='cancelled';save(current);fs.unlinkSync(file);syncParent(file);return publicTicket(current)}finally{guard.close()}
}
