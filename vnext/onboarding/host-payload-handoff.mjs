// One private maintenance ticket joins a native App to an independent updater.
// The existing migration owns configuration, trust, native absence and rollback.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {inspectHostPayloadCandidate,planHostPayloadMigration,applyHostPayloadMigration} from './host-payload-migration.mjs';
import {verifyMacPreviewApp} from '../host/macos-preview-trust.mjs';
import {requirePrivateDirectory,requirePrivateFile,requirePrivatePaths,ensurePrivateDirectory,openPrivateFile,configureWindowsAclHelper} from '../host/private-storage.mjs';
import {acquireRecoveryGuard} from './recovery-guard.mjs';
const KIND='host-payload-handoff-v1',FILE='host-payload-handoff.json',PREPARE='host-payload-handoff-prepare.lock',EXECUTE='host-payload-handoff-execute.lock',TTL=15*60*1000;
const id=x=>/^[a-f0-9]{32}$/.test(x??''),digest=x=>/^[a-f0-9]{64}$/.test(x??''),sha=b=>createHash('sha256').update(b).digest('hex');
const fail=c=>{throw Error(c)},assert=(ok,c)=>{if(!ok)fail(c)},encode=x=>Buffer.from(JSON.stringify(x,null,2)+'\n');
function root(d){assert(typeof d==='string'&&path.isAbsolute(d)&&path.normalize(d)===d,'handoff_absolute_state_required');requirePrivateDirectory(d);return d}
function read(file,max=2*1024*1024){const s=requirePrivateFile(file);assert(s.size<=max,'handoff_record_too_large');return JSON.parse(fs.readFileSync(file))}
function syncParent(file){if(process.platform==='win32')return;const fd=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
function write(file,value){const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp);try{fs.writeFileSync(fd,encode(value));fs.fsyncSync(fd)}finally{fs.closeSync(fd)}try{fs.renameSync(tmp,file);syncParent(file)}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}}
function ticket(d){const f=path.join(root(d),FILE);if(!fs.existsSync(f))return null;const t=read(f);assert(t.schema===1&&t.kind===KIND&&t.stateDir===d&&id(t.ticketId)&&digest(t.token)&&Number.isSafeInteger(t.ownerPid)&&t.ownerPid>0&&Number.isFinite(t.expiresAt),'handoff_invalid_ticket');if(t.preparationOnly===true){assert(['preparing','cancelled'].includes(t.status)&&t.candidate===undefined&&t.candidateBinding===undefined&&t.appPath===undefined,'handoff_invalid_preparation');}else{assert(t.preparationOnly===undefined&&digest(t.candidateBinding)&&t.candidate&&typeof t.candidate==='object','handoff_invalid_ticket');}return t}
function orphan(d){const f=path.join(d,PREPARE);if(!fs.existsSync(f))return null;const r=read(f);assert(r.kind===KIND&&id(r.transactionId),'handoff_unknown_preparation');return{schema:1,ticketId:r.transactionId,status:'preparing',reason:'handoff_preparation_interrupted',nativeHealth:'NOT RUN',accountAcceptance:'NOT RUN'}}
function publicTicket(t){return t?{schema:1,ticketId:t.ticketId,status:t.status,...(t.reason?{reason:t.reason}:{}),...(t.preparationOnly?{}:{current:t.candidate.current,target:t.candidate.target}),expiresAt:t.expiresAt,...(t.transactionId?{transactionId:t.transactionId}:{}),nativeHealth:'NOT RUN',accountAcceptance:'NOT RUN',...(t.status==='applied_stopped'?{appPath:t.appPath}: {})}:{schema:1,status:'not_started'}}
function admission(t){return{schema:1,kind:KIND,stateDir:t.stateDir,ticketId:t.ticketId,token:t.token,pid:t.ownerPid,candidateBinding:t.candidateBinding}}
function owns(t){const f=path.join(t.stateDir,'advance.lock');let observed;try{observed=read(f)}catch{fail('handoff_admission_changed')}assert(JSON.stringify(observed)===JSON.stringify(admission(t)),'handoff_admission_changed');return f}
function dead(pid){try{process.kill(pid,0);return false}catch(e){return e.code==='ESRCH'}}
function save(t){write(path.join(t.stateDir,FILE),t)}
function runtimeDirectory(t){return path.join(path.dirname(t.stateDir),'host-payload-updaters',sha(t.stateDir).slice(0,16),t.ticketId)}
function inventory(source,relative,files){const s=fs.lstatSync(source);assert(!s.isSymbolicLink(),'handoff_source_redirected');if(s.isDirectory()){for(const n of fs.readdirSync(source).sort())inventory(path.join(source,n),path.posix.join(relative,n),files)}else{assert(s.isFile(),'handoff_source_not_regular');files.push({source,relative,executable:!!(s.mode&0o111)})}}
async function resolveApp({stateDir,config}){
 if(process.platform==='win32')return(await import('../host/windows/host-payload-handoff.mjs')).resolveWindowsHostPayloadHandoffApp({stateDir,config});
 assert(process.platform==='darwin','handoff_native_app_platform_required');const app=verifyMacPreviewApp(config.host?.macPreviewApp),resources=path.join(app.path,'Contents/Resources'),files=[];
 inventory(path.join(app.path,'Contents/MacOS/StyxUpdater'),'StyxUpdater',files);inventory(path.join(resources,'runtime/node'),'node',files);inventory(path.join(resources,'onboarding/vnext'),'vnext',files);
 return{appPath:app.path,bundle:path.join(resources,'host-bundle'),identity:app,files};
}
function safeFiles(app){assert(path.isAbsolute(app.appPath)&&path.isAbsolute(app.bundle)&&Array.isArray(app.files)&&app.files.length>0&&app.files.length<=12000,'handoff_updater_sources_invalid');const names=new Set();for(const f of app.files){assert(path.isAbsolute(f.source)&&typeof f.relative==='string'&&!path.posix.isAbsolute(f.relative)&&!f.relative.includes('\\')&&f.relative.split('/').every(p=>p&&p!=='.'&&p!=='..')&&!names.has(f.relative),'handoff_updater_source_invalid');names.add(f.relative)}return app}
function stage(t,app){const parent=path.dirname(t.stateDir);requirePrivateDirectory(parent);const updates=path.join(parent,'host-payload-updaters');ensurePrivateDirectory(updates);const dir=path.join(updates,sha(t.stateDir).slice(0,16));ensurePrivateDirectory(dir);const destination=runtimeDirectory(t);ensurePrivateDirectory(destination,{exclusive:true});let total=0;const files=[];
 for(const f of app.files){const s=fs.lstatSync(f.source);assert(s.isFile()&&!s.isSymbolicLink(),'handoff_source_redirected');total+=s.size;assert(s.size<=256*1024*1024&&total<=2*1024*1024*1024,'handoff_source_size_invalid');const bytes=fs.readFileSync(f.source),target=path.join(destination,...f.relative.split('/'));fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});fs.writeFileSync(target,bytes,{flag:'wx',mode:f.executable?0o700:0o600});files.push({...f,sha256:sha(bytes)})}
 write(path.join(destination,'input.json'),{stateDir:t.stateDir,ticketId:t.ticketId,appPath:t.appPath});return files;
}
function checkFiles(t,files,{source=false}={}){for(let index=0;index<files.length;index+=32){const batch=files.slice(index,index+32),paths=batch.map(f=>({path:path.join(runtimeDirectory(t),...f.relative.split('/')),kind:'file'}));requirePrivatePaths(paths);for(let i=0;i<batch.length;i++){const f=batch[i],target=paths[i].path;assert(sha(fs.readFileSync(target))===f.sha256,'handoff_runtime_changed');if(source){const s=fs.lstatSync(f.source);assert(s.isFile()&&!s.isSymbolicLink()&&sha(fs.readFileSync(f.source))===f.sha256,'handoff_source_changed')}}}}

function verifyRuntime(t){
 const f=path.join(runtimeDirectory(t),'runtime-manifest.json');requirePrivateFile(f);
 assert(digest(t.runtimeManifestSha256)&&sha(fs.readFileSync(f))===t.runtimeManifestSha256,'handoff_runtime_manifest_changed');
 const files=read(f,8*1024*1024);
 // The independent Host transaction uses the same read-only native adapter.
 // Bootstrap trust with the existing private-file check and ticket-bound
 // manifest before selecting it; never take an executable from environment.
 const helper=process.platform==='win32'?files.find(item=>item.relative==='StyxPrivateStorage.exe'):null;
 if(helper){const file=path.join(runtimeDirectory(t),'StyxPrivateStorage.exe');requirePrivateFile(file);configureWindowsAclHelper(file,helper.sha256);}
 checkFiles(t,files);
}
function applied(t){const file=path.join(t.stateDir,'host-payload-migration.json');if(!fs.existsSync(file))return null;const j=read(file);if(j.plan?.handoffTicketId!==t.ticketId)return null;const {planId,...body}=j.plan;assert(j.schema===1&&j.kind==='host-payload-migration-v1'&&id(j.transactionId)&&j.plan.stateDir===t.stateDir&&sha(JSON.stringify(body))===planId,'handoff_migration_binding_invalid');assert(JSON.stringify(j.plan.current)===JSON.stringify(t.candidate.current)&&JSON.stringify(j.plan.target)===JSON.stringify(t.candidate.target),'handoff_migration_target_changed');if(!['applied','rolled_back'].includes(j.status))return null;for(const f of j.plan.changes)assert(sha(fs.readFileSync(f.path))===(j.status==='applied'?f.afterSha256:f.beforeSha256),'handoff_applied_files_changed');for(const f of j.plan.preserved)assert(sha(fs.readFileSync(f.path))===f.sha256,'handoff_preserved_files_changed');return{transactionId:j.transactionId,status:j.status==='applied'?'applied_stopped':'rolled_back'}}
function rolledBack(t){if(!t||t.preparationOnly)return null;const file=path.join(t.stateDir,'host-payload-migration.json');return fs.existsSync(file)&&read(file).status==='rolled_back'?applied(t):null}
export function readHostPayloadHandoff({stateDir}={}){const t=ticket(stateDir);const recovered=rolledBack(t);return t?publicTicket(recovered?{...t,...recovered}:t):orphan(stateDir)??publicTicket(null)}
export async function prepareHostPayloadHandoff({stateDir,bundle,authorize=false}={},adapters={}){
 assert(authorize===true,'explicit_handoff_authorization_required');root(stateDir);const previous=ticket(stateDir);const priorStatus=rolledBack(previous)?.status??previous?.status;assert(!previous||['cancelled','applied_stopped','rolled_back'].includes(priorStatus),'handoff_requires_recovery');assert(!fs.existsSync(path.join(stateDir,PREPARE)),'handoff_preparation_requires_recovery');
 // Persist preparation before resolving the App or checking its payload. Those
 // checks can fail too; the same journal must stop automatic replay on reopen.
 const now=adapters.now?.()??Date.now(),t={schema:1,kind:KIND,stateDir,ticketId:randomBytes(16).toString('hex'),token:randomBytes(32).toString('hex'),ownerPid:process.pid,createdAt:now,expiresAt:now+TTL,status:'preparing',preparationOnly:true};
 const guard=acquireRecoveryGuard(path.join(stateDir,PREPARE),{kind:KIND,transactionId:t.ticketId});let fd,hasAdmission=false,recorded=false;const lock=path.join(stateDir,'advance.lock');
 try{const latest=ticket(stateDir),latestStatus=rolledBack(latest)?.status??latest?.status;assert(!latest||['cancelled','applied_stopped','rolled_back'].includes(latestStatus),'handoff_requires_recovery');save(t);recorded=true;adapters.onPhase?.('preparation_recorded',t);
  const config=read(path.join(stateDir,'deployment.json')),resolve=adapters.resolveApp??resolveApp,app=safeFiles(await resolve({stateDir,config}));assert(bundle===undefined||bundle===app.bundle,'handoff_registered_payload_required');
  const inspect=adapters.inspectCandidate??inspectHostPayloadCandidate,candidate=await inspect({stateDir,bundle:app.bundle});assert(['darwin','win32'].includes(candidate.platform)&&digest(candidate.bindingSha256),'handoff_candidate_invalid');
  Object.assign(t,{candidateBinding:candidate.bindingSha256,candidate,appPath:app.appPath});delete t.preparationOnly;save(t);adapters.onPhase?.('ticket_prepared',t);try{fd=openPrivateFile(lock)}catch{fail('handoff_management_busy')}fs.writeFileSync(fd,encode(admission(t)));fs.fsyncSync(fd);syncParent(lock);hasAdmission=true;adapters.onPhase?.('admitted',t);
  const next=await inspect({stateDir,bundle:app.bundle});assert(next.bindingSha256===t.candidateBinding,'handoff_candidate_changed');const files=stage(t,app);adapters.onPhase?.('copied',t);
  const verified=safeFiles(await resolve({stateDir,config}));assert(JSON.stringify(verified)===JSON.stringify(app),'handoff_app_changed');checkFiles(t,files,{source:true});const manifest=path.join(runtimeDirectory(t),'runtime-manifest.json');write(manifest,files);t.runtimeManifestSha256=sha(fs.readFileSync(manifest));owns(t);t.status='awaiting_exit';save(t);return publicTicket(t);
 }catch(error){try{if(hasAdmission){owns(t);fs.unlinkSync(lock);syncParent(lock)}if(recorded){t.status='cancelled';t.reason='handoff_preparation_failed';save(t)}}catch{}throw error}finally{if(fd!==undefined)fs.closeSync(fd);guard.close()}
}
export async function executeHostPayloadHandoff({stateDir,ticketId,authorize=false}={},adapters={}){
 assert(authorize===true&&id(ticketId),'explicit_handoff_authorization_required');let t=ticket(stateDir);assert(t?.ticketId===ticketId,'handoff_ticket_changed');if(['applied_stopped','rolled_back'].includes(t.status))return publicTicket(t);assert(['awaiting_exit','blocked','needs_recovery'].includes(t.status),'handoff_requires_recovery');if(!(adapters.ownerDead??dead)(t.ownerPid))return{...publicTicket(t),status:'waiting_for_exit'};
 const guard=acquireRecoveryGuard(path.join(stateDir,EXECUTE),{kind:KIND,transactionId:t.ticketId});
 try{t=ticket(stateDir);assert(t?.ticketId===ticketId&&['awaiting_exit','blocked','needs_recovery'].includes(t.status),'handoff_ticket_changed');const recovered=applied(t);if(recovered){t.status=recovered.status;t.transactionId=recovered.transactionId;delete t.reason;save(t);return publicTicket(t)}
  owns(t);assert((adapters.now?.()??Date.now())<=t.expiresAt,'handoff_ticket_expired');verifyRuntime(t);const handoffAdmission={ticketId:t.ticketId,token:t.token,ownerPid:t.ownerPid,candidateBinding:t.candidateBinding};
  const p=await(adapters.plan??planHostPayloadMigration)({stateDir,bundle:t.candidate.bundle},{handoffAdmission});if(p.status!=='offline_reviewable'){t.status='blocked';t.reason=p.reason??'handoff_offline_required';save(t);return publicTicket(t)}write(path.join(runtimeDirectory(t),'reviewed-plan.json'),p);
  const result=await(adapters.apply??applyHostPayloadMigration)({stateDir,plan:p,authorize:true},{handoffAdmission});assert(result.status==='applied_stopped','handoff_apply_not_confirmed');adapters.onPhase?.('applied_before_ticket',t);t.status='applied_stopped';t.transactionId=result.transactionId;delete t.reason;save(t);return publicTicket(t);
 }catch(error){t.status='needs_recovery';t.reason='handoff_execution_requires_review';save(t);throw error}finally{guard.close()}
}
export function cancelHostPayloadHandoff({stateDir,ticketId,authorize=false}={}){
 assert(authorize===true&&id(ticketId),'explicit_handoff_authorization_required');let t=ticket(stateDir);if(!t){assert(orphan(stateDir)?.ticketId===ticketId,'handoff_ticket_changed');const guard=acquireRecoveryGuard(path.join(stateDir,PREPARE),{kind:KIND,transactionId:ticketId});guard.close();return{schema:1,ticketId,status:'cancelled'}}
 assert(t.ticketId===ticketId&&['preparing','awaiting_exit','blocked','needs_recovery'].includes(t.status),'handoff_cancel_not_available');assert(t.ownerPid===process.pid||dead(t.ownerPid),'handoff_owner_still_alive');
 const execute=acquireRecoveryGuard(path.join(stateDir,EXECUTE),{kind:KIND,transactionId:t.ticketId});let prepare;
 try{if(fs.existsSync(path.join(stateDir,PREPARE)))prepare=acquireRecoveryGuard(path.join(stateDir,PREPARE),{kind:KIND,transactionId:t.ticketId});t=ticket(stateDir);assert(t?.ticketId===ticketId&&['preparing','awaiting_exit','blocked','needs_recovery'].includes(t.status),'handoff_cancel_not_available');const lock=path.join(stateDir,'advance.lock');if(!t.preparationOnly){if(fs.existsSync(lock))owns(t);else assert(t.status==='preparing','handoff_admission_changed');}t.status='cancelled';save(t);if(!t.preparationOnly&&fs.existsSync(lock)){fs.unlinkSync(lock);syncParent(lock)}return publicTicket(t)}finally{prepare?.close();execute.close()}
}
