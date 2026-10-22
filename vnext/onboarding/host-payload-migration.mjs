// Explicit offline Host payload migration. No process start, credential change,
// permission grant or automatic publisher adoption is performed here.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,randomBytes} from 'node:crypto';
import {validateDeployment} from './deployment-config.mjs';
import {verifySignedRelease,stageSignedRelease,activeRelease} from '../host/installer.mjs';
import {assertMacPreviewContinuity,verifyMacPreviewApp} from '../host/macos-preview-trust.mjs';
import {requirePrivateDirectory,requirePrivateFile,ensurePrivateDirectory,openPrivateFile} from '../host/private-storage.mjs';
import {acquireRecoveryGuard} from './recovery-guard.mjs';
const KIND='host-payload-migration-v1',JOURNAL='host-payload-migration.json',RECOVERY='host-payload-migration-recovery.lock';
const LOCKS=['advance.lock','background.lock','capabilities.lock','onboarding-plugin.lock','account-acceptance.lock'];
const BOOTSTRAP=['private-storage.mjs','installer.mjs','launch.mjs','node'];
const abandoned=new Set(),sha=x=>createHash('sha256').update(x).digest('hex'),encode=x=>Buffer.from(JSON.stringify(x,null,2)+'\n');
const fail=code=>{throw Error(code)},assert=(ok,code)=>{if(!ok)fail(code)};
const absolute=x=>typeof x==='string'&&path.isAbsolute(x)&&path.normalize(x)===x;
const id=x=>/^[a-f0-9]{32}$/.test(x??''),digest=x=>/^[a-f0-9]{64}$/.test(x??'');
function bytes(file,large=false){assert(requirePrivateFile(file).size<=(large?256*1024*1024:2*1024*1024),'host_payload_file_too_large');return fs.readFileSync(file)}
const read=file=>JSON.parse(bytes(file));
function sync(dir){if(process.platform==='win32')return;const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
function atomic(file,data,mode=0o600){const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp,mode);try{fs.writeFileSync(fd,data);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}try{fs.renameSync(tmp,file);sync(path.dirname(file))}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}}
function journal(d){
 const file=path.join(d,JOURNAL);let j=fs.existsSync(file)?read(file):null;
 if(j)assert(j.schema===1&&j.kind===KIND&&id(j.transactionId)&&j.plan?.stateDir===d&&['capturing','prepared','writing','applied','rolling_back','rolled_back','uncertain'].includes(j.status),'host_payload_invalid_journal');
 // A complete review-bound admission record is written to advance.lock before
 // staging or snapshot I/O. Recover it even when an earlier terminal journal
 // exists, so a process exit before the first journal write remains recoverable.
 const lock=path.join(d,'advance.lock');if(fs.existsSync(lock)){
  const r=read(lock);if(r.kind===KIND&&r.plan&&r.transactionId!==j?.transactionId){
   assert(!j||['applied','rolled_back'].includes(j.status),'host_payload_foreign_transaction');
   const {planId,...body}=r.plan;assert(id(r.transactionId)&&r.plan.stateDir===d&&digest(planId)&&sha(JSON.stringify(body))===planId,'host_payload_invalid_admission');
   const {plan,...owner}=r;j={schema:1,kind:KIND,transactionId:r.transactionId,plan,owner,files:plan.changes,preserved:plan.preserved,status:'capturing',captureComplete:false};
  }
 }
 return j;
}
function publicJournal(j){return j?{schema:1,transactionId:j.transactionId,status:j.status,current:j.plan.current,target:j.plan.target,nativeHealth:'NOT RUN',accountAcceptance:'NOT RUN',serviceMutation:'NONE',identityMutation:'NONE',systemPermissions:'UNCHANGED'}:{schema:1,status:'not_started'}}
export function readHostPayloadMigration({stateDir}={}){assert(absolute(stateDir),'absolute_state_directory_required');requirePrivateDirectory(stateDir);return publicJournal(journal(stateDir))}
function pin(pem){const key=createPublicKey(pem);assert(key.asymmetricKeyType==='ed25519','host_payload_ed25519_publisher_required');return sha(key.export({type:'spki',format:'der'}))}
function inventory(dir,files){if(!fs.existsSync(dir))return;requirePrivateDirectory(dir);for(const name of fs.readdirSync(dir).sort()){const file=path.join(dir,name),s=fs.lstatSync(file);assert(!s.isSymbolicLink(),'host_payload_preserved_path_redirected');if(s.isDirectory())inventory(file,files);else files.push({path:file,sha256:sha(bytes(file))});assert(files.length<=512,'host_payload_preserved_inventory_too_large')}}
function complete(release,host){
 const required=['host/private-storage.mjs','host/installer.mjs','host/launch.mjs','host/connect.mjs','host/enroll.mjs','host/setup-native.mjs','host/doctor.mjs','host/macos-launchagent.mjs','host/macos-native-launcher.mjs','bin/node','bin/codex','bin/cua-driver'];
 if(host.browser?.enabled)required.push('host/browser.mjs','packages/styx-browser-provider/host.mjs','packages/styx-browser-provider/config.mjs','packages/styx-browser-provider/prepare.mjs','packages/styx-browser-provider/contract.mjs','packages/styx-browser-provider/playwright-contract-0.0.83.json','packages/styx-browser-provider/node_modules/@playwright/mcp/package.json',...(host.browser.channel||host.browser.persistLogin?['packages/styx-browser-provider/installed.mjs','packages/styx-browser-provider/login-state.mjs']:[]));
 assert(required.every(name=>release.manifest.files.some(f=>f.path===name&&(!name.startsWith('bin/')||f.executable))),'host_payload_complete_signed_release_required');
}
function roots(d,base){return {deployment:path.join(d,'deployment.json'),service:path.join(base,'service.json'),receipt:path.join(base,'setup-receipt.json'),publisher:path.join(base,'publisher.pem'),pointer:path.join(base,'install/active.json'),...Object.fromEntries(BOOTSTRAP.map(n=>['bootstrap_'+n,path.join(base,'install',n)])),background:path.join(d,'background.json'),capabilities:path.join(d,'capabilities.json'),state:path.join(d,'state.json')}}
function snapshot(d){
 assert(absolute(d),'absolute_state_directory_required');requirePrivateDirectory(d);
 const config=read(path.join(d,'deployment.json')),state=read(path.join(d,'state.json'));validateDeployment(config,{checkNetwork:false});
 assert(state.schema===1&&state.mode===config.mode&&state.configSha256===sha(bytes(path.join(d,'deployment.json')))&&Array.isArray(state.steps),'host_payload_deployment_binding_changed');
 assert(config.host&&state.steps.some(s=>s.id==='host.prepare'&&s.status==='succeeded'),'host_payload_prepared_host_required');
 assert(!state.steps.some(s=>['running','uncertain'].includes(s.status))&&![...(state.maintenance??[]),...(state.gatewayMaintenance??[])].some(s=>['running','uncertain'].includes(s.status)),'host_payload_uncertain_deployment');
 const base=config.host.baseDir,root=path.join(base,'install');requirePrivateDirectory(base);requirePrivateDirectory(root);
 const names=roots(d,base),service=read(names.service),host=read(path.join(base,'device/host.json')),identity=read(path.join(base,'device/identity.json'));
 assert(service.installRoot===root&&service.hostConfigFile===path.join(base,'device/host.json')&&service.trustPublicKeyFile===names.publisher&&absolute(service.nodeBinary)&&service.nodeBinary.startsWith(root+path.sep)&&/^app\.styx\.[a-z0-9.-]+$/.test(service.label??''),'host_payload_service_binding_changed');
 const expectedGateway=new URL(config.gateway.url);expectedGateway.protocol='wss:';
 assert(host.host_id===identity.device_id&&new URL(host.gateway_ws_url).href===expectedGateway.href&&host.token_file===path.join(base,'device/host.token'),'host_payload_identity_binding_changed');
 assert(sha(createPublicKey(bytes(path.join(base,'device/identity.pem'))).export({type:'spki',format:'der'}))===identity.fingerprint,'host_payload_identity_binding_changed');
 const pem=bytes(names.publisher);assert(pin(pem)===config.host.publisherSha256,'publisher_fingerprint_mismatch');
 const active=activeRelease(root,pem,{platform:'darwin',arch:process.arch});assert(active,'host_payload_active_release_required');
 const current=verifySignedRelease(active.release_root,pem,{platform:'darwin',arch:process.arch});complete(current,host);
 assert([path.join(root,'node'),path.join(active.release_root,'bin/node')].includes(service.nodeBinary)&&sha(bytes(service.nodeBinary,true))===current.manifest.files.find(f=>f.path==='bin/node')?.sha256,'host_payload_service_node_changed');
 const receipt=read(names.receipt);assert(receipt.schema===1&&receipt.version===current.version&&receipt.publisher_sha256===pin(pem)&&receipt.node===service.nodeBinary&&receipt.release_root===active.release_root&&receipt.service_config===names.service,'host_payload_receipt_binding_changed');
 for(const n of BOOTSTRAP){const source=n==='node'?'bin/node':'host/'+n;assert(sha(bytes(names['bootstrap_'+n],true))===current.manifest.files.find(f=>f.path===source)?.sha256,'host_payload_bootstrap_changed')}
 for(const step of state.steps.filter(s=>s.status==='succeeded'))for(const value of Object.values(step.evidence??{}))if(value&&typeof value==='object'&&absolute(value.path)&&digest(value.sha256))assert(sha(bytes(value.path))===value.sha256,'host_payload_completed_evidence_changed');
 const files=[];for(const [name,file]of Object.entries(names)){if(['background','capabilities'].includes(name)&&!fs.existsSync(file))continue;const before=bytes(file,name.startsWith('bootstrap_'));files.push({name,path:file,before,mode:fs.statSync(file).mode&0o777});if(['background','capabilities'].includes(name)){const value=JSON.parse(before);assert(value.schema===1&&value.configSha256===state.configSha256&&!['configuring','running','uncertain','rolling_back'].includes(value.status)&&!value.operations?.some(s=>['running','uncertain'].includes(s.status)),'host_payload_auxiliary_requires_reconciliation')}}
 const preserved=[];inventory(path.join(base,'device'),preserved);inventory(path.join(d,'gateway'),preserved);
 for(const file of [path.join(base,'enrollment.json'),path.join(base,'setup-state.json'),path.join(base,'gateway-ca.pem'),path.join(d,'onboarding-plugin.json'),path.join(d,'account-acceptance.json')])if(fs.existsSync(file))preserved.push({path:file,sha256:sha(bytes(file))});
 inventory(path.join(d,'tunnel'),preserved);
 if(host.browser?.profileRoot){assert(host.browser.profileRoot===path.join(base,'browser'),'host_payload_browser_profile_binding_changed');requirePrivateDirectory(host.browser.profileRoot)}
 return {d,config,state,base,root,names,service,host,pem,active,current,files,preserved};
}
function noActivity(d,root){for(const file of [path.join(d,'foreground.lock'),path.join(d,'host-update-recovery.lock'),...['.health-update-lock','.health-operation-lock','.health-recovery-guard'].map(n=>path.join(root,n))])assert(!fs.existsSync(file),'host_payload_active_or_uncertain_owner');for(const [name,statuses] of [['host-update.json',['completed','recovered']],['mac-signing-registration.json',['applied','rolled_back']]]){const f=path.join(d,name);if(fs.existsSync(f)){const r=read(f);assert(statuses.includes(r.phase??r.status),'host_payload_other_transaction_requires_recovery')}}}
async function absent(s,adapters){
 assert((adapters.platform??process.platform)==='darwin','host_payload_macos_offline_only');
 const observe=adapters.observeAbsence??(await import('./host-payload-native.mjs')).observeMacHostPayloadAbsence;
 const result=await observe({stateDir:s.d,installRoot:s.root,hostConfigFile:s.service.hostConfigFile,hostServiceLabel:s.service.label,appPath:s.config?.host?.macPreviewApp?.path??'/Applications/Styx.app'});
 assert(result?.status==='absent','host_payload_native_absence_required');
}
function target(s,bundle,adapters){
 assert(absolute(bundle),'absolute_host_payload_bundle_required');
 let pem=s.pem,app=null;
 try{verifySignedRelease(bundle,pem,{platform:'darwin',arch:process.arch})}catch{
  const registered=s.config.host.macPreviewApp,appPath=registered?.path;
  assert(absolute(appPath)&&path.basename(appPath)==='Styx.app'&&digest(registered.certificateSha256)&&/^[a-f0-9]{40}$/.test(registered.certificateSha1??''),'host_payload_registered_certificate_required');
  app=(adapters.verifyApp??verifyMacPreviewApp)(registered);
  assert(app?.trust==='local_certificate_preview_not_notarized'&&!assertMacPreviewContinuity(registered,app).migrationRequired,'host_payload_app_identity_changed');
  const resources=path.join(appPath,'Contents/Resources');
  assert(bundle===path.join(resources,'host-bundle')&&fs.realpathSync(bundle)===bundle,'host_payload_candidate_must_be_registered_app_resource');
  const defaultsFile=path.join(resources,'artifact-defaults.json'),publicFile=path.join(resources,'publisher.pem');
  for(const file of [defaultsFile,publicFile]){const st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&fs.realpathSync(file)===file&&st.size<=65536,'host_payload_app_resource_changed')}
  const defaults=JSON.parse(fs.readFileSync(defaultsFile));assert(Object.keys(defaults).length===3&&defaults.bundle==='host-bundle'&&defaults.publisherKeyFile==='publisher.pem'&&digest(defaults.publisherSha256),'host_payload_app_artifacts_invalid');
  pem=fs.readFileSync(publicFile);assert(pin(pem)===defaults.publisherSha256,'host_payload_app_publisher_changed');
 }
 const release=verifySignedRelease(bundle,pem,{platform:'darwin',arch:process.arch});complete(release,s.host);
 assert(release.version!==s.current.version,'distinct_host_payload_version_required');
 return {pem,release,bundle,app:app?{path:app.path,cdhash:app.cdhash,certificateSha1:app.certificateSha1,certificateSha256:app.certificateSha256}:null};
}
function proposed(s,t){
 const config=structuredClone(s.config),service={...s.service,nodeBinary:path.join(s.root,'node')},state=structuredClone(s.state);
 config.host={...config.host,bundle:path.join(s.root,'releases',t.release.version),publisherKeyFile:s.names.publisher,publisherSha256:pin(t.pem)};
 const after={deployment:encode(config),service:encode(service),publisher:t.pem,pointer:encode({schema:1,version:t.release.version,previous:null,manifest_sha256:t.release.sha256})};
 const receipt=JSON.parse(s.files.find(f=>f.name==='receipt').before);after.receipt=encode({...receipt,version:t.release.version,publisher_sha256:pin(t.pem),node:service.nodeBinary,release_root:config.host.bundle});
 for(const n of BOOTSTRAP){const source=n==='node'?'bin/node':'host/'+n;const content=fs.readFileSync(path.join(t.bundle,source));assert(sha(content)===t.release.manifest.files.find(f=>f.path===source)?.sha256,'host_payload_candidate_changed');after['bootstrap_'+n]=content}
 state.configSha256=sha(after.deployment);if(state.onboardingDecisions?.background?.configSha256===s.state.configSha256)state.onboardingDecisions.background.configSha256=state.configSha256;
 const prepared=state.steps.find(x=>x.id==='host.prepare');prepared.evidence={...prepared.evidence,version:t.release.version,publisher_sha256:pin(t.pem),node:service.nodeBinary,release_root:config.host.bundle};
 for(const step of state.steps)for(const evidence of Object.values(step.evidence??{}))if(evidence&&typeof evidence==='object'&&absolute(evidence.path)){const file=s.files.find(f=>f.path===evidence.path);if(file&&after[file.name])evidence.sha256=sha(after[file.name])}
 state.steps=state.steps.map(step=>step.id==='host.doctor'||step.id.startsWith('host.service.')?{id:step.id,status:'pending'}:step);
 after.state=encode(state);
 for(const name of ['background','capabilities']){const file=s.files.find(f=>f.name===name);if(file)after[name]=encode({...JSON.parse(file.before),configSha256:state.configSha256,...(name==='background'?{status:'needs_attention',reason:'host_payload_changed_requires_verification',host:'not_observed',hostConnection:'not_checked',gateway:'not_observed'}:{})})}
 return s.files.map(f=>({...f,after:after[f.name],afterMode:f.name==='bootstrap_node'?0o700:f.mode}));
}
async function build(stateDir,bundle,adapters,ownTransaction){
 const s=snapshot(stateDir);noActivity(stateDir,s.root);const old=journal(stateDir);assert(!old||['applied','rolled_back'].includes(old.status)||old.transactionId===ownTransaction&&old.status==='capturing','host_payload_requires_rollback');
 const t=target(s,bundle,adapters);await absent(s,adapters);
 const files=proposed(s,t),body={schema:1,kind:KIND,stateDir,status:'offline_reviewable',bundle,current:{version:s.current.version,manifestSha256:s.current.sha256,publisherSha256:pin(s.pem)},target:{version:t.release.version,manifestSha256:t.release.sha256,publisherSha256:pin(t.pem)},publisherChange:pin(s.pem)!==pin(t.pem),app:t.app,changes:files.map(f=>({name:f.name,path:f.path,beforeSha256:sha(f.before),afterSha256:sha(f.after),beforeMode:f.mode,afterMode:f.afterMode})),preserved:s.preserved,nativeAbsence:'observed',serviceMutation:'NONE',nativeHealth:'NOT RUN',accountAcceptance:'NOT RUN'};
 return {s,t,files,plan:{...body,planId:sha(JSON.stringify(body))}};
}
export async function planHostPayloadMigration({stateDir,bundle}={},adapters={}){assert(absolute(stateDir),'absolute_state_directory_required');for(const n of [...LOCKS,RECOVERY])assert(!fs.existsSync(path.join(stateDir,n)),'host_payload_management_busy');return (await build(stateDir,bundle,adapters)).plan}
function checkPreserved(entries){for(const f of entries)assert(sha(bytes(f.path))===f.sha256,'host_payload_preserved_state_changed')}
function locks(d,transactionId,{recover,owner,plan}={}){
 const held=[],recoveryOwner=recover&&LOCKS.some(n=>fs.existsSync(path.join(d,n)))?owner:null;
 const token=recoveryOwner?.token??randomBytes(32).toString('hex'),record=recoveryOwner??{schema:1,kind:KIND,transactionId,pid:process.pid,token},value=encode({...record,plan});
 // Validate every retained owner before taking over any lock. Keep its record
 // during recovery: the separate recovery guard serializes reclaimers, and a
 // crash during adoption must not leave mixed, unrecognizable owner tokens.
 if(recoveryOwner)for(const name of LOCKS){const file=path.join(d,name);if(!fs.existsSync(file))continue;const r=read(file);assert(r.kind===KIND&&r.transactionId===transactionId&&r.token===owner?.token&&r.pid===owner?.pid,'host_payload_foreign_lock');let dead=false;try{process.kill(r.pid,0)}catch(e){dead=e.code==='ESRCH'}assert(dead||r.pid===process.pid&&abandoned.has(r.token),'host_payload_lock_owner_alive')}
 const close=keep=>{for(const h of held.reverse()){try{if(!keep){const now=requirePrivateFile(h.file);assert(now.ino===h.info.ino&&now.dev===h.info.dev&&bytes(h.file).equals(value),'host_payload_lock_changed');fs.unlinkSync(h.file)}}finally{fs.closeSync(h.fd)}}if(keep)abandoned.add(token)};
 try{
  for(const name of LOCKS){const file=path.join(d,name);
   if(fs.existsSync(file)&&recover){const before=bytes(file),r=JSON.parse(before),info=requirePrivateFile(file);assert(r.kind===KIND&&r.transactionId===transactionId&&r.token===owner?.token&&r.pid===owner?.pid,'host_payload_foreign_lock');let dead=false;try{process.kill(r.pid,0)}catch(e){dead=e.code==='ESRCH'}assert(dead||r.pid===process.pid&&abandoned.has(r.token),'host_payload_lock_owner_alive');const after=requirePrivateFile(file);assert(after.ino===info.ino&&after.dev===info.dev&&bytes(file).equals(before),'host_payload_lock_changed');// Retain the advance lock continuously while adopting a dead owner.
    const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);held.push({file,fd,info:fs.fstatSync(fd)});continue}
   let fd;try{fd=openPrivateFile(file)}catch{fail('host_payload_management_busy')}const info=fs.fstatSync(fd);fs.writeFileSync(fd,value);fs.fsyncSync(fd);held.push({file,fd,info});
  }
  const assertOwned=()=>{for(const h of held){const now=requirePrivateFile(h.file);assert(now.ino===h.info.ino&&now.dev===h.info.dev&&bytes(h.file).equals(value),'host_payload_lock_changed')}};
  return {owner:record,close,assertOwned};
 }catch(e){close(!!recoveryOwner);throw e}
}
function save(d,j,status,activeFile){j.status=status;j.updatedAt=new Date().toISOString();if(activeFile)j.activeFile=activeFile;else delete j.activeFile;atomic(path.join(d,JOURNAL),encode(j))}
function assertFiles(files,side){for(const f of files)assert(bytes(f.path,f.name.startsWith('bootstrap_')).equals(f[side]),'host_payload_managed_file_changed')}
export async function applyHostPayloadMigration({stateDir,plan,authorize=false}={},adapters={}){
 assert(authorize===true,'explicit_host_payload_authorization_required');assert(plan?.stateDir===stateDir&&digest(plan.planId),'host_payload_reviewed_plan_required');
 assert(!fs.existsSync(path.join(stateDir,RECOVERY)),'host_payload_recovery_in_progress');
 const initial=await build(stateDir,plan.bundle,adapters);assert(JSON.stringify(initial.plan)===JSON.stringify(plan),'host_payload_review_stale');
 const transactionId=randomBytes(16).toString('hex'),held=locks(stateDir,transactionId,{plan});let pending=true,j=journal(stateDir);
 try{
  adapters.onPhase?.('locked');
  assert(!fs.existsSync(path.join(stateDir,RECOVERY)),'host_payload_recovery_in_progress');
  const b=await build(stateDir,plan.bundle,adapters,transactionId);held.assertOwned();assert(JSON.stringify(b.plan)===JSON.stringify(plan),'host_payload_review_stale');
  stageSignedRelease({sourceDir:b.t.bundle,installRoot:b.s.root,publicKeyPem:b.t.pem,platform:'darwin',arch:process.arch});
  assert(verifySignedRelease(path.join(b.s.root,'releases',plan.target.version),b.t.pem,{platform:'darwin',arch:process.arch}).sha256===plan.target.manifestSha256,'host_payload_candidate_changed');
  const directory=path.join(stateDir,'host-payload-migration-snapshots',transactionId);ensurePrivateDirectory(path.dirname(directory));ensurePrivateDirectory(directory,{exclusive:true});
  for(const f of b.files){atomic(path.join(directory,f.name+'.before'),f.before,f.mode);atomic(path.join(directory,f.name+'.after'),f.after,f.afterMode);adapters.onPhase?.('snapshot_'+f.name)}
  const previous=path.join(stateDir,JOURNAL);if(fs.existsSync(previous))atomic(path.join(directory,'previous-journal.json'),bytes(previous));
  j={schema:1,kind:KIND,transactionId,plan,owner:held.owner,files:plan.changes,preserved:plan.preserved,status:'prepared',captureComplete:true};save(stateDir,j,'prepared');pending=true;adapters.onPhase?.('prepared');
  await absent(b.s,adapters);held.assertOwned();noActivity(stateDir,b.s.root);checkPreserved(b.s.preserved);assertFiles(b.files,'before');
  for(const f of b.files){held.assertOwned();assert(bytes(f.path,f.name.startsWith('bootstrap_')).equals(f.before),'host_payload_managed_file_changed');save(stateDir,j,'writing',f.name);atomic(f.path,f.after,f.afterMode);adapters.onPhase?.('written_'+f.name)}
  assertFiles(b.files,'after');checkPreserved(b.s.preserved);assert(activeRelease(b.s.root,b.t.pem,{platform:'darwin',arch:process.arch})?.version===plan.target.version,'host_payload_activation_invalid');
  save(stateDir,j,'applied');pending=false;return {...publicJournal(j),status:'applied_stopped',nextAction:'verify_host_before_start'};
 }catch(e){if(pending&&j){try{save(stateDir,j,'uncertain')}catch{}fail('host_payload_interrupted_explicit_rollback_required')}throw e}finally{held.close(pending)}
}
function rollbackFiles(d,j){
 const {planId,...body}=j.plan;assert(sha(JSON.stringify(body))===planId&&JSON.stringify(j.files)===JSON.stringify(j.plan.changes)&&JSON.stringify(j.preserved)===JSON.stringify(j.plan.preserved),'host_payload_snapshot_invalid');
 const directory=path.join(d,'host-payload-migration-snapshots',j.transactionId);requirePrivateDirectory(directory);
 const config=JSON.parse(bytes(path.join(directory,'deployment.before'))),state=JSON.parse(bytes(path.join(directory,'state.before')));validateDeployment(config,{checkNetwork:false});assert(state.configSha256===sha(bytes(path.join(directory,'deployment.before')))&&state.mode===config.mode,'host_payload_snapshot_invalid');
 const expected=roots(d,config.host.baseDir);assert(Array.isArray(j.files)&&j.files.length>=10&&new Set(j.files.map(f=>f.name)).size===j.files.length,'host_payload_snapshot_invalid');
 assert(Object.keys(expected).filter(n=>!['background','capabilities'].includes(n)).every(n=>j.files.some(f=>f.name===n)),'host_payload_snapshot_invalid');
 for(const name of ['background','capabilities'])assert(j.files.some(f=>f.name===name)||!fs.existsSync(expected[name]),'host_payload_new_auxiliary_state');
 const files=j.files.map(f=>{assert(expected[f.name]===f.path&&Number.isInteger(f.beforeMode)&&(f.beforeMode&0o077)===0&&f.beforeMode>=0&&f.beforeMode<=0o700&&Number.isInteger(f.afterMode)&&(f.afterMode&0o077)===0&&f.afterMode>=0&&f.afterMode<=0o700&&digest(f.beforeSha256)&&digest(f.afterSha256),'host_payload_snapshot_invalid');const before=bytes(path.join(directory,f.name+'.before'),f.name.startsWith('bootstrap_')),after=bytes(path.join(directory,f.name+'.after'),f.name.startsWith('bootstrap_'));assert(sha(before)===f.beforeSha256&&sha(after)===f.afterSha256&&[f.beforeSha256,f.afterSha256].includes(sha(bytes(f.path,f.name.startsWith('bootstrap_')))),'host_payload_rollback_scope_changed');return {...f,before,after}});
 const pem=files.find(f=>f.name==='publisher').before,root=path.join(config.host.baseDir,'install'),pointer=JSON.parse(files.find(f=>f.name==='pointer').before);
 assert(pin(pem)===config.host.publisherSha256&&pointer.version===j.plan.current.version&&pointer.manifest_sha256===j.plan.current.manifestSha256,'host_payload_snapshot_invalid');
 const old=verifySignedRelease(path.join(root,'releases',pointer.version),pem,{platform:'darwin',arch:process.arch});assert(old.sha256===pointer.manifest_sha256,'host_payload_previous_release_changed');
 for(const n of BOOTSTRAP)assert(sha(files.find(f=>f.name==='bootstrap_'+n).before)===old.manifest.files.find(f=>f.path===(n==='node'?'bin/node':'host/'+n))?.sha256,'host_payload_previous_bootstrap_changed');
 return {files,s:{d,root,config,service:JSON.parse(files.find(f=>f.name==='service').before)}};
}
export async function rollbackHostPayloadMigration({stateDir,transactionId,authorize=false}={},adapters={}){
 assert(authorize===true&&absolute(stateDir)&&id(transactionId),'explicit_host_payload_rollback_required');requirePrivateDirectory(stateDir);
 const guard=acquireRecoveryGuard(path.join(stateDir,RECOVERY),{kind:KIND,transactionId});let held,pending=false,j;
 try{
  j=journal(stateDir);assert(j&&j.transactionId===transactionId&&j.status!=='rolled_back','host_payload_rollback_not_available');
  held=locks(stateDir,transactionId,{recover:true,owner:j.owner,plan:j.plan});
  if(!['applied','rolled_back'].includes(j.status)){pending=true;j.owner=held.owner;save(stateDir,j,j.status)}
  if(j.captureComplete===false){
   const s=snapshot(stateDir);noActivity(stateDir,s.root);await absent(s,adapters);held.assertOwned();guard.assertOwned();
   const changes=s.files.map(f=>({name:f.name,path:f.path,beforeSha256:sha(f.before),beforeMode:f.mode}));
   assert(JSON.stringify(changes)===JSON.stringify(j.plan.changes.map(({name,path,beforeSha256,beforeMode})=>({name,path,beforeSha256,beforeMode})))&&JSON.stringify(s.preserved)===JSON.stringify(j.plan.preserved),'host_payload_admission_state_changed');
   assert(s.current.version===j.plan.current.version&&s.current.sha256===j.plan.current.manifestSha256&&pin(s.pem)===j.plan.current.publisherSha256,'host_payload_admission_state_changed');
   checkPreserved(j.preserved);save(stateDir,j,'rolled_back');pending=false;return {...publicJournal(j),status:'rolled_back_stopped'};
  }
  const {files,s}=rollbackFiles(stateDir,j);noActivity(stateDir,s.root);await absent(s,adapters);held.assertOwned();guard.assertOwned();checkPreserved(j.preserved);
  j.owner=held.owner;save(stateDir,j,'rolling_back');pending=true;adapters.onPhase?.('rolling_back');
  for(const f of files){held.assertOwned();guard.assertOwned();assert([f.beforeSha256,f.afterSha256].includes(sha(bytes(f.path,f.name.startsWith('bootstrap_')))),'host_payload_rollback_scope_changed');save(stateDir,j,'rolling_back',f.name);atomic(f.path,f.before,f.beforeMode);adapters.onPhase?.('restored_'+f.name)}
  assertFiles(files,'before');checkPreserved(j.preserved);guard.assertOwned();save(stateDir,j,'rolled_back');pending=false;return {...publicJournal(j),status:'rolled_back_stopped'};
 }catch(e){if(pending&&j){try{save(stateDir,j,'uncertain')}catch{}fail('host_payload_rollback_interrupted')}throw e}finally{try{held?.close(pending)}finally{guard.close()}}
}
