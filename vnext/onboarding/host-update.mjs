// Review-bound Host upgrades reuse the signed service transaction engine.
// Native execution is admitted only where durable inhibition and real health exist.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,randomBytes} from 'node:crypto';
import {readDeployment} from './core.mjs';
import {activeRelease,verifySignedRelease,stageSignedRelease} from '../host/installer.mjs';
import {inspectServiceUpdate,updateServiceRelease,recoverServiceUpdate} from '../host/service-update.mjs';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
import {createHostUpdateRuntime} from './host-update-runtime.mjs';
import {normalizeConnector} from '../host/connect.mjs';
import {acquireRecoveryGuard} from './recovery-guard.mjs';
const fail=code=>{throw Error(code)};
const sha=value=>createHash('sha256').update(value).digest('hex');
const hash=file=>sha(fs.readFileSync(file));
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
const version=value=>/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value??'');
const id=value=>/^[a-f0-9]{32}$/.test(value??'');
function read(file){if(requirePrivateFile(file).size>1024*1024)fail('host_update_file_too_large');return JSON.parse(fs.readFileSync(file,'utf8'));}
function scope(stateDir,{allowInvalidCurrent=false}={}){
 if(!absolute(stateDir))fail('absolute_state_directory_required');
 const state=readDeployment(stateDir),config=read(path.join(stateDir,'deployment.json'));
 if(!config.host)fail('local_host_not_configured');
 if(!state.steps.some(step=>step.id==='host.prepare'&&step.status==='succeeded'))fail('prepared_local_host_required');
 const base=config.host.baseDir,installRoot=path.join(base,'install'),publisherFile=path.join(base,'publisher.pem');requirePrivateDirectory(base);requirePrivateDirectory(installRoot);requirePrivateFile(publisherFile);
 const pem=fs.readFileSync(publisherFile,'utf8'),key=createPublicKey(pem);
 if(key.asymmetricKeyType!=='ed25519'||sha(key.export({type:'spki',format:'der'}))!==config.host.publisherSha256)fail('publisher_fingerprint_mismatch');
 const serviceFile=path.join(base,'service.json'),raw=read(serviceFile),windows=process.platform==='win32';
 const service={id:windows?raw.task_name:process.platform==='darwin'?raw.label:raw.unitName,installRoot:windows?raw.install_root:raw.installRoot,hostConfigFile:windows?raw.host_config_file:raw.hostConfigFile,publisherKeyFile:windows?raw.publisher_key_file:raw.trustPublicKeyFile,nodeBinary:windows?raw.node_binary:raw.nodeBinary,...(raw.restartSec!==undefined?{restartSec:raw.restartSec}:{})};
 if(service.installRoot!==installRoot||service.hostConfigFile!==path.join(base,'device/host.json')||service.publisherKeyFile!==publisherFile||!absolute(service.nodeBinary)||typeof service.id!=='string'||!service.id)fail('host_update_service_binding_changed');
 const host=normalizeConnector(read(service.hostConfigFile));
 const expectedGateway=new URL(config.gateway.url);expectedGateway.protocol='wss:';if(new URL(host.gateway_ws_url).href!==expectedGateway.href)fail('host_update_gateway_binding_changed');
 const identityFile=path.join(base,'device/identity.json'),identity=read(identityFile);
 if(identity.device_id!==host.host_id)fail('host_update_device_identity_changed');
 const preserved={hostConfiguration:hash(service.hostConfigFile),deviceIdentity:hash(identityFile)};
 for(const [name,file] of [['pluginProfile',path.join(stateDir,'onboarding-plugin.json')],['gatewayCertificate',path.join(stateDir,'gateway/certificate.pem')],['gatewayOwner',path.join(stateDir,'gateway/owner.json')],['gatewayModelCredential',path.join(stateDir,'gateway/model.token')],['gatewayAdminCredential',path.join(stateDir,'gateway/admin.token')]])if(fs.existsSync(file))preserved[name]=hash(file);
 for(const [name,file] of [['identityPrivateKey',path.join(base,'device/identity.pem')],['credential',host.token_file],['clientCertificate',host.client_cert_file],['clientPrivateKey',host.client_key_file],['gatewayTrust',host.gateway_ca_file]])if(file!==undefined){requirePrivateFile(file);preserved[name]=hash(file);}
 let active=null,current=null;
 try{active=activeRelease(installRoot,pem);if(!active)fail('no_active_host_release');current=verifySignedRelease(active.release_root,pem);}
 catch{if(!allowInvalidCurrent)fail('active_host_release_unavailable_or_changed');}
 return {stateDir,state,config,base,installRoot,pem,service,host,preserved,current,active,configurationSha256:hash(path.join(stateDir,'deployment.json')),serviceConfigurationSha256:hash(serviceFile)};
}
function completeHostRelease(release,host){
 const computer=host.computer?.enabled===true;
 const suffix=process.platform==='win32'?'.exe':'',required=['host/private-storage.mjs','host/installer.mjs','host/launch.mjs','host/connect.mjs','bin/node'+suffix,'bin/codex'+suffix,...(computer?['bin/cua-driver'+suffix]:[])];
 if(host.browser?.enabled)required.push('host/browser.mjs','packages/styx-browser-provider/host.mjs','packages/styx-browser-provider/config.mjs','packages/styx-browser-provider/prepare.mjs','packages/styx-browser-provider/contract.mjs','packages/styx-browser-provider/playwright-contract-0.0.83.json','packages/styx-browser-provider/node_modules/@playwright/mcp/package.json');
 if(required.some(name=>!release.manifest.files.some(entry=>entry.path===name&&(!name.startsWith('bin/')||entry.executable))))fail('complete_signed_host_update_required');
}
function lockObservation(ctx){
 const lock=path.join(ctx.installRoot,'.health-update-lock');if(!fs.existsSync(lock))return {status:'absent',transactionId:null};
 try{requirePrivateDirectory(lock);const owner=path.join(lock,'owner');if(requirePrivateFile(owner).size>128)fail('invalid_update_owner');const value=fs.readFileSync(owner,'utf8');return id(value)?{status:'present',transactionId:value}:{status:'unknown',transactionId:null};}
 catch{return {status:'unknown',transactionId:null};}
}
function operationObservation(ctx){
 const present=name=>{try{fs.lstatSync(path.join(ctx.installRoot,name));return 'present_requires_owner_inspection'}
   catch(error){return error.code==='ENOENT'?'absent':'unavailable'}};
 return {update:present('.health-operation-lock'),recovery:present('.health-recovery-guard')};
}
function transaction(ctx,transactionId){
 if(!id(transactionId))fail('invalid_transaction_id');
 const file=path.join(ctx.installRoot,'update-transactions',transactionId+'.json');if(requirePrivateFile(file).size>1024*1024)fail('host_update_file_too_large');
 const record=inspectServiceUpdate({installRoot:ctx.installRoot,transactionId});
 const previous=verifySignedRelease(path.join(ctx.installRoot,'releases',record.previousVersion),ctx.pem),candidate=verifySignedRelease(path.join(ctx.installRoot,'releases',record.candidateVersion),ctx.pem);
 if(record.platform!==process.platform||record.arch!==process.arch||previous.sha256!==record.previousManifest||candidate.sha256!==record.candidateManifest)fail('host_update_receipt_release_binding_changed');
 const terminal=['activated','rolled_back','recovered_stopped'].includes(record.phase);let matchesExpected=false;
 try{requirePrivateFile(path.join(ctx.installRoot,'active.json'));matchesExpected=fs.readFileSync(path.join(ctx.installRoot,'active.json'),'utf8')===record.expectedPointer;}catch{}
  return {transactionId,status:terminal?record.phase:'needs_recovery',phase:record.phase,previousVersion:record.previousVersion,candidateVersion:record.candidateVersion,previousManifestSha256:record.previousManifest,candidateManifestSha256:record.candidateManifest,
  updatedAt:typeof record.updatedAt==='string'?record.updatedAt:null,activePointer:{matchesExpected,selectedGeneration:ctx.current?ctx.active?.version:null},ownsUpdateLock:lockObservation(ctx).transactionId===transactionId,
  restartInhibition:'required_not_observed',service:'not_observed',candidateHealth:'not_observed',receiptEvidence:'signed_generations_verified',accountAcceptance:'NOT RUN'};
}
export function readHostUpdate({stateDir,transactionId}={}){
 const ctx=scope(stateDir,{allowInvalidCurrent:true}),lock=lockObservation(ctx),operation=operationObservation(ctx),folder=path.join(ctx.installRoot,'update-transactions');let transactions=[];
 if(transactionId!==undefined)transactions=[transaction(ctx,transactionId)];
 else if(fs.existsSync(folder)){
  requirePrivateDirectory(folder);const names=fs.readdirSync(folder);if(names.length>1024)fail('host_update_transaction_limit');
  transactions=names.filter(name=>/^[a-f0-9]{32}\.json$/.test(name)).sort().map(name=>{
   const selected=name.slice(0,-5);try{return transaction(ctx,selected);}catch{return {transactionId:selected,status:'unverified',reason:'receipt_or_signed_generation_unavailable_or_changed',candidateHealth:'not_observed',service:'not_observed'};}
  });
 }
 return {schema:1,role:'host',status:!ctx.current||lock.status!=='absent'||Object.values(operation).some(value=>value!=='absent')||transactions.some(row=>['needs_recovery','unverified'].includes(row.status))||managedRecord(ctx)&&!['completed','recovered'].includes(managedRecord(ctx).phase)?'needs_recovery':'reported',current:{version:ctx.current?.version??null,manifestSha256:ctx.current?.sha256??null,signature:ctx.current?'verified':'unverified',...(!ctx.current?{reason:'active_release_unavailable_or_changed'}:{}),runtimeHealth:'not_observed'},lock,operation,transactions,
  managed:managedProjection(managedRecord(ctx)),recovery:{status:process.platform==='linux'&&ctx.config.mode==='create-local'?'explicit_stopped_recovery_available':'not_implemented',requires:['observe_owned_service_stopped_and_durably_restart_inhibited','verify_previous_signed_generation_and_transaction_ownership','restore_signed_bootstrap_without_replaying_uncertain_start']},accountAcceptance:'NOT RUN'};
}
export function planHostUpdate({stateDir,bundle,rollback=false}={}){
 const ctx=scope(stateDir);if(typeof rollback!=='boolean'||rollback&&bundle!==undefined)fail('host_update_select_bundle_or_rollback');
 let source=bundle;
 if(rollback){if(!version(ctx.active.previous))fail('no_rollback_generation');source=path.join(ctx.installRoot,'releases',ctx.active.previous);}
 if(!absolute(source))fail('absolute_host_update_bundle_required');
 const candidate=verifySignedRelease(source,ctx.pem);completeHostRelease(candidate,ctx.host);completeHostRelease(ctx.current,ctx.host);
 if(candidate.version===ctx.current.version)fail('distinct_host_update_version_required');
 const blockers=[];
 if(process.platform!=='linux')blockers.push('durably_inhibited_native_candidate_start_required');
 if(ctx.config.mode!=='create-local')blockers.push('real_candidate_exec_health_and_gateway_connection_identity_required');
 for(const name of ['foreground.lock','background.lock','capabilities.lock'])if(fs.existsSync(path.join(stateDir,name)))blockers.push('active_or_uncertain_'+name.replace('.lock','')+'_owner_requires_reconciliation');
 const managed=managedRecord(ctx);if(managed&&!['completed','recovered'].includes(managed.phase))blockers.push('managed_host_update_requires_recovery');
 const stableNode=path.join(ctx.installRoot,process.platform==='win32'?'node.exe':'node');
 if(ctx.service.nodeBinary!==stableNode)blockers.push('service_generation_node_pin_migration_required');
 const executable=fs.realpathSync(process.execPath),realInstall=fs.realpathSync(ctx.installRoot);
 if(executable===realInstall||executable.startsWith(realInstall+path.sep))blockers.push('independent_updater_runtime_required');
 const lock=lockObservation(ctx);if(lock.status!=='absent'||Object.values(operationObservation(ctx)).some(value=>value!=='absent'))blockers.push('existing_host_update_requires_receipt_inspection_and_reconciliation');
 if(ctx.state.steps.some(step=>['running','uncertain'].includes(step.status))||ctx.state.hostServiceMaintenance?.hasUncertainMutation)blockers.push('uncertain_deployment_action_requires_reconciliation');
 const plan={schema:1,role:'host',status:blockers.length?'blocked':'ready',action:rollback?'rollback':'update',stateDir,configurationSha256:ctx.configurationSha256,serviceConfigurationSha256:ctx.serviceConfigurationSha256,
  current:{version:ctx.current.version,manifestSha256:ctx.current.sha256,pointerSha256:hash(path.join(ctx.installRoot,'active.json'))},target:{version:candidate.version,manifestSha256:candidate.sha256,bundle:source},preservedEvidence:ctx.preserved,
  service:{id:ctx.service.id,runtime:ctx.service.nodeBinary===stableNode?'stable_signed_node':'generation_or_external_node',state:'not_observed',persistence:'not_observed'},blockers,
  prerequisites:['stop_and_durably_inhibit_only_verified_owned_service','start_candidate_without_enabling_login_boot_or_recovery_triggers','observe_real_candidate_exec_rpc_and_bound_gateway_identity','keep_inhibition_through_health_or_signed_rollback','review_service_config_and_native_permission_identity_migration'],
  installation:'NOT RUN',candidateHealth:'NOT RUN',nativePermissions:'NOT RUN',accountAcceptance:'NOT RUN'};
 return {...plan,reviewSha256:sha(JSON.stringify(plan))};
}

function atomic(file,value){
 const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp);
 try{fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 try{fs.renameSync(tmp,file);const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}finally{fs.rmSync(tmp,{force:true})}
}
function managedRecord(ctx){
 const file=path.join(ctx.stateDir,'host-update.json');if(!fs.existsSync(file))return null;
 const value=read(file);
 if(value.schema!==1||!id(value.transactionId)||value.plan?.stateDir!==ctx.stateDir||!['prepared','staged','executing','finalizing','completed','recovering','recovered','needs_recovery'].includes(value.phase)||value.engineTransactionId!==undefined&&!id(value.engineTransactionId))fail('invalid_managed_host_update_receipt');
 return value;
}
function managedProjection(value){return value?{transactionId:value.transactionId,phase:value.phase,status:['completed','recovered'].includes(value.phase)?value.phase:'needs_recovery',engineTransactionId:value.engineTransactionId??null,outcome:value.outcome??null,nativeHealth:value.health??'not_observed',accountAcceptance:'NOT RUN'}:null}
function managementLock(stateDir,{recover=false,transactionId}={}){
 let recoveryGuard;
 const held=[],acquire=file=>{
  let fd;try{fd=openPrivateFile(file)}catch{fail('host_update_management_busy')}
  const stat=fs.fstatSync(fd),data=JSON.stringify({schema:1,kind:'managed-host-update',pid:process.pid,nonce:randomBytes(32).toString('hex')});
  try{fs.writeFileSync(fd,data);fs.fsyncSync(fd)}catch(error){fs.closeSync(fd);throw error}held.push({file,fd,stat,data});
 };
 const verify=h=>{const s=requirePrivateFile(h.file);if(s.ino!==h.stat.ino||s.dev!==h.stat.dev||fs.readFileSync(h.file,'utf8')!==h.data)fail('host_update_management_lock_changed')};
 const release=()=>{try{for(const h of held.reverse()){try{verify(h);fs.unlinkSync(h.file)}finally{fs.closeSync(h.fd)}}}finally{recoveryGuard?.close()}};
 release.assertOwned=()=>{recoveryGuard?.assertOwned();for(const h of held)verify(h)};
 try{
  const guard=path.join(stateDir,'host-update-recovery.lock'),file=path.join(stateDir,'advance.lock');
  if(recover){
   recoveryGuard=acquireRecoveryGuard(guard,{kind:'managed-host-update-recovery',transactionId});
   if(fs.existsSync(file)){
    const previous=read(file),stat=requirePrivateFile(file),bytes=fs.readFileSync(file,'utf8');
    if(previous.kind!=='managed-host-update'||!Number.isSafeInteger(previous.pid)||previous.pid<1)fail('host_update_management_busy');
    let dead=false;try{process.kill(previous.pid,0)}catch(error){dead=error.code==='ESRCH'}if(!dead)fail('host_update_management_busy');
    const now=requirePrivateFile(file);if(now.ino!==stat.ino||now.dev!==stat.dev||fs.readFileSync(file,'utf8')!==bytes)fail('host_update_management_lock_changed');fs.unlinkSync(file);
   }
  }else if(fs.existsSync(guard))fail('host_update_management_busy');
  acquire(file);return release;
 }catch(error){release();throw error}
}
function unchanged(ctx,plan){
 if(ctx.configurationSha256!==plan.configurationSha256||ctx.serviceConfigurationSha256!==plan.serviceConfigurationSha256||JSON.stringify(ctx.preserved)!==JSON.stringify(plan.preservedEvidence))fail('host_update_preserved_identity_changed');
}
function saveManaged(ctx,record,phase){record.phase=phase;record.updatedAt=new Date().toISOString();atomic(path.join(ctx.stateDir,'host-update.json'),record)}
function requireOwnerOffline(stateDir){for(const name of ['foreground.lock','background.lock','capabilities.lock'])if(fs.existsSync(path.join(stateDir,name)))fail('host_update_active_management_owner')}
export async function applyHostUpdate({stateDir,plan,authorize=false}={}, {runtimeFactory=createHostUpdateRuntime,timeoutMs=30000}={}){
 if(authorize!==true)fail('explicit_host_update_authorization_required');
 if(!plan||plan.stateDir!==stateDir||!['update','rollback'].includes(plan.action))fail('invalid_host_update_plan');
 const release=managementLock(stateDir);let ctx,record;
 try{
  const reviewed=planHostUpdate({stateDir,...(plan.action==='rollback'?{rollback:true}:{bundle:plan.target?.bundle})});
  if(JSON.stringify(reviewed)!==JSON.stringify(plan))fail('host_update_review_stale');if(plan.status!=='ready')fail('host_update_plan_blocked');
  ctx=scope(stateDir);requireOwnerOffline(stateDir);unchanged(ctx,plan);
  const runtime=runtimeFactory(ctx);record={schema:1,transactionId:randomBytes(16).toString('hex'),plan,phase:'prepared'};
  const saveNative=native=>{record.native=native;saveManaged(ctx,record,record.phase)};
  await runtime.prepare(saveNative);
  stageSignedRelease({sourceDir:plan.target.bundle,installRoot:ctx.installRoot,publicKeyPem:ctx.pem});
  if(verifySignedRelease(path.join(ctx.installRoot,'releases',plan.target.version),ctx.pem).sha256!==plan.target.manifestSha256)fail('host_update_candidate_changed');
  saveManaged(ctx,record,'staged');
  const check=()=>{requireOwnerOffline(stateDir);unchanged(scope(stateDir,{allowInvalidCurrent:true}),plan)};
  const result=await updateServiceRelease({installRoot:ctx.installRoot,version:plan.target.version,publicKeyPem:ctx.pem,timeoutMs,
   stopService:async call=>{check();record.engineTransactionId=call.transactionId;saveManaged(ctx,record,'executing');return runtime.stop(call,native=>{if(call.signal.aborted)fail('host_update_stop_completion_expired');return saveNative(native)})},
   startService:async call=>{check();return runtime.start(call)},
   checkHealth:async call=>{check();const healthy=await runtime.health(call);if(call.signal.aborted)fail('host_update_health_completion_expired');check();if(healthy){record.health={status:'verified',version:call.version,method:'mcp_exec_candidate_process_ancestry_and_authenticated_host_connection',at:new Date().toISOString()};saveManaged(ctx,record,'executing')}return healthy}
  });
  record.engineTransactionId=result.transactionId;record.outcome=result.status;
  if(['activated','rolled_back'].includes(result.status)){
   check();saveManaged(ctx,record,'finalizing');record.persistence=await runtime.finish(saveNative);saveManaged(ctx,record,'completed');
  }else saveManaged(ctx,record,'needs_recovery');
  return {...managedProjection(record),status:record.phase==='completed'?result.status:'needs_recovery'};
 }catch(error){if(record?.native){saveManaged(ctx,record,'needs_recovery');return {...managedProjection(record),reason:'host_update_interrupted_inspect_receipt'}}throw error}
 finally{release()}
}
export async function recoverHostUpdate({stateDir,transactionId,authorize=false}={}, {runtimeFactory=createHostUpdateRuntime,timeoutMs=30000}={}){
 if(authorize!==true)fail('explicit_host_update_authorization_required');if(!id(transactionId))fail('invalid_transaction_id');
 const release=managementLock(stateDir,{recover:true,transactionId});let ctx,record;
 try{
  ctx=scope(stateDir,{allowInvalidCurrent:true});record=managedRecord(ctx);
  if(!record||record.transactionId!==transactionId||['completed','recovered'].includes(record.phase))fail('host_update_recovery_binding_mismatch');
  requireOwnerOffline(stateDir);unchanged(ctx,record.plan);
  if(!record.native)fail('host_update_native_receipt_missing');
  const runtime=runtimeFactory(ctx),saveNative=native=>{record.native=native;saveManaged(ctx,record,record.phase)};
  release.assertOwned();await runtime.prepare(saveNative,record.native);release.assertOwned();saveManaged(ctx,record,'recovering');
  // Recovery explicitly stops/inhibits; it never replays uncertain starts or commands.
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),timeoutMs);
  try{release.assertOwned();await runtime.stop({signal:abort.signal},saveNative);release.assertOwned()}finally{clearTimeout(timer);abort.abort()}
  let outcome='recovered_stopped';
  if(record.engineTransactionId){
   const engine=inspectServiceUpdate({installRoot:ctx.installRoot,transactionId:record.engineTransactionId});
   if(!['activated','rolled_back','recovered_stopped'].includes(engine.phase)){
    const result=await recoverServiceUpdate({installRoot:ctx.installRoot,publicKeyPem:ctx.pem,transactionId:record.engineTransactionId,timeoutMs,confirmStopped:()=>{release.assertOwned();return runtime.confirmStopped()}});outcome=result.status;
   }
  }
  release.assertOwned();unchanged(scope(stateDir,{allowInvalidCurrent:true}),record.plan);
  if(outcome==='recovered_stopped'){
   record.persistence=await runtime.finish(saveNative,{restoreEnabled:false});release.assertOwned();record.outcome=outcome;saveManaged(ctx,record,'recovered');
  }else saveManaged(ctx,record,'needs_recovery');
  return {...managedProjection(record),status:outcome};
 }finally{release()}
}
