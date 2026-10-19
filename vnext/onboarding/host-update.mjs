// Shared read-only Host upgrade review. Native inhibited start and candidate
// health are not implemented here; this module cannot stage, start or recover.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey} from 'node:crypto';
import {readDeployment} from './core.mjs';
import {activeRelease,verifySignedRelease} from '../host/installer.mjs';
import {inspectServiceUpdate} from '../host/service-update.mjs';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {normalizeConnector} from '../host/connect.mjs';
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
 const service={id:windows?raw.task_name:process.platform==='darwin'?raw.label:raw.unitName,installRoot:windows?raw.install_root:raw.installRoot,hostConfigFile:windows?raw.host_config_file:raw.hostConfigFile,publisherKeyFile:windows?raw.publisher_key_file:raw.trustPublicKeyFile,nodeBinary:windows?raw.node_binary:raw.nodeBinary};
 if(service.installRoot!==installRoot||service.hostConfigFile!==path.join(base,'device/host.json')||service.publisherKeyFile!==publisherFile||!absolute(service.nodeBinary)||typeof service.id!=='string'||!service.id)fail('host_update_service_binding_changed');
 const host=normalizeConnector(read(service.hostConfigFile)),identityFile=path.join(base,'device/identity.json'),identity=read(identityFile);
 if(identity.device_id!==host.host_id)fail('host_update_device_identity_changed');
 const preserved={hostConfiguration:hash(service.hostConfigFile),deviceIdentity:hash(identityFile)};
 for(const [name,file] of [['identityPrivateKey',path.join(base,'device/identity.pem')],['credential',host.token_file],['clientCertificate',host.client_cert_file],['clientPrivateKey',host.client_key_file],['gatewayTrust',host.gateway_ca_file]])if(file!==undefined){requirePrivateFile(file);preserved[name]=hash(file);}
 let active=null,current=null;
 try{active=activeRelease(installRoot,pem);if(!active)fail('no_active_host_release');current=verifySignedRelease(active.release_root,pem);}
 catch{if(!allowInvalidCurrent)fail('active_host_release_unavailable_or_changed');}
 return {stateDir,state,config,base,installRoot,pem,service,host,preserved,current,active,configurationSha256:hash(path.join(stateDir,'deployment.json')),serviceConfigurationSha256:hash(serviceFile)};
}
function completeHostRelease(release,computer){
 const suffix=process.platform==='win32'?'.exe':'',required=['host/private-storage.mjs','host/installer.mjs','host/launch.mjs','host/connect.mjs','bin/node'+suffix,'bin/codex'+suffix,...(computer?['bin/cua-driver'+suffix]:[])];
 if(required.some(name=>!release.manifest.files.some(entry=>entry.path===name&&(!name.startsWith('bin/')||entry.executable))))fail('complete_signed_host_update_required');
}
function lockObservation(ctx){
 const lock=path.join(ctx.installRoot,'.health-update-lock');if(!fs.existsSync(lock))return {status:'absent',transactionId:null};
 try{requirePrivateDirectory(lock);const owner=path.join(lock,'owner');if(requirePrivateFile(owner).size>128)fail('invalid_update_owner');const value=fs.readFileSync(owner,'utf8');return id(value)?{status:'present',transactionId:value}:{status:'unknown',transactionId:null};}
 catch{return {status:'unknown',transactionId:null};}
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
 const ctx=scope(stateDir,{allowInvalidCurrent:true}),lock=lockObservation(ctx),folder=path.join(ctx.installRoot,'update-transactions');let transactions=[];
 if(transactionId!==undefined)transactions=[transaction(ctx,transactionId)];
 else if(fs.existsSync(folder)){
  requirePrivateDirectory(folder);const names=fs.readdirSync(folder);if(names.length>1024)fail('host_update_transaction_limit');
  transactions=names.filter(name=>/^[a-f0-9]{32}\.json$/.test(name)).sort().map(name=>{
   const selected=name.slice(0,-5);try{return transaction(ctx,selected);}catch{return {transactionId:selected,status:'unverified',reason:'receipt_or_signed_generation_unavailable_or_changed',candidateHealth:'not_observed',service:'not_observed'};}
  });
 }
 return {schema:1,role:'host',status:!ctx.current||lock.status!=='absent'||transactions.some(row=>['needs_recovery','unverified'].includes(row.status))?'needs_recovery':'reported',current:{version:ctx.current?.version??null,manifestSha256:ctx.current?.sha256??null,signature:ctx.current?'verified':'unverified',...(!ctx.current?{reason:'active_release_unavailable_or_changed'}:{}),runtimeHealth:'not_observed'},lock,transactions,
  recovery:{status:'not_implemented',requires:['observe_owned_service_stopped_and_durably_restart_inhibited','verify_previous_signed_generation_and_transaction_ownership','restore_signed_bootstrap_without_replaying_uncertain_start']},accountAcceptance:'NOT RUN'};
}
export function planHostUpdate({stateDir,bundle,rollback=false}={}){
 const ctx=scope(stateDir);if(typeof rollback!=='boolean'||rollback&&bundle!==undefined)fail('host_update_select_bundle_or_rollback');
 let source=bundle;
 if(rollback){if(!version(ctx.active.previous))fail('no_rollback_generation');source=path.join(ctx.installRoot,'releases',ctx.active.previous);}
 if(!absolute(source))fail('absolute_host_update_bundle_required');
 const candidate=verifySignedRelease(source,ctx.pem);completeHostRelease(candidate,ctx.host.computer?.enabled===true);completeHostRelease(ctx.current,ctx.host.computer?.enabled===true);
 if(candidate.version===ctx.current.version)fail('distinct_host_update_version_required');
 const blockers=['managed_host_update_execution_not_implemented','durably_inhibited_native_candidate_start_required','real_candidate_exec_health_and_gateway_connection_identity_required'];
 const stableNode=path.join(ctx.installRoot,process.platform==='win32'?'node.exe':'node');
 if(ctx.service.nodeBinary!==stableNode)blockers.push('service_generation_node_pin_migration_required');
 const executable=fs.realpathSync(process.execPath),realInstall=fs.realpathSync(ctx.installRoot);
 if(executable===realInstall||executable.startsWith(realInstall+path.sep))blockers.push('independent_updater_runtime_required');
 const lock=lockObservation(ctx);if(lock.status!=='absent')blockers.push('existing_host_update_requires_receipt_inspection_and_reconciliation');
 if(ctx.state.steps.some(step=>['running','uncertain'].includes(step.status))||ctx.state.hostServiceMaintenance?.hasUncertainMutation)blockers.push('uncertain_deployment_action_requires_reconciliation');
 const plan={schema:1,role:'host',status:'blocked',action:rollback?'rollback':'update',stateDir,configurationSha256:ctx.configurationSha256,serviceConfigurationSha256:ctx.serviceConfigurationSha256,
  current:{version:ctx.current.version,manifestSha256:ctx.current.sha256},target:{version:candidate.version,manifestSha256:candidate.sha256,bundle:source},preservedEvidence:ctx.preserved,
  service:{id:ctx.service.id,runtime:ctx.service.nodeBinary===stableNode?'stable_signed_node':'generation_or_external_node',state:'not_observed',persistence:'not_observed'},blockers,
  prerequisites:['stop_and_durably_inhibit_only_verified_owned_service','start_candidate_without_enabling_login_boot_or_recovery_triggers','observe_real_candidate_exec_rpc_and_bound_gateway_identity','keep_inhibition_through_health_or_signed_rollback','review_service_config_and_native_permission_identity_migration'],
  installation:'NOT RUN',candidateHealth:'NOT RUN',nativePermissions:'NOT RUN',accountAcceptance:'NOT RUN'};
 return {...plan,reviewSha256:sha(JSON.stringify(plan))};
}
