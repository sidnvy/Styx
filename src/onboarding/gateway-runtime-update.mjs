// Offline, review-bound runtime changes. Core's authoritative deployment stays
// unchanged; only the signed Node generation and its execution journal move.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash,createPublicKey,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {readDeployment} from './core.mjs';
import {readGatewayRuntime,verifyGatewayRuntimeRelease} from './gateway-runtime.mjs';
import {gatewayServiceIdentity} from './gateway-service.mjs';
import {platformGatewayService} from './gateway-platform-services.mjs';
import {stageSignedRelease,activateRelease} from '../host/installer.mjs';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile,openPrivateFile,writePrivateFile} from '../host/private-storage.mjs';
import {observeLinuxGatewayProcesses} from '../host/linux-gateway-quiescence.mjs';

const fail=code=>{throw Error(code)};
const sum=bytes=>createHash('sha256').update(bytes).digest('hex');
const hash=file=>sum(fs.readFileSync(file));
const abs=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
const nodeName=()=>process.platform==='win32'?'node.exe':'node';
const runner=fileURLToPath(new URL('./gateway-runner.mjs',import.meta.url));
function read(file){requirePrivateFile(file);if(fs.statSync(file).size>1024*1024)fail('runtime_change_file_too_large');return JSON.parse(fs.readFileSync(file,'utf8'));}
function syncFile(file){const fd=fs.openSync(file,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function syncDirectory(dir){
 // Node does not expose a Windows directory FlushFileBuffers handle. Native
 // power-loss persistence remains unaccepted there; never label it tested.
 if(process.platform==='win32')return;
 const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
function syncRelease(root,verified){
 const directories=new Set([root]);
 for(const name of [...verified.manifest.files.map(e=>e.path),'manifest.json','manifest.sig']){
  const file=path.join(root,name);syncFile(file);let dir=path.dirname(file);while(dir.startsWith(root)){directories.add(dir);if(dir===root)break;dir=path.dirname(dir);}
 }
 for(const dir of [...directories].sort((a,b)=>b.length-a.length))syncDirectory(dir);
 syncDirectory(path.dirname(root));
}
function atomic(file,value){
 const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp,0o600);
 try{fs.writeFileSync(fd,typeof value==='string'||Buffer.isBuffer(value)?value:JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 try{fs.renameSync(tmp,file);syncDirectory(path.dirname(file));}finally{fs.rmSync(tmp,{force:true});}
}
function deployment(stateDir,{observationOnly=false}={}){
 if(!abs(stateDir))fail('absolute_state_directory_required');
 const observed=readDeployment(stateDir),config=read(path.join(stateDir,'deployment.json')),state=read(path.join(stateDir,'state.json'));
 if(config.mode!=='create-local'||!config.gateway.runtime)fail('independent_gateway_runtime_required');
 if(!observationOnly&&observed.gatewayRuntime.status==='running')fail('foreground_gateway_must_be_stopped');
 if(!observationOnly&&(state.steps.some(x=>['running','uncertain'].includes(x.status))||[...(state.maintenance??[]),...(state.gatewayMaintenance??[])].some(x=>['running','uncertain'].includes(x.status))))fail('uncertain_deployment_action_requires_reconciliation');
 const cfg=config.gateway.runtime;requirePrivateDirectory(cfg.baseDir);
 return {stateDir,config:cfg,deviceIngressConfigured:Object.hasOwn(config.gateway,'deviceIngress'),opensslConfigurationConfigured:Object.hasOwn(config.gateway,'opensslConfig'),state,configSha256:hash(path.join(stateDir,'deployment.json')),installRoot:path.join(cfg.baseDir,'install'),journal:path.join(cfg.baseDir,'runtime-change.json')};
}
function pending(scope){
 if(!fs.existsSync(scope.journal))return null;
 const record=read(scope.journal);if(record.schema!==1||!['completed','recovered','committing','prepared','staged'].includes(record.status))fail('invalid_runtime_change_journal');
 if(!/^[a-f0-9]{32}$/.test(record.id??'')||record.plan?.installRoot!==scope.installRoot||record.plan?.stateDir!==scope.stateDir||![record.plan.current?.version,record.plan.target?.version].every(v=>/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(v??'')))fail('invalid_runtime_change_journal');
 return ['completed','recovered'].includes(record.status)?null:record;
}
function requireCompatibleApplication(scope,verified){
 // Even a disabled entry is a strict deployment field that historical signed
 // readers cannot parse. Preserve the authority and require explicit removal
 // through the additional-entry rollback before selecting an older app.
 const compatible=verified.manifest.component==='gateway-application'&&verified.manifest.sourceContract>=2;
 if(scope.deviceIngressConfigured&&!compatible)fail('device_ingress_requires_compatible_gateway_application');
 if(scope.opensslConfigurationConfigured&&!compatible)fail('openssl_configuration_requires_compatible_gateway_application');
}
function targetRelease(scope,{bundle,rollback}){
 const pem=fs.readFileSync(path.join(scope.config.baseDir,'publisher.pem'),'utf8');
 let source=bundle;
 if(rollback===true){
  if(bundle!==undefined)fail('runtime_change_select_update_or_rollback');
  const pointer=read(path.join(scope.installRoot,'active.json'));
  if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(pointer.previous??''))fail('no_rollback_generation');
  source=path.join(scope.installRoot,'releases',pointer.previous);
 }else if(rollback!==undefined&&rollback!==false)fail('invalid_runtime_rollback_selection');
 if(!abs(source))fail('absolute_gateway_runtime_bundle_required');
 const verified=verifyGatewayRuntimeRelease(source,pem);
 requireCompatibleApplication(scope,verified);
 return {pem,source,verified};
}
export function planGatewayRuntimeChange({stateDir,bundle,rollback}={}){
 const scope=deployment(stateDir);if(pending(scope))fail('unfinished_runtime_change_requires_recovery');
 const active=readGatewayRuntime(scope.config),target=targetRelease(scope,{bundle,rollback});
 if(target.verified.sha256===active.manifestSha256)fail('runtime_change_has_no_effect');
 if(target.verified.version===active.version)fail('runtime_release_version_reuse_forbidden');
 const application=target.verified.manifest.component==='gateway-application';
 const plan={schema:1,stateDir,action:rollback===true?'rollback':'update',configSha256:scope.configSha256,installRoot:scope.installRoot,
  current:{version:active.version,manifestSha256:active.manifestSha256,nodeSha256:hash(active.nodeBinary),pointerSha256:hash(path.join(scope.installRoot,'active.json')),application:active.application,runner:active.runnerBinary??runner},
  target:{version:target.verified.version,manifestSha256:target.verified.sha256,bundle:target.source,application:application?'signed_application':'source_checkout_preview',runner:application?path.join(scope.installRoot,'releases',target.verified.version,target.verified.manifest.entrypoint):runner},
  changes:['signed_node_runtime',...(application?['signed_gateway_application']:[]),'active_release_pointer','runtime_receipt_and_execution_journal'],preserves:['deployment_configuration','gateway_identity','tls_certificate','credentials','device_approvals'],
  precondition:'gateway_service_uninstalled_and_no_runtime_processes',nativeRebootAcceptance:'NOT RUN'};
 return {...plan,reviewSha256:sum(JSON.stringify(plan))};
}
function lock(stateDir,{transactionId,recover=false}={}){
 if(!abs(stateDir))fail('absolute_state_directory_required');
 requirePrivateDirectory(stateDir);
 const file=path.join(stateDir,'advance.lock'),guardFile=path.join(stateDir,'gateway-runtime-recovery.lock');
 const held=[];
 const acquire=target=>{
  let fd;try{fd=openPrivateFile(target,0o600);}catch{fail('onboarding_busy_or_interrupted_lock');}
  const identity=fs.fstatSync(fd),token=randomBytes(32).toString('hex');
  const value=JSON.stringify({schema:1,kind:'gateway-runtime-change',pid:process.pid,transactionId,token})+'\n';
  const handle={target,fd,identity,value};
  // Retain a partially written/unsynced lock for explicit inspection. Never
  // guess ownership from its path alone if durable initialization failed.
  try{fs.writeFileSync(fd,value);fs.fsyncSync(fd);syncDirectory(stateDir);}
  catch{fs.closeSync(fd);fail('onboarding_busy_or_interrupted_lock');}
  held.push(handle);return handle;
 };
 const release=()=>{
  let changed=false;
  for(const handle of held.reverse()){
   try{
    const current=requirePrivateFile(handle.target);
    if(current.ino!==handle.identity.ino||current.dev!==handle.identity.dev||fs.readFileSync(handle.target,'utf8')!==handle.value){changed=true;continue;}
    fs.unlinkSync(handle.target);syncDirectory(stateDir);
   }catch{changed=true;}
   finally{fs.closeSync(handle.fd);}
  }
  held.length=0;
  if(changed)fail('runtime_change_lock_ownership_changed');
 };
 try{
  // A separate exclusive guard serializes *the whole recovery*, before any
  // reading/adoption of advance.lock. Checking a dead PID and then unlinking
  // alone lets two recoverers remove one another's newly live lock. A guard
  // left by process death is intentionally not stolen, even when its PID died.
  if(recover)acquire(guardFile);
  else{
   // An interrupted recovery guard also blocks a fresh update; do not bypass
   // an ownership question merely because advance.lock is temporarily absent.
   try{fs.lstatSync(guardFile);fail('onboarding_busy_or_interrupted_lock');}
   catch(error){if(error.code!=='ENOENT')throw error;}
  }
  if(recover&&fs.existsSync(file)){
   let prior,identity,raw;
   try{identity=requirePrivateFile(file);raw=fs.readFileSync(file,'utf8');prior=JSON.parse(raw);}
   catch{fail('onboarding_busy_or_interrupted_lock');}
   if(prior.schema!==1||prior.kind!=='gateway-runtime-change'||prior.transactionId!==transactionId||!Number.isSafeInteger(prior.pid)||prior.pid<1||prior.token!==undefined&&!/^[a-f0-9]{64}$/.test(prior.token))fail('onboarding_busy_or_interrupted_lock');
   let dead=false;try{process.kill(prior.pid,0);}catch(error){if(error.code==='ESRCH')dead=true;}
   if(!dead)fail('onboarding_busy_or_interrupted_lock');
   const current=requirePrivateFile(file);
   if(current.ino!==identity.ino||current.dev!==identity.dev||raw!==JSON.stringify(prior)+'\n'||fs.readFileSync(file,'utf8')!==raw)fail('onboarding_busy_or_interrupted_lock');
   fs.unlinkSync(file);syncDirectory(stateDir);
  }
  acquire(file);
  return release;
 }catch(error){
  // Release only successfully initialized locks acquired by this invocation.
  // A foreign advance.lock or pre-existing recovery guard remains untouched.
  try{release();}catch{fail('runtime_change_lock_ownership_changed');}
  throw error;
 }
}

export function readGatewayRuntimeChange({stateDir}={}){
 const scope=deployment(stateDir,{observationOnly:true});
 // The guard may represent live recovery or an interrupted owner. Never turn
 // its mere existence (including foreign/corrupt contents) into a clean state.
 let guarded=false;try{fs.lstatSync(path.join(stateDir,'gateway-runtime-recovery.lock'));guarded=true;}catch(error){if(error.code!=='ENOENT')guarded=true;}
 if(!fs.existsSync(scope.journal))return {status:guarded?'recovery_required':'none',...(guarded?{recoveryGuard:'present_requires_owner_inspection'}:{}),nativeRebootAcceptance:'NOT RUN'};
 pending(scope);const record=read(scope.journal);
 if(guarded)return {status:'recovery_required',transactionId:record.id,phase:record.status,recoveryGuard:'present_requires_owner_inspection',nativeRebootAcceptance:'NOT RUN'};
 return {status:['completed','recovered'].includes(record.status)?record.status:'recovery_required',transactionId:record.id,phase:record.status,action:record.plan.action,fromVersion:record.plan.current.version,toVersion:record.plan.target.version,nativeRebootAcceptance:'NOT RUN'};
}

// No negative observation is inferred from a failed command, missing bus, or
// inaccessible argv. Linux may instead prove current executable inode exclusion
// for an inaccessible exe link; it still requires complete process arguments.
export function observeGatewayRuntimeQuiescence({stateDir,installRoot},{run=execFileSync,home=os.homedir()}={}){
 const name=gatewayServiceIdentity(stateDir),nodeBinary=path.join(installRoot,nodeName());
 const descriptor={stateDir,nodeBinary,runner,identityHash:sum(stateDir)};
 if(process.platform==='linux'){
  const file=path.join(home,'.config/systemd/user',name);
  let definitionPresent=false;try{fs.lstatSync(file);definitionPresent=true}catch(error){if(error.code!=='ENOENT')fail('gateway_service_quiescence_unknown')}
  if(definitionPresent)fail('gateway_service_definition_must_be_uninstalled');
  let text;try{text=String(run('/usr/bin/systemctl',['--user','show',name,'--property=LoadState,ActiveState,MainPID'],{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']}));}catch{fail('gateway_service_quiescence_unknown');}
  const values=Object.fromEntries(text.trim().split('\n').map(s=>s.split('=')));
  if(values.LoadState!=='not-found'||values.ActiveState!=='inactive'||values.MainPID!=='0')fail('gateway_service_definition_must_be_uninstalled');
  const processObservation=observeLinuxGatewayProcesses({stateDir,installRoot});
  return {service:'not_installed',processes:'none',checkedAt:new Date().toISOString(),processObservation};
 }else{
  let service;try{service=platformGatewayService({action:'status',descriptor},{run,home});}catch{fail('gateway_service_quiescence_unknown');}
  if(service.status!=='not_installed')fail('gateway_service_definition_must_be_uninstalled');
  if(process.platform==='darwin'){
   let text;try{text=String(run('/bin/ps',['-ax','-o','pid=,uid=,command='],{encoding:'utf8',timeout:10000,maxBuffer:8*1024*1024}));}catch{fail('gateway_process_quiescence_unknown');}
   for(const line of text.split('\n').filter(Boolean)){
    const match=/^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line);if(!match)fail('gateway_process_quiescence_unknown');
    if(Number(match[2])===process.getuid()&&(match[3].includes(installRoot)||Number(match[1])!==process.pid&&match[3].includes(stateDir)))fail('gateway_runtime_process_still_running');
   }
  }else if(process.platform==='win32'){
   const script="$ErrorActionPreference='Stop';@(Get-CimInstance Win32_Process -Filter \"Name='node.exe'\"|Select-Object ProcessId,ExecutablePath,CommandLine)|ConvertTo-Json -Compress";
   let rows;try{const raw=String(run('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:30000,maxBuffer:8*1024*1024,windowsHide:true}));rows=JSON.parse(raw||'[]');if(!Array.isArray(rows))rows=[rows];}catch{fail('gateway_process_quiescence_unknown');}
   for(const row of rows){if(!row.ExecutablePath||!row.CommandLine)fail('gateway_process_quiescence_unknown');if(row.ExecutablePath.toLowerCase().startsWith((installRoot+path.sep).toLowerCase())||row.ProcessId!==process.pid&&row.CommandLine.toLowerCase().includes(stateDir.toLowerCase()))fail('gateway_runtime_process_still_running');}
  }else fail('gateway_runtime_offline_change_platform_not_supported');
 }
 return {service:'not_installed',processes:'none',checkedAt:new Date().toISOString()};
}
function quiet(scope,stateDir,observe){
 const result=observe({stateDir,installRoot:scope.installRoot});
 if(result?.service!=='not_installed'||result?.processes!=='none')fail('gateway_runtime_quiescence_not_confirmed');
 return result;
}
function checkpoint(scope,record,status,afterCheckpoint){record.status=status;record.updatedAt=new Date().toISOString();atomic(scope.journal,record);afterCheckpoint?.(status);}
function archive(scope,record){
 const folder=path.join(scope.config.baseDir,'runtime-changes');ensurePrivateDirectory(folder);
 const file=path.join(folder,record.id+'.json');if(!fs.existsSync(file))atomic(file,record);
}
function receipt(scope,result){
 atomic(path.join(scope.config.baseDir,'runtime-receipt.json'),{schema:1,...result,exec:'NOT INSTALLED',cua:'NOT INSTALLED',service:'NOT INSTALLED'});
 atomic(path.join(scope.config.baseDir,'runtime-state.json'),{schema:1,status:'prepared',version:result.version});
}
export function applyGatewayRuntimeChange({stateDir,plan,authorize=false}={}, {observeQuiescence=observeGatewayRuntimeQuiescence,afterCheckpoint}={}){
 if(authorize!==true)fail('gateway_runtime_change_authorization_required');
 if(!plan||plan.stateDir!==stateDir||!['update','rollback'].includes(plan.action))fail('invalid_gateway_runtime_change_plan');
 const id=randomBytes(16).toString('hex'),release=lock(stateDir,{transactionId:id});
 try{
  const reviewed=planGatewayRuntimeChange({stateDir,...(plan.action==='rollback'?{rollback:true}:{bundle:plan.target?.bundle})});
  if(JSON.stringify(reviewed)!==JSON.stringify(plan))fail('gateway_runtime_change_review_stale');
  const scope=deployment(stateDir),observation=quiet(scope,stateDir,observeQuiescence),active=readGatewayRuntime(scope.config),target=targetRelease(scope,{bundle:plan.target.bundle});
  const backup=path.join(scope.config.baseDir,'runtime-node-backup-'+id);
  writePrivateFile(backup,fs.readFileSync(active.nodeBinary),{mode:0o700});syncFile(backup);syncDirectory(scope.config.baseDir);
  const record={schema:1,id,status:'prepared',plan,configSha256:scope.configSha256,backupNode:backup,backupNodeSha256:hash(backup),backupPointer:fs.readFileSync(path.join(scope.installRoot,'active.json')).toString('base64'),quiescence:observation,startedAt:new Date().toISOString()};
  checkpoint(scope,record,'prepared',afterCheckpoint);
  stageSignedRelease({sourceDir:target.source,installRoot:scope.installRoot,publicKeyPem:target.pem});
  const staged=verifyGatewayRuntimeRelease(path.join(scope.installRoot,'releases',plan.target.version),target.pem);if(staged.sha256!==plan.target.manifestSha256)fail('gateway_runtime_change_target_changed');
  syncRelease(path.join(scope.installRoot,'releases',plan.target.version),staged);
  checkpoint(scope,record,'staged',afterCheckpoint);
  quiet(scope,stateDir,observeQuiescence);
  if(hash(path.join(scope.installRoot,'active.json'))!==plan.current.pointerSha256||hash(active.nodeBinary)!==plan.current.nodeSha256)fail('gateway_runtime_change_review_stale');
  checkpoint(scope,record,'committing',afterCheckpoint);
  const tmp=active.nodeBinary+'.switch-'+id;
  writePrivateFile(tmp,fs.readFileSync(path.join(scope.installRoot,'releases',plan.target.version,'bin',nodeName())),{mode:0o700});syncFile(tmp);fs.renameSync(tmp,active.nodeBinary);syncDirectory(scope.installRoot);
  afterCheckpoint?.('node_switched');
  activateRelease(scope.installRoot,plan.target.version,target.pem);
  syncFile(path.join(scope.installRoot,'active.json'));syncDirectory(scope.installRoot);
  afterCheckpoint?.('pointer_switched');
  const verified=readGatewayRuntime(scope.config);if(verified.manifestSha256!==plan.target.manifestSha256)fail('gateway_runtime_change_commit_verification_failed');
  receipt(scope,verified);
  checkpoint(scope,record,'completed',afterCheckpoint);archive(scope,record);fs.rmSync(backup,{force:true});
  return {status:'completed',transactionId:id,action:plan.action,version:verified.version,manifestSha256:verified.manifestSha256,gatewayIdentity:'preserved',service:'not_installed',nativeRebootAcceptance:'NOT RUN'};
 }finally{release();}
}
export function recoverGatewayRuntimeChange({stateDir,transactionId,authorize=false}={}, {observeQuiescence=observeGatewayRuntimeQuiescence}={}){
 if(authorize!==true)fail('gateway_runtime_change_authorization_required');
 if(!/^[a-f0-9]{32}$/.test(transactionId??''))fail('invalid_runtime_change_transaction');
 const release=lock(stateDir,{transactionId,recover:true});
 try{
  const scope=deployment(stateDir),record=pending(scope);if(!record||record.id!==transactionId||record.configSha256!==scope.configSha256)fail('runtime_change_recovery_binding_mismatch');
  if(record.backupNode!==path.join(scope.config.baseDir,'runtime-node-backup-'+record.id)||hash(record.backupNode)!==record.backupNodeSha256||record.backupNodeSha256!==record.plan.current.nodeSha256)fail('runtime_change_backup_changed');
  requirePrivateFile(record.backupNode);quiet(scope,stateDir,observeQuiescence);
  const pem=fs.readFileSync(path.join(scope.config.baseDir,'publisher.pem'),'utf8');
  if(sum(createPublicKey(pem).export({type:'spki',format:'der'}))!==scope.config.publisherSha256)fail('publisher_fingerprint_mismatch');
  const previous=verifyGatewayRuntimeRelease(path.join(scope.installRoot,'releases',record.plan.current.version),pem);
  requireCompatibleApplication(scope,previous);
  if(previous.sha256!==record.plan.current.manifestSha256)fail('runtime_change_previous_release_changed');
  if(previous.manifest.files.find(e=>e.path==='bin/'+nodeName()).sha256!==record.backupNodeSha256)fail('runtime_change_backup_changed');
  const pointer=Buffer.from(record.backupPointer,'base64');if(sum(pointer)!==record.plan.current.pointerSha256)fail('runtime_change_backup_changed');
  const oldPointer=JSON.parse(pointer);if(oldPointer.version!==record.plan.current.version||oldPointer.manifest_sha256!==previous.sha256)fail('runtime_change_backup_changed');
  const currentPointer=read(path.join(scope.installRoot,'active.json'));
  if(![record.plan.current.version,record.plan.target.version].includes(currentPointer.version))fail('runtime_change_active_generation_changed');
  if(currentPointer.manifest_sha256!==(currentPointer.version===record.plan.current.version?record.plan.current.manifestSha256:record.plan.target.manifestSha256))fail('runtime_change_active_generation_changed');
  const currentNode=path.join(scope.installRoot,nodeName()),tmp=currentNode+'.recover-'+record.id;
  if(fs.existsSync(tmp))fail('runtime_change_recovery_file_requires_inspection');
  writePrivateFile(tmp,fs.readFileSync(record.backupNode),{mode:0o700});syncFile(tmp);fs.renameSync(tmp,currentNode);syncDirectory(scope.installRoot);atomic(path.join(scope.installRoot,'active.json'),pointer);
  const result=readGatewayRuntime(scope.config);if(result.manifestSha256!==record.plan.current.manifestSha256)fail('runtime_change_recovery_verification_failed');
  receipt(scope,result);
  checkpoint(scope,record,'recovered');archive(scope,record);fs.rmSync(record.backupNode,{force:true});
  return {status:'recovered',transactionId:record.id,version:result.version,gatewayIdentity:'preserved',service:'not_installed',nativeRebootAcceptance:'NOT RUN'};
 }finally{release();}
}
