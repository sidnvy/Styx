// Reviewed offline first-device ingress change. It preserves all identities and
// credentials; a new self-signed certificate is an explicit TLS trust change.
// Existing peers require a separate revalidation workflow, never silent repair.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import {createHash,createPrivateKey,createPublicKey,randomBytes,X509Certificate} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile,ensurePrivateDirectory,openPrivateFile,writePrivateFile} from '../host/private-storage.mjs';
import {validateDeployment,localGatewayAddresses} from './deployment-config.mjs';
import {readGatewayDeployment} from './gateway-deployment-reader.mjs';
import {observeGatewayRuntimeQuiescence} from './gateway-runtime-update.mjs';
import {observeHostService} from './service-lifecycle.mjs';
import {acquireRecoveryGuard} from './recovery-guard.mjs';

const kind='first-device-ipv4-ingress-v1',sha=value=>createHash('sha256').update(value).digest('hex');
const fail=code=>{throw Error(code)},encode=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
const lockNames=['advance.lock','background.lock','capabilities.lock','onboarding-plugin.lock','account-acceptance.lock'];
const ownerToken=randomBytes(32).toString('hex'),active=new Set();
function keys(value,allowed){if(!object(value)||Object.keys(value).some(key=>!allowed.includes(key)))fail('ingress_change_invalid_options')}
function absolute(value){if(typeof value!=='string'||!path.isAbsolute(value)||path.normalize(value)!==value||/[\x00-\x1f\x7f]/.test(value))fail('ingress_change_absolute_path_required');return value}
function exists(file){try{fs.lstatSync(file);return true}catch(error){if(error.code==='ENOENT')return false;throw error}}
function bytes(file){if(requirePrivateFile(file).size>2*1024*1024)fail('ingress_change_file_too_large');return fs.readFileSync(file)}
const read=file=>JSON.parse(bytes(file));
function syncDirectory(dir){if(process.platform==='win32')return;const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
function atomic(file,data){const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp,0o600);try{fs.writeFileSync(fd,data);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}try{fs.renameSync(tmp,file);syncDirectory(path.dirname(file))}finally{if(exists(tmp))fs.unlinkSync(tmp)}}
function inventory(directory,excluded,result){
 if(!exists(directory))return;requirePrivateDirectory(directory);
 for(const name of fs.readdirSync(directory).sort()){
  const file=path.join(directory,name),info=fs.lstatSync(file);if(info.isSymbolicLink())fail('ingress_change_preserved_path_redirected');
  if(info.isDirectory())inventory(file,excluded,result);else if(!excluded.has(file))result.push({path:file,sha256:sha(bytes(file))});
 }
}
function snapshot(d){
 absolute(d);requirePrivateDirectory(d);
 const gateway=readGatewayDeployment(d),config=gateway.config,state=read(path.join(d,'state.json')),root=path.join(d,'gateway');
 const files=[],add=(name,file)=>{const before=bytes(file);files.push({name,path:file,before});return JSON.parse(before)};
 add('deployment',path.join(d,'deployment.json'));add('runtime',path.join(root,'runtime.json'));add('owner',path.join(root,'owner.json'));
 files.push({name:'certificate',path:path.join(root,'certificate.pem'),before:bytes(path.join(root,'certificate.pem'))});
 const blockers=[];
 if((config.gateway.listenHost??'127.0.0.1')!=='127.0.0.1')blockers.push('existing_remote_entry_requires_peer_trust_revalidation');
 if(state.steps.some(step=>['running','uncertain'].includes(step.status))||[...(state.maintenance??[]),...(state.gatewayMaintenance??[])].some(step=>['running','uncertain'].includes(step.status)))blockers.push('uncertain_deployment_requires_reconciliation');
 let localDevice=null;
 if(config.host&&exists(config.host.baseDir)){
  const base=config.host.baseDir;requirePrivateDirectory(base);
  const enrollmentFile=path.join(base,'enrollment.json'),hostFile=path.join(base,'device/host.json'),caFile=path.join(base,'gateway-ca.pem');
  if(!state.steps.some(step=>step.id==='host.prepare'&&step.status==='succeeded'))blockers.push('partial_host_preparation_requires_reconciliation');
  else{
   const enrollment=add('hostEnrollment',enrollmentFile);
   if(enrollment.gateway_url!==config.gateway.url||enrollment.gateway_ca_file!==caFile||enrollment.storage_dir!==path.join(base,'device'))fail('ingress_change_host_enrollment_binding_changed');
   if(!bytes(caFile).equals(files.find(file=>file.name==='certificate').before))fail('ingress_change_host_tls_binding_changed');
   files.push({name:'hostCertificate',path:caFile,before:bytes(caFile)});
   if(exists(hostFile)){
    const host=add('host',hostFile),identity=read(path.join(base,'device/identity.json'));
    const privateKey=path.join(base,'device/identity.pem'),publicKey=createPublicKey(bytes(privateKey));
    const expected=new URL(config.gateway.url);expected.protocol='wss:';
    if(host.gateway_ws_url!==expected.href||host.gateway_ca_file!==caFile||host.host_id!==identity.device_id||identity.fingerprint!==sha(publicKey.export({type:'spki',format:'der'}))||host.token_file!==path.join(base,'device/host.token'))fail('ingress_change_host_identity_binding_changed');
    bytes(host.token_file);localDevice={id:identity.device_id,fingerprint:identity.fingerprint};
   }
  }
 }
 const databaseFile=path.join(root,'enrollment/state.json');
 if(exists(databaseFile)){
  const db=read(databaseFile);
  if(db.version!==1||!Array.isArray(db.devices)||!Array.isArray(db.pending)||!Array.isArray(db.invitations))fail('ingress_change_enrollment_database_invalid');
  if(db.devices.some(device=>device.status==='approved'&&(device.id!==localDevice?.id||device.fingerprint!==localDevice?.fingerprint)))blockers.push('approved_remote_devices_require_trust_revalidation');
  if(db.pending.some(item=>item.status==='pending'&&(!Number.isFinite(item.exp)||item.exp>Date.now())||item.status==='approved'&&(!Number.isFinite(item.claim_expires_at)||item.claim_expires_at>Date.now()))||db.invitations.some(item=>!item.used&&(!Number.isFinite(item.exp)||item.exp>Date.now())))blockers.push('outstanding_pairing_requires_close_or_expiry_reconciliation');
 }
 // Current tunnel/plugin implementations pin loopback. Until their owner-origin
 // adapters support this transaction, refuse to break an existing chat setup.
 if(exists(path.join(d,'tunnel/connection.json'))||exists(path.join(d,'onboarding-plugin.json')))blockers.push('chat_entry_requires_owned_origin_migration_support');
 for(const name of ['background','capabilities']){
  const file=path.join(d,name+'.json');if(!exists(file))continue;
  const value=add(name,file);
  if(value.schema!==1||value.configSha256!==state.configSha256)fail('ingress_change_auxiliary_binding_changed');
  if(['running','uncertain','configuring'].includes(value.status)&&name==='capabilities'||name==='background'&&(value.status==='configuring'||!Array.isArray(value.operations)||value.operations.some(item=>['running','uncertain'].includes(item.status))))blockers.push('uncertain_auxiliary_operation_requires_reconciliation');
 }
 add('state',path.join(d,'state.json'));
 for(const step of state.steps.filter(step=>step.status==='succeeded'))for(const value of Object.values(step.evidence??{})){
  if(object(value)&&typeof value.path==='string'&&typeof value.sha256==='string'&&sha(bytes(value.path))!==value.sha256)fail('ingress_change_completed_evidence_changed');
 }
 const excluded=new Set(files.map(file=>file.path)),preserved=[];
 for(const runtimeRoot of [config.host?.baseDir,config.gateway.runtime?.baseDir].filter(Boolean)){
  for(const name of ['.health-update-lock','.health-operation-lock','.health-recovery-guard'])if(exists(path.join(runtimeRoot,'install',name)))blockers.push('runtime_update_requires_reconciliation');
 }
 if(config.gateway.runtime&&exists(config.gateway.runtime.baseDir)){
  for(const name of ['publisher.pem','runtime-state.json','runtime-receipt.json','runtime-change.json','install/active.json']){
   const file=path.join(config.gateway.runtime.baseDir,name);if(!exists(file))continue;
   if(name==='runtime-change.json'&&!['completed','recovered'].includes(read(file).status))blockers.push('gateway_runtime_update_requires_reconciliation');
   preserved.push({path:file,sha256:sha(bytes(file))});
  }
 }
 inventory(root,excluded,preserved);
 if(config.host&&exists(config.host.baseDir)){
  inventory(path.join(config.host.baseDir,'device'),excluded,preserved);
  for(const name of ['service.json','publisher.pem','setup-state.json','setup-receipt.json','install/active.json']){
   const file=path.join(config.host.baseDir,name);if(exists(file))preserved.push({path:file,sha256:sha(bytes(file))});
  }
 }
 for(const name of ['onboarding-plugin.json','account-acceptance.json']){const file=path.join(d,name);if(exists(file))preserved.push({path:file,sha256:sha(bytes(file))})}
 inventory(path.join(d,'tunnel'),excluded,preserved);
 return {d,config,state,files,preserved,blockers,localDevice};
}
function proposed(s,listenHost,certificatePem){
 const config=structuredClone(s.config);config.gateway={...config.gateway,url:'https://'+listenHost+':'+new URL(config.gateway.url).port,listenHost,allowRemoteHosts:true};validateDeployment(config,{checkNetwork:false});
 const after=new Map();after.set('deployment',encode(config));after.set('certificate',Buffer.from(certificatePem));
 for(const file of s.files){
  if(after.has(file.name)||file.name==='state')continue;
  const value=JSON.parse(file.name==='hostCertificate'?'{}':file.before);
  if(file.name==='runtime'){value.url=config.gateway.url;value.listenHost=listenHost}
  if(file.name==='owner')value.gateway_url=config.gateway.url;
  if(file.name==='hostEnrollment')value.gateway_url=config.gateway.url;
  if(file.name==='host'){const url=new URL(config.gateway.url);url.protocol='wss:';value.gateway_ws_url=url.href}
  if(file.name==='background'||file.name==='capabilities')value.configSha256=sha(after.get('deployment'));
  if(file.name==='background'){value.status='needs_attention';value.reason='gateway_entry_changed_requires_verification'}
  after.set(file.name,file.name==='hostCertificate'?Buffer.from(certificatePem):encode(value));
 }
 const state=structuredClone(s.state);state.configSha256=sha(after.get('deployment'));
 for(const step of state.steps){
  for(const value of Object.values(step.evidence??{}))if(object(value)&&typeof value.path==='string'){
   const file=s.files.find(file=>file.path===value.path);if(file&&after.has(file.name))value.sha256=sha(after.get(file.name));
  }
  if(['gateway.start','gateway.verify','host.doctor','host.service.status'].includes(step.id)){step.status='pending';delete step.evidence;delete step.error}
 }
 if(state.onboardingDecisions?.background?.configSha256===s.state.configSha256)state.onboardingDecisions.background.configSha256=state.configSha256;
 after.set('state',encode(state));return s.files.map(file=>after.get(file.name));
}
function build(d,listenHost,reviewNonce,certificatePem,adapters={}){
 const s=snapshot(d);
 if(net.isIP(listenHost)!==4||listenHost==='0.0.0.0'||listenHost.startsWith('127.')||!(adapters.addresses??localGatewayAddresses)().includes(listenHost))fail('ingress_change_exact_owned_ipv4_required');
 const keyPath=path.join(d,'gateway/private-key.pem'),key=createPrivateKey(bytes(keyPath));
 if(certificatePem===undefined)certificatePem=String((adapters.run??execFileSync)(s.config.gateway.openssl,['req','-x509','-key',keyPath,'-sha256','-days','30','-subj','/CN=Styx local Gateway','-addext','subjectAltName=IP:'+listenHost],{encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:20000,maxBuffer:16384}));
 if(typeof certificatePem!=='string'||Buffer.byteLength(certificatePem)>16384)fail('ingress_change_candidate_certificate_invalid');
 const cert=new X509Certificate(certificatePem),old=new X509Certificate(s.files.find(file=>file.name==='certificate').before);
 if(certificatePem.trim()!==cert.toString().trim()||!cert.checkPrivateKey(key)||!cert.verify(createPublicKey(key))||cert.subjectAltName!=='IP Address:'+listenHost||!cert.ca||Date.parse(cert.validFrom)>Date.now()+60000||Date.parse(cert.validTo)<=Date.now()+86400000||Date.parse(cert.validTo)>Date.now()+31*86400000)fail('ingress_change_candidate_certificate_invalid');
 const after=proposed(s,listenHost,certificatePem),body={schema:1,kind,stateDir:d,reviewNonce,listenHost,origin:'https://'+listenHost+':'+new URL(s.config.gateway.url).port,
  status:s.blockers.length?'blocked':'reviewable',blockers:s.blockers,certificatePem,
  tls:{beforeSha256:sha(old.raw),afterSha256:sha(cert.raw),publicKeySha256:sha(cert.publicKey.export({type:'spki',format:'der'})),identityChange:'certificate_reissued_same_private_key',peerTrust:'explicit_reverification_required',validTo:new Date(cert.validTo).toISOString()},
  changes:s.files.map((file,i)=>({name:file.name,path:file.path,beforeSha256:sha(file.before),afterSha256:sha(after[i])})),preserved:s.preserved,
  requires:['gateway_and_host_stopped_without_automatic_restart','no_foreground_owner','old_and_new_port_exclusive_reservation','explicit_exact_plan_authorization','restart_and_real_tls_and_host_verification'],
  remoteUsable:false,remoteReachability:'NOT VERIFIED',firewallMutation:'NONE',networkScope:'single_owned_interface_address_all_sources_with_styx_authentication',accountAcceptance:'REQUIRED AGAIN'};
 return {s,after,plan:{...body,reviewSha256:sha(JSON.stringify(body))}};
}
export function planDeviceIngressChange(d,options={},adapters={}){keys(options,['listenHost']);return build(d,options.listenHost,randomBytes(16).toString('hex'),undefined,adapters).plan}
function directory(d,id){if(!/^[a-f0-9]{64}$/.test(id??''))fail('ingress_change_transaction_id_invalid');return path.join(absolute(d),'ingress-changes',id)}
function comparePlan(a,b){if(JSON.stringify(a)!==JSON.stringify(b))fail('ingress_change_reviewed_plan_changed')}
function checkPreserved(preserved){for(const item of preserved)if(sha(bytes(item.path))!==item.sha256)fail('ingress_change_preserved_identity_or_credentials_changed')}
async function quiet(d,config,adapters){
 if(exists(path.join(d,'foreground.lock'))||exists(path.join(d,'tunnel/owner.lock')))fail('ingress_change_foreground_or_tunnel_owner_present');
 const root=config.gateway.runtime?.baseDir??config.host?.baseDir;if(!root)fail('ingress_change_runtime_binding_required');
 const observer=adapters.observeGateway??observeGatewayRuntimeQuiescence;
 const observed=await observer({stateDir:d,installRoot:path.join(root,'install')});
 if(observed?.service!=='not_installed'||observed?.processes!=='none')fail('ingress_change_gateway_quiescence_required');
 if(config.host&&exists(path.join(config.host.baseDir,'service.json'))){
  const host=await (adapters.observeHost??observeHostService)({serviceConfigFile:path.join(config.host.baseDir,'service.json')});
  if(host?.status!=='reported'||host.installed!==false||!['stopped','not_installed'].includes(host.state))fail('ingress_change_host_quiescence_required');
  if(config.gateway.runtime){const processCheck=await observer({stateDir:d,installRoot:path.join(config.host.baseDir,'install')});if(processCheck?.service!=='not_installed'||processCheck?.processes!=='none')fail('ingress_change_host_process_quiescence_required')}
 }
}
async function reserve(config,listenHost){
 const held=[];
 try{
  for(const host of new Set([config.gateway.listenHost??'127.0.0.1',listenHost])){
   const server=net.createServer(socket=>socket.destroy());
   await new Promise((resolve,reject)=>{server.once('error',reject);server.listen({host,port:Number(new URL(config.gateway.url).port),exclusive:true},resolve)});held.push(server);
  }
 }catch{for(const server of held)await new Promise(resolve=>server.close(resolve));fail('ingress_change_listener_running_or_address_unavailable')}
 return async()=>{for(const server of held)await new Promise(resolve=>server.close(resolve))};
}
function locks(d,id,prior){
 const held=[];
 try{
  for(const name of lockNames){
   const file=path.join(d,name);let fd,value;
   if(exists(file)){
    if(!prior?.[name])fail('ingress_change_foreign_or_interrupted_lock');
    const info=requirePrivateFile(file),old=read(file),expected=prior[name];
    if(String(info.ino)!==expected.ino||String(info.dev)!==expected.dev||old.token!==expected.token||old.kind!==kind||old.transactionId!==id)fail('ingress_change_lock_identity_changed');
    let dead=false;try{process.kill(old.pid,0)}catch(error){dead=error.code==='ESRCH'}
    if(!(old.pid===process.pid&&old.ownerToken===ownerToken)&&!dead)fail('ingress_change_live_or_unknown_lock_owner');
    fd=fs.openSync(file,'r+');const opened=fs.fstatSync(fd);
    if(opened.ino!==info.ino||opened.dev!==info.dev){fs.closeSync(fd);fail('ingress_change_lock_identity_changed')}
    value={...old,pid:process.pid,ownerToken};fs.ftruncateSync(fd,0);
   }else{
    fd=openPrivateFile(file,0o600);value={kind,transactionId:id,pid:process.pid,ownerToken,token:randomBytes(32).toString('hex')};
   }
   fs.writeFileSync(fd,encode(value));fs.fsyncSync(fd);const info=fs.fstatSync(fd);held.push({name,file,fd,value,info});
  }
 }catch(error){for(const entry of held){fs.closeSync(entry.fd);if(!prior?.[entry.name])fs.unlinkSync(entry.file)}throw error}
 const identity=Object.fromEntries(held.map(entry=>[entry.name,{ino:String(entry.info.ino),dev:String(entry.info.dev),token:entry.value.token}]));syncDirectory(d);
 return {identity,close(retain=false){for(const entry of held.reverse())try{const current=requirePrivateFile(entry.file);if(!retain){if(current.ino!==entry.info.ino||current.dev!==entry.info.dev||read(entry.file).token!==entry.value.token)fail('ingress_change_lock_identity_changed');fs.unlinkSync(entry.file)}}finally{fs.closeSync(entry.fd)}syncDirectory(d)}};
}
function publicResult(journal){return {schema:1,kind,transactionId:journal.plan.reviewSha256,status:journal.status,origin:journal.plan.origin,tls:journal.plan.tls,identityAndCredentials:'preserved',remoteUsable:false,remoteReachability:'NOT VERIFIED',serviceMutation:'NONE',firewallMutation:'NONE',accountAcceptance:'REQUIRED AGAIN'}}
export async function applyDeviceIngressChange(d,options={},adapters={}){
 keys(options,['plan','authorize']);if(options.authorize!==true||!object(options.plan)||!/^[a-f0-9]{32}$/.test(options.plan.reviewNonce??''))fail('ingress_change_explicit_reviewed_plan_required');
 const reviewed=structuredClone(options.plan),first=build(d,reviewed.listenHost,reviewed.reviewNonce,reviewed.certificatePem,adapters);comparePlan(reviewed,first.plan);
 if(reviewed.blockers.length)fail('ingress_change_plan_blocked');
 const id=reviewed.reviewSha256,dir=directory(d,id);if(active.has(id)||exists(dir))fail('ingress_change_transaction_exists_no_replay');
 const ownership=locks(d,id);active.add(id);let releasePorts,journal,attempted=false;
 try{
  await quiet(d,first.s.config,adapters);releasePorts=await (adapters.reservePorts??reserve)(first.s.config,reviewed.listenHost);
  const current=build(d,reviewed.listenHost,reviewed.reviewNonce,reviewed.certificatePem,adapters);comparePlan(reviewed,current.plan);
  ensurePrivateDirectory(path.dirname(dir));ensurePrivateDirectory(dir,{exclusive:true});
  for(let i=0;i<current.s.files.length;i++){const file=current.s.files[i];writePrivateFile(path.join(dir,file.name+'.before'),file.before);writePrivateFile(path.join(dir,file.name+'.after'),current.after[i]);for(const suffix of ['before','after']){const fd=fs.openSync(path.join(dir,file.name+'.'+suffix),'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}}
  journal={schema:1,kind,status:'prepared',plan:reviewed,locks:ownership.identity,createdAt:new Date().toISOString()};atomic(path.join(dir,'journal.json'),encode(journal));syncDirectory(path.dirname(dir));
  checkPreserved(reviewed.preserved);
  for(let i=0;i<current.s.files.length;i++){
   const file=current.s.files[i];if(sha(bytes(file.path))!==reviewed.changes[i].beforeSha256)fail('ingress_change_managed_file_changed');
   journal.status='applying';journal.activeFile=file.name;atomic(path.join(dir,'journal.json'),encode(journal));attempted=true;
   (adapters.replaceManagedFile??atomic)(file.path,current.after[i]);if(sha(bytes(file.path))!==reviewed.changes[i].afterSha256)fail('ingress_change_write_verification_failed');
  }
  checkPreserved(reviewed.preserved);readGatewayDeployment(d);
  journal.status='configured_unverified';delete journal.activeFile;atomic(path.join(dir,'journal.json'),encode(journal));return publicResult(journal);
 }catch(error){if(attempted&&journal){journal.status='uncertain';try{atomic(path.join(dir,'journal.json'),encode(journal))}catch{}fail('ingress_change_uncertain_explicit_rollback_required')}throw error}
 finally{try{await releasePorts?.()}finally{try{ownership.close(attempted&&journal?.status!=='configured_unverified')}finally{active.delete(id)}}}
}
function rollbackSnapshot(d,id){
 const dir=directory(d,id);requirePrivateDirectory(dir);const journal=read(path.join(dir,'journal.json')),plan=journal.plan;
 if(journal.schema!==1||journal.kind!==kind||!['configured_unverified','applying','uncertain','rolling_back'].includes(journal.status)||!object(plan)||plan.stateDir!==d||plan.reviewSha256!==id)fail('ingress_change_transaction_not_rollbackable');
 const {reviewSha256,...body}=plan;if(sha(JSON.stringify(body))!==reviewSha256)fail('ingress_change_journal_binding_changed');
 const config=JSON.parse(bytes(path.join(dir,'deployment.before')));validateDeployment(config,{checkNetwork:false});
 const expected={deployment:path.join(d,'deployment.json'),runtime:path.join(d,'gateway/runtime.json'),owner:path.join(d,'gateway/owner.json'),certificate:path.join(d,'gateway/certificate.pem'),state:path.join(d,'state.json'),background:path.join(d,'background.json'),capabilities:path.join(d,'capabilities.json')};
 if(config.host)Object.assign(expected,{hostEnrollment:path.join(config.host.baseDir,'enrollment.json'),hostCertificate:path.join(config.host.baseDir,'gateway-ca.pem'),host:path.join(config.host.baseDir,'device/host.json')});
 if(!Array.isArray(plan.changes)||new Set(plan.changes.map(file=>file.name)).size!==plan.changes.length)fail('ingress_change_invalid_rollback_scope');
 for(const file of plan.changes){
  if(file.path!==expected[file.name]||sha(bytes(path.join(dir,file.name+'.before')))!==file.beforeSha256||sha(bytes(path.join(dir,file.name+'.after')))!==file.afterSha256)fail('ingress_change_backup_or_scope_changed');
  if(![file.beforeSha256,file.afterSha256].includes(sha(bytes(file.path))))fail('ingress_change_foreign_changes_refuse_rollback');
 }
 for(const name of ['background','capabilities','host','hostEnrollment','hostCertificate'])if(expected[name]&&!plan.changes.some(file=>file.name===name)&&exists(expected[name]))fail('ingress_change_new_derived_state_refuse_rollback');
 checkPreserved(plan.preserved);return {dir,journal,config};
}
export async function rollbackDeviceIngressChange(d,options={},adapters={}){
 keys(options,['transactionId','authorize']);if(options.authorize!==true)fail('ingress_change_explicit_rollback_authorization_required');
 const id=options.transactionId;if(active.has(id))fail('ingress_change_transaction_active');
 let {dir,journal,config}=rollbackSnapshot(d,id);
 const guard=acquireRecoveryGuard(path.join(dir,'recovery.lock'),{kind:'device-ingress-rollback',transactionId:id});
 let ownership,releasePorts,attempted=false;const retainedPrior=lockNames.some(name=>exists(path.join(d,name)));active.add(id);
 try{
  ownership=locks(d,id,journal.locks);journal.locks=ownership.identity;atomic(path.join(dir,'journal.json'),encode(journal));await quiet(d,config,adapters);releasePorts=await (adapters.reservePorts??reserve)(config,journal.plan.listenHost);
  guard.assertOwned();({journal}=rollbackSnapshot(d,id));journal.locks=ownership.identity;journal.status='rolling_back';atomic(path.join(dir,'journal.json'),encode(journal));
  for(const file of [...journal.plan.changes].reverse()){
   guard.assertOwned();
   if(sha(bytes(file.path))===file.beforeSha256)continue;
   journal.activeFile=file.name;atomic(path.join(dir,'journal.json'),encode(journal));attempted=true;
   (adapters.replaceManagedFile??atomic)(file.path,bytes(path.join(dir,file.name+'.before')));
   if(sha(bytes(file.path))!==file.beforeSha256)fail('ingress_change_rollback_write_verification_failed');
  }
  guard.assertOwned();checkPreserved(journal.plan.preserved);readGatewayDeployment(d);journal.status='rolled_back';delete journal.activeFile;atomic(path.join(dir,'journal.json'),encode(journal));return publicResult(journal);
 }catch(error){if(attempted){journal.status='uncertain';try{atomic(path.join(dir,'journal.json'),encode(journal))}catch{}fail('ingress_change_rollback_uncertain_preserve_state')}throw error}
 finally{try{await releasePorts?.()}finally{try{ownership?.close((retainedPrior||attempted)&&journal.status!=='rolled_back')}finally{try{guard.close()}finally{active.delete(id)}}}}
}
