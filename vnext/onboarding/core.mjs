import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {isIP} from 'node:net';
import {randomBytes,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {prepareNativeSetup} from '../host/setup-native.mjs';
import {requestEnrollment,claimEnrollment} from '../host/enroll.mjs';
import {ownerCommand} from '../gateway/enroll-admin.mjs';
import {verifyGatewayConnection} from './connection.mjs';
import {pairDevice,createLocalPairingTransport} from './pairing.mjs';
import {doctor} from '../host/doctor.mjs';

const live=new Map();
const fail=code=>{throw Error(code)};
const obj=x=>x&&typeof x==='object'&&!Array.isArray(x);
const abs=x=>typeof x==='string'&&path.isAbsolute(x)&&path.normalize(x)===x;
const exact=(x,keys)=>{if(!obj(x)||Object.keys(x).some(k=>!keys.includes(k)))fail('invalid_configuration_fields')};
const filename=(d,n)=>path.join(d,n);
function read(file){requirePrivateFile(file);if(fs.statSync(file).size>1024*1024)fail('state_file_too_large');return JSON.parse(fs.readFileSync(file,'utf8'));}
function write(file,value){const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=fs.openSync(tmp,'wx',0o600);try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}try{requirePrivateFile(tmp);fs.renameSync(tmp,file);if(process.platform!=='win32'){const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp);}}
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const evidenceFile=file=>({path:file,sha256:hash(file)});
export function localGatewayAddresses(){return [...new Set(Object.values(os.networkInterfaces()).flatMap(items=>items??[]).filter(x=>!x.internal&&isIP(x.address)===4).map(x=>x.address))].sort();}
export function validateDeployment(config,{checkNetwork=true}={}){
 exact(config,['schema','mode','gateway','host','invitationFile','pairingMode']);
 if(config.schema!==1||!['create-local','join-existing'].includes(config.mode))fail('unsupported_deployment_schema_or_mode');
 if(config.pairingMode!==undefined&&!['manual','owner-local'].includes(config.pairingMode))fail('invalid_pairing_mode');
 if(config.mode==='join-existing'&&config.pairingMode==='owner-local')fail('join_requires_external_owner_approval');
 exact(config.gateway,['url','openssl','caFile','listenHost','allowRemoteHosts']);
 let u;try{u=new URL(config.gateway.url)}catch{fail('gateway_https_origin_required')}
 if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||u.pathname!=='/')fail('gateway_https_origin_required');
 if(config.mode==='create-local'){
  if(!u.port||Number(u.port)<1024||!abs(config.gateway.openssl)||config.gateway.caFile!==undefined)fail('local_gateway_requires_port_and_trusted_openssl');
  const listen=config.gateway.listenHost??'127.0.0.1';
  if(isIP(listen)!==4||u.hostname!==listen)fail('gateway_url_must_match_exact_bind_ip');
  if(config.gateway.allowRemoteHosts!==undefined&&typeof config.gateway.allowRemoteHosts!=='boolean')fail('invalid_network_exposure_authorization');
  if(listen!=='127.0.0.1'&&(config.gateway.allowRemoteHosts!==true||checkNetwork&&!localGatewayAddresses().includes(listen)))fail('explicit_owned_network_interface_required');
  const st=fs.lstatSync(config.gateway.openssl);if(!st.isFile()||st.isSymbolicLink())fail('trusted_openssl_regular_file_required');
 }else if(['openssl','listenHost','allowRemoteHosts'].some(k=>config.gateway[k]!==undefined))fail('join_cannot_prepare_gateway');
 if(config.gateway.caFile!==undefined&&!abs(config.gateway.caFile))fail('absolute_ca_file_required');
 exact(config.host,['bundle','publisherKeyFile','publisherSha256','baseDir','label','computer','macTeamID','wayland','shell','macPreviewApp']);
 for(const k of ['bundle','publisherKeyFile','baseDir'])if(!abs(config.host[k]))fail('absolute_host_paths_required');
 if(!/^[a-f0-9]{64}$/.test(config.host.publisherSha256??'')||typeof config.host.label!=='string'||!config.host.label||config.host.label.length>72||typeof config.host.computer!=='boolean')fail('invalid_host_setup');
 if(config.host.wayland!==undefined&&typeof config.host.wayland!=='boolean')fail('invalid_wayland_selection');
 if(config.host.shell!==undefined&&!abs(config.host.shell))fail('absolute_native_shell_required');
 if(config.host.macTeamID!==undefined&&!/^[A-Z0-9]{10}$/.test(config.host.macTeamID))fail('invalid_mac_team_identity');
 if(config.invitationFile!==undefined&&(!abs(config.invitationFile)||config.mode!=='join-existing'))fail('invalid_invitation_file');
 return config;
}
function load(d){if(!abs(d))fail('absolute_state_directory_required');requirePrivateDirectory(d);const config=read(filename(d,'deployment.json')),state=read(filename(d,'state.json'));validateDeployment(config,{checkNetwork:false});if(state.schema!==1||state.mode!==config.mode||state.configSha256!==hash(filename(d,'deployment.json'))||!Array.isArray(state.steps))fail('invalid_onboarding_state');return {config,state};}
function publicState(d,state){
 const observations=[...state.steps.filter(s=>s.id.startsWith('host.service.')&&s.evidence).map(s=>({at:s.updatedAt,evidence:s.evidence})),...(state.maintenance??[])].filter(x=>x.evidence).sort((a,b)=>String(a.at??'').localeCompare(String(b.at??'')));
 const hostServiceMaintenance={lastObservation:observations.at(-1)?.evidence??null,hasUncertainMutation:hasUncertainServiceMutation(state),history:(state.maintenance??[]).map(x=>({action:x.action,status:x.status,at:x.at}))};
 return {schema:1,mode:state.mode,stateDir:d,hostServiceMaintenance,gatewayRuntime:{status:live.has(d)?'running':'not_owned_by_current_process',ownership:live.has(d)?'current_process':'none',persistentService:'NOT OBSERVED'},activeStep:state.steps.find(s=>s.status==='running')?.id??null,steps:state.steps.map(s=>({...s,...(s.status==='running'?{status:'uncertain',error:'interrupted_or_in_progress_do_not_replay'}:{})})),accountAcceptance:'NOT RUN'};}
export function createDeployment(configFile,{stateDir}={}){
 if(!abs(configFile)||!abs(stateDir))fail('absolute_paths_required');
 const config=validateDeployment(read(configFile));requirePrivateDirectory(path.dirname(stateDir));if(fs.existsSync(stateDir))fail('deployment_directory_already_exists');
 ensurePrivateDirectory(stateDir);write(filename(stateDir,'deployment.json'),config);
 const localPair=config.mode==='create-local'&&config.pairingMode!=='manual';
 const ids=[...(config.mode==='create-local'?['gateway.prepare','gateway.start','gateway.verify']:[]),'host.prepare',...(localPair?['host.pair']:[...(config.mode==='create-local'?['host.invite']:[]),'host.request','host.claim']),'host.doctor','host.service.install','host.service.start','host.service.status'];
 const state={schema:1,mode:config.mode,configSha256:hash(filename(stateDir,'deployment.json')),steps:ids.map(id=>({id,status:'pending'}))};write(filename(stateDir,'state.json'),state);return publicState(stateDir,state);
}
export function readDeployment(stateDir){const {state}=load(stateDir);return publicState(stateDir,state);}
export function planDeployment(stateDir){const {config,state}=load(stateDir);return {schema:1,mode:config.mode,steps:state.steps.map((s,i)=>({id:s.id,status:s.status,requires:state.steps.slice(0,i).map(x=>x.id),authorizationRequired:true})),ownerPairingScope:config.mode==='create-local'?{gatewayUrl:config.gateway.url,label:config.host.label,enableComputer:config.host.computer}:null,service:{status:'not_checked',lastObservation:publicState(stateDir,state).hostServiceMaintenance.lastObservation,configFile:path.join(config.host.baseDir,'service.json'),platform:process.platform},accountAcceptance:'NOT RUN'};}
function lock(d){const file=filename(d,'advance.lock');let fd;try{fd=fs.openSync(file,'wx',0o600);}catch{fail('onboarding_busy_or_interrupted_lock');}return ()=>{fs.closeSync(fd);fs.unlinkSync(file)};}
function serviceScope(c,action){
 const serviceConfigFile=path.join(c.host.baseDir,'service.json'),raw=read(serviceConfigFile),windows=process.platform==='win32';
 return {approved:true,action,role:'host',serviceConfigFile,serviceId:windows?raw.task_name:process.platform==='darwin'?raw.label:raw.unitName,installRoot:windows?raw.install_root:raw.installRoot,hostConfigFile:windows?raw.host_config_file:raw.hostConfigFile,trustPublicKeyFile:windows?raw.publisher_key_file:raw.trustPublicKeyFile,nodeBinary:windows?raw.node_binary:raw.nodeBinary,...(raw.logDir!==undefined?{logDir:raw.logDir}:{}),...(raw.restartSec!==undefined?{restartSec:raw.restartSec}:{})};
}
function verifyEvidence(state){
 for(const done of state.steps.filter(s=>s.status==='succeeded'))for(const value of Object.values(done.evidence??{})){
  if(obj(value)&&typeof value.path==='string'&&typeof value.sha256==='string'&&hash(value.path)!==value.sha256)fail('completed_step_evidence_changed');
 }
}
function hasUncertainServiceMutation(state){
 return (state.maintenance??[]).some(x=>x.action!=='status'&&['uncertain','running'].includes(x.status))||state.steps.some(x=>x.id.startsWith('host.service.')&&x.id!=='host.service.status'&&['uncertain','running'].includes(x.status));
}
function guardServiceMutation(state,action){if(['install','start'].includes(action)&&hasUncertainServiceMutation(state))fail('uncertain_service_action_requires_manual_reconciliation');}
export async function controlDeploymentHostService(d,{action,authorize=false}={}){
 if(authorize!==true||!['install','start','stop','status'].includes(action))fail('explicit_fixed_host_service_authorization_required');
 load(d);const release=lock(d);
 try{
  const {config,state}=load(d);verifyEvidence(state);
  if(['install','start'].includes(action)&&state.steps.find(s=>s.id==='host.doctor')?.status!=='succeeded')fail('successful_host_doctor_required');
  guardServiceMutation(state,action);
  const authorization=serviceScope(config,action),entry={action,status:'running',at:new Date().toISOString()};
  state.maintenance=[...(state.maintenance??[]).slice(-49),entry];write(filename(d,'state.json'),state);
  let result;try{const {hostServiceAction}=await import('./service-lifecycle.mjs');result=await hostServiceAction({action,role:'host',serviceConfigFile:authorization.serviceConfigFile,authorization});}
  catch{result={status:'uncertain',action,role:'host',reason:'service_adapter_failed_no_replay'};}
  entry.status=result.status==='needs_attention'&&action!=='status'?'uncertain':result.status;entry.evidence=result;write(filename(d,'state.json'),state);return result;
 }finally{release();}
}
function gatewayPaths(d){const root=filename(d,'gateway');return {root,cert:filename(root,'certificate.pem'),key:filename(root,'private-key.pem'),model:filename(root,'model.token'),admin:filename(root,'admin.token'),owner:filename(root,'owner.json'),runtime:filename(root,'runtime.json'),catalog:filename(root,'targets.json')};}
function prepareGateway(d,c){
 const p=gatewayPaths(d);if(fs.existsSync(p.root))fail('gateway_directory_already_exists');ensurePrivateDirectory(p.root);
 for(const f of [p.model,p.admin])fs.writeFileSync(f,randomBytes(48).toString('base64url')+'\n',{flag:'wx',mode:0o600});
 execFileSync(c.gateway.openssl,['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','30','-keyout',p.key,'-out',p.cert,'-subj','/CN=Styx local Gateway','-addext','subjectAltName=IP:'+(c.gateway.listenHost??'127.0.0.1')],{stdio:'ignore',timeout:20000});
 fs.chmodSync(p.key,0o600);fs.chmodSync(p.cert,0o600);requirePrivateFile(p.key);requirePrivateFile(p.cert);
 write(p.catalog,{version:1,targets:[]});write(p.owner,{gateway_url:c.gateway.url,gateway_ca_file:p.cert,admin_token_file:p.admin});
 write(p.runtime,{schema:1,url:c.gateway.url,listenHost:c.gateway.listenHost??'127.0.0.1',tlsCertificateFile:p.cert,tlsPrivateKeyFile:p.key,modelTokenFile:p.model,adminTokenFile:p.admin,enrollmentDir:filename(p.root,'enrollment'),catalogFile:p.catalog});
 return {runtime:evidenceFile(p.runtime),certificate:evidenceFile(p.cert),ownerConfig:p.owner,ownerConfiguration:evidenceFile(p.owner),modelCredentialFile:p.model,tlsTrust:'dedicated_self_signed_ca_local_only',publicIngress:'NOT CONFIGURED'};
}
export async function startDeploymentGateway(d){
 const {config,state}=load(d);if(config.mode!=='create-local')fail('not_local_gateway');validateDeployment(config);verifyEvidence(state);
 if(live.has(d))return {status:'running',url:config.gateway.url,ownership:'current_process'};
 if(state.steps.find(s=>s.id==='gateway.prepare')?.status!=='succeeded')fail('gateway_prepare_required');
 const p=gatewayPaths(d),cfg=read(p.runtime);
 const {createStyxGateway}=await import('../gateway/index.mjs');const {createGatewayHttp}=await import('../gateway/http.mjs');const {EnrollmentController}=await import('../gateway/enrollment.mjs');
 const gateway=createStyxGateway({catalog:read(cfg.catalogFile)});
 const enrollment=new EnrollmentController({rootDir:cfg.enrollmentDir,adminTokenFile:cfg.adminTokenFile,registry:gateway.registry,relay:gateway.relay});
 let handle;try{handle=await createGatewayHttp(gateway,{token:fs.readFileSync(cfg.modelTokenFile,'utf8').trim(),host:cfg.listenHost,port:Number(new URL(cfg.url).port),allowedHosts:[new URL(cfg.url).host],tlsCertificateFile:cfg.tlsCertificateFile,tlsPrivateKeyFile:cfg.tlsPrivateKeyFile,enrollment});}catch(e){await gateway.close();throw e;}
 live.set(d,{http:handle,gateway,controller:enrollment});return {status:'running',url:cfg.url,ownership:'current_process',persistentService:'NOT OBSERVED'};
}
export async function stopDeploymentGateway(d){if(!abs(d))fail('absolute_state_directory_required');const h=live.get(d);if(!h)return {status:'not_owned_by_current_process'};let timer;try{await Promise.race([(async()=>{await h.gateway.relay.close();await h.http.close();})(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('gateway_shutdown_timed_out')),5000);})]);live.delete(d);}finally{clearTimeout(timer);}return {status:'stopped',ownership:'current_process'};}
function ownedGateway(d){
 const {config,state}=load(d);if(config.mode!=='create-local')fail('owned_local_gateway_required');verifyEvidence(state);
 const p=gatewayPaths(d),owner=read(p.owner);
 if(new URL(owner.gateway_url).origin!==new URL(config.gateway.url).origin||owner.gateway_ca_file!==p.cert||owner.admin_token_file!==p.admin)fail('owner_gateway_binding_changed');
 return {config,controller:live.get(d)?.controller,owner};
}
async function pendingOwned(g){return g.controller?g.controller.listPending():ownerCommand(g.owner,'pending');}
// Owner-only return value contains a short-lived invitation secret. Never expose
// this operation as MCP or include its result in public status/diagnostic logs.
export async function createDeploymentPairingLink(d,options={}){
 exact(options,['authorize']);if(options.authorize!==true)fail('explicit_owner_link_authorization_required');
 const g=ownedGateway(d),release=lock(d);
 try{const {createPairingLink}=await import('./pairing-links.mjs');
  const invitation=g.controller?g.controller.invite({ttl_seconds:600}):await ownerCommand(g.owner,'invite',['600']);
  return {...createPairingLink({controller:{invite:()=>invitation},gatewayOrigin:g.config.gateway.url,approved:true,caPem:fs.readFileSync(gatewayPaths(d).cert,'utf8'),ttlSeconds:600}),reachability:(g.config.gateway.listenHost??'127.0.0.1')==='127.0.0.1'?'loopback_only':'local_interface_configured_unverified',remoteUsable:false,reachabilityVerification:'NOT RUN'};
 }catch{throw Error('owner_pairing_link_failed_inspect_private_gateway');}finally{release();}
}
function pendingPublic(items){
 if(!Array.isArray(items))fail('invalid_pending_response');
 return items.map(x=>{if(!/^[a-f0-9]{32}$/.test(x.request_id??'')||!/^styx-[a-f0-9]{24}$/.test(x.device_id??'')||!/^([a-f0-9]{64})$/.test(x.fingerprint??''))fail('invalid_pending_response');return {request_id:x.request_id,device_id:x.device_id,label:x.label,platform:x.platform,cwd:x.cwd,shell:x.shell,fingerprint:x.fingerprint,computer_requested:x.computer_requested,expires_at:x.expires_at};});
}
export async function listDeploymentPending(d,options={}){
 exact(options,['authorize']);if(options.authorize!==true)fail('explicit_owner_pending_authorization_required');
 try{return pendingPublic(await pendingOwned(ownedGateway(d)));}catch{throw Error('owner_pending_read_failed');}
}
export async function approveDeploymentPending(d,options={}){
 exact(options,['authorize','requestId','fingerprint','enableComputer']);
 if(options.authorize!==true||!/^([a-f0-9]{32})$/.test(options.requestId??'')||!/^([a-f0-9]{64})$/.test(options.fingerprint??'')||typeof options.enableComputer!=='boolean')fail('explicit_scoped_pending_approval_required');
 const g=ownedGateway(d),release=lock(d);
 try{
  const request=pendingPublic(await pendingOwned(g)).find(x=>x.request_id===options.requestId);
  if(!request||request.fingerprint!==options.fingerprint||options.enableComputer&&!request.computer_requested)fail('pending_identity_or_capability_mismatch');
  const result=g.controller?g.controller.approve({request_id:options.requestId,fingerprint:options.fingerprint,enable_computer:options.enableComputer}):await ownerCommand(g.owner,'approve',[options.requestId,options.fingerprint,...(options.enableComputer?['computer']:[])]);
  return {status:result.status,device_id:result.device_id,fingerprint:result.fingerprint,approved_capabilities:result.approved_capabilities};
 }catch(e){if(e.message==='pending_identity_or_capability_mismatch')throw e;throw Error('owner_approval_failed_inspect_private_gateway');}finally{release();}
}
export async function verifyDeploymentGateway(d){
 const {config}=load(d);if(config.mode!=='create-local')fail('join_connection_verification_requires_explicit_model_credential');
 const p=gatewayPaths(d);return verifyGatewayConnection({url:new URL('/mcp',config.gateway.url).href,tokenFile:p.model,caFile:p.cert,independentStyx:true,freshConnection:true});
}
async function execute(d,c,id,ownerApproval){
 const p=gatewayPaths(d),base=c.host.baseDir;
 const enrollment=()=>read(path.join(base,'enrollment.json'));
 if(id==='gateway.prepare')return prepareGateway(d,c);
 if(id==='gateway.start')return startDeploymentGateway(d);
 if(id==='gateway.verify')return verifyDeploymentGateway(d);
 if(id==='host.prepare'){
  const r=prepareNativeSetup({...c.host,gatewayUrl:c.gateway.url,...(c.mode==='create-local'?{gatewayCaFile:p.cert}:c.gateway.caFile?{gatewayCaFile:c.gateway.caFile}:{})});
  return {status:r.status,version:r.version,receipt:evidenceFile(path.join(base,'setup-receipt.json')),serviceConfiguration:evidenceFile(path.join(base,'service.json')),enrollmentConfiguration:evidenceFile(path.join(base,'enrollment.json')),node:r.node,release_root:r.release_root};
 }
 if(id==='host.pair'){
  const cfg=enrollment();return pairDevice({controller:live.get(d).controller,transport:createLocalPairingTransport(cfg),authorization:{...cfg,platform:process.platform,approve:true,enable_computer:ownerApproval.enableComputer},ttlSeconds:600});
 }
 if(id==='host.invite'){
  const r=await ownerCommand(read(p.owner),'invite',['600']);const file=filename(d,'invitation');fs.writeFileSync(file,r.invitation+'\n',{mode:0o600,flag:'wx'});requirePrivateFile(file);return {invitationFile:file,oneUse:true};
 }
 if(id==='host.request'){
  const file=c.mode==='create-local'?filename(d,'invitation'):c.invitationFile;if(!file)fail('private_invitation_file_required');requirePrivateFile(file);
  const r=await requestEnrollment(enrollment(),fs.readFileSync(file,'utf8').trim());return {status:r.status,request_id:r.request_id,device_id:r.device_id,fingerprint:r.fingerprint,ownerApproval:'REQUIRED'};
 }
 if(id==='host.claim'){
  const r=await claimEnrollment(enrollment());return {status:r.status,...(r.device_id?{device_id:r.device_id}:{}),...(r.status==='ready_to_connect'?{hostConfigFile:r.local_host_config}:{ownerApproval:'REQUIRED'})};
 }
 if(id.startsWith('host.service.')){
  const action=id.slice('host.service.'.length),authorization=serviceScope(c,action);
  const {hostServiceAction}=await import('./service-lifecycle.mjs');
  return hostServiceAction({action,role:'host',serviceConfigFile:authorization.serviceConfigFile,authorization});
 }
 if(id==='host.doctor'){
  const r=await doctor(read(path.join(base,'device','host.json')),{installRoot:path.join(base,'install'),trustPublicKeyFile:path.join(base,'publisher.pem')});
  return {status:r.status,blockers:r.blockers,warnings:r.warnings};
 }
 fail('unsupported_onboarding_step');
}
// Resume advances only explicitly authorized pending/read-only-blocked steps.
// A lock left by a crash is intentionally retained for owner inspection; never steal it.
export async function advanceDeployment(d,{authorize=[],ownerApproval}={}){
 if(!Array.isArray(authorize)||authorize.some(x=>typeof x!=='string')||new Set(authorize).size!==authorize.length)fail('explicit_step_authorization_required');
 load(d);
 const release=lock(d);
 try{
  const {config,state}=load(d);
  if(authorize.some(id=>!state.steps.some(s=>s.id===id)))fail('unknown_authorized_step');
  if(authorize.includes('host.pair')){
   exact(ownerApproval,['approve','gatewayUrl','label','enableComputer']);
   if(ownerApproval.approve!==true||ownerApproval.gatewayUrl!==config.gateway.url||ownerApproval.label!==config.host.label||typeof ownerApproval.enableComputer!=='boolean'||ownerApproval.enableComputer&&!config.host.computer)fail('explicit_scoped_owner_approval_required');
   if(!live.has(d))fail('local_gateway_must_be_running');
  }
  verifyEvidence(state);
  for(const step of state.steps){
   if(step.status==='succeeded')continue;
   if(!authorize.includes(step.id))break;
   if(['running','uncertain'].includes(step.status))fail('uncertain_step_requires_manual_reconciliation');
   if(step.id.startsWith('host.service.'))guardServiceMutation(state,step.id.slice('host.service.'.length));
   step.status='running';delete step.error;write(filename(d,'state.json'),state);
   try{
    step.updatedAt=new Date().toISOString();
    step.evidence=await execute(d,config,step.id,ownerApproval);
    step.status=['needs_owner_attention','uncertain'].includes(step.evidence.status)||(step.id.startsWith('host.service.')&&step.id!=='host.service.status'&&step.evidence.status==='needs_attention')?'uncertain':['blocked','needs_attention','not_implemented'].includes(step.evidence.status)?'blocked':step.id==='host.claim'&&step.evidence.status==='pending'?'awaiting_approval':step.id==='host.doctor'&&step.evidence.status!=='ready_for_exec'?'blocked':'succeeded';
    write(filename(d,'state.json'),state);
    if(step.status!=='succeeded')break;
   }catch{
    step.status=['host.doctor','host.claim','gateway.start','gateway.verify','host.service.status'].includes(step.id)?'blocked':'uncertain';step.error='step_failed_inspect_local_evidence_no_automatic_replay';write(filename(d,'state.json'),state);break;
   }
  }
  return publicState(d,state);
 }finally{release();}
}
