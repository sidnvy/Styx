import fs from 'node:fs';
import {localGatewayAddresses,validateDeployment} from './deployment-config.mjs';
export {localGatewayAddresses,validateDeployment} from './deployment-config.mjs';
import {readGatewayDeployment} from './gateway-deployment-reader.mjs';
import {deploymentRoles} from './roles.mjs';
import path from 'node:path';
import {randomBytes,createHash,createPublicKey} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {activeRelease} from '../host/installer.mjs';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile,openPrivateFile,writePrivateFile} from '../host/private-storage.mjs';
import {prepareNativeSetup} from '../host/setup-native.mjs';
import {requestEnrollment,claimEnrollment} from '../host/enroll.mjs';
import {ownerCommand} from '../gateway/enroll-admin.mjs';
import {verifyGatewayConnection} from './connection.mjs';
import {pairDevice,createLocalPairingTransport} from './pairing.mjs';
import {doctor} from '../host/doctor.mjs';
import {readDeploymentAcceptance} from './account-acceptance.mjs';

const live=new Map();
const fail=code=>{throw Error(code)};
const obj=x=>x&&typeof x==='object'&&!Array.isArray(x);
const abs=x=>typeof x==='string'&&path.isAbsolute(x)&&path.normalize(x)===x;
const exact=(x,keys)=>{if(!obj(x)||Object.keys(x).some(k=>!keys.includes(k)))fail('invalid_configuration_fields')};
const filename=(d,n)=>path.join(d,n);
function read(file){requirePrivateFile(file);if(fs.statSync(file).size>1024*1024)fail('state_file_too_large');return JSON.parse(fs.readFileSync(file,'utf8'));}
function write(file,value){const tmp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(tmp,0o600);try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}try{requirePrivateFile(tmp);fs.renameSync(tmp,file);if(process.platform!=='win32'){const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}}}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp);}}
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const evidenceFile=file=>({path:file,sha256:hash(file)});

function load(d){if(!abs(d))fail('absolute_state_directory_required');requirePrivateDirectory(d);const config=read(filename(d,'deployment.json')),state=read(filename(d,'state.json'));validateDeployment(config,{checkNetwork:false});if(state.schema!==1||state.mode!==config.mode||state.configSha256!==hash(filename(d,'deployment.json'))||!Array.isArray(state.steps))fail('invalid_onboarding_state');return {config,state};}
function publicState(d,state,config){
 const observations=[...state.steps.filter(s=>s.id.startsWith('host.service.')&&s.evidence).map(s=>({at:s.updatedAt,evidence:s.evidence})),...(state.maintenance??[])].filter(x=>x.evidence).sort((a,b)=>String(a.at??'').localeCompare(String(b.at??'')));
 const hostServiceMaintenance={lastObservation:observations.at(-1)?.evidence??null,hasUncertainMutation:hasUncertainServiceMutation(state),history:(state.maintenance??[]).map(x=>({action:x.action,status:x.status,at:x.at}))};
 return {schema:1,mode:state.mode,roles:deploymentRoles(config),stateDir:d,hostServiceMaintenance,gatewayServiceMaintenance:{lastObservation:state.gatewayMaintenance?.at(-1)?.evidence??null,hasUncertainMutation:(state.gatewayMaintenance??[]).some(x=>['running','uncertain'].includes(x.status))},gatewayRuntime:{status:live.has(d)?'running':'not_owned_by_current_process',ownership:live.has(d)?'current_process':'none',persistentService:'NOT OBSERVED'},activeStep:state.steps.find(s=>s.status==='running')?.id??null,steps:state.steps.map(s=>({...s,...(s.status==='running'?{status:'uncertain',error:'interrupted_or_in_progress_do_not_replay'}:{})})),accountAcceptance:readDeploymentAcceptance(d).complete?'user_confirmed_with_mcp_evidence':'NOT RUN'};}
export function createDeployment(configFile,{stateDir}={}){
 if(!abs(configFile)||!abs(stateDir))fail('absolute_paths_required');
 const config=validateDeployment(read(configFile));requirePrivateDirectory(path.dirname(stateDir));if(fs.existsSync(stateDir))fail('deployment_directory_already_exists');
 ensurePrivateDirectory(stateDir,{exclusive:true});write(filename(stateDir,'deployment.json'),config);
 const localPair=!!config.host&&config.mode==='create-local'&&config.pairingMode!=='manual';
 const ids=[...(config.gateway.runtime?['gateway.runtime.prepare']:[]),...(config.mode==='create-local'?['gateway.prepare','gateway.start','gateway.verify']:[]),...(config.host?['host.prepare',...(localPair?['host.pair']:[...(config.mode==='create-local'?['host.invite']:[]),'host.request','host.claim']),'host.doctor','host.service.install','host.service.start','host.service.status']:[])];
 const state={schema:1,mode:config.mode,configSha256:hash(filename(stateDir,'deployment.json')),steps:ids.map(id=>({id,status:'pending'}))};write(filename(stateDir,'state.json'),state);return publicState(stateDir,state,config);
}
export function readDeployment(stateDir){const {config,state}=load(stateDir);return publicState(stateDir,state,config);}
// Browser installation is optional, Host-local preparation. Only an already
// approved local configuration and a verified active release can select code.
function browserPreparationScope(d,{ownsAdvance=false}={}){
 const {config,state}=load(d);
 if(!config.host?.browser?.enabled)return {configured:false};
 if(!state.steps.some(s=>s.id==='host.prepare'&&s.status==='succeeded')||!state.steps.some(s=>['host.pair','host.claim'].includes(s.id)&&s.status==='succeeded'))return {configured:true,pending:true};
 if(state.steps.some(s=>['running','uncertain'].includes(s.status))||hasUncertainServiceMutation(state)||(state.gatewayMaintenance??[]).some(s=>['running','uncertain'].includes(s.status)))fail('browser_preparation_management_operation_in_progress');
 for(const name of [...(ownsAdvance?[]:['advance.lock']),'capabilities.lock','background.lock'])if(fs.existsSync(path.join(d,name)))fail('browser_preparation_management_operation_in_progress');
 const base=config.host.baseDir,install=path.join(base,'install'),publisher=path.join(base,'publisher.pem');requirePrivateDirectory(base);requirePrivateDirectory(install);requirePrivateFile(publisher);
 for(const name of ['.health-update-lock','.health-operation-lock','.health-recovery-guard'])if(fs.existsSync(path.join(install,name)))fail('browser_preparation_management_operation_in_progress');
 const pem=fs.readFileSync(publisher,'utf8'),key=createPublicKey(pem);
 if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex')!==config.host.publisherSha256)fail('browser_publisher_binding_changed');
 const active=activeRelease(install,pem);if(!active)fail('browser_enabled_host_bundle_required');
 const moduleFile=path.join(active.release_root,'packages/styx-browser-provider/prepare.mjs');
 if(!fs.existsSync(moduleFile))fail('browser_enabled_host_bundle_required');
 const hostFile=path.join(base,'device/host.json'),identityFile=path.join(base,'device/identity.json'),privateFile=path.join(base,'device/identity.pem'),host=read(hostFile),identity=read(identityFile);requirePrivateFile(privateFile);
 if(identity.device_id!==host.host_id||createHash('sha256').update(createPublicKey(fs.readFileSync(privateFile)).export({type:'spki',format:'der'})).digest('hex')!==identity.fingerprint||host.token_file!==path.join(base,'device/host.token'))fail('browser_identity_binding_changed');
 requirePrivateFile(host.token_file);
 const profileRoot=path.join(base,'browser');
 if(host.browser?.enabled!==true)fail('approved_browser_host_required');
 if(host.browser.profileRoot!==profileRoot)fail('browser_profile_binding_changed');
 requirePrivateDirectory(profileRoot);
 const preserved=[path.join(d,'deployment.json'),path.join(d,'state.json'),hostFile,identityFile,privateFile,host.token_file,publisher,path.join(install,'active.json')].map(file=>[file,hash(file)]);
 return {configured:true,moduleFile,profileRoot,unchanged:()=>preserved.every(([file,digest])=>hash(file)===digest)};
}
function browserPreparationProjection(result){
 if(!['prepared','not_prepared','preparation_blocked'].includes(result?.status))fail('browser_preparation_result_invalid');
 return {schema:1,configured:true,status:result.status,observation:result.status==='prepared'?'verified_private_runtime_receipt':result.status==='preparation_blocked'?'private_preparation_ownership':'private_runtime_receipt_absent',...(result.status==='preparation_blocked'?{reason:/^[a-z][a-z0-9_]{1,100}$/.test(result.reason??'')?result.reason:'browser_preparation_reconciliation_required'}:{}),...(typeof result.playwright==='string'?{playwrightVersion:result.playwright}:{}),readiness:'not_verified',accountAcceptance:'NOT RUN'};
}
async function browserPreparationModule(scope){
 const api=await import(pathToFileURL(scope.moduleFile).href+'?sha256='+hash(scope.moduleFile));
 if(typeof api.readManagedBrowser!=='function'||typeof api.prepareManagedBrowser!=='function')fail('browser_enabled_host_bundle_required');
 return api;
}
export async function readDeploymentBrowser(d){
 const scope=browserPreparationScope(d);
 if(!scope.configured)return {schema:1,configured:false,status:'not_configured',readiness:'not_verified',accountAcceptance:'NOT RUN'};
 if(scope.pending)return {schema:1,configured:true,status:'awaiting_host_approval',readiness:'not_verified',accountAcceptance:'NOT RUN'};
 const api=await browserPreparationModule(scope);if(!scope.unchanged())fail('browser_preparation_scope_changed');
 const result=api.readManagedBrowser(scope.profileRoot);if(!scope.unchanged())fail('browser_preparation_scope_changed');
 return browserPreparationProjection(result);
}
export async function prepareDeploymentBrowser(d,options={}){
 exact(options,['authorize','signal','recover']);if(options.authorize!==true||options.recover!==undefined&&typeof options.recover!=='boolean'||options.signal!==undefined&&!(options.signal instanceof AbortSignal))fail('explicit_browser_preparation_authorization_required');
 const first=browserPreparationScope(d);if(!first.configured)fail('browser_not_configured');if(first.pending)fail('approved_browser_host_required');
 const release=lock(d);
 try{
  const scope=browserPreparationScope(d,{ownsAdvance:true}),api=await browserPreparationModule(scope);
  if(!scope.unchanged())fail('browser_preparation_scope_changed');
  const result=await api.prepareManagedBrowser({profileRoot:scope.profileRoot,authorize:true,...(options.recover!==undefined?{recover:options.recover}:{}),...(options.signal?{signal:options.signal}:{})});
  if(!scope.unchanged())fail('browser_preparation_scope_changed');
  return browserPreparationProjection(result);
 }finally{release();}
}
export function planDeployment(stateDir){const {config,state}=load(stateDir);return {schema:1,mode:config.mode,roles:deploymentRoles(config),steps:state.steps.map((s,i)=>({id:s.id,status:s.status,requires:state.steps.slice(0,i).map(x=>x.id),authorizationRequired:true})),ownerPairingScope:config.host&&config.mode==='create-local'?{gatewayUrl:config.gateway.url,label:config.host.label,enableComputer:config.host.computer,enableBrowser:config.host.browser?.enabled===true}:null,service:{status:'not_checked',lastObservation:publicState(stateDir,state,config).hostServiceMaintenance.lastObservation,configFile:config.host?path.join(config.host.baseDir,'service.json'):null,platform:process.platform},accountAcceptance:readDeploymentAcceptance(stateDir).complete?'user_confirmed_with_mcp_evidence':'NOT RUN'};}
function lock(d){const file=filename(d,'advance.lock');let fd;try{fd=openPrivateFile(file,0o600);}catch{fail('onboarding_busy_or_interrupted_lock');}return ()=>{fs.closeSync(fd);fs.unlinkSync(file)};}
function serviceScope(c,action){
 const serviceConfigFile=path.join(c.host.baseDir,'service.json'),raw=read(serviceConfigFile),windows=process.platform==='win32';
 return {approved:true,action,role:'host',serviceConfigFile,serviceId:windows?raw.task_name:process.platform==='darwin'?raw.label:raw.unitName,installRoot:windows?raw.install_root:raw.installRoot,hostConfigFile:windows?raw.host_config_file:raw.hostConfigFile,trustPublicKeyFile:windows?raw.publisher_key_file:raw.trustPublicKeyFile,nodeBinary:windows?raw.node_binary:raw.nodeBinary,...(raw.logDir!==undefined?{logDir:raw.logDir}:{}),...(raw.restartSec!==undefined?{restartSec:raw.restartSec}:{}),...(raw.nativeApp!==undefined?{nativeApp:raw.nativeApp}:{})};
}
function verifyEvidence(state,{role}={}){
 for(const done of state.steps.filter(s=>s.status==='succeeded'&&(!role||s.id.startsWith(role+'.'))))for(const value of Object.values(done.evidence??{})){
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
  const {config,state}=load(d);if(!config.host)fail('local_host_not_configured');verifyEvidence(state,{role:'host'});
  if(['install','start'].includes(action)&&state.steps.find(s=>s.id==='host.doctor')?.status!=='succeeded')fail('successful_host_doctor_required');
  guardServiceMutation(state,action);
  const authorization=serviceScope(config,action),entry={action,status:'running',at:new Date().toISOString()};
  state.maintenance=[...(state.maintenance??[]).slice(-49),entry];write(filename(d,'state.json'),state);
  let result;try{const {hostServiceAction}=await import('./service-lifecycle.mjs');result=await hostServiceAction({action,role:'host',serviceConfigFile:authorization.serviceConfigFile,authorization});}
  catch{result={status:'uncertain',action,role:'host',reason:'service_adapter_failed_no_replay'};}
  entry.status=result.status==='needs_attention'&&action!=='status'?'uncertain':result.status;entry.evidence=result;write(filename(d,'state.json'),state);return result;
 }finally{release();}
}
// One management API and journal for App, CLI and background handoff.
export async function controlDeploymentService(d,{role,action,authorize=false}={},operations={}){
 if(role==='host')return controlDeploymentHostService(d,{action,authorize});
 if(role!=='gateway'||!['install','start','stop','status','enable','disable','uninstall'].includes(action))fail('invalid_deployment_service_action');
 if(action!=='status'&&authorize!==true)fail('gateway_service_authorization_required');
 const {config}=load(d);if(config.mode!=='create-local')fail('local_gateway_required');
 const gatewayControl=operations.gateway??(await import('./gateway-service.mjs')).controlGatewayService;
 // Observation must not mutate config or the execution journal.
 if(action==='status')return gatewayControl(d,{action});
 const release=lock(d);
 try{
  const {state}=load(d);verifyEvidence(state,{role:'gateway'});
  if(!['stop','disable'].includes(action)&&(state.gatewayMaintenance??[]).some(x=>['running','uncertain'].includes(x.status)))fail('uncertain_gateway_service_action_requires_reconciliation');
  const entry={action,status:'running',at:new Date().toISOString()};
  state.gatewayMaintenance=[...(state.gatewayMaintenance??[]).slice(-49),entry];write(filename(d,'state.json'),state);
  let result;try{result=await gatewayControl(d,{action,authorize:true});}
  catch{result={status:'uncertain',role,action,reason:'gateway_service_action_failed_no_replay'};}
  const confirmed=action==='start'?result.active==='active'&&result.pid>0&&['enabled','default'].includes(result.enabled):action==='stop'?result.active==='inactive'&&!result.pid&&['disabled','default'].includes(result.enabled):action==='enable'?['enabled','default'].includes(result.enabled):action==='disable'?['disabled'].includes(result.enabled):true;
  if(!confirmed&&!['blocked','uncertain'].includes(result.status))result={...result,status:'needs_attention',reason:'gateway_service_target_not_confirmed'};
  entry.status=['uncertain','needs_attention','needs_owner_attention'].includes(result.status)?'uncertain':result.status==='blocked'?'blocked':'succeeded';
  entry.evidence=result;write(filename(d,'state.json'),state);return result;
 }finally{release();}
}
export async function inspectDeployment(d){
 const deployment=readDeployment(d);
 const {observeDeploymentBackground}=await import('./background.mjs');
 return {deployment,observations:await observeDeploymentBackground(d),accountAcceptance:readDeploymentAcceptance(d).complete?'user_confirmed_with_mcp_evidence':'NOT RUN'};
}
function gatewayPaths(d){const root=filename(d,'gateway');return {root,cert:filename(root,'certificate.pem'),key:filename(root,'private-key.pem'),model:filename(root,'model.token'),admin:filename(root,'admin.token'),owner:filename(root,'owner.json'),runtime:filename(root,'runtime.json'),catalog:filename(root,'targets.json')};}
function prepareGateway(d,c){
 const p=gatewayPaths(d);if(fs.existsSync(p.root))fail('gateway_directory_already_exists');ensurePrivateDirectory(p.root,{exclusive:true});
 for(const f of [p.model,p.admin])writePrivateFile(f,randomBytes(48).toString('base64url')+'\n');
 writePrivateFile(p.key,'');writePrivateFile(p.cert,'');
 execFileSync(c.gateway.openssl,['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','30','-keyout',p.key,'-out',p.cert,'-subj','/CN=Styx local Gateway','-addext','subjectAltName=IP:'+(c.gateway.listenHost??'127.0.0.1')],{stdio:'ignore',timeout:20000});
 fs.chmodSync(p.key,0o600);fs.chmodSync(p.cert,0o600);requirePrivateFile(p.key);requirePrivateFile(p.cert);
 write(p.catalog,{version:1,targets:[]});write(p.owner,{gateway_url:c.gateway.url,gateway_ca_file:p.cert,admin_token_file:p.admin});
 write(p.runtime,{schema:1,url:c.gateway.url,listenHost:c.gateway.listenHost??'127.0.0.1',tlsCertificateFile:p.cert,tlsPrivateKeyFile:p.key,modelTokenFile:p.model,adminTokenFile:p.admin,enrollmentDir:filename(p.root,'enrollment'),catalogFile:p.catalog});
 return {runtime:evidenceFile(p.runtime),certificate:evidenceFile(p.cert),ownerConfig:p.owner,ownerConfiguration:evidenceFile(p.owner),modelCredentialFile:p.model,tlsTrust:'dedicated_self_signed_ca_local_only',publicIngress:'NOT CONFIGURED'};
}
export async function startDeploymentGateway(d){
 const {config,state}=load(d);if(config.mode!=='create-local')fail('not_local_gateway');validateDeployment(config);
 if(live.has(d))return {status:'running',url:config.gateway.url,ownership:'current_process'};
 if(state.steps.find(s=>s.id==='gateway.prepare')?.status!=='succeeded')fail('gateway_prepare_required');
 const {runtime:cfg,catalog}=readGatewayDeployment(d);
 const {createStyxGateway}=await import('../gateway/index.mjs');const {createGatewayHttp}=await import('../gateway/http.mjs');const {EnrollmentController}=await import('../gateway/enrollment.mjs');
 const {createAcceptanceObserver}=await import('../shared/onboarding-evidence.mjs');
 const gateway=createStyxGateway({catalog,onToolResult:createAcceptanceObserver(d)});
 const enrollment=new EnrollmentController({rootDir:cfg.enrollmentDir,adminTokenFile:cfg.adminTokenFile,registry:gateway.registry,relay:gateway.relay});
 let handle;try{handle=await createGatewayHttp(gateway,{token:fs.readFileSync(cfg.modelTokenFile,'utf8').trim(),host:cfg.listenHost,port:Number(new URL(cfg.url).port),allowedHosts:[new URL(cfg.url).host],tlsCertificateFile:cfg.tlsCertificateFile,tlsPrivateKeyFile:cfg.tlsPrivateKeyFile,enrollment});}catch(e){await gateway.close();throw e;}
 live.set(d,{http:handle,gateway,controller:enrollment});return {status:'running',url:cfg.url,ownership:'current_process',persistentService:'NOT OBSERVED'};
}
export async function stopDeploymentGateway(d){if(!abs(d))fail('absolute_state_directory_required');const h=live.get(d);if(!h)return {status:'not_owned_by_current_process'};let timer;try{await Promise.race([(async()=>{await h.gateway.relay.close();await h.http.close();})(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('gateway_shutdown_timed_out')),5000);})]);live.delete(d);}finally{clearTimeout(timer);}return {status:'stopped',ownership:'current_process'};}
function ownedGateway(d){
 const {config,state}=load(d);if(config.mode!=='create-local')fail('owned_local_gateway_required');readGatewayDeployment(d);
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
 return items.map(x=>{if(!/^[a-f0-9]{32}$/.test(x.request_id??'')||!/^styx-[a-f0-9]{24}$/.test(x.device_id??'')||!/^([a-f0-9]{64})$/.test(x.fingerprint??''))fail('invalid_pending_response');return {request_id:x.request_id,device_id:x.device_id,label:x.label,platform:x.platform,cwd:x.cwd,shell:x.shell,fingerprint:x.fingerprint,computer_requested:x.computer_requested,browser_requested:x.browser_requested===true,expires_at:x.expires_at};});
}
export async function listDeploymentPending(d,options={}){
 exact(options,['authorize']);if(options.authorize!==true)fail('explicit_owner_pending_authorization_required');
 try{return pendingPublic(await pendingOwned(ownedGateway(d)));}catch{throw Error('owner_pending_read_failed');}
}
export async function approveDeploymentPending(d,options={}){
 exact(options,['authorize','requestId','fingerprint','enableComputer','enableBrowser']);
 if(options.authorize!==true||!/^([a-f0-9]{32})$/.test(options.requestId??'')||!/^([a-f0-9]{64})$/.test(options.fingerprint??'')||typeof options.enableComputer!=='boolean'||options.enableBrowser!==undefined&&typeof options.enableBrowser!=='boolean')fail('explicit_scoped_pending_approval_required');
 const g=ownedGateway(d),release=lock(d);
 try{
  const request=pendingPublic(await pendingOwned(g)).find(x=>x.request_id===options.requestId);
  if(!request||request.fingerprint!==options.fingerprint||options.enableComputer&&!request.computer_requested||options.enableBrowser===true&&!request.browser_requested||request.browser_requested&&typeof options.enableBrowser!=='boolean')fail('pending_identity_or_capability_mismatch');
  const result=g.controller?g.controller.approve({request_id:options.requestId,fingerprint:options.fingerprint,enable_computer:options.enableComputer,enable_browser:options.enableBrowser===true}):await ownerCommand(g.owner,'approve',[options.requestId,options.fingerprint,...(options.enableComputer?['computer']:[]),...(options.enableBrowser?['browser']:[])]);
  return {status:result.status,device_id:result.device_id,fingerprint:result.fingerprint,approved_capabilities:result.approved_capabilities};
 }catch(e){if(e.message==='pending_identity_or_capability_mismatch')throw e;throw Error('owner_approval_failed_inspect_private_gateway');}finally{release();}
}
export async function readDeploymentDevices(d){
 const g=ownedGateway(d);
 const rows=g.controller?g.controller.devices():await ownerCommand(g.owner,'devices');
 return rows.filter(r=>r.status==='approved').map(r=>({device_id:r.device_id,label:r.label,platform:r.platform,is_default:r.is_default===true,computer:r.capabilities?.computer===true,browser:r.capabilities?.browser===true}));
}
// Revocation uses the existing owner controller and durable tombstone. It does
// not delete the Host identity or silently enroll replacement credentials.
export async function revokeDeploymentDevice(d,options={}){
 exact(options,['authorize','deviceId']);
 if(options.authorize!==true||!/^styx-[a-f0-9]{24}$/.test(options.deviceId??''))fail('explicit_device_revocation_required');
 const g=ownedGateway(d),release=lock(d);
 try{return g.controller?g.controller.revoke({device_id:options.deviceId}):await ownerCommand(g.owner,'revoke',[options.deviceId]);}
 finally{release();}
}
export async function setDeploymentDefault(d,{authorize=false,deviceId}={}){
 if(authorize!==true||!/^styx-[a-f0-9]{24}$/.test(deviceId??''))fail('explicit_default_device_selection_required');
 const g=ownedGateway(d),release=lock(d);
 try{return g.controller?g.controller.setDefault({device_id:deviceId}):await ownerCommand(g.owner,'set-default',[deviceId]);}
 finally{release();}
}
export async function setLocalDeploymentDefault(d){
 const {config,state}=load(d);
 if(!config.host||config.mode!=='create-local'||state.steps.find(s=>s.id==='host.pair')?.status!=='succeeded')fail('paired_local_device_required');
 const identity=read(path.join(config.host.baseDir,'device','identity.json'));
 return setDeploymentDefault(d,{authorize:true,deviceId:identity.device_id});
}
export async function verifyDeploymentGateway(d){
 const {config}=load(d);if(config.mode!=='create-local')fail('join_connection_verification_requires_explicit_model_credential');
 readGatewayDeployment(d);const p=gatewayPaths(d);return verifyGatewayConnection({url:new URL('/mcp',config.gateway.url).href,tokenFile:p.model,caFile:p.cert,independentStyx:true,freshConnection:true});
}
async function execute(d,c,id,ownerApproval){
 const p=gatewayPaths(d),base=c.host?.baseDir;
 if(id==='gateway.runtime.prepare'){const {prepareGatewayRuntime}=await import('./gateway-runtime.mjs');return prepareGatewayRuntime(c.gateway.runtime);}
 const enrollment=()=>read(path.join(base,'enrollment.json'));
 if(id==='gateway.prepare')return prepareGateway(d,c);
 if(id==='gateway.start')return startDeploymentGateway(d);
 if(id==='gateway.verify')return verifyDeploymentGateway(d);
 if(id==='host.prepare'){
  const r=prepareNativeSetup({...c.host,gatewayUrl:c.gateway.url,...(c.mode==='create-local'?{gatewayCaFile:p.cert}:c.gateway.caFile?{gatewayCaFile:c.gateway.caFile}:{})});
  return {status:r.status,version:r.version,receipt:evidenceFile(path.join(base,'setup-receipt.json')),serviceConfiguration:evidenceFile(path.join(base,'service.json')),enrollmentConfiguration:evidenceFile(path.join(base,'enrollment.json')),node:r.node,release_root:r.release_root};
 }
 if(id==='host.pair'){
  const cfg=enrollment();return pairDevice({controller:live.get(d).controller,transport:createLocalPairingTransport(cfg),authorization:{...cfg,platform:process.platform,approve:true,enable_computer:ownerApproval.enableComputer,enable_browser:ownerApproval.enableBrowser===true},ttlSeconds:600});
 }
 if(id==='host.invite'){
  const r=await ownerCommand(read(p.owner),'invite',['600']);const file=filename(d,'invitation');writePrivateFile(file,r.invitation+'\n');requirePrivateFile(file);return {invitationFile:file,oneUse:true};
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
   exact(ownerApproval,['approve','gatewayUrl','label','enableComputer','enableBrowser']);
   if(ownerApproval.approve!==true||ownerApproval.gatewayUrl!==config.gateway.url||ownerApproval.label!==config.host.label||typeof ownerApproval.enableComputer!=='boolean'||ownerApproval.enableComputer&&!config.host.computer||ownerApproval.enableBrowser!==undefined&&typeof ownerApproval.enableBrowser!=='boolean'||config.host.browser?.enabled===true&&typeof ownerApproval.enableBrowser!=='boolean'||ownerApproval.enableBrowser===true&&config.host.browser?.enabled!==true)fail('explicit_scoped_owner_approval_required');
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
  return publicState(d,state,config);
 }finally{release();}
}

// These observations never alter network exposure or trust.
export {planDeviceIngress,verifyDeviceIngress} from './device-ingress.mjs';

export {planGatewayRuntimeChange,applyGatewayRuntimeChange,recoverGatewayRuntimeChange,readGatewayRuntimeChange} from './gateway-runtime-update.mjs';
export {planNativeSupervisorMigration,applyNativeSupervisorMigration,rollbackNativeSupervisorMigration} from './migration.mjs';

export {inspectPairingLink,acceptPairingLink} from './pairing-links.mjs';

export {planHostUpdate,readHostUpdate,applyHostUpdate,recoverHostUpdate} from './host-update.mjs';

export {readDeploymentAcceptance,beginDeploymentAcceptance,confirmDeploymentAcceptance,recordDeploymentDesktopReadback,readDeploymentConnectionHandoff,prepareDeploymentConnectionHandoff} from './account-acceptance.mjs';
export {readDeploymentPlugin,setDeploymentPluginProfile,exportDeploymentPlugin,recordDeploymentPluginAction} from './plugin-flow.mjs';
export {readDeploymentPermissions} from './permissions.mjs';
export {startDeploymentForeground,stopDeploymentForeground,observeDeploymentForeground as readDeploymentForeground} from './foreground.mjs';
export function readDeploymentOnboardingPreference(stateDir){
 const {state}=load(stateDir),decision=state.onboardingDecisions?.background;
 return {background:decision?.configSha256===state.configSha256&&['foreground','login'].includes(decision.choice)?decision.choice:'not_decided',configurationBound:decision?.configSha256===state.configSha256};
}
export function setDeploymentOnboardingPreference(stateDir,options={}){
 exact(options,['background','authorize']);if(options.authorize!==true||!['foreground','login'].includes(options.background))fail('explicit_onboarding_background_choice_required');
 const release=lock(stateDir);try{const {state}=load(stateDir);state.onboardingDecisions={...state.onboardingDecisions,background:{choice:options.background,configSha256:state.configSha256,at:new Date().toISOString()}};write(filename(stateDir,'state.json'),state);return {...readDeploymentOnboardingPreference(stateDir),serviceMutation:'NOT RUN'};}finally{release()}
}

export {readDeploymentAppLifecycle,controlDeploymentAppLifecycle} from './app-lifecycle.mjs';

export {planDeviceIngressChange,applyDeviceIngressChange,rollbackDeviceIngressChange} from './device-ingress-change.mjs';

export {changeDeploymentCapabilities,readDeploymentCapabilities,rollbackDeploymentCapabilities} from './capabilities.mjs';
