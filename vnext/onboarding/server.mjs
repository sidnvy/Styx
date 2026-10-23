// Local browser setup control plane. Does not expose an unauthenticated LAN API.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {completeLocalSetup,isRetryableLocalCheck} from './local-setup.mjs';
import {nativeHostStartupDecision} from './native-host-startup.mjs';
import {enableDeploymentBackground,observeDeploymentBackground} from './background.mjs';
import {configureTunnel,TunnelRuntime} from './tunnel-runtime.mjs';
import {changeDeploymentCapabilities,readDeploymentCapabilities} from './capabilities.mjs';
import {readOnboardingJourney,readOnboardingDiagnostics,readOnboardingTunnel,publicAcceptance} from './journey.mjs';
import {requirePrivateFile,writePrivateFile,ensurePrivateDirectory} from '../host/private-storage.mjs';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const UI=fileURLToPath(new URL('./ui/',import.meta.url));
const STEPS=new Set(['gateway.runtime.prepare','gateway.prepare','gateway.start','host.prepare','host.invite','host.request','host.claim','host.doctor','host.pair','gateway.verify','host.service.install','host.service.start','host.service.status']);
const STATES=new Set(['pending','running','succeeded','failed','uncertain','blocked','skipped','awaiting_approval']);
const ERRORS=new Set(['interrupted_or_in_progress_do_not_replay','step_failed_inspect_local_evidence_no_automatic_replay']);
const DOCTOR_BLOCKERS=new Set(['signed_install_unavailable','invalid_host_configuration','host_credential_unavailable','codex_executor_unavailable','signed_computer_runtime_unavailable','macos_requires_embedded_cua_socket']);
const MODES=new Set(['create-local','join-existing']);
const LOCAL_SETUP_STEPS=new Set([...STEPS].filter(id=>!id.startsWith('host.service.')));
const equal=(a,b)=>typeof a==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const fail=code=>{throw Error(code)};
export function browserOrigin(value){
 const url=new URL(value);
 if(url.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(url.hostname)||url.username||url.password||url.pathname!=='/'||url.search||url.hash)fail('trusted_loopback_browser_origin_required');
 return url.origin;
}
export function gatewayServiceUiCapabilities(platform,available){return {supported:available===true&&['linux','darwin','win32'].includes(platform),startEnablesStartup:['linux','darwin','win32'].includes(platform),enableCanTriggerRecovery:platform==='win32'}}
export function nativeBrowserPrepared(deployment,browser){
 if(deployment?.roles?.browser!=='requested')return true;
 return browser?.configured===true&&(browser.status==='prepared'&&browser.approved===true||browser.status==='not_approved'&&browser.approved===false);
}
// Reopening needs the preparation journal, not a complete diagnostics scan of
// services, the tunnel and account evidence. Actual start still performs its
// own signature, ownership, identity and connection checks.
export function nativeLocalPrepared(deployment){
 const steps=(deployment?.steps??[]).filter(step=>LOCAL_SETUP_STEPS.has(step.id));
 return steps.length>0&&steps.every(step=>step.status==='succeeded');
}
export function nativeForegroundOwnsConnections(foreground){
 return ['current_process','authenticated_foreground_owner'].includes(foreground?.observation)
  &&['started','connected'].includes(foreground?.status)
  &&foreground.host==='foreground'&&['foreground','external'].includes(foreground.gateway);
}
export function publicService(value){
 if(!value||typeof value!=='object')return null;const out={};
 for(const key of ['status','action','role','manager','serviceId','name','state','persistence','health','active','substate','enabled'])if(typeof value[key]==='string'&&/^[A-Za-z0-9_.-]{1,120}$/.test(value[key]))out[key]=value[key];
 if(value.executionIdentity){const identity=value.executionIdentity;if(['legacy_node','signed_native_supervisor'].includes(identity.launcher))out.executionIdentity={launcher:identity.launcher,nativeResponsibility:identity.launcher==='legacy_node'?'not_established':'configured_unverified',tccAttribution:'NOT RUN'};}
 if(Number.isSafeInteger(value.pid)&&value.pid>=0)out.pid=value.pid;return out;
}
export function publicDeployment(value){
 if(value==null)return null;
 const steps=Array.isArray(value.steps)?value.steps:[];
 return {schema:1,mode:MODES.has(value.mode)?value.mode:null,
  roles: value.roles ? {
   gateway:['local','external'].includes(value.roles.gateway)?value.roles.gateway:'unknown',
   host:['local','disabled'].includes(value.roles.host)?value.roles.host:'unknown',
   exec:['enabled','disabled'].includes(value.roles.exec)?value.roles.exec:'unknown',
   computer:['requested','disabled'].includes(value.roles.computer)?value.roles.computer:'unknown',
   browser:['requested','disabled'].includes(value.roles.browser)?value.roles.browser:'disabled',
   deviceIngress:['loopback_only','configured_unverified','not_hosted'].includes(value.roles.deviceIngress)?value.roles.deviceIngress:'unknown',
   readiness:'not_inferred'
  } : null,
  activeStep:STEPS.has(value.activeStep)?value.activeStep:null,
  hostServiceMaintenance:{lastObservation:publicService(value.hostServiceMaintenance?.lastObservation),hasUncertainMutation:value.hostServiceMaintenance?.hasUncertainMutation===true},
  gatewayServiceMaintenance:{lastObservation:publicService(value.gatewayServiceMaintenance?.lastObservation),hasUncertainMutation:value.gatewayServiceMaintenance?.hasUncertainMutation===true},
  gatewayRuntime:typeof value.gatewayRuntime?.status==='string'&&['running','stopped','not_owned_by_current_process'].includes(value.gatewayRuntime.status)?value.gatewayRuntime.status:'unknown',
  accountAcceptance:value.accountAcceptance==='user_confirmed_with_mcp_evidence'?'user_confirmed_with_mcp_evidence':'NOT RUN',providerIdentity:'not_verified',
  steps:steps.filter(s=>s&&STEPS.has(s.id)).map(s=>({id:s.id,status:STATES.has(s.status)?s.status:'uncertain',
   ...(isRetryableLocalCheck(s)?{retryable:true,blockers:[...new Set((Array.isArray(s.evidence?.blockers)?s.evidence.blockers:[]).filter(code=>DOCTOR_BLOCKERS.has(code)))]}:{}),
   ...(s.id.startsWith('host.service.')?{service:publicService(s.evidence)}:{}),
   ...(s.evidence?.ownerApproval==='REQUIRED'?{ownerApproval:'REQUIRED'}:{}),
   ...(/^[a-f0-9]{64}$/.test(s.evidence?.fingerprint??'')?{fingerprint:s.evidence.fingerprint}:{}),
   ...(/^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$/.test(s.evidence?.comparison_code??'')?{comparison_code:s.evidence.comparison_code}:{}),
   ...(s.error?{error:ERRORS.has(s.error)?s.error:'step_failed_inspect_local_state'}:{})}))};
}
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
function keys(value,allowed){if(!object(value)||Object.keys(value).some(k=>!allowed.includes(k)))fail('invalid_configuration_fields')}
export function validateUiConfig(config,{trustedOpenSSL,trustedOpenSSLConfig}={}){
 keys(config,['schema','mode','gateway','host','invitationFile']);
 if(config.schema!==1||!MODES.has(config.mode))fail('invalid_configuration');
 keys(config.gateway,['url','caFile','listenHost','allowRemoteHosts','runtime']);if(config.host!==undefined)keys(config.host,['bundle','publisherKeyFile','publisherSha256','baseDir','label','computer','browser','macTeamID','wayland']);
 for(const [name,value]of Object.entries(config.gateway)){if(name==='runtime'){keys(value,['bundle','publisherKeyFile','publisherSha256','baseDir']);for(const v of Object.values(value))if(typeof v!=='string'||!v||v.length>4096)fail('invalid_runtime_field')}else if(name==='allowRemoteHosts'){if(value!==true)fail('explicit_network_exposure_required')}else if(typeof value!=='string'||!value||value.length>4096)fail('invalid_gateway_field');}
 for(const [name,value]of Object.entries(config.host??{})){
  if(name==='browser'){keys(value,['enabled','headless','executablePath','channel','persistLogin']);if(value.persistLogin!==undefined&&typeof value.persistLogin!=='boolean'||value.channel!==undefined&&!['auto','chrome','msedge'].includes(value.channel)||typeof value.enabled!=='boolean'||value.headless!==undefined&&typeof value.headless!=='boolean'||value.executablePath!==undefined&&(typeof value.executablePath!=='string'||!path.isAbsolute(value.executablePath)||path.normalize(value.executablePath)!==value.executablePath))fail('invalid_browser_selection')}
  else if(['computer','wayland'].includes(name)){if(typeof value!=='boolean')fail('invalid_capability_selection')}
  else if(typeof value!=='string'||!value||value.length>4096)fail('invalid_host_field');
 }
 if(config.host!==undefined)for(const name of ['bundle','publisherKeyFile','publisherSha256','baseDir','label'])if(typeof config.host[name]!=='string')fail('required_host_field');
 if(config.host!==undefined&&typeof config.host.computer!=='boolean')fail('required_capability_selection');
 if(config.invitationFile!==undefined&&(typeof config.invitationFile!=='string'||!config.invitationFile||config.invitationFile.length>4096))fail('invalid_invitation_file');
 if(config.mode==='join-existing'&&!config.invitationFile)fail('invitation_file_required');
 if(config.mode==='create-local'&&(!trustedOpenSSL||!path.isAbsolute(trustedOpenSSL)))fail('local_tls_helper_not_configured');
 if(config.mode==='create-local'&&trustedOpenSSLConfig!==undefined&&(!path.isAbsolute(trustedOpenSSLConfig)||path.normalize(trustedOpenSSLConfig)!==trustedOpenSSLConfig))fail('local_tls_configuration_not_configured');
 return {...config,gateway:{...config.gateway,...(config.mode==='create-local'?{openssl:trustedOpenSSL,...(trustedOpenSSLConfig!==undefined?{opensslConfig:trustedOpenSSLConfig}:{})}:{})}};
}
async function body(req,maximumBytes=65536){
 if(req.headers['content-type']!=='application/json')fail('json_required');
 req.setEncoding('utf8');let data='';for await(const chunk of req){data+=chunk;if(Buffer.byteLength(data)>maximumBytes)fail('body_too_large')}
 try{return JSON.parse(data)}catch{fail('invalid_json')}
}
export async function createOnboardingServer({stateDir,port=0,trustedForwardOrigin,trustedOpenSSL=process.platform==='win32'?undefined:'/usr/bin/openssl',trustedOpenSSLConfig,core,artifactDefaultsFile,verifyConnection,gatewayService,pairingLinks,trustedMacPreviewApp,backgroundControl=enableDeploymentBackground,backgroundRead=observeDeploymentBackground,trustedTunnelClient,nativeAppAuthority,trustedWindowsApp}={}){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir))fail('absolute_state_directory_required');
 if(!Number.isInteger(port)||port<0||port>65535)fail('invalid_port');
 const forwarded=trustedForwardOrigin?browserOrigin(trustedForwardOrigin):null;
 const tunnel=trustedTunnelClient?new TunnelRuntime({stateDir,...trustedTunnelClient}):null;
 const api=core??await import('./core.mjs');
 // Do not create the tunnel directory merely by opening a read-only status API.
 const tunnelRead=async()=>tunnel&&fs.existsSync(path.join(stateDir,'tunnel'))?tunnel.health():readOnboardingTunnel(stateDir);
 const journeyOptions={core:api,backgroundRead,tunnelRead};
 let macPreviewApp,nativeSigningMigrationRequired=false;
 if(trustedMacPreviewApp!==undefined){
  const {verifyMacPreviewApp,assertMacPreviewContinuity}=await import('../host/macos-preview-trust.mjs');macPreviewApp=verifyMacPreviewApp(trustedMacPreviewApp);
  const file=path.join(stateDir,'deployment.json');
  if(fs.existsSync(file)){
   if(requirePrivateFile(file).size>1024*1024)fail('native_signing_configuration_too_large');
   nativeSigningMigrationRequired=assertMacPreviewContinuity(JSON.parse(fs.readFileSync(file,'utf8')).host?.macPreviewApp,macPreviewApp).migrationRequired;
  }
 }
 let artifacts={};
 if(artifactDefaultsFile){requirePrivateFile(artifactDefaultsFile);if(fs.statSync(artifactDefaultsFile).size>65536)fail('artifact_defaults_too_large');const value=JSON.parse(fs.readFileSync(artifactDefaultsFile,'utf8'));keys(value,['bundle','publisherKeyFile','publisherSha256']);if(!['bundle','publisherKeyFile'].every(k=>typeof value[k]==='string'&&path.isAbsolute(value[k]))||!/^[a-f0-9]{64}$/.test(value.publisherSha256??''))fail('invalid_trusted_artifact_defaults');artifacts=value;}
 const probe=net.createServer();await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(0,'127.0.0.1',resolve)});const suggestedPort=probe.address().port;await new Promise(resolve=>probe.close(resolve));
 const defaults={label:os.hostname().slice(0,72),baseDir:path.join(path.dirname(stateDir),'styx-host-'+randomBytes(5).toString('hex')),gatewayUrl:'https://127.0.0.1:'+suggestedPort,...artifacts};
 const session=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url');
 let origin,closing=null,busy=false;
 let nativeStartup={status:'not_requested',observation:'current_process'};
 let signingPlan=null,payloadPlan=null;
 let workAdmission=null;
 const cancelWorkAdmission=async()=>{if(!workAdmission)return;await api.cancelDeploymentWorkAdmission(stateDir,{ticketId:workAdmission.ticketId,authorize:true});workAdmission=null;};
 const admitWork=async(purpose,commit=false)=>{
  if(typeof api.prepareDeploymentWorkAdmission!=='function'||typeof api.commitDeploymentWorkAdmission!=='function'||typeof api.cancelDeploymentWorkAdmission!=='function')fail('work_state_unknown');
  let admission=await api.prepareDeploymentWorkAdmission(stateDir,{authorize:true,purpose});workAdmission=admission;
  try{
   // A remote click can request an update before its own Cua response returns.
   // Keep the fence closed while already dispatched work settles naturally;
   // retained commands and uncertain outcomes never enter this grace period.
   const deadline=performance.now()+2000;
   while(admission?.status==='waiting'&&admission.retained===0&&admission.active>0&&performance.now()<deadline){
    await new Promise(resolve=>setTimeout(resolve,25));
    admission=await api.prepareDeploymentWorkAdmission(stateDir,{authorize:true,purpose});
    if(admission?.ticketId!==workAdmission.ticketId)fail('work_state_unknown');
   }
   if(admission?.status!=='ready')fail(admission?.status==='waiting'?'work_in_progress':'work_state_unknown');
   if(commit){const committed=await api.commitDeploymentWorkAdmission(stateDir,{ticketId:admission.ticketId,authorize:true});if(committed?.status!=='ready')fail(committed?.status==='waiting'?'work_in_progress':'work_state_unknown');}
   return admission;
  }catch(error){await cancelWorkAdmission();throw error}
 };
 const signingApp=()=>Object.fromEntries(['path','cdhash','certificateSha1','certificateSha256'].map(key=>[key,macPreviewApp?.[key]]));
 const startupFailure=error=>{
  const code=error?.message;
  const reason=['foreground_host_service_state_unknown','foreground_gateway_service_state_unknown','foreground_host_handoff_required'].includes(code)?'existing_service_requires_review':
   code==='foreground_host_already_connected_not_owned'?'connection_owned_elsewhere':
   ['foreground_uncertain_state_requires_reconciliation','foreground_management_operation_in_progress'].includes(code)?'interrupted_operation_requires_review':'connection_start_failed';
  nativeStartup={status:'reconciliation_required',observation:'current_process',reason};
 };
 const nativeAppOwned=!!macPreviewApp||(typeof nativeAppAuthority==='function'&&nativeAppAuthority()?.source==='current_windows_native_app');
 const nativeAppLifecycleSupported=!!macPreviewApp||(nativeAppOwned&&typeof trustedWindowsApp==='function');
 const lifecycleContext=()=>{
  if(macPreviewApp)return {trustedAppPath:macPreviewApp.path};
  const app=trustedWindowsApp?.();
  if(!nativeAppLifecycleSupported||app?.authority?.source!=='current_windows_native_app')fail('native_app_lifecycle_unavailable');
  return {trustedWindowsApp:app};
 };
 const checkNativeHostStartup=async()=>{
  if(!nativeAppOwned)return true;
  const decision=await nativeHostStartupDecision(stateDir,{artifacts,core:api});
  if(decision.status==='continue')return true;
  nativeStartup=decision;return false;
 };
 const resumeNativeStartup=async()=>{
  if(!await checkNativeHostStartup())return;
  try{
   const deployment=await api.readDeployment(stateDir);
   const browser=deployment.roles?.browser==='requested'?await api.readDeploymentBrowser?.(stateDir):null;
   if(nativeLocalPrepared(deployment)&&nativeBrowserPrepared(deployment,browser)){
    await api.startDeploymentForeground(stateDir,{authorize:true});nativeStartup={status:'started',observation:'current_process'};
   }else nativeStartup={status:'preparation_required',observation:'current_process'};
  }catch(error){startupFailure(error)}
 };
 const services={host:null,gateway:null};
 let pendingLink,acceptedLink;
 const linkImportAvailable=!!pairingLinks||fs.existsSync(new URL('./pairing-links.mjs',import.meta.url));
 const linkApi=async()=>pairingLinks??await import('./pairing-links.mjs');
 const gatewayServiceCapability=gatewayServiceUiCapabilities(process.platform,typeof gatewayService==='function'||fs.existsSync(new URL('./gateway-service.mjs',import.meta.url)));
 const gatewayServiceAvailable=gatewayServiceCapability.supported;
 const readStatus=async(observedApi=api,observeBackground=backgroundRead,observeTunnel=tunnelRead)=>{
  try{
   const deployment=publicDeployment(await observedApi.readDeployment(stateDir)),plan=await observedApi.planDeployment(stateDir);
   const dependencies=Array.isArray(plan?.steps)?plan.steps.filter(s=>STEPS.has(s.id)).map(s=>({id:s.id,requires:Array.isArray(s.requires)?s.requires.filter(id=>STEPS.has(id)):[]})):[];
   const scope=plan?.ownerPairingScope;
   const ownerPairingScope=scope&&typeof scope.gatewayUrl==='string'&&typeof scope.label==='string'&&typeof scope.enableComputer==='boolean'?{gatewayUrl:scope.gatewayUrl,label:scope.label,enableComputer:scope.enableComputer,enableBrowser:scope.enableBrowser===true}:null;
   let background=null;try{background=await observeBackground(stateDir)}catch{}
   let tunnelStatus=null;try{tunnelStatus=tunnel?await observeTunnel():null}catch{}
   let deviceCapabilities=null;try{deviceCapabilities=readDeploymentCapabilities(stateDir)}catch{}
   let foreground=null;try{foreground=await observedApi.readDeploymentForeground?.(stateDir)}catch{}
   let ownedForeground=null;try{ownedForeground=observedApi.readOwnedDeploymentForeground?.(stateDir)}catch{}
   const components=typeof observedApi.readDeploymentComponents==='function'?await observedApi.readDeploymentComponents(stateDir,{artifacts:artifacts.bundle?artifacts:undefined}):null;
   const joinRecovery=typeof api.readDeploymentJoinRecovery==='function'?await api.readDeploymentJoinRecovery(stateDir):null;
   return {joinRecovery,deployment,dependencies,ownerPairingScope,services,background,foreground,ownedForeground,deviceCapabilities,components,tunnel:tunnelStatus,nativeStartup,busy};
  }catch(error){if(!fs.existsSync(stateDir))return {deployment:null,dependencies:[],busy};throw error}
 };
 const readNativeStatus=async()=>{
  // Component lifetime and permission recovery must remain observable even
  // when unrelated page data (such as a damaged plugin profile) cannot load.
  // Use a fresh, authenticated foreground observation on every request.
  let foreground=null;try{foreground=await api.readDeploymentForeground?.(stateDir)}catch{}
  return readStatus({...api,readDeploymentForeground:()=>foreground},()=>nativeForegroundOwnsConnections(foreground)?null:backgroundRead(stateDir));
 };
 const readSnapshot=async()=>{
  // Deduplication lasts for this one response only. Every refresh reads fresh
  // Core evidence; no running state, grant or account proof is cached.
  const reads=new Map(),once=(name,fn)=>{
   if(!reads.has(name))reads.set(name,Promise.resolve().then(fn));
   return reads.get(name);
  };
  const observedApi={...api};
  for(const name of ['readDeployment','planDeployment','readDeploymentForeground','readDeploymentAcceptance','readDeploymentConnectionHandoff','readDeploymentOnboardingPreference','readDeploymentPermissions','readDeploymentPlugin']){
   if(typeof api[name]==='function')observedApi[name]=()=>once(name,()=>api[name](stateDir));
  }
  let foreground=null;try{foreground=await observedApi.readDeploymentForeground?.(stateDir)}catch{}
  // Current foreground ownership is already authenticated and scope-checked
  // by Core. Scanning unused services cannot make these App-owned connections
  // more current. Service reuse or uncertain owners retain full observation.
  // Omission stays not_observed; it never becomes background-service readiness.
  const observeBackground=()=>once('background',()=>nativeForegroundOwnsConnections(foreground)?null:backgroundRead(stateDir));
  const observeTunnel=()=>once('tunnel',()=>tunnelRead());
  const status=await readStatus(observedApi,observeBackground,observeTunnel);
  const journey=await readOnboardingJourney(stateDir,{core:observedApi,backgroundRead:observeBackground,tunnelRead:observeTunnel});
  let browser=null,plugin=null,acceptance=null,lifecycle=null;
  if(status.deployment){
   if(nativeLocalPrepared(status.deployment)&&status.deployment.roles?.browser==='requested')try{browser=await api.readDeploymentBrowser?.(stateDir)}catch{}
   acceptance=publicAcceptance(typeof observedApi.readDeploymentAcceptance==='function'?await observedApi.readDeploymentAcceptance(stateDir):null,{includeChallenge:true});
   if(status.deployment.mode!=='join-existing'&&typeof observedApi.readDeploymentPlugin==='function')plugin=await observedApi.readDeploymentPlugin(stateDir);
  }
  if(nativeAppLifecycleSupported&&typeof api.readDeploymentAppLifecycle==='function')try{lifecycle=await api.readDeploymentAppLifecycle(stateDir,lifecycleContext())}catch{}
  return {status,journey,browser,acceptance,plugin,lifecycle};
 };
 const assets=new Map([['/',['index.html','text/html; charset=utf-8']],['/ui/app.mjs',['app.mjs','text/javascript; charset=utf-8']],['/ui/style.css',['style.css','text/css; charset=utf-8']]]);
 const server=http.createServer(async(req,res)=>{
  const send=(status,value)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value))};
  res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  const expectedHost=new URL(origin).host;
  if(req.headers.host!==expectedHost){send(403,{error:'host_refused'});return}
  let url;try{url=new URL(req.url,origin)}catch{send(400,{error:'invalid_url'});return}
  if(url.search){send(400,{error:'query_refused'});return}
  if(assets.has(url.pathname)&&req.method==='GET'){
   const[file,type]=assets.get(url.pathname);res.writeHead(200,{'Content-Type':type});res.end(fs.readFileSync(path.join(UI,file)));return;
  }
  if(!url.pathname.startsWith('/api/')){send(404,{error:'not_found'});return}
  if(!equal(req.headers.authorization,'Bearer '+session)){send(401,{error:'session_required'});return}
  if(req.headers.origin!==undefined&&req.headers.origin!==origin){send(403,{error:'origin_refused'});return}
  if(req.method==='POST'&&(req.headers.origin!==origin||!equal(req.headers['x-styx-csrf'],csrf))){send(403,{error:'mutation_refused'});return}
  // A first transition from byte-pinned ad-hoc code to a persistent signer is
  // a reviewed Core migration, never an incidental status/startup side effect.
  if(nativeSigningMigrationRequired&&req.method==='POST'&&!['/api/app/quit','/api/native-signing/plan','/api/native-signing/apply'].includes(url.pathname)){send(409,{error:'native_signing_registration_required'});return}
  // Connections and setup mutations cannot race an admitted native bundle
  // reconciliation. Recovery/quit stay reachable; read-only status stays honest.
  if(nativeAppOwned&&nativeStartup.reason?.startsWith('host_payload_')&&req.method==='POST'&&!['/api/app/quit','/api/app/quit-admission'].includes(url.pathname)&&!url.pathname.startsWith('/api/host-payload/')){send(409,{error:nativeStartup.reason});return}
  if(req.method==='GET'&&url.pathname==='/api/session'){
   send(200,{csrf,platform:process.platform,journeySupported:true,nativeAppLifecycleSupported,nativeSigningUpgradeSupported:!!macPreviewApp,diagnosticsSupported:true,browserPreparationSupported:typeof api.readDeploymentBrowser==='function'&&typeof api.prepareDeploymentBrowser==='function',foregroundSupported:typeof api.startDeploymentForeground==='function'&&typeof api.stopDeploymentForeground==='function',acceptanceSupported:['readDeploymentAcceptance','beginDeploymentAcceptance','confirmDeploymentAcceptance','recordDeploymentDesktopReadback'].every(k=>typeof api[k]==='function'),connectionHandoffSupported:typeof api.prepareDeploymentConnectionHandoff==='function',packagedPreviewTrusted:!!macPreviewApp,backgroundSupported:true,capabilityChangeSupported:true,deviceSettingsSupported:typeof api.readDeploymentDevices==='function',tunnelSupported:!!tunnel,localGatewayAvailable:!!trustedOpenSSL,pauseSupported:typeof api.stopDeploymentGateway==='function',startSupported:typeof api.startDeploymentGateway==='function',
    deviceIngressSupported:typeof api.planDeviceIngress==='function'&&typeof api.verifyDeviceIngress==='function',pairingLinkImportSupported:linkImportAvailable,joinRecoverySupported:typeof api.recoverDeploymentJoin==='function',pairingLinkCreateSupported:typeof api.createDeploymentPairingLink==='function',pendingApprovalSupported:typeof api.listDeploymentPending==='function'&&typeof api.approveDeploymentPending==='function',hostServiceSupported:typeof api.controlDeploymentHostService==='function',gatewayServiceSupported:gatewayServiceAvailable,gatewayService:gatewayServiceCapability,localGatewayAddresses:typeof api.localGatewayAddresses==='function'?api.localGatewayAddresses():[],defaults,accountAcceptance:'NOT RUN',nativeInstaller:'NOT RUN',trustedForwarding:!!forwarded});return;
  }
  if(req.method==='GET'&&url.pathname==='/api/app/lifecycle'){
   if(!nativeAppLifecycleSupported||typeof api.readDeploymentAppLifecycle!=='function'){send(409,{error:'native_app_lifecycle_unavailable'});return}
   try{send(200,{lifecycle:await api.readDeploymentAppLifecycle(stateDir,lifecycleContext())})}catch{send(409,{error:'native_app_lifecycle_observation_failed'})}return;
  }
  if(req.method==='GET'&&url.pathname==='/api/native-signing/status'){
   if(!macPreviewApp){send(409,{error:'native_signing_upgrade_unavailable'});return}
   let requiresReview=nativeStartup.reason==='native_signing_upgrade_requires_review';
   try{const journal=fs.existsSync(path.join(stateDir,'deployment.json'))?await api.readDeploymentMacSigningRegistration?.(stateDir):null;if(journal&&!['not_started','applied','rolled_back'].includes(journal.status))requiresReview=true}catch{requiresReview=true}
   send(200,{upgrade:{status:requiresReview?'needs_review':nativeSigningMigrationRequired?'required':'not_required'}});return;
  }
  if(req.method==='GET'&&url.pathname==='/api/join/recovery'){send(200,{recovery:await api.readDeploymentJoinRecovery(stateDir)});return;}
  if(req.method==='GET'&&url.pathname==='/api/plugin'){
   if(typeof api.readDeploymentPlugin!=='function'){send(404,{error:'plugin_workflow_unavailable'});return}
   try{send(200,{plugin:await api.readDeploymentPlugin(stateDir)})}catch{send(409,{error:'plugin_state_unavailable'})}return;
  }
  if(req.method==='GET'&&url.pathname==='/api/components'){
   if(typeof api.readDeploymentComponents!=='function'){send(404,{error:'component_observation_unavailable'});return}
   send(200,{components:await api.readDeploymentComponents(stateDir,{artifacts:artifacts.bundle?artifacts:undefined})});return;
  }
  if(req.method==='GET'&&url.pathname==='/api/status'){
   try{send(200,await readStatus())}catch{send(409,{error:'deployment_unavailable'})}return;
  }
  if(req.method==='GET'&&url.pathname==='/api/native-status'){
   try{send(200,await readNativeStatus())}catch{send(409,{error:'deployment_unavailable'})}return;
  }
  if(req.method==='GET'&&url.pathname==='/api/snapshot'){
   try{send(200,await readSnapshot())}catch{send(409,{error:'observation_unavailable'})}return;
  }
  if(req.method==='GET'&&url.pathname==='/api/browser'){try{if(typeof api.readDeploymentBrowser!=='function')fail('browser_preparation_unavailable');send(200,{browser:await api.readDeploymentBrowser(stateDir)});}catch{send(409,{error:'browser_preparation_unavailable'})}return;}
  if(req.method==='GET'&&['/api/journey','/api/diagnostics','/api/acceptance'].includes(url.pathname)){
   try{
    if(url.pathname==='/api/journey')send(200,{journey:await readOnboardingJourney(stateDir,journeyOptions)});
    else if(url.pathname==='/api/diagnostics')send(200,{diagnostics:await readOnboardingDiagnostics(stateDir,journeyOptions)});
    else send(200,{acceptance:publicAcceptance(typeof api.readDeploymentAcceptance==='function'?await api.readDeploymentAcceptance(stateDir):null,{includeChallenge:true})});
   }catch{send(409,{error:'observation_unavailable'})}return;
  }
  if(req.method!=='POST'){send(405,{error:'method_refused'});return}
  if(!['/api/join/recover','/api/join/rollback','/api/app/quit-admission','/api/host-payload/handoff/prepare','/api/host-payload/handoff/status','/api/host-payload/handoff/cancel','/api/host-payload/plan','/api/host-payload/apply','/api/host-payload/rollback','/api/host-payload/status','/api/native-signing/plan','/api/native-signing/apply','/api/app/quit','/api/app/login','/api/plugin/profile','/api/plugin/export','/api/plugin/record','/api/foreground','/api/foreground/stop','/api/browser/prepare','/api/journey/background-preference','/api/connection-handoff','/api/acceptance/begin','/api/acceptance/confirm','/api/acceptance/desktop-readback','/api/host-update/plan','/api/host-update/status','/api/host-update/apply','/api/host-update/recover','/api/runtime-change/status','/api/runtime-change/plan','/api/runtime-change/apply','/api/runtime-change/recover','/api/native-migration/plan','/api/native-migration/apply','/api/native-migration/rollback','/api/device-ingress/plan','/api/device-ingress/verify','/api/device-ingress/prepare','/api/device-ingress/status','/api/device-ingress/recover','/api/pairing-link/close','/api/create','/api/devices','/api/default-device','/api/device/revoke','/api/capabilities','/api/capabilities/rollback','/api/tunnel/configure','/api/tunnel/start','/api/tunnel/stop','/api/background','/api/local-setup','/api/advance','/api/pause','/api/start','/api/verify-gateway','/api/service','/api/pairing-link/inspect','/api/pairing-link/accept','/api/pairing-link/create','/api/pending/list','/api/pending/approve'].includes(url.pathname)){send(404,{error:'not_found'});return}
  if(busy){send(409,{error:'operation_in_progress'});return}busy=true;
  try{
   const data=await body(req,url.pathname==='/api/plugin/profile'?400*1024:65536);
   if(['/api/native-signing/plan','/api/native-signing/apply'].includes(url.pathname)){
    if(!macPreviewApp||!nativeSigningMigrationRequired||typeof api.planDeploymentMacSigningRegistration!=='function'||typeof api.applyDeploymentMacSigningRegistration!=='function')fail('native_signing_upgrade_unavailable');
    if(url.pathname.endsWith('/plan')){
     keys(data,[]);signingPlan=null;
     signingPlan=await api.planDeploymentMacSigningRegistration(stateDir,{app:signingApp()});
     send(200,{upgrade:{status:'reviewable',planId:signingPlan.planId,scope:'app_signing_registration_only',identityMutation:'NONE',serviceMutation:'NONE',systemPermissions:'UNCHANGED'}});return;
    }
    keys(data,['authorize','planId']);
    if(data.authorize!==true||!signingPlan||data.planId!==signingPlan.planId)fail('native_signing_upgrade_plan_required');
    const reviewed=signingPlan;signingPlan=null;
    try{
     const result=await api.applyDeploymentMacSigningRegistration(stateDir,{authorize:true,plan:reviewed});
     if(result?.status!=='applied')fail('native_signing_upgrade_unconfirmed');
     nativeSigningMigrationRequired=false;
     await resumeNativeStartup();
     if(tunnel)await tunnel.resume().catch(()=>{});
     send(200,{upgrade:{status:'applied',rollbackRecorded:true},nativeStartup});
    }catch{
     nativeStartup={status:'reconciliation_required',observation:'current_process',reason:'native_signing_upgrade_requires_review'};
     send(409,{error:'native_signing_upgrade_requires_review'});
    }
    return;
   }
   if(url.pathname==='/api/app/quit-admission'){
    keys(data,['authorize']);if(data.authorize!==true)fail('explicit_work_admission_required');const admission=await admitWork('quit',true);send(200,{quit:{status:'ready_to_quit',ticketId:admission.ticketId}});return;
   }else if(['/api/app/quit','/api/app/login'].includes(url.pathname)){
    const action=url.pathname.endsWith('/quit')?'quit':'login';
    keys(data,action==='quit'?['authorize']:['authorize','enabled']);
    if(!nativeAppLifecycleSupported||data.authorize!==true||typeof api.controlDeploymentAppLifecycle!=='function')fail('native_app_lifecycle_unavailable');
    if(action==='quit')await admitWork('quit',true);
    try{send(200,{lifecycle:await api.controlDeploymentAppLifecycle(stateDir,{...data,action},lifecycleContext())});}catch(error){if(action==='quit')await cancelWorkAdmission();throw error}return;
   }else if(url.pathname==='/api/plugin/profile'){
    keys(data,['authorize','presentation','selection']);if(data.authorize!==true||typeof api.setDeploymentPluginProfile!=='function')fail('plugin_authorization_required');send(200,{plugin:await api.setDeploymentPluginProfile(stateDir,data)});return;
   }else if(url.pathname==='/api/plugin/record'){
    keys(data,['authorize','stage','pluginUrl']);if(data.authorize!==true||typeof api.recordDeploymentPluginAction!=='function')fail('plugin_authorization_required');send(200,{plugin:await api.recordDeploymentPluginAction(stateDir,data)});return;
   }else if(url.pathname==='/api/plugin/export'){
    keys(data,['authorize']);if(data.authorize!==true||typeof api.exportDeploymentPlugin!=='function')fail('plugin_authorization_required');
    const result=await api.exportDeploymentPlugin(stateDir,data);
    if(!Buffer.isBuffer(result?.archive)||result.archive.length>2*1024*1024||result.fileName!=='styx-native.zip')fail('invalid_plugin_archive');
    res.writeHead(200,{'Content-Type':'application/zip','Content-Disposition':'attachment; filename="styx-native.zip"','Content-Length':result.archive.length});res.end(result.archive);return;
   }else if(url.pathname==='/api/foreground/stop'){
    keys(data,['authorize']);
    if(!macPreviewApp||data.authorize!==true||typeof api.stopOwnedDeploymentForeground!=='function')fail('native_owned_foreground_control_required');
    const result=await api.stopOwnedDeploymentForeground(stateDir,{authorize:true});
    if(result?.status!=='stopped'||result.observation!=='current_process'||result.foregroundRestartRequired!==true)fail('foreground_stop_unconfirmed');
    send(200,{foreground:result});return;
   }else if(url.pathname==='/api/foreground'){
    keys(data,['authorize']);if(data.authorize!==true||typeof api.startDeploymentForeground!=='function')fail('foreground_authorization_required');try{const foreground=await api.startDeploymentForeground(stateDir,{authorize:true});nativeStartup={status:'started',observation:'current_process'};send(200,{foreground});}catch(error){startupFailure(error);throw error}return;
   }else if(url.pathname==='/api/journey/background-preference'){
    keys(data,['background','authorize']);if(data.authorize!==true||!['foreground','login'].includes(data.background)||typeof api.setDeploymentOnboardingPreference!=='function')fail('background_preference_authorization_required');
    const result=await api.setDeploymentOnboardingPreference(stateDir,data);send(200,{preference:{background:['foreground','login'].includes(result?.background)?result.background:'not_decided',configurationBound:result?.configurationBound===true}});return;
   }else if(url.pathname==='/api/connection-handoff'){
    keys(data,['authorize']);if(data.authorize!==true||typeof api.prepareDeploymentConnectionHandoff!=='function')fail('connection_handoff_authorization_required');
    const result=await api.prepareDeploymentConnectionHandoff(stateDir,{authorize:true});
    // This is the only authenticated local UI response that carries the model
    // credential. It is never retained in the generic status/diagnostic cache.
    send(200,{handoff:result});return;
   }else if(['/api/acceptance/begin','/api/acceptance/confirm','/api/acceptance/desktop-readback'].includes(url.pathname)){
    const which=url.pathname.split('/').at(-1),name=which==='begin'?'beginDeploymentAcceptance':which==='confirm'?'confirmDeploymentAcceptance':'recordDeploymentDesktopReadback';
    keys(data,which==='begin'?['authorize']:which==='confirm'?['authorize','challengeId','observedInTargetChat']:['authorize','challengeId','value','pid','windowId']);
    if(data.authorize!==true||typeof api[name]!=='function')fail('acceptance_authorization_required');
    send(200,{acceptance:publicAcceptance(await api[name](stateDir,data),{includeChallenge:true})});return;
   }else if(url.pathname==='/api/host-payload/handoff/prepare'){
    keys(data,['authorize']);if(data.authorize!==true||!artifacts.bundle||typeof api.prepareHostPayloadHandoff!=='function')fail('host_payload_handoff_authorization_required');
    await admitWork('host-update');try{send(200,{handoff:await api.prepareHostPayloadHandoff({stateDir,bundle:artifacts.bundle,authorize:true})});}catch(error){await cancelWorkAdmission();throw error}return;
   }else if(url.pathname==='/api/host-payload/handoff/status'){
    keys(data,[]);if(typeof api.readHostPayloadHandoff!=='function')fail('host_payload_handoff_unavailable');
    send(200,{handoff:await api.readHostPayloadHandoff({stateDir})});return;
   }else if(url.pathname==='/api/host-payload/handoff/cancel'){
    keys(data,['authorize','ticketId']);if(data.authorize!==true||typeof api.cancelHostPayloadHandoff!=='function')fail('host_payload_handoff_authorization_required');
    const handoff=await api.cancelHostPayloadHandoff({stateDir,ticketId:data.ticketId,authorize:true});await cancelWorkAdmission();send(200,{handoff});return;
   }else if(url.pathname==='/api/host-payload/plan'){
    keys(data,[]);payloadPlan=null;
    if(!artifacts.bundle||typeof api.planHostPayloadMigration!=='function')fail('host_payload_upgrade_unavailable');
    payloadPlan=await api.planHostPayloadMigration({stateDir,bundle:artifacts.bundle});
    const release=value=>({version:value?.version,manifestSha256:value?.manifestSha256,publisherSha256:value?.publisherSha256});
    send(200,{upgrade:{status:payloadPlan.status,reason:payloadPlan.reason,planId:payloadPlan.planId,current:release(payloadPlan.current),target:release(payloadPlan.target),publisherChange:payloadPlan.publisherChange===true,receiptReconciliation:payloadPlan.receiptReconciliation,preparationEvidenceReconciliation:payloadPlan.preparationEvidenceReconciliation,requiresApplicationExit:true,installation:'NOT RUN',runtimeHealth:'NOT RUN'}});return;
   }else if(url.pathname==='/api/host-payload/apply'){
    keys(data,['authorize','planId']);
    if(data.authorize!==true||payloadPlan?.status!=='offline_reviewable'||data.planId!==payloadPlan.planId||typeof api.applyHostPayloadMigration!=='function')fail('host_payload_reviewed_plan_required');
    const reviewed=payloadPlan;payloadPlan=null;
    send(200,{upgrade:await api.applyHostPayloadMigration({stateDir,plan:reviewed,authorize:true})});return;
   }else if(url.pathname==='/api/host-payload/rollback'){
    keys(data,['authorize','transactionId']);
    if(data.authorize!==true||typeof api.rollbackHostPayloadMigration!=='function')fail('host_payload_rollback_authorization_required');
    payloadPlan=null;
    send(200,{upgrade:await api.rollbackHostPayloadMigration({stateDir,transactionId:data.transactionId,authorize:true})});return;
   }else if(url.pathname==='/api/host-payload/status'){
    keys(data,[]);if(typeof api.readHostPayloadMigration!=='function')fail('host_payload_upgrade_unavailable');
    send(200,{upgrade:await api.readHostPayloadMigration({stateDir})});return;
   }else if(url.pathname==='/api/host-update/plan'){
    keys(data,['bundle','rollback']);send(200,{plan:await api.planHostUpdate({stateDir,...data})});return;
   }else if(url.pathname==='/api/host-update/apply'){
    keys(data,['authorize','plan']);if(data.authorize!==true||typeof api.applyHostUpdate!=='function')fail('host_update_unavailable');send(200,{update:await api.applyHostUpdate({stateDir,plan:data.plan,authorize:true})});return;
   }else if(url.pathname==='/api/host-update/recover'){
    keys(data,['authorize','transactionId']);if(data.authorize!==true||typeof api.recoverHostUpdate!=='function')fail('host_update_unavailable');send(200,{update:await api.recoverHostUpdate({stateDir,transactionId:data.transactionId,authorize:true})});return;
   }else if(url.pathname==='/api/host-update/status'){
    keys(data,['transactionId']);send(200,{update:await api.readHostUpdate({stateDir,...data})});return;
   }else if(url.pathname==='/api/runtime-change/status'){
    keys(data,[]);send(200,{change:await api.readGatewayRuntimeChange({stateDir})});return;
   }else if(url.pathname==='/api/runtime-change/plan'){
    keys(data,['bundle','rollback']);send(200,{plan:await api.planGatewayRuntimeChange({stateDir,...data})});return;
   }else if(url.pathname==='/api/runtime-change/apply'){
    keys(data,['plan','authorize']);send(200,{change:await api.applyGatewayRuntimeChange({stateDir,...data})});return;
   }else if(url.pathname==='/api/runtime-change/recover'){
    keys(data,['transactionId','authorize']);send(200,{change:await api.recoverGatewayRuntimeChange({stateDir,...data})});return;
   }else if(url.pathname==='/api/native-migration/plan'){
    keys(data,['nativeApp']);send(200,{plan:await api.planNativeSupervisorMigration(stateDir,data)});return;
   }else if(url.pathname==='/api/native-migration/apply'){
    keys(data,['plan','authorize']);send(200,{migration:await api.applyNativeSupervisorMigration(stateDir,data)});return;
   }else if(url.pathname==='/api/native-migration/rollback'){
    keys(data,['transactionId','authorize']);send(200,{migration:await api.rollbackNativeSupervisorMigration(stateDir,data)});return;
   }else if(url.pathname==='/api/device-ingress/plan'){
    keys(data,[]);send(200,{ingress:await api.planDeviceIngress(stateDir)});return;
   }else if(url.pathname==='/api/device-ingress/verify'){
    keys(data,['url']);if(typeof data.url!=='string'||data.url.length>4096)fail('exact_ingress_url_required');send(200,{ingress:await api.verifyDeviceIngress(stateDir,{url:data.url})});return;
   }else if(url.pathname==='/api/create'){
    const{joinLinkId,...input}=data;
    if(joinLinkId!==undefined){if(!acceptedLink||acceptedLink.id!==joinLinkId||input.mode!=='join-existing'||input.gateway?.url!==acceptedLink.refs.gatewayOrigin||(!Number.isSafeInteger(acceptedLink.refs.expiresAt)||acceptedLink.refs.expiresAt<=Date.now())||input.invitationFile||input.gateway.caFile)fail('accepted_pairing_scope_required');input.invitationFile=acceptedLink.refs.invitationFile;input.gateway={...input.gateway,...(acceptedLink.refs.gatewayCaFile?{caFile:acceptedLink.refs.gatewayCaFile}:{})}}
    const config=validateUiConfig(input,{trustedOpenSSL,trustedOpenSSLConfig});
    if(macPreviewApp&&config.host)config.host={...config.host,macPreviewApp:{path:macPreviewApp.path,cdhash:macPreviewApp.cdhash,...(macPreviewApp.certificateSha1?{certificateSha1:macPreviewApp.certificateSha1,certificateSha256:macPreviewApp.certificateSha256}:{})}};
    if(config.mode==='create-local'&&new URL(config.gateway.url).hostname!=='127.0.0.1'&&config.gateway.allowRemoteHosts!==true)fail('explicit_network_exposure_required');
    if(config.gateway.allowRemoteHosts){const addresses=typeof api.localGatewayAddresses==='function'?api.localGatewayAddresses():[];if(!addresses.includes(config.gateway.listenHost)||new URL(config.gateway.url).hostname!==config.gateway.listenHost)fail('explicit_owned_network_interface_required')}
    const temp=path.join(os.tmpdir(),'styx-ui-config-'+randomBytes(16).toString('hex'));ensurePrivateDirectory(temp,{exclusive:true});
    try{const file=path.join(temp,'config.json');writePrivateFile(file,JSON.stringify(config));await api.createDeployment(file,{stateDir})}
    finally{fs.rmSync(temp,{recursive:true,force:true})}
   }else if(url.pathname==='/api/devices'){
    keys(data,[]);if(typeof api.readDeploymentDevices!=='function')fail('device_settings_unavailable');send(200,{devices:await api.readDeploymentDevices(stateDir)});return;
   }else if(url.pathname==='/api/device/revoke'){
    keys(data,['authorize','deviceId']);if(data.authorize!==true||typeof api.revokeDeploymentDevice!=='function')fail('explicit_device_revocation_required');
    const result=await api.revokeDeploymentDevice(stateDir,data);send(200,{device:result});return;
   }else if(url.pathname==='/api/default-device'){
    keys(data,['authorize','deviceId']);if(typeof api.setDeploymentDefault!=='function')fail('device_settings_unavailable');await api.setDeploymentDefault(stateDir,data);send(200,{status:'updated'});return;
   }else if(url.pathname==='/api/browser/prepare'){
    keys(data,['authorize','recover']);if(data.authorize!==true||data.recover!==undefined&&typeof data.recover!=='boolean'||typeof api.prepareDeploymentBrowser!=='function')fail('explicit_browser_preparation_authorization_required');send(200,{browser:await api.prepareDeploymentBrowser(stateDir,{authorize:true,...(data.recover!==undefined?{recover:data.recover}:{})})});return;
   }else if(url.pathname==='/api/capabilities/rollback'){
    keys(data,['authorize','transactionId']);const result=await api.rollbackDeploymentCapabilities(stateDir,data);send(200,{capabilities:result});return;
   }else if(url.pathname==='/api/capabilities'){
    keys(data,['authorize','computer','browser','browserChannel','persistLogin']);const result=await changeDeploymentCapabilities(stateDir,data,{trustedMacPreviewApp:macPreviewApp});send(200,{capabilities:result});return;
   }else if(url.pathname==='/api/tunnel/configure'){
    keys(data,['tunnelId','apiKey','authorize','autoStart']);if(!tunnel)fail('bundled_tunnel_unavailable');
    const result=configureTunnel(stateDir,data);send(200,{tunnel:result});return;
   }else if(url.pathname==='/api/tunnel/start'){
    keys(data,['authorize']);if(!tunnel||data.authorize!==true)fail('explicit_tunnel_authorization_required');
    const result=await tunnel.start({authorize:true});send(200,{tunnel:result});return;
   }else if(url.pathname==='/api/tunnel/stop'){
    keys(data,['authorize']);if(!tunnel||data.authorize!==true)fail('explicit_tunnel_authorization_required');
    const result=await tunnel.stop();send(200,{tunnel:result});return;
   }else if(url.pathname==='/api/background'){
    keys(data,['authorize']);if(data.authorize!==true)fail('explicit_background_authorization_required');
    const background=await backgroundControl(stateDir,{authorize:true});if(background.reason==='foreground_host_handoff_required'){send(409,{error:background.reason});return}send(200,{background});return;
   }else if(url.pathname==='/api/local-setup'){
    keys(data,['ownerApproval']);
    const result=await completeLocalSetup(api,stateDir,data.ownerApproval);
    send(200,{workflow:result,deployment:publicDeployment(await api.readDeployment(stateDir))});return;
   }else if(url.pathname==='/api/advance'){
    keys(data,['authorize','ownerApproval']);if(!Array.isArray(data.authorize)||data.authorize.length!==1||!STEPS.has(data.authorize[0]))fail('one_known_step_required');
    if(data.authorize[0]==='host.pair'){keys(data.ownerApproval,['approve','gatewayUrl','label','enableComputer','enableBrowser']);if(data.ownerApproval.approve!==true||typeof data.ownerApproval.gatewayUrl!=='string'||typeof data.ownerApproval.label!=='string'||typeof data.ownerApproval.enableComputer!=='boolean'||data.ownerApproval.enableBrowser!==undefined&&typeof data.ownerApproval.enableBrowser!=='boolean')fail('explicit_owner_pairing_scope_required')}else if(data.ownerApproval!==undefined)fail('unexpected_owner_approval');
    await api.advanceDeployment(stateDir,{authorize:data.authorize,...(data.ownerApproval?{ownerApproval:data.ownerApproval}:{})});
   }else if(url.pathname==='/api/join/recover'){
    keys(data,['authorize','joinLinkId']);if(data.authorize!==true||!acceptedLink||acceptedLink.id!==data.joinLinkId||typeof api.recoverDeploymentJoin!=='function')fail('accepted_pairing_scope_required');
    const pairingFile=acceptedLink.file;const recovery=await api.recoverDeploymentJoin(stateDir,{authorize:true,pairingFile});acceptedLink=null;send(200,{recovery});return;
   }else if(url.pathname==='/api/join/rollback'){
    keys(data,['authorize','transactionId']);send(200,{recovery:await api.rollbackDeploymentJoin(stateDir,data)});return;
   }else if(url.pathname==='/api/pairing-link/inspect'){
    keys(data,['link']);if(!linkImportAvailable||typeof data.link!=='string'||data.link.length>65536)fail('pairing_link_required');const helper=await linkApi(),preview=helper.inspectPairingLink(data.link);const publicPreview={origin:preview.origin,expiresAt:preview.expiresAt,requiresCertificateApproval:preview.requiresCertificateApproval===true,...(preview.caSha256?{caSha256:preview.caSha256}:{})};pendingLink={id:randomBytes(16).toString('hex'),link:data.link,preview:publicPreview};send(200,{inspectionId:pendingLink.id,preview:publicPreview});return;
   }else if(url.pathname==='/api/pairing-link/accept'){
    keys(data,['inspectionId','approvedGatewayOrigin','approvedCaSha256']);if(!pendingLink||data.inspectionId!==pendingLink.id||data.approvedGatewayOrigin!==pendingLink.preview.origin||(pendingLink.preview.caSha256&&data.approvedCaSha256!==pendingLink.preview.caSha256))fail('pairing_scope_confirmation_required');
    const helper=await linkApi(),directory=path.join(path.dirname(stateDir),'styx-pairing-'+randomBytes(8).toString('hex'));const result=helper.acceptPairingLink(pendingLink.link,{stateDir:directory,approvedGatewayOrigin:data.approvedGatewayOrigin,...(data.approvedCaSha256?{approvedCaSha256:data.approvedCaSha256}:{})});
    const file=path.join(directory,'pairing.json');requirePrivateFile(file);acceptedLink={id:randomBytes(16).toString('hex'),file,refs:JSON.parse(fs.readFileSync(file,'utf8'))};pendingLink=null;send(200,{joinLinkId:acceptedLink.id,status:result.status,origin:result.origin,expiresAt:result.expiresAt,customCertificateApproved:result.customCertificateApproved===true});return;
   }else if(url.pathname==='/api/device-ingress/prepare'){
    keys(data,['authorize','listenHost','port']);if(data.authorize!==true||typeof api.prepareDeploymentDeviceIngress!=='function')fail('device_ingress_authorization_required');send(200,{ingress:await api.prepareDeploymentDeviceIngress(stateDir,data)});return;
   }else if(url.pathname==='/api/device-ingress/status'){
    keys(data,[]);send(200,{setup:await api.readDeploymentDeviceIngressSetup(stateDir)});return;
   }else if(url.pathname==='/api/device-ingress/recover'){
    keys(data,['authorize','action']);if(data.authorize!==true||!['retry','rollback'].includes(data.action))fail('device_ingress_recovery_authorization_required');send(200,{setup:await api.recoverDeploymentDeviceIngress(stateDir,data)});return;
   }else if(url.pathname==='/api/pairing-link/close'){
    keys(data,['authorize']);if(data.authorize!==true)fail('owner_pairing_close_required');send(200,{ingress:await api.closeDeploymentPairingWindow(stateDir,data)});return;
   }else if(url.pathname==='/api/pairing-link/create'){
    keys(data,['authorize','listenHost','port']);if(data.authorize!==true||typeof api.createDeploymentPairingLink!=='function')fail('owner_link_not_supported');const result=await api.createDeploymentPairingLink(stateDir,data);send(200,{link:result.link,origin:result.origin,expiresAt:result.expiresAt,...(result.caSha256?{caSha256:result.caSha256}:{}),reachability:result.reachability,remoteUsable:result.remoteUsable===true});return;
   }else if(url.pathname==='/api/pending/list'){
    keys(data,['authorize']);if(data.authorize!==true||typeof api.listDeploymentPending!=='function')fail('owner_list_not_supported');const rows=await api.listDeploymentPending(stateDir,{authorize:true});
    const pending=rows.filter(r=>/^[a-f0-9]{32}$/.test(r.request_id??'')&&/^[a-f0-9]{64}$/.test(r.fingerprint??'')).map(r=>({request_id:r.request_id,fingerprint:r.fingerprint,label:String(r.label??'').slice(0,72),platform:['linux','darwin','win32'].includes(r.platform)?r.platform:'unknown',cwd:String(r.cwd??'').slice(0,4096),shell:String(r.shell??'').slice(0,4096),computer_requested:r.computer_requested===true,browser_requested:r.browser_requested===true,comparison_code:r.comparison_code,expires_at:r.expires_at}));send(200,{pending});return;
   }else if(url.pathname==='/api/pending/approve'){
    keys(data,['authorize','requestId','fingerprint','fingerprintConfirmation','comparisonCodeConfirmation','enableComputer','enableBrowser']);
    if(data.authorize!==true||typeof api.approveDeploymentPending!=='function'||typeof api.listDeploymentPending!=='function'||!/^[a-f0-9]{32}$/.test(data.requestId??''))fail('explicit_device_approval_required');
    const requests=await api.listDeploymentPending(stateDir,{authorize:true}),selected=requests.find(r=>r.request_id===data.requestId);
    if(!selected||!/^[a-f0-9]{64}$/.test(selected.fingerprint??''))fail('pending_device_not_found');
    const typed=data.comparisonCodeConfirmation??data.fingerprintConfirmation??data.fingerprint;
    if(typeof typed!=='string'||typed.length>80)fail('fingerprint_confirmation_required');
    const confirmation=typed.replace(/[\s-]/g,'').toLowerCase();
    if(data.comparisonCodeConfirmation!==undefined){
     if(typeof selected.comparison_code!=='string'||confirmation!==selected.comparison_code.replace(/-/g,'').toLowerCase())fail('pairing_comparison_mismatch');
    }else if(!/^(?:[a-f0-9]{16}|[a-f0-9]{64})$/.test(confirmation)||(confirmation.length===64?selected.fingerprint!==confirmation:!!selected.comparison_code||selected.fingerprint.slice(0,16)!==confirmation))fail('fingerprint_confirmation_mismatch');
    for(const [key,requested]of [['enableComputer','computer_requested'],['enableBrowser','browser_requested']])if(data[key]!==undefined&&(typeof data[key]!=='boolean'||data[key]!== (selected[requested]===true)))fail('pending_identity_or_capability_mismatch');
    const result=await api.approveDeploymentPending(stateDir,{authorize:true,requestId:data.requestId,fingerprint:selected.fingerprint});send(200,{status:result.status??'approved'});return;
   }else if(url.pathname==='/api/service'){
    keys(data,['role','action','authorize']);if(data.authorize!==true||!['host','gateway'].includes(data.role))fail('explicit_service_authorization_required');
    let result;
    if(data.role==='host'){if(typeof api.controlDeploymentHostService!=='function'||!['install','start','stop','status'].includes(data.action))fail('host_service_not_supported');result=await api.controlDeploymentHostService(stateDir,{action:data.action,authorize:true});}
    else{if(!gatewayServiceAvailable||!['install','start','stop','status','enable','disable','uninstall'].includes(data.action))fail('gateway_service_not_supported');if(data.action==='start'&&(await api.readDeployment(stateDir)).gatewayRuntime?.status==='running')fail('stop_owned_foreground_gateway_first');const control=gatewayService??(typeof api.controlDeploymentService==='function'?((d,o)=>api.controlDeploymentService(d,{role:'gateway',...o})):(await import('./gateway-service.mjs')).controlGatewayService);result=await control(stateDir,{action:data.action,authorize:true});}
    services[data.role]={...publicService(result),observedAt:new Date().toISOString()};
    send(200,{service:services[data.role]});return;
   }else if(url.pathname==='/api/verify-gateway'){
    keys(data,['url','tokenFile','caFile','independentStyx','freshConnection']);
    if(data.independentStyx!==true||data.freshConnection!==true||typeof data.url!=='string'||data.url.length>4096||typeof data.tokenFile!=='string'||!path.isAbsolute(data.tokenFile)||(data.caFile!==undefined&&(typeof data.caFile!=='string'||!path.isAbsolute(data.caFile))))fail('explicit_gateway_verification_required');
    const verify=verifyConnection??(await import('./connection.mjs')).verifyGatewayConnection;
    const result=await verify(data);if(result.status!=='gateway_verified'||result.scope!=='sdk_gateway')fail('gateway_not_verified');
    send(200,{status:'gateway_verified',scope:'sdk_gateway',accountAcceptance:'NOT RUN'});return;
   }else if(url.pathname==='/api/start'){
    keys(data,[]);if(typeof api.startDeploymentGateway!=='function'){send(409,{error:'start_not_supported'});return}
    await api.startDeploymentGateway(stateDir);
   }else{
    keys(data,[]);if(typeof api.stopDeploymentGateway!=='function'){send(409,{error:'pause_not_supported'});return}
    await api.stopDeploymentGateway(stateDir);
   }
   send(200,{deployment:publicDeployment(await api.readDeployment(stateDir))});
  }catch(error){const safe=['work_in_progress','work_state_unknown','windows_native_app_binding_required','desktop_acceptance_native_app_changed','device_ingress_recovery_required','device_ingress_recovery_guard_requires_inspection','device_ingress_select_interface','device_ingress_network_unavailable','device_ingress_address_change_requires_review','device_ingress_gateway_upgrade_required','device_ingress_exact_owned_interface_required','device_ingress_listener_not_confirmed','device_ingress_requires_compatible_gateway_application','openssl_configuration_requires_compatible_gateway_application','foreground_not_owned_or_unsafe_for_capability_change','foreground_stop_unconfirmed','native_owned_foreground_control_required','browser_enabled_host_bundle_required','approved_browser_host_required','browser_profile_binding_changed','browser_preparation_scope_changed','browser_preparation_management_operation_in_progress','browser_capability_foreground_must_be_stopped','browser_capability_host_must_be_stopped','browser_capability_all_connections_must_be_offline','browser_enabled_host_update_required','foreground_host_handoff_required','tunnel_running_or_interrupted','tunnel_client_integrity_failed','background_uncertain_requires_reconciliation','capability_uncertain_requires_reconciliation','local_owner_capability_change_only','host_state_not_safe_for_capability_change'];send(409,{error:safe.includes(error?.message)?error.message:'operation_failed_check_status'})}finally{busy=false}
 });
 server.requestTimeout=30000;server.headersTimeout=10000;server.maxHeadersCount=30;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve)});
 origin=forwarded??`http://127.0.0.1:${server.address().port}`;
 // A verified native App reopens the same prepared deployment. This is an
 // explicit lifecycle boundary, never a side effect of a GET/status request.
 // Foreground Core verifies native service ownership and refuses duplicate or
 // uncertain owners; it never regenerates pairing identities on reconnect.
 if(nativeSigningMigrationRequired)nativeStartup={status:'reconciliation_required',observation:'current_process',reason:'native_signing_registration_required'};
 if(nativeAppOwned&&!nativeSigningMigrationRequired&&fs.existsSync(path.join(stateDir,'deployment.json'))&&typeof api.startDeploymentForeground==='function'){
  await resumeNativeStartup();
 }
 // Only a previously recorded user opt-in can resume this App-owned connection.
 if(tunnel&&!nativeSigningMigrationRequired&&!nativeStartup.reason?.startsWith('host_payload_')&&fs.existsSync(stateDir))await tunnel.resume().catch(()=>{});
 return {server,origin,url:origin+'/#session='+session,
  close(){if(closing)return closing;pendingLink=null;
   closing=(async()=>{
    let failure;
    // Every owned lifetime must be settled even if an earlier cleanup fails.
    // Keep the failure visible on repeated close calls rather than marking an
    // interrupted shutdown successful after setting a boolean too early.
    for(const stop of [()=>tunnel?.stop(),()=>new Promise(resolve=>server.close(resolve)),()=>api.stopDeploymentForeground?.(stateDir),()=>api.stopDeploymentGateway?.(stateDir)])try{await stop()}catch(error){failure??=error}
    if(failure)throw failure;
   })();return closing;
  }};
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 try{
  const[flag,stateDir]=process.argv.slice(2);if(flag!=='--state')fail('usage_server_state_absolute_directory');
  const instance=await createOnboardingServer({stateDir,port:Number(process.env.STYX_ONBOARDING_PORT??0),trustedForwardOrigin:process.env.STYX_ONBOARDING_BROWSER_ORIGIN,artifactDefaultsFile:process.env.STYX_ONBOARDING_ARTIFACTS,trustedOpenSSL:process.env.STYX_ONBOARDING_OPENSSL??(process.platform==='win32'?undefined:'/usr/bin/openssl')});
  // Local terminal bootstrap only: URL fragment never travels in HTTP requests.
  process.stdout.write('Open this private local setup URL in your browser:\n'+instance.url+'\n');
  for(const sig of['SIGINT','SIGTERM'])process.once(sig,()=>void instance.close().then(()=>process.exit(0)));
 }catch{process.stderr.write('Styx local setup could not start. Check the local state path and core installation.\n');process.exitCode=2}
}
