// Local browser setup control plane. Does not expose an unauthenticated LAN API.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import {completeLocalSetup} from './local-setup.mjs';
import {enableDeploymentBackground,observeDeploymentBackground} from './background.mjs';
import {configureTunnel,TunnelRuntime} from './tunnel-runtime.mjs';
import {changeDeploymentCapabilities,readDeploymentCapabilities} from './capabilities.mjs';
import {requirePrivateFile} from '../host/private-storage.mjs';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const UI=fileURLToPath(new URL('./ui/',import.meta.url));
const STEPS=new Set(['gateway.prepare','gateway.start','host.prepare','host.invite','host.request','host.claim','host.doctor','host.pair','gateway.verify','host.service.install','host.service.start','host.service.status']);
const STATES=new Set(['pending','running','succeeded','failed','uncertain','blocked','skipped','awaiting_approval']);
const ERRORS=new Set(['interrupted_or_in_progress_do_not_replay','step_failed_inspect_local_evidence_no_automatic_replay']);
const MODES=new Set(['create-local','join-existing']);
const equal=(a,b)=>typeof a==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const fail=code=>{throw Error(code)};
export function browserOrigin(value){
 const url=new URL(value);
 if(url.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(url.hostname)||url.username||url.password||url.pathname!=='/'||url.search||url.hash)fail('trusted_loopback_browser_origin_required');
 return url.origin;
}
export function gatewayServiceUiCapabilities(platform,available){return {supported:available===true&&['linux','darwin','win32'].includes(platform),startEnablesStartup:['darwin','win32'].includes(platform),enableCanTriggerRecovery:platform==='win32'}}
export function publicService(value){
 if(!value||typeof value!=='object')return null;const out={};
 for(const key of ['status','action','role','manager','serviceId','name','state','persistence','health','active','substate','enabled'])if(typeof value[key]==='string'&&/^[A-Za-z0-9_.-]{1,120}$/.test(value[key]))out[key]=value[key];
 if(Number.isSafeInteger(value.pid)&&value.pid>=0)out.pid=value.pid;return out;
}
export function publicDeployment(value){
 if(value==null)return null;
 const steps=Array.isArray(value.steps)?value.steps:[];
 return {schema:1,mode:MODES.has(value.mode)?value.mode:null,
  roles: value.roles ? {
   gateway:['local','external'].includes(value.roles.gateway)?value.roles.gateway:'unknown',
   host:value.roles.host==='local'?'local':'unknown',
   exec:value.roles.exec==='enabled'?'enabled':'unknown',
   computer:['requested','disabled'].includes(value.roles.computer)?value.roles.computer:'unknown',
   deviceIngress:['loopback_only','configured_unverified','not_hosted'].includes(value.roles.deviceIngress)?value.roles.deviceIngress:'unknown',
   readiness:'not_inferred'
  } : null,
  activeStep:STEPS.has(value.activeStep)?value.activeStep:null,
  hostServiceMaintenance:{lastObservation:publicService(value.hostServiceMaintenance?.lastObservation),hasUncertainMutation:value.hostServiceMaintenance?.hasUncertainMutation===true},
  gatewayRuntime:typeof value.gatewayRuntime?.status==='string'&&['running','stopped','not_owned_by_current_process'].includes(value.gatewayRuntime.status)?value.gatewayRuntime.status:'unknown',
  steps:steps.filter(s=>s&&STEPS.has(s.id)).map(s=>({id:s.id,status:STATES.has(s.status)?s.status:'uncertain',
   ...(s.id.startsWith('host.service.')?{service:publicService(s.evidence)}:{}),
   ...(s.evidence?.ownerApproval==='REQUIRED'?{ownerApproval:'REQUIRED'}:{}),
   ...(/^[a-f0-9]{64}$/.test(s.evidence?.fingerprint??'')?{fingerprint:s.evidence.fingerprint}:{}),
   ...(s.error?{error:ERRORS.has(s.error)?s.error:'step_failed_inspect_local_state'}:{})}))};
}
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
function keys(value,allowed){if(!object(value)||Object.keys(value).some(k=>!allowed.includes(k)))fail('invalid_configuration_fields')}
export function validateUiConfig(config,{trustedOpenSSL}={}){
 keys(config,['schema','mode','gateway','host','invitationFile']);
 if(config.schema!==1||!MODES.has(config.mode))fail('invalid_configuration');
 keys(config.gateway,['url','caFile','listenHost','allowRemoteHosts']);keys(config.host,['bundle','publisherKeyFile','publisherSha256','baseDir','label','computer','macTeamID','wayland']);
 for(const [name,value]of Object.entries(config.gateway)){if(name==='allowRemoteHosts'){if(value!==true)fail('explicit_network_exposure_required')}else if(typeof value!=='string'||!value||value.length>4096)fail('invalid_gateway_field');}
 for(const [name,value]of Object.entries(config.host)){
  if(['computer','wayland'].includes(name)){if(typeof value!=='boolean')fail('invalid_capability_selection')}
  else if(typeof value!=='string'||!value||value.length>4096)fail('invalid_host_field');
 }
 for(const name of ['bundle','publisherKeyFile','publisherSha256','baseDir','label'])if(typeof config.host[name]!=='string')fail('required_host_field');
 if(typeof config.host.computer!=='boolean')fail('required_capability_selection');
 if(config.invitationFile!==undefined&&(typeof config.invitationFile!=='string'||!config.invitationFile||config.invitationFile.length>4096))fail('invalid_invitation_file');
 if(config.mode==='join-existing'&&!config.invitationFile)fail('invitation_file_required');
 if(config.mode==='create-local'&&(!trustedOpenSSL||!path.isAbsolute(trustedOpenSSL)))fail('local_tls_helper_not_configured');
 return {...config,gateway:{...config.gateway,...(config.mode==='create-local'?{openssl:trustedOpenSSL}:{})}};
}
async function body(req){
 if(req.headers['content-type']!=='application/json')fail('json_required');
 req.setEncoding('utf8');let data='';for await(const chunk of req){data+=chunk;if(Buffer.byteLength(data)>65536)fail('body_too_large')}
 try{return JSON.parse(data)}catch{fail('invalid_json')}
}
export async function createOnboardingServer({stateDir,port=0,trustedForwardOrigin,trustedOpenSSL=process.platform==='win32'?undefined:'/usr/bin/openssl',core,artifactDefaultsFile,verifyConnection,gatewayService,pairingLinks,trustedMacPreviewApp,backgroundControl=enableDeploymentBackground,backgroundRead=observeDeploymentBackground,trustedTunnelClient}={}){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir))fail('absolute_state_directory_required');
 if(!Number.isInteger(port)||port<0||port>65535)fail('invalid_port');
 const forwarded=trustedForwardOrigin?browserOrigin(trustedForwardOrigin):null;
 const tunnel=trustedTunnelClient?new TunnelRuntime({stateDir,...trustedTunnelClient}):null;
 const api=core??await import('./core.mjs');
 let macPreviewApp;
 if(trustedMacPreviewApp!==undefined){const {verifyMacPreviewApp}=await import('../host/macos-preview-trust.mjs');macPreviewApp=verifyMacPreviewApp(trustedMacPreviewApp);}
 let artifacts={};
 if(artifactDefaultsFile){requirePrivateFile(artifactDefaultsFile);if(fs.statSync(artifactDefaultsFile).size>65536)fail('artifact_defaults_too_large');const value=JSON.parse(fs.readFileSync(artifactDefaultsFile,'utf8'));keys(value,['bundle','publisherKeyFile','publisherSha256']);if(!['bundle','publisherKeyFile'].every(k=>typeof value[k]==='string'&&path.isAbsolute(value[k]))||!/^[a-f0-9]{64}$/.test(value.publisherSha256??''))fail('invalid_trusted_artifact_defaults');artifacts=value;}
 const probe=net.createServer();await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(0,'127.0.0.1',resolve)});const suggestedPort=probe.address().port;await new Promise(resolve=>probe.close(resolve));
 const defaults={label:os.hostname().slice(0,72),baseDir:path.join(path.dirname(stateDir),'styx-host-'+randomBytes(5).toString('hex')),gatewayUrl:'https://127.0.0.1:'+suggestedPort,...artifacts};
 const session=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url');
 let origin,closed=false,busy=false;
 const services={host:null,gateway:null};
 let pendingLink,acceptedLink;
 const linkImportAvailable=!!pairingLinks||fs.existsSync(new URL('./pairing-links.mjs',import.meta.url));
 const linkApi=async()=>pairingLinks??await import('./pairing-links.mjs');
 const gatewayServiceCapability=gatewayServiceUiCapabilities(process.platform,typeof gatewayService==='function'||fs.existsSync(new URL('./gateway-service.mjs',import.meta.url)));
 const gatewayServiceAvailable=gatewayServiceCapability.supported;
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
  if(req.method==='GET'&&url.pathname==='/api/session'){
   send(200,{csrf,platform:process.platform,packagedPreviewTrusted:!!macPreviewApp,backgroundSupported:true,capabilityChangeSupported:true,deviceSettingsSupported:typeof api.readDeploymentDevices==='function',tunnelSupported:!!tunnel,localGatewayAvailable:!!trustedOpenSSL,pauseSupported:typeof api.stopDeploymentGateway==='function',startSupported:typeof api.startDeploymentGateway==='function',
    pairingLinkImportSupported:linkImportAvailable,pairingLinkCreateSupported:typeof api.createDeploymentPairingLink==='function',pendingApprovalSupported:typeof api.listDeploymentPending==='function'&&typeof api.approveDeploymentPending==='function',hostServiceSupported:typeof api.controlDeploymentHostService==='function',gatewayServiceSupported:gatewayServiceAvailable,gatewayService:gatewayServiceCapability,localGatewayAddresses:typeof api.localGatewayAddresses==='function'?api.localGatewayAddresses():[],defaults,accountAcceptance:'NOT RUN',nativeInstaller:'NOT RUN',trustedForwarding:!!forwarded});return;
  }
  if(req.method==='GET'&&url.pathname==='/api/status'){
   try{
    const deployment=publicDeployment(await api.readDeployment(stateDir)),plan=await api.planDeployment(stateDir);
    const dependencies=Array.isArray(plan?.steps)?plan.steps.filter(s=>STEPS.has(s.id)).map(s=>({id:s.id,requires:Array.isArray(s.requires)?s.requires.filter(id=>STEPS.has(id)):[]})):[];
    const scope=plan?.ownerPairingScope;
    const ownerPairingScope=scope&&typeof scope.gatewayUrl==='string'&&typeof scope.label==='string'&&typeof scope.enableComputer==='boolean'?{gatewayUrl:scope.gatewayUrl,label:scope.label,enableComputer:scope.enableComputer}:null;
    let background=null;try{background=await backgroundRead(stateDir)}catch{}
    let tunnelStatus=null;try{tunnelStatus=tunnel?await tunnel.health():null}catch{}
    let deviceCapabilities=null;try{deviceCapabilities=readDeploymentCapabilities(stateDir)}catch{}
    send(200,{deployment,dependencies,ownerPairingScope,services,background,deviceCapabilities,tunnel:tunnelStatus,busy});
   }catch{if(!fs.existsSync(stateDir))send(200,{deployment:null,dependencies:[],busy});else send(409,{error:'deployment_unavailable'})}return;
  }
  if(req.method!=='POST'){send(405,{error:'method_refused'});return}
  if(!['/api/create','/api/devices','/api/default-device','/api/capabilities','/api/tunnel/configure','/api/tunnel/start','/api/tunnel/stop','/api/background','/api/local-setup','/api/advance','/api/pause','/api/start','/api/verify-gateway','/api/service','/api/pairing-link/inspect','/api/pairing-link/accept','/api/pairing-link/create','/api/pending/list','/api/pending/approve'].includes(url.pathname)){send(404,{error:'not_found'});return}
  if(busy){send(409,{error:'operation_in_progress'});return}busy=true;
  try{
   const data=await body(req);
   if(url.pathname==='/api/create'){
    const{joinLinkId,...input}=data;
    if(joinLinkId!==undefined){if(!acceptedLink||acceptedLink.id!==joinLinkId||input.mode!=='join-existing'||input.gateway?.url!==acceptedLink.refs.gatewayOrigin||(!Number.isSafeInteger(acceptedLink.refs.expiresAt)||acceptedLink.refs.expiresAt<=Date.now())||input.invitationFile||input.gateway.caFile)fail('accepted_pairing_scope_required');input.invitationFile=acceptedLink.refs.invitationFile;input.gateway={...input.gateway,...(acceptedLink.refs.gatewayCaFile?{caFile:acceptedLink.refs.gatewayCaFile}:{})}}
    const config=validateUiConfig(input,{trustedOpenSSL});
    if(macPreviewApp)config.host={...config.host,macPreviewApp:{path:macPreviewApp.path,cdhash:macPreviewApp.cdhash}};
    if(config.mode==='create-local'&&new URL(config.gateway.url).hostname!=='127.0.0.1'&&config.gateway.allowRemoteHosts!==true)fail('explicit_network_exposure_required');
    if(config.gateway.allowRemoteHosts){const addresses=typeof api.localGatewayAddresses==='function'?api.localGatewayAddresses():[];if(!addresses.includes(config.gateway.listenHost)||new URL(config.gateway.url).hostname!==config.gateway.listenHost)fail('explicit_owned_network_interface_required')}
    const temp=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ui-config-'));fs.chmodSync(temp,0o700);
    try{const file=path.join(temp,'config.json');fs.writeFileSync(file,JSON.stringify(config),{mode:0o600});await api.createDeployment(file,{stateDir})}
    finally{fs.rmSync(temp,{recursive:true,force:true})}
   }else if(url.pathname==='/api/devices'){
    keys(data,[]);if(typeof api.readDeploymentDevices!=='function')fail('device_settings_unavailable');send(200,{devices:await api.readDeploymentDevices(stateDir)});return;
   }else if(url.pathname==='/api/default-device'){
    keys(data,['authorize','deviceId']);if(typeof api.setDeploymentDefault!=='function')fail('device_settings_unavailable');await api.setDeploymentDefault(stateDir,data);send(200,{status:'updated'});return;
   }else if(url.pathname==='/api/capabilities'){
    keys(data,['authorize','computer']);const result=await changeDeploymentCapabilities(stateDir,data,{trustedMacPreviewApp:macPreviewApp});send(200,{capabilities:result});return;
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
    if(data.authorize[0]==='host.pair'){keys(data.ownerApproval,['approve','gatewayUrl','label','enableComputer']);if(data.ownerApproval.approve!==true||typeof data.ownerApproval.gatewayUrl!=='string'||typeof data.ownerApproval.label!=='string'||typeof data.ownerApproval.enableComputer!=='boolean')fail('explicit_owner_pairing_scope_required')}else if(data.ownerApproval!==undefined)fail('unexpected_owner_approval');
    await api.advanceDeployment(stateDir,{authorize:data.authorize,...(data.ownerApproval?{ownerApproval:data.ownerApproval}:{})});
   }else if(url.pathname==='/api/pairing-link/inspect'){
    keys(data,['link']);if(!linkImportAvailable||typeof data.link!=='string'||data.link.length>65536)fail('pairing_link_required');const helper=await linkApi(),preview=helper.inspectPairingLink(data.link);const publicPreview={origin:preview.origin,expiresAt:preview.expiresAt,requiresCertificateApproval:preview.requiresCertificateApproval===true,...(preview.caSha256?{caSha256:preview.caSha256}:{})};pendingLink={id:randomBytes(16).toString('hex'),link:data.link,preview:publicPreview};send(200,{inspectionId:pendingLink.id,preview:publicPreview});return;
   }else if(url.pathname==='/api/pairing-link/accept'){
    keys(data,['inspectionId','approvedGatewayOrigin','approvedCaSha256']);if(!pendingLink||data.inspectionId!==pendingLink.id||data.approvedGatewayOrigin!==pendingLink.preview.origin||(pendingLink.preview.caSha256&&data.approvedCaSha256!==pendingLink.preview.caSha256))fail('pairing_scope_confirmation_required');
    const helper=await linkApi(),directory=path.join(path.dirname(stateDir),'styx-pairing-'+randomBytes(8).toString('hex'));const result=helper.acceptPairingLink(pendingLink.link,{stateDir:directory,approvedGatewayOrigin:data.approvedGatewayOrigin,...(data.approvedCaSha256?{approvedCaSha256:data.approvedCaSha256}:{})});
    const file=path.join(directory,'pairing.json');requirePrivateFile(file);acceptedLink={id:randomBytes(16).toString('hex'),refs:JSON.parse(fs.readFileSync(file,'utf8'))};pendingLink=null;send(200,{joinLinkId:acceptedLink.id,status:result.status,origin:result.origin,expiresAt:result.expiresAt,customCertificateApproved:result.customCertificateApproved===true});return;
   }else if(url.pathname==='/api/pairing-link/create'){
    keys(data,['authorize']);if(data.authorize!==true||typeof api.createDeploymentPairingLink!=='function')fail('owner_link_not_supported');const result=await api.createDeploymentPairingLink(stateDir,{authorize:true});send(200,{link:result.link,origin:result.origin,expiresAt:result.expiresAt,...(result.caSha256?{caSha256:result.caSha256}:{}),reachability:result.reachability,remoteUsable:result.remoteUsable===true});return;
   }else if(url.pathname==='/api/pending/list'){
    keys(data,['authorize']);if(data.authorize!==true||typeof api.listDeploymentPending!=='function')fail('owner_list_not_supported');const rows=await api.listDeploymentPending(stateDir,{authorize:true});
    const pending=rows.filter(r=>/^[a-f0-9]{32}$/.test(r.request_id??'')&&/^[a-f0-9]{64}$/.test(r.fingerprint??'')).map(r=>({request_id:r.request_id,fingerprint:r.fingerprint,label:String(r.label??'').slice(0,72),platform:['linux','darwin','win32'].includes(r.platform)?r.platform:'unknown',cwd:String(r.cwd??'').slice(0,4096),shell:String(r.shell??'').slice(0,4096),computer_requested:r.computer_requested===true,expires_at:r.expires_at}));send(200,{pending});return;
   }else if(url.pathname==='/api/pending/approve'){
    keys(data,['authorize','requestId','fingerprint','fingerprintConfirmation','enableComputer']);if(data.authorize!==true||typeof api.approveDeploymentPending!=='function'||typeof api.listDeploymentPending!=='function'||!/^[a-f0-9]{32}$/.test(data.requestId??'')||typeof data.enableComputer!=='boolean')fail('explicit_device_approval_required');const typed=data.fingerprintConfirmation??data.fingerprint;if(typeof typed!=='string'||typed.length>80)fail('fingerprint_confirmation_required');const confirmation=typed.replace(/[\s-]/g,'').toLowerCase();if(!/^(?:[a-f0-9]{16}|[a-f0-9]{64})$/.test(confirmation))fail('fingerprint_confirmation_required');const requests=await api.listDeploymentPending(stateDir,{authorize:true}),selected=requests.find(r=>r.request_id===data.requestId);if(!selected||!/^[a-f0-9]{64}$/.test(selected.fingerprint??'')||(confirmation.length===64?selected.fingerprint!==confirmation:selected.fingerprint.slice(0,16)!==confirmation))fail('fingerprint_confirmation_mismatch');const result=await api.approveDeploymentPending(stateDir,{authorize:true,requestId:data.requestId,fingerprint:selected.fingerprint,enableComputer:data.enableComputer});send(200,{status:result.status??'approved'});return;
   }else if(url.pathname==='/api/service'){
    keys(data,['role','action','authorize']);if(data.authorize!==true||!['host','gateway'].includes(data.role))fail('explicit_service_authorization_required');
    let result;
    if(data.role==='host'){if(typeof api.controlDeploymentHostService!=='function'||!['install','start','stop','status'].includes(data.action))fail('host_service_not_supported');result=await api.controlDeploymentHostService(stateDir,{action:data.action,authorize:true});}
    else{if(!gatewayServiceAvailable||!['install','start','stop','status','enable','disable','uninstall'].includes(data.action))fail('gateway_service_not_supported');if(data.action==='start'&&(await api.readDeployment(stateDir)).gatewayRuntime?.status==='running')fail('stop_owned_foreground_gateway_first');const control=gatewayService??(await import('./gateway-service.mjs')).controlGatewayService;result=await control(stateDir,{action:data.action,authorize:true});}
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
  }catch(error){const safe=['foreground_host_handoff_required','tunnel_running_or_interrupted','tunnel_client_integrity_failed','background_uncertain_requires_reconciliation','capability_uncertain_requires_reconciliation','local_owner_capability_change_only','host_state_not_safe_for_capability_change'];send(409,{error:safe.includes(error?.message)?error.message:'operation_failed_check_status'})}finally{busy=false}
 });
 server.requestTimeout=30000;server.headersTimeout=10000;server.maxHeadersCount=30;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve)});
 origin=forwarded??`http://127.0.0.1:${server.address().port}`;
 // Only a previously recorded user opt-in can resume this App-owned connection.
 if(tunnel&&fs.existsSync(stateDir))await tunnel.resume().catch(()=>{});
 return {server,origin,url:origin+'/#session='+session,
  async close(){if(closed)return;closed=true;pendingLink=null;await tunnel?.stop();await new Promise(resolve=>server.close(resolve));await Promise.resolve().then(()=>api.stopDeploymentGateway?.(stateDir)).catch(()=>{})}};
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
