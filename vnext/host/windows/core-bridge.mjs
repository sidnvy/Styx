// The native shell uses the same private HTTP Core API as the Mac app.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory,writePrivateFile,requirePrivateDirectory,configureWindowsAclHelper} from '../private-storage.mjs';
import {launchWindowsHostPayloadHandoff} from './host-payload-handoff.mjs';
import {writeStartupDiagnostics} from './startup-diagnostics.mjs';
import {observeWindowsNativeAppAuthority} from './native-app-authority.mjs';
const SAFE_NATIVE_ERRORS=new Set(['windows_native_app_binding_required','desktop_acceptance_native_app_changed','work_in_progress','work_state_unknown']);
export const OPERATIONS=Object.freeze(['status','create','inspectJoin','join','recoverJoin','rollbackJoin','prepare','connect','disconnect','setCapabilities','tunnelSave','tunnelStart','tunnelStop','acceptanceBegin','acceptanceConfirm','acceptanceDesktopReadback','devices','setDefault','revokeDevice','inviteComputer','closePairing','recoverIngress','pendingComputers','approveComputer','runtimeUpgradePrepare','runtimeUpgradeLaunch','runtimeUpgradeStatus','runtimeUpgradeCancel','quitAdmission','runtimeUpgradeRollback','startupStatus','startupDiagnostics','appLifecycle','appLogin']);
export function bootstrap(url){const u=new URL(url);if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||!u.port||u.pathname!=='/'||u.search||u.username||u.password||!/^#session=[A-Za-z0-9_-]{43}$/.test(u.hash))throw Error('invalid_bootstrap');const token=u.hash.slice(9);u.hash='';return {origin:u.origin,token};}
export async function createClient(instance,{fetchImpl=fetch}={}){
 const {origin,token}=bootstrap(instance.url);let csrf;
 const call=async(route,body)=>{const response=await fetchImpl(origin+'/api/'+route,{method:body?'POST':'GET',redirect:'error',headers:{Authorization:'Bearer '+token,Origin:origin,...(body?{'Content-Type':'application/json','X-Styx-CSRF':csrf}:{})},...(body?{body:JSON.stringify(body)}:{}),...(['advance','local-setup','browser/prepare','host-payload/handoff/prepare'].includes(route)?{}:{signal:AbortSignal.timeout(body||route==='snapshot'?120000:20000)})});if(!response.headers.get('content-type')?.startsWith('application/json'))throw Error('core_rejected');const text=await response.text();if(Buffer.byteLength(text)>2*1024*1024)throw Error('core_response_too_large');const value=JSON.parse(text);if(!response.ok)throw Error(SAFE_NATIVE_ERRORS.has(value?.error)?value.error:'core_rejected');return value;};
 const session=await call('session');csrf=session.csrf;if(!/^[A-Za-z0-9_-]{43}$/.test(csrf??''))throw Error('invalid_csrf');let inspected,accepted,observation;
 const interruptedJoin=async()=>{
  if(session.joinRecoverySupported!==true)return null;
  const {recovery}=await call('join/recovery');
  if(recovery?.rollbackRequired!==true||!/^[a-f0-9]{32}$/.test(recovery.transactionId??''))return null;
  return {status:{joinRecovery:recovery}};
 };
 const observe=(fresh=false)=>{
  if(fresh)observation=undefined;
  if(!observation){
   const pending=call('snapshot').catch(async error=>{try{const interrupted=await interruptedJoin();if(interrupted)return interrupted;}catch{}if(instance.hostPayloadHandoffSupported!==true)throw error;const recovery=await call('host-payload/handoff/status',{});if(!/^[a-f0-9]{32}$/.test(recovery.handoff?.ticketId??'')||!['preparing','awaiting_exit','blocked','needs_recovery','applied_stopped'].includes(recovery.handoff?.status))throw error;return {status:{deployment:null},componentRecovery:recovery.handoff};}).then(snapshot=>({session:{joinRecoverySupported:session.joinRecoverySupported===true,localGatewayAvailable:session.localGatewayAvailable,tunnelSupported:session.tunnelSupported,artifactsAvailable:!!session.defaults?.bundle,desktopAcceptanceSupported:instance.desktopAcceptanceSupported===true,hostPayloadHandoffSupported:instance.hostPayloadHandoffSupported===true},...snapshot}));
   observation=pending;
   const clear=()=>{if(observation===pending)observation=undefined;};pending.then(clear,clear);
  }
  return observation;
 };
 return {async dispatch(request){
  if(!request||request.schema!==1||!Number.isSafeInteger(request.id)||!OPERATIONS.includes(request.operation)||!request.input||typeof request.input!=='object'||Array.isArray(request.input))throw Error('invalid_native_request');
  const i=request.input,op=request.operation;
  if(op==='startupDiagnostics'){if(typeof instance.writeStartupDiagnostics!=='function')throw Error('startup_diagnostics_unavailable');return instance.writeStartupDiagnostics(i);}
  if(op==='startupStatus'){let value;try{value=await call('components');}catch(error){const interrupted=await interruptedJoin().catch(()=>null);if(interrupted)return {session:{joinRecoverySupported:true},...interrupted};throw error;}if(value.components?.host?.status==='not_configured')return observe();return {session:{joinRecoverySupported:session.joinRecoverySupported===true,localGatewayAvailable:session.localGatewayAvailable,tunnelSupported:session.tunnelSupported,artifactsAvailable:!!session.defaults?.bundle,desktopAcceptanceSupported:instance.desktopAcceptanceSupported===true,hostPayloadHandoffSupported:instance.hostPayloadHandoffSupported===true},status:{components:value.components},loadingDetails:true};}
  if(op==='rollbackJoin'){if(session.joinRecoverySupported!==true||!/^[a-f0-9]{32}$/.test(i.transactionId??''))throw Error('join_recovery_unavailable');try{return await call('join/rollback',{authorize:true,transactionId:i.transactionId});}finally{observation=undefined;}}
  if(op==='appLifecycle')return call('app/lifecycle');
  if(op==='appLogin'){if(Object.keys(i).length!==1||typeof i.enabled!=='boolean')throw Error('invalid_native_request');return call('app/login',{authorize:true,enabled:i.enabled});}
  if(op==='quitAdmission')return call('app/quit-admission',{authorize:true});
  if(op==='runtimeUpgradePrepare')return call('host-payload/handoff/prepare',{authorize:true});
  if(op==='runtimeUpgradeStatus'){const handoff=await call('host-payload/handoff/status',{}),upgrade=await call('host-payload/status',{});return {...handoff,...upgrade};}
  if(op==='runtimeUpgradeCancel')return call('host-payload/handoff/cancel',{authorize:true,ticketId:i.ticketId});
  if(op==='runtimeUpgradeLaunch'||op==='runtimeUpgradeRollback'){
   if(typeof instance.launchHostPayloadHandoff!=='function'||!/^[a-f0-9]{32}$/.test(i.ticketId??''))throw Error('native_handoff_unavailable');
   return instance.launchHostPayloadHandoff(i.ticketId,op==='runtimeUpgradeRollback'?'rollback':'apply');
  }
  if(op==='devices')return call('devices',{});
  if(op==='pendingComputers')return call('pending/list',{authorize:true});
  if(op==='approveComputer')return call('pending/approve',{authorize:true,requestId:i.requestId,comparisonCodeConfirmation:i.comparisonCode});
  if(op==='closePairing')return call('pairing-link/close',{authorize:true});
  if(op==='recoverIngress')return call('device-ingress/recover',{authorize:true,action:i.action});
  if(op==='inviteComputer'){
   const {ingress}=await call('device-ingress/plan',{});
   if(!ingress||ingress.gateway!=='local'||ingress.blockers?.length)return {status:'network_setup_required',ingress};
   if(ingress.requiresInterfaceChoice&&!i.listenHost)return {status:'select_network_interface',candidates:ingress.candidates};
   return {status:'waiting_for_computer',invitation:await call('pairing-link/create',{authorize:true,...(i.listenHost?{listenHost:i.listenHost}:{})})};
  }
  if(op==='setDefault'||op==='revokeDevice')return call(op==='setDefault'?'default-device':'device/revoke',{authorize:true,deviceId:i.deviceId});
  if(op==='status')return observe();
  if(op==='inspectJoin'){inspected=undefined;inspected=await call('pairing-link/inspect',{link:i.link});return inspected;}
  if(op==='join'||op==='recoverJoin'){
   if(op==='recoverJoin'&&session.joinRecoverySupported!==true)throw Error('join_recovery_unavailable');
   if(!inspected||i.approvedGatewayOrigin!==inspected.preview.origin||i.approvedCaSha256!==inspected.preview.caSha256)throw Error('explicit_join_confirmation_required');
   const confirmed=inspected;inspected=undefined;
   accepted=await call('pairing-link/accept',{inspectionId:confirmed.inspectionId,approvedGatewayOrigin:i.approvedGatewayOrigin,...(i.approvedCaSha256?{approvedCaSha256:i.approvedCaSha256}:{})});
   if(op==='recoverJoin'){try{return await call('join/recover',{authorize:true,joinLinkId:accepted.joinLinkId});}finally{observation=undefined;}}
  }
  if(op==='create'||op==='join'){
   const d=session.defaults,host=Object.fromEntries(['bundle','publisherKeyFile','publisherSha256','baseDir'].map(k=>[k,d[k]]));if(Object.values(host).some(v=>typeof v!=='string'))throw Error('bundled_artifacts_required');
   Object.assign(host,{label:i.label,computer:i.computer===true,browser:{enabled:i.browser===true,headless:false,channel:['auto','chrome','msedge'].includes(i.browserChannel)?i.browserChannel:'auto',persistLogin:i.persistLogin===true}});
   return call('create',{schema:1,mode:op==='join'?'join-existing':'create-local',gateway:{url:op==='join'?accepted.origin:d.gatewayUrl},host,...(op==='join'?{joinLinkId:accepted.joinLinkId}:{})});
  }
  if(op==='prepare'){
   try{
   let status=await call('status');
   if(status.deployment?.mode==='join-existing'){
    for(let n=0;n<4;n++){
     if(status.nativeStartup?.reason?.startsWith('host_payload_'))break;
     const step=status.deployment.steps.find(s=>!['succeeded','skipped'].includes(s.status));
     if(!step||!['host.prepare','host.request','host.claim','host.doctor'].includes(step.id)||!(['pending','awaiting_approval'].includes(step.status)||step.status==='blocked'&&(step.id==='host.claim'||step.id==='host.doctor'&&step.retryable===true)))break;
     await call('advance',{authorize:[step.id]});status=await call('status');if(status.deployment.steps.find(s=>s.id===step.id)?.status!=='succeeded')break;
    }
   }else{if(!status.ownerPairingScope)throw Error('owner_scope_required');await call('local-setup',{ownerApproval:{...status.ownerPairingScope,approve:true}});}
   status=await call('status');
   const local=new Set(['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.invite','host.request','host.claim','host.doctor']);const ready=status.deployment?.steps.filter(s=>local.has(s.id)).every(s=>s.status==='succeeded');
   if(ready&&status.deployment.roles?.browser==='requested'){const {browser}=await call('browser');if(browser?.status==='not_prepared'||browser?.status==='not_configured'||browser?.status==='preparation_required')await call('browser/prepare',{authorize:true});}
   return await observe(true);
   }catch(error){observation=undefined;throw error;}
  }
  const routes={connect:'foreground',disconnect:'foreground/stop',setCapabilities:'capabilities',tunnelSave:'tunnel/configure',tunnelStart:'tunnel/start',tunnelStop:'tunnel/stop',acceptanceBegin:'acceptance/begin',acceptanceConfirm:'acceptance/confirm',acceptanceDesktopReadback:'acceptance/desktop-readback'};
  const body=op==='tunnelSave'?{authorize:true,tunnelId:i.tunnelId,apiKey:i.runtimeKey,autoStart:true}:op==='setCapabilities'?{authorize:true,computer:i.computer,browser:i.browser,browserChannel:i.browserChannel,persistLogin:i.persistLogin}:op==='acceptanceConfirm'?{authorize:true,challengeId:i.challengeId,observedInTargetChat:true}:op==='acceptanceDesktopReadback'?{authorize:true,challengeId:i.challengeId,value:i.value,pid:i.pid,windowId:i.windowId}:{authorize:true};
  return call(routes[op],body);
 }};
}
// Package input only: HTTP/pipe callers cannot choose a probe or executable.
export function nativeDesktopAvailable(resourceRoot,pin,{run=execFileSync,platform=process.platform}={}){
 try{
  if(platform!=='win32'||pin?.path!=='StyxSessionProbe.exe'||!/^[a-f0-9]{64}$/.test(pin?.sha256??''))return false;
  const file=path.join(resourceRoot,pin.path),stat=fs.lstatSync(file);
  if(!stat.isFile()||stat.isSymbolicLink()||!fs.realpathSync(file).startsWith(fs.realpathSync(resourceRoot)+path.sep)||createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==pin.sha256)return false;
  const env=Object.fromEntries(['SystemRoot','WINDIR','TEMP','TMP'].filter(k=>process.env[k]!==undefined).map(k=>[k,process.env[k]]));
  const text=run(file,[],{encoding:'utf8',timeout:5000,maxBuffer:4096,windowsHide:true,stdio:['ignore','pipe','ignore'],env});
  if(typeof text!=='string'||Buffer.byteLength(text)>4096)return false;
  const value=JSON.parse(text);return value?.schema===1&&value.status==='available'&&Number.isInteger(value.sessionId)&&value.sessionId>0&&value.interactive===true&&value.windowStation==='WinSta0'&&value.inputDesktop==='Default';
 }catch{return false;}
}
export function verifyOpenSslBundle(resourceRoot,pin){
 if(!pin?.files){if(pin?.config!==undefined)throw Error('invalid_tls_helper_bundle');return;}
 if(!Array.isArray(pin.files)||pin.files.length<1||pin.files.length>=4000||!pin.path?.startsWith('runtime/openssl/'))throw Error('invalid_tls_helper_bundle');
 const bundleRoot=path.join(resourceRoot,'runtime/openssl'),rootInfo=fs.lstatSync(bundleRoot);if(!rootInfo.isDirectory()||rootInfo.isSymbolicLink()||path.resolve(fs.realpathSync(bundleRoot)).toLowerCase()!==path.resolve(bundleRoot).toLowerCase())throw Error('redirected_tls_helper_bundle');
 const names=new Set();for(const item of pin.files){if(!item||Object.keys(item).some(k=>!['path','sha256'].includes(k))||typeof item.path!=='string'||!item.path.startsWith('runtime/openssl/')||item.path.includes('\\')||item.path.includes(':')||item.path.split('/').some(x=>!x||x==='..'||x==='.')||names.has(item.path)||!/^[a-f0-9]{64}$/.test(item.sha256??''))throw Error('invalid_tls_helper_bundle');names.add(item.path);const file=path.join(resourceRoot,...item.path.split('/')),stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==item.sha256)throw Error('tls_helper_bundle_changed');}
 const files=[];const walk=(directory,prefix)=>{for(const item of fs.readdirSync(directory,{withFileTypes:true})){if(item.isSymbolicLink())throw Error('redirected_tls_helper_bundle');const relative=prefix+'/'+item.name;if(item.isDirectory())walk(path.join(directory,item.name),relative);else if(item.isFile())files.push(relative);else throw Error('invalid_tls_helper_bundle');}};
 walk(path.join(resourceRoot,'runtime/openssl'),'runtime/openssl');if(!names.has(pin.path)||JSON.stringify(files.sort())!==JSON.stringify([...names].sort()))throw Error('tls_helper_bundle_changed');
 if(pin.config!==undefined){const config=pin.config;if(!config||Object.keys(config).some(k=>!['path','sha256'].includes(k))||!pin.files.some(item=>item.path===config.path&&item.sha256===config.sha256))throw Error('invalid_tls_helper_bundle');return path.join(resourceRoot,...config.path.split('/'));}
}
export async function startWindowsCore(resourceRoot,stateRoot){
 if(!path.isAbsolute(stateRoot)||!path.isAbsolute(resourceRoot))throw Error('absolute_native_paths_required');
 ensurePrivateDirectory(stateRoot);requirePrivateDirectory(stateRoot);
 let desktopAcceptanceSupported=false,hostPayloadHandoffSupported=false,appLoginReconciliation={status:'not_observed'};
 let options={stateDir:path.join(stateRoot,'deployment'),trustedOpenSSL:undefined};
 const manifest=path.join(resourceRoot,'windows-runtime.json');
 if(fs.existsSync(manifest)){
  const cfg=JSON.parse(fs.readFileSync(manifest,'utf8'));
  const member=(relative,sha)=>{if(typeof relative!=='string'||path.isAbsolute(relative)||relative.split(/[\\/]/).some(x=>['','..','.'].includes(x)))throw Error('invalid_resource');const file=path.join(resourceRoot,relative);if(!fs.realpathSync(file).startsWith(fs.realpathSync(resourceRoot)+path.sep))throw Error('redirected_resource');if(sha&&createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==sha)throw Error('resource_integrity_failed');return file;};
  if(process.platform==='win32'){
   if(cfg.privateStorage){
    if(cfg.privateStorage.path!=='StyxPrivateStorage.exe'||!/^[a-f0-9]{64}$/.test(cfg.privateStorage.sha256??''))throw Error('invalid_private_acl_helper');
    configureWindowsAclHelper(member(cfg.privateStorage.path,cfg.privateStorage.sha256),cfg.privateStorage.sha256);
   }
   const core=await import('../../onboarding/core.mjs'),nativeDesktopApp=()=>observeWindowsNativeAppAuthority(resourceRoot,cfg);
   options.nativeAppAuthority=nativeDesktopApp;
   options.trustedWindowsApp=()=>({resourceRoot,authority:nativeDesktopApp()});
   try{appLoginReconciliation=await core.reconcileDeploymentAppLifecycle(options.stateDir,{trustedWindowsApp:options.trustedWindowsApp()});}catch{appLoginReconciliation={status:'needs_attention'};}
   hostPayloadHandoffSupported=cfg.hostUpdater?.path==='StyxUpdater.exe'&&/^[a-f0-9]{64}$/.test(cfg.hostUpdater?.sha256??'');
   desktopAcceptanceSupported=cfg.desktopApp?.path==='StyxPreview.exe'&&/^[a-f0-9]{64}$/.test(cfg.desktopApp?.sha256??'')&&cfg.desktopProbe?.path==='StyxSessionProbe.exe'&&/^[a-f0-9]{64}$/.test(cfg.desktopProbe?.sha256??'');
   options.core={...core,startDeploymentForeground:(directory,authorization)=>core.startDeploymentForeground(directory,authorization,{guiAvailable:()=>nativeDesktopAvailable(resourceRoot,cfg.desktopProbe)}),beginDeploymentAcceptance:(directory,authorization)=>core.beginDeploymentAcceptance(directory,authorization,{nativeDesktopApp}),recordDeploymentDesktopReadback:(directory,authorization)=>core.recordDeploymentDesktopReadback(directory,authorization,{nativeDesktopApp})};
  }
  if(cfg.artifacts){const artifacts={bundle:member(cfg.artifacts.bundle),publisherKeyFile:member(cfg.artifacts.publisherKeyFile),publisherSha256:cfg.artifacts.publisherSha256};const file=path.join(stateRoot,'artifacts.json');if(fs.existsSync(file))fs.unlinkSync(file);writePrivateFile(file,JSON.stringify(artifacts));options.artifactDefaultsFile=file;}
  if(cfg.openssl){const config=verifyOpenSslBundle(resourceRoot,cfg.openssl);options.trustedOpenSSL=member(cfg.openssl.path,cfg.openssl.sha256);if(config)options.trustedOpenSSLConfig=config;}
  if(cfg.tunnel)options.trustedTunnelClient={binary:member(cfg.tunnel.path,cfg.tunnel.sha256),sha256:cfg.tunnel.sha256};
 }
 const {createOnboardingServer}=await import('../../onboarding/server.mjs');const instance=await createOnboardingServer(options);return {...instance,writeStartupDiagnostics:value=>writeStartupDiagnostics(stateRoot,value),desktopAcceptanceSupported,hostPayloadHandoffSupported,appLoginReconciliation,...(hostPayloadHandoffSupported?{launchHostPayloadHandoff:(ticketId,mode)=>launchWindowsHostPayloadHandoff({stateDir:options.stateDir,ticketId,mode})}:{})};
}
export async function serve({input=process.stdin,output=process.stdout,instance,client:providedClient}={}){
 let owned=instance,client;
 try{owned??=await startWindowsCore(process.env.STYX_NATIVE_RESOURCES,process.env.STYX_NATIVE_STATE);client=providedClient??await createClient(owned);}catch{}
 const lines=readline.createInterface({input,crlfDelay:Infinity});
 try{for await(const line of lines){let request;try{if(Buffer.byteLength(line)>65536)throw Error('oversize');request=JSON.parse(line);if(!client)throw Error('unavailable');const result=await client.dispatch(request);output.write(JSON.stringify({schema:1,id:request.id,ok:true,result})+'\n');}catch(error){output.write(JSON.stringify({schema:1,id:Number.isSafeInteger(request?.id)?request.id:0,ok:false,error:client?(SAFE_NATIVE_ERRORS.has(error?.message)?error.message:'operation_failed_review_settings'):'native_core_unavailable'})+'\n');}}}finally{await owned?.close();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))await serve();
