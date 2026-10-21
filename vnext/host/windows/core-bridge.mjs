// The native shell uses the same private HTTP Core API as the Mac app.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory,writePrivateFile,requirePrivateDirectory} from '../private-storage.mjs';
export const OPERATIONS=Object.freeze(['status','create','inspectJoin','join','prepare','connect','disconnect','setCapabilities','tunnelSave','tunnelStart','tunnelStop','acceptanceBegin','acceptanceConfirm','devices','setDefault','revokeDevice','inviteComputer','pendingComputers','approveComputer']);
export function bootstrap(url){const u=new URL(url);if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||!u.port||u.pathname!=='/'||u.search||u.username||u.password||!/^#session=[A-Za-z0-9_-]{43}$/.test(u.hash))throw Error('invalid_bootstrap');const token=u.hash.slice(9);u.hash='';return {origin:u.origin,token};}
export async function createClient(instance,{fetchImpl=fetch}={}){
 const {origin,token}=bootstrap(instance.url);let csrf;
 const call=async(route,body)=>{const response=await fetchImpl(origin+'/api/'+route,{method:body?'POST':'GET',redirect:'error',headers:{Authorization:'Bearer '+token,Origin:origin,...(body?{'Content-Type':'application/json','X-Styx-CSRF':csrf}:{})},...(body?{body:JSON.stringify(body)}:{}),...(['advance','local-setup','browser/prepare'].includes(route)?{}:{signal:AbortSignal.timeout(body?120000:20000)})});if(!response.ok||!response.headers.get('content-type')?.startsWith('application/json'))throw Error('core_rejected');const text=await response.text();if(Buffer.byteLength(text)>2*1024*1024)throw Error('core_response_too_large');return JSON.parse(text);};
 const session=await call('session');csrf=session.csrf;if(!/^[A-Za-z0-9_-]{43}$/.test(csrf??''))throw Error('invalid_csrf');let inspected,accepted;
 return {async dispatch(request){
  if(!request||request.schema!==1||!Number.isSafeInteger(request.id)||!OPERATIONS.includes(request.operation)||!request.input||typeof request.input!=='object'||Array.isArray(request.input))throw Error('invalid_native_request');
  const i=request.input,op=request.operation;
  if(op==='devices')return call('devices',{});
  if(op==='pendingComputers')return call('pending/list',{authorize:true});
  if(op==='approveComputer')return call('pending/approve',{authorize:true,requestId:i.requestId,comparisonCodeConfirmation:i.comparisonCode});
  if(op==='inviteComputer'){
   const {ingress}=await call('device-ingress/plan',{});
   if(!ingress||ingress.gateway!=='local'||ingress.blockers?.length)return {status:'network_setup_required'};
   return {status:'waiting_for_computer',invitation:await call('pairing-link/create',{authorize:true})};
  }
  if(op==='setDefault'||op==='revokeDevice')return call(op==='setDefault'?'default-device':'device/revoke',{authorize:true,deviceId:i.deviceId});
  if(op==='status')return {session:{localGatewayAvailable:session.localGatewayAvailable,tunnelSupported:session.tunnelSupported,artifactsAvailable:!!session.defaults?.bundle},...await call('snapshot')};
  if(op==='inspectJoin'){inspected=await call('pairing-link/inspect',{link:i.link});return inspected;}
  if(op==='join'){
   if(!inspected||i.approvedGatewayOrigin!==inspected.preview.origin||i.approvedCaSha256!==inspected.preview.caSha256)throw Error('explicit_join_confirmation_required');
   accepted=await call('pairing-link/accept',{inspectionId:inspected.inspectionId,approvedGatewayOrigin:i.approvedGatewayOrigin,...(i.approvedCaSha256?{approvedCaSha256:i.approvedCaSha256}:{})});
  }
  if(op==='create'||op==='join'){
   const d=session.defaults,host=Object.fromEntries(['bundle','publisherKeyFile','publisherSha256','baseDir'].map(k=>[k,d[k]]));if(Object.values(host).some(v=>typeof v!=='string'))throw Error('bundled_artifacts_required');
   Object.assign(host,{label:i.label,computer:i.computer===true,browser:{enabled:i.browser===true,headless:false,channel:['auto','chrome','msedge'].includes(i.browserChannel)?i.browserChannel:'auto',persistLogin:i.persistLogin===true}});
   return call('create',{schema:1,mode:op==='join'?'join-existing':'create-local',gateway:{url:op==='join'?accepted.origin:d.gatewayUrl},host,...(op==='join'?{joinLinkId:accepted.joinLinkId}:{})});
  }
  if(op==='prepare'){
   let status=await call('status');
   if(status.deployment?.mode==='join-existing'){
    for(let n=0;n<4;n++){
     const step=status.deployment.steps.find(s=>!['succeeded','skipped'].includes(s.status));
     if(!step||!['host.prepare','host.request','host.claim','host.doctor'].includes(step.id)||!(['pending','awaiting_approval'].includes(step.status)||step.status==='blocked'&&(step.id==='host.claim'||step.id==='host.doctor'&&step.retryable===true)))break;
     await call('advance',{authorize:[step.id]});status=await call('status');if(status.deployment.steps.find(s=>s.id===step.id)?.status!=='succeeded')break;
    }
   }else{if(!status.ownerPairingScope)throw Error('owner_scope_required');await call('local-setup',{ownerApproval:{...status.ownerPairingScope,approve:true}});}
   status=await call('status');
   const local=new Set(['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.invite','host.request','host.claim','host.doctor']);const ready=status.deployment?.steps.filter(s=>local.has(s.id)).every(s=>s.status==='succeeded');
   if(ready&&status.deployment.roles?.browser==='requested'){const {browser}=await call('browser');if(browser?.status==='not_prepared'||browser?.status==='not_configured'||browser?.status==='preparation_required')await call('browser/prepare',{authorize:true});}
   return call('snapshot');
  }
  const routes={connect:'foreground',disconnect:'foreground/stop',setCapabilities:'capabilities',tunnelSave:'tunnel/configure',tunnelStart:'tunnel/start',tunnelStop:'tunnel/stop',acceptanceBegin:'acceptance/begin',acceptanceConfirm:'acceptance/confirm'};
  const body=op==='tunnelSave'?{authorize:true,tunnelId:i.tunnelId,apiKey:i.runtimeKey,autoStart:false}:op==='setCapabilities'?{authorize:true,computer:i.computer,browser:i.browser,browserChannel:i.browserChannel,persistLogin:i.persistLogin}:op==='acceptanceConfirm'?{authorize:true,challengeId:i.challengeId,observedInTargetChat:true}:{authorize:true};
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
export async function startWindowsCore(resourceRoot,stateRoot){
 if(!path.isAbsolute(stateRoot)||!path.isAbsolute(resourceRoot))throw Error('absolute_native_paths_required');
 ensurePrivateDirectory(stateRoot);requirePrivateDirectory(stateRoot);
 let options={stateDir:path.join(stateRoot,'deployment'),trustedOpenSSL:undefined};
 const manifest=path.join(resourceRoot,'windows-runtime.json');
 if(fs.existsSync(manifest)){
  const cfg=JSON.parse(fs.readFileSync(manifest,'utf8'));
  const member=(relative,sha)=>{if(typeof relative!=='string'||path.isAbsolute(relative)||relative.split(/[\\/]/).some(x=>['','..','.'].includes(x)))throw Error('invalid_resource');const file=path.join(resourceRoot,relative);if(!fs.realpathSync(file).startsWith(fs.realpathSync(resourceRoot)+path.sep))throw Error('redirected_resource');if(sha&&createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==sha)throw Error('resource_integrity_failed');return file;};
  if(process.platform==='win32'){const core=await import('../../onboarding/core.mjs');options.core={...core,startDeploymentForeground:(directory,authorization)=>core.startDeploymentForeground(directory,authorization,{guiAvailable:()=>nativeDesktopAvailable(resourceRoot,cfg.desktopProbe)})};}
  if(cfg.artifacts){const artifacts={bundle:member(cfg.artifacts.bundle),publisherKeyFile:member(cfg.artifacts.publisherKeyFile),publisherSha256:cfg.artifacts.publisherSha256};const file=path.join(stateRoot,'artifacts.json');if(fs.existsSync(file))fs.unlinkSync(file);writePrivateFile(file,JSON.stringify(artifacts));options.artifactDefaultsFile=file;}
  if(cfg.openssl)options.trustedOpenSSL=member(cfg.openssl.path,cfg.openssl.sha256);
  if(cfg.tunnel)options.trustedTunnelClient={binary:member(cfg.tunnel.path,cfg.tunnel.sha256),sha256:cfg.tunnel.sha256};
 }
 const {createOnboardingServer}=await import('../../onboarding/server.mjs');return createOnboardingServer(options);
}
export async function serve({input=process.stdin,output=process.stdout,instance,client:providedClient}={}){
 let owned=instance,client;
 try{owned??=await startWindowsCore(process.env.STYX_NATIVE_RESOURCES,process.env.STYX_NATIVE_STATE);client=providedClient??await createClient(owned);}catch{}
 const lines=readline.createInterface({input,crlfDelay:Infinity});
 try{for await(const line of lines){let request;try{if(Buffer.byteLength(line)>65536)throw Error('oversize');request=JSON.parse(line);if(!client)throw Error('unavailable');const result=await client.dispatch(request);output.write(JSON.stringify({schema:1,id:request.id,ok:true,result})+'\n');}catch{output.write(JSON.stringify({schema:1,id:Number.isSafeInteger(request?.id)?request.id:0,ok:false,error:client?'operation_failed_review_settings':'native_core_unavailable'})+'\n');}}}finally{await owned?.close();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))await serve();
