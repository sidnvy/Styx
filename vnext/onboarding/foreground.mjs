import {deploymentConnectionHash} from '../shared/deployment-scope.mjs';
// Process-owned foreground lifecycle. No wrapper, service installation,
// enrollment, credential regeneration or permission grant is performed here.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,randomBytes} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
import {activeRelease} from '../host/installer.mjs';
import {activeHostConfig} from '../host/launch.mjs';
import {normalizeConnector,runHostConnector} from '../host/connect.mjs';
import {computerConfig,runComputerConnectors} from '../host/computer.mjs';
import {observeHostService} from './service-lifecycle.mjs';
import {startForegroundObservation,observeForegroundOwner} from './foreground-observation.mjs';

const owners=new Map(),starting=new Map();
const fail=code=>{throw Error(code)};
const sha=value=>createHash('sha256').update(value).digest('hex');
const absolute=d=>{if(typeof d!=='string'||!path.isAbsolute(d)||path.normalize(d)!==d)fail('absolute_state_directory_required');return d};
function read(file){if(requirePrivateFile(file).size>1024*1024)fail('foreground_private_state_too_large');return JSON.parse(fs.readFileSync(file,'utf8'));}
const lockFile=d=>path.join(d,'foreground.lock');
function claim(d){
 const file=lockFile(d);let fd;try{fd=openPrivateFile(file)}catch{fail('foreground_owned_or_interrupted_do_not_take_over')}
 const identity=fs.fstatSync(fd),token=randomBytes(32).toString('hex');let initialized=false;
 const release=()=>{
  try{
   const current=requirePrivateFile(file);
   if(current.ino!==identity.ino||current.dev!==identity.dev||fs.readFileSync(file,'utf8')!==token)fail('foreground_lock_ownership_changed');
   fs.unlinkSync(file);
  }finally{fs.closeSync(fd)}
 };
 try{fs.writeFileSync(fd,token);fs.fsyncSync(fd);initialized=true;return release;}
 finally{if(!initialized)fs.closeSync(fd)}
}
function projection(entry){
 const connected=entry.execConnection==='connected';
 return {schema:1,status:entry.stopping?'stopping':entry.failed?'needs_attention':connected?'connected':entry.host==='service'?'using_service':'started',observation:'current_process',host:entry.host,gateway:entry.gateway,execConnection:entry.execConnection,desktopConnection:entry.desktopConnection,browserConnection:entry.browserConnection,browserRequested:entry.browserRequested,computerRequested:entry.computerRequested,toolHealth:'not_verified',accountAcceptance:'NOT RUN',appExit:'owned_foreground_connections_stop',serviceMutation:'NOT RUN'};
}
export function readDeploymentForeground(d){
 absolute(d);const entry=owners.get(d);if(entry){try{if(!entry.scopeValid())return {...projection(entry),status:'needs_attention',execConnection:'not_observed',desktopConnection:'not_observed',browserConnection:'not_observed',reason:'foreground_scope_changed'}}catch{return {...projection(entry),status:'needs_attention',execConnection:'not_observed',desktopConnection:'not_observed',browserConnection:'not_observed',reason:'foreground_scope_changed'}}return projection(entry)}
 return {schema:1,status:fs.existsSync(lockFile(d))?'needs_attention':'not_running',observation:'current_process',host:'not_owned',gateway:'not_owned',execConnection:'not_observed',desktopConnection:'not_observed',browserConnection:'not_observed',toolHealth:'not_verified',accountAcceptance:'NOT RUN',...(fs.existsSync(lockFile(d))?{reason:'foreground_owned_or_interrupted_do_not_take_over'}:{})};
}
// Public status may observe another process; it never adopts that process.
export async function observeDeploymentForeground(d){absolute(d);return observeForegroundOwner(d)}
async function guiAvailable(api,d){
 if(process.platform==='darwin')return (await api.readDeploymentPermissions?.(d))?.source==='current_native_app_preflight';
 if(process.platform==='linux')return !!(process.env.DISPLAY||process.env.WAYLAND_DISPLAY);
 // This independent Core payload has no packaged Windows input-desktop probe.
 // Windows foreground remains Exec-only until that native adapter is admitted.
 return false;
}
function scope(d,state,config){
 if(state.mode!==config.mode)fail('foreground_configuration_changed');
 if(state.activeStep||state.steps?.some(s=>['uncertain','running'].includes(s.status))||state.hostServiceMaintenance?.hasUncertainMutation||state.gatewayServiceMaintenance?.hasUncertainMutation)fail('foreground_uncertain_state_requires_reconciliation');
 for(const name of ['advance.lock','capabilities.lock','background.lock'])if(fs.existsSync(path.join(d,name)))fail('foreground_management_operation_in_progress');
 if(!config.host)return {host:null};
 if(!['host.prepare','host.doctor'].every(id=>state.steps?.some(s=>s.id===id&&s.status==='succeeded'))||!state.steps.some(s=>['host.pair','host.claim'].includes(s.id)&&s.status==='succeeded'))fail('foreground_prepared_paired_host_doctor_required');
 const base=config.host.baseDir,root=path.join(base,'install'),publisher=path.join(base,'publisher.pem');requirePrivateDirectory(base);requirePrivateFile(publisher);
 for(const name of ['.health-update-lock','.health-operation-lock'])if(fs.existsSync(path.join(root,name)))fail('foreground_host_update_in_progress');
 const pem=fs.readFileSync(publisher,'utf8'),key=createPublicKey(pem);
 if(key.asymmetricKeyType!=='ed25519'||sha(key.export({format:'der',type:'spki'}))!==config.host.publisherSha256)fail('foreground_publisher_binding_changed');
 const active=activeRelease(root,pem);if(!active)fail('foreground_signed_active_host_required');
 const file=path.join(base,'device/host.json'),identity=read(path.join(base,'device/identity.json')),raw=read(file),privateKey=path.join(base,'device/identity.pem');requirePrivateFile(privateKey);
 if(identity.device_id!==raw.host_id||sha(createPublicKey(fs.readFileSync(privateKey)).export({format:'der',type:'spki'}))!==identity.fingerprint||raw.token_file!==path.join(base,'device/host.token'))fail('foreground_host_identity_binding_changed');
 requirePrivateFile(raw.token_file);
 const gateway=new URL(config.gateway.url);gateway.protocol='wss:';
 if(new URL(raw.gateway_ws_url).href!==gateway.href)fail('foreground_gateway_binding_changed');
 const host=normalizeConnector(activeHostConfig(raw,active.release_root));
 if(host.computer?.enabled)computerConfig(host);
 const preserve=[file,path.join(base,'device/identity.json'),privateKey,raw.token_file,publisher,path.join(root,'active.json'),...(raw.gateway_ca_file?[raw.gateway_ca_file]:[])];
 const hashes=preserve.map(f=>{requirePrivateFile(f);return [f,sha(fs.readFileSync(f))]});
 return {host,serviceConfigFile:path.join(base,'service.json'),unchanged:()=>hashes.every(([f,h])=>{requirePrivateFile(f);return sha(fs.readFileSync(f))===h})};
}

export async function startDeploymentForeground(d,options={},operations={}){
 absolute(d);if(!options||Object.keys(options).some(k=>k!=='authorize')||options.authorize!==true)fail('explicit_foreground_authorization_required');
 if(starting.has(d))return starting.get(d).promise;
 if(owners.has(d)){const entry=owners.get(d),observed=readDeploymentForeground(d);if(observed.status==='needs_attention')fail('foreground_scope_changed');if(entry.desktopConnection==='session_unavailable_or_unobserved')await entry.resumeComputer?.();return projection(entry)}
 const abort=new AbortController(),task=start(d,operations,abort);starting.set(d,{promise:task,abort});try{return await task}finally{starting.delete(d)}
}
async function start(d,operations,abort){
 const api=operations.core??await import('./core.mjs');requirePrivateDirectory(d);
 const state=await api.readDeployment(d),config=read(path.join(d,'deployment.json')),configurationHash=deploymentConnectionHash(fs.readFileSync(path.join(d,'deployment.json'))),selected=scope(d,state,config);
 const hostStatus=selected.host?await (operations.hostStatus??observeHostService)({serviceConfigFile:selected.serviceConfigFile}):null;
 if(selected.host&&(hostStatus?.status!=='reported'||!['running','stopped','not_installed'].includes(hostStatus.state)))fail('foreground_host_service_state_unknown');
 const gatewayStatus=config.mode==='create-local'?await (operations.gatewayStatus??((dir)=>api.controlDeploymentService(dir,{role:'gateway',action:'status'})))(d):null;
 const gatewayServiceRunning=gatewayStatus?.active==='active'&&gatewayStatus.pid>0;
 if(config.mode==='create-local'&&!gatewayServiceRunning&&gatewayStatus?.status!=='not_installed'&&!(gatewayStatus?.active==='inactive'&&!gatewayStatus.pid))fail('foreground_gateway_service_state_unknown');
 if(gatewayServiceRunning&&state.gatewayRuntime?.status==='running')fail('foreground_conflicting_gateway_owners');
 if(selected.host){
  const capabilityFile=path.join(d,'capabilities.json');if(fs.existsSync(capabilityFile)&&['running','uncertain'].includes(read(capabilityFile).status))fail('foreground_capability_state_uncertain');
 }
 if(selected.unchanged&&!selected.unchanged()||deploymentConnectionHash(fs.readFileSync(path.join(d,'deployment.json')))!==configurationHash)fail('foreground_scope_changed');
 if(abort.signal.aborted)fail('foreground_start_cancelled');
 const release=claim(d);
 const entry={abort,release,host:selected.host?hostStatus.state==='running'?'service':'foreground':'disabled',gateway:config.mode==='join-existing'?'external':gatewayServiceRunning?'service':'foreground',execConnection:selected.host?'connecting':'not_required',desktopConnection:'not_requested',browserConnection:selected.host?.browser?.enabled?'connecting':'not_requested',browserRequested:selected.host?.browser?.enabled===true,computerRequested:selected.host?.computer?.enabled===true,startedGateway:false,stopping:false,failed:false,tasks:[],api,scopeValid:()=>deploymentConnectionHash(fs.readFileSync(path.join(d,'deployment.json')))===configurationHash&&(!selected.unchanged||selected.unchanged())};
 owners.set(d,entry);
 try{
  entry.observer=await startForegroundObservation({stateDir:d,configurationHash,projection:()=>readDeploymentForeground(d)});
  if(config.mode==='create-local'&&!gatewayServiceRunning){await api.startDeploymentGateway(d);entry.startedGateway=state.gatewayRuntime?.status!=='running';}
  if(abort.signal.aborted)fail('foreground_start_cancelled');
  if(config.mode==='create-local'){
   const verified=await api.verifyDeploymentGateway(d);if(verified.status!=='gateway_verified')fail('foreground_gateway_not_verified');
   // Detect an already connected, independently owned Host before duplicating
   // its identity. Service reuse is based on the actual scoped native observer.
   if(selected.host){const connection=await (operations.hostConnection??(await import('./background.mjs')).observeLocalHostConnection)(d);if(connection?.status!=='observed')fail('foreground_host_connection_unknown');if(hostStatus.state!=='running'&&connection.online)fail('foreground_host_already_connected_not_owned');if(hostStatus.state==='running')entry.execConnection=connection.online?'connected':'not_connected';}
  }else if(entry.host==='service')entry.execConnection='not_observed';
  if(abort.signal.aborted)fail('foreground_start_cancelled');
  if(entry.host==='foreground'){
   const track=(runner,config,options)=>{
    // Attach rejection handling immediately; no raw subprocess diagnostics.
    const task=Promise.resolve().then(()=>runner(config,options)).then(()=>{if(!entry.stopping&&!abort.signal.aborted)entry.failed=true},()=>{entry.failed=true;abort.abort()});entry.tasks.push(task);
   };
   const signal=abort.signal,retryMinMs=500,retryMaxMs=1500;
   track(operations.runHost??runHostConnector,selected.host,{signal,retryMinMs,retryMaxMs,onReady:()=>{entry.execConnection='connected'},onStatus:()=>{entry.execConnection='disconnected'}});
   if(entry.browserRequested){const runner=operations.runBrowser??(await import('../host/browser.mjs')).runBrowserConnector;track(runner,selected.host,{signal,onReady:()=>{entry.browserConnection='connected'},onStatus:state=>{entry.browserConnection=state}});}
   if(entry.computerRequested&&process.platform==='linux'&&(!operations.guiAvailable||operations.runLinuxDesktop)){
    const {runLinuxDesktopLifecycle,resolveLinuxDesktopSession}=await import('../host/linux-desktop.mjs');
    track((_config,options)=>(operations.runLinuxDesktop??runLinuxDesktopLifecycle)({
     signal:options.signal,
     onStatus:state=>{entry.desktopConnection=state==='session_available'?'connecting':'session_unavailable_or_unobserved'},
     resolveSession:()=>entry.scopeValid()?resolveLinuxDesktopSession({env:{...process.env,...selected.host.computer.env}}):{available:false,reason:'foreground_scope_changed'},
     connect:(session,{signal:desktopSignal})=>(operations.runComputer??runComputerConnectors)({...selected.host,
      computer:{...selected.host.computer,env:{...selected.host.computer.env,DISPLAY:'',WAYLAND_DISPLAY:'',...session.env}}},
      {signal:desktopSignal,retryMinMs,retryMaxMs,onReady:()=>{entry.desktopConnection='connected'},onStatus:()=>{entry.desktopConnection='disconnected'}})
    }),selected.host,{signal});
   }else if(entry.computerRequested){
    const currentScope=()=>{try{return entry.scopeValid()}catch{return false}};
    entry.resumeComputer=async()=>{
     if(entry.computerStarted)return;
     if(entry.computerStarting)return entry.computerStarting;
     const attempt=(async()=>{
      if(!currentScope())fail('foreground_scope_changed');
      const gui=await (operations.guiAvailable??guiAvailable)(api,d);
      if(abort.signal.aborted)fail('foreground_start_cancelled');
      if(!currentScope())fail('foreground_scope_changed');
      entry.desktopConnection=gui?'connecting':'session_unavailable_or_unobserved';
      if(gui){
       entry.computerStarted=true;
       track(operations.runComputer??runComputerConnectors,selected.host,{signal,retryMinMs,retryMaxMs,onReady:()=>{entry.desktopConnection='connected'},onStatus:()=>{entry.desktopConnection='disconnected'}});
      }
     })();entry.computerStarting=attempt;try{await attempt}finally{entry.computerStarting=null}
    };
    await entry.resumeComputer();
    if(entry.desktopConnection==='session_unavailable_or_unobserved'){
     const interval=operations.guiObservationIntervalMs??1000;
     if(!Number.isSafeInteger(interval)||interval<1||interval>60000)fail('foreground_gui_observation_interval_invalid');
     // The App can publish its approved Cua descriptor after foreground starts.
     // Observe that boundary without replaying any tool or restarting a child.
     // This task is separate from connector failures: a changed/unknown GUI
     // observation must not abort a healthy Exec connection.
     entry.computerObservation=(async()=>{
      while(!signal.aborted&&!entry.computerStarted){
       try{await delay(interval,undefined,{signal})}catch{if(signal.aborted)return;throw Error('foreground_gui_observation_wait_failed')}
       if(signal.aborted||!currentScope())return;
       try{await entry.resumeComputer()}catch{
        if(signal.aborted||!currentScope())return;
        entry.desktopConnection='session_unavailable_or_unobserved';
       }
      }
     })().catch(()=>{if(!signal.aborted)entry.desktopConnection='session_unavailable_or_unobserved'});
    }
   }
  }else{if(entry.computerRequested)entry.desktopConnection='not_observed';if(entry.browserRequested)entry.browserConnection='not_observed';}
  return projection(entry);
 }catch(error){
  await stopEntry(d,entry);if(entry.startedGateway)await api.stopDeploymentGateway(d);throw error;
 }
}
// A capability edit may suspend only this manager's known, healthy connector.
// Independent CLI managers, native services and uncertain owners are never adopted.
export async function stopOwnedDeploymentForeground(d,options={}){
 absolute(d);
 if(!options||Object.keys(options).some(k=>k!=='authorize')||options.authorize!==true)fail('explicit_foreground_authorization_required');
 const entry=owners.get(d),observed=readDeploymentForeground(d);
 if(!entry||starting.has(d)||observed.host!=='foreground'||!['started','connected'].includes(observed.status))fail('foreground_not_owned_or_unsafe_for_capability_change');
 return stopEntry(d,entry);
}
export async function stopDeploymentForeground(d){
 absolute(d);const pending=starting.get(d);if(pending){pending.abort.abort();await pending.promise.catch(()=>{})}
 const entry=owners.get(d);if(!entry)return readDeploymentForeground(d);
 return stopEntry(d,entry);
}
async function stopEntry(d,entry){
 if(entry.stop)return entry.stop;
 entry.stopping=true;entry.abort.abort();
 entry.stop=(async()=>{
  // Settlement includes the actual stdio child close path. A timeout must not
  // manufacture a stopped result or release another generation's ownership.
  await entry.computerObservation;
  await entry.computerStarting?.catch(()=>{});
  await Promise.all(entry.tasks);
  // Gateway has an independent Core lifetime: background/capability handoff
  // still needs it after Host settlement. App/CLI shutdown closes it next.
  await entry.observer?.close();entry.release();owners.delete(d);
  return {schema:1,status:'stopped',observation:'current_process',host:'not_owned',gateway:'not_owned',foregroundRestartRequired:entry.host==='foreground',serviceMutation:'NOT RUN',identityMutation:'NOT RUN'};
 })();return entry.stop;
}
