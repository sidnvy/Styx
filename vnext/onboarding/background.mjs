// Fixed owner-local handoff from setup's foreground Gateway to user services.
// The journal records intent before every mutation; interrupted work never replays.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
import {readDeployment,planDeployment,controlDeploymentHostService,controlDeploymentService,stopDeploymentGateway,verifyDeploymentGateway} from './core.mjs';
import {observeHostService} from './service-lifecycle.mjs';
import {ownerCommand} from '../gateway/enroll-admin.mjs';
import {controlMacLoginRecovery} from './macos-login-recovery.mjs';
import {stopDeploymentForeground,readDeploymentForeground} from './foreground.mjs';
function desktopRecovery(d,action){
 if(process.platform!=='darwin')return {status:'not_applicable'};
 const file=path.join(d,'deployment.json');requirePrivateFile(file);
 const app=JSON.parse(fs.readFileSync(file,'utf8')).host?.macPreviewApp;
 if(!app)return {status:'not_configured'};
 const result=controlMacLoginRecovery({appPath:app.path,logDir:path.join(d,'login-recovery-logs')},{action,authorize:action==='install'});
 return {status:result.services.every(s=>s.installed&&s.loaded&&s.running)?'running':'needs_attention',...result};
}
const fail=code=>{throw Error(code)};
const defaults={desktopRecovery,read:readDeployment,host:controlDeploymentHostService,gateway:(d,o)=>controlDeploymentService(d,{role:'gateway',...o}),
 stopForeground:stopDeploymentGateway,verifyGateway:verifyDeploymentGateway,hostConnection:observeLocalHostConnection,
 sleep:ms=>new Promise(resolve=>setTimeout(resolve,ms)),stopOwnedForeground:stopDeploymentForeground,readForeground:readDeploymentForeground};
// Owner-authenticated, identity-bound Exec relay observation. This is not tool
// execution readiness: connected() only confirms an open authenticated Exec lane.
export async function observeLocalHostConnection(d){
 const read=file=>{requirePrivateFile(file);return JSON.parse(fs.readFileSync(file,'utf8'))};
 const state=readDeployment(d),config=read(path.join(d,'deployment.json'));
 if(state.mode!=='create-local')fail('local_owner_connection_observation_required');
 const identity=read(path.join(config.host.baseDir,'device','identity.json'));
 const owner=read(path.join(d,'gateway','owner.json'));
 if(owner.gateway_url!==config.gateway.url||owner.gateway_ca_file!==path.join(d,'gateway','certificate.pem')||owner.admin_token_file!==path.join(d,'gateway','admin.token'))fail('owner_gateway_binding_changed');
 const devices=await ownerCommand(owner,'devices');
 const current=devices.find(x=>x.device_id===identity.device_id&&x.fingerprint===identity.fingerprint&&x.status==='approved');
 if(!current||typeof current.online!=='boolean')fail('host_connection_observation_unavailable');
 return {status:'observed',online:current.online};
}
function scope(d){
 if(typeof d!=='string'||!path.isAbsolute(d)||path.normalize(d)!==d)fail('absolute_state_directory_required');
 requirePrivateDirectory(d);const file=path.join(d,'deployment.json');requirePrivateFile(file);
 return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}
function readJournal(d,digest){
 const file=path.join(d,'background.json');
 if(!fs.existsSync(file))return {schema:1,configSha256:digest,status:'not_configured',operations:[]};
 requirePrivateFile(file);if(fs.statSync(file).size>65536)fail('background_journal_invalid');
 const data=JSON.parse(fs.readFileSync(file,'utf8'));
 if(data.schema!==1||data.configSha256!==digest||!Array.isArray(data.operations))fail('background_scope_changed');
 return data;
}
function save(d,journal){
 const file=path.join(d,'background.json'),temp=file+'.'+randomBytes(8).toString('hex')+'.tmp';
 const fd=openPrivateFile(temp,0o600);
 try{fs.writeFileSync(fd,JSON.stringify(journal)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd)}
 try{fs.renameSync(temp,file)}finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}
 if(process.platform!=='win32'){const dir=fs.openSync(d,'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}
}
function projection(journal){return {schema:1,status:journal.status,
 observation:'last_recorded',startup:'current_user_login',systemBootWithoutLogin:'NOT CONFIGURED',
 gateway:journal.gateway??'not_observed',host:journal.host??'not_observed',desktop:journal.desktop??'not_observed',
 gatewayConnection:journal.gatewayConnection??'not_checked',hostConnection:journal.hostConnection??'not_checked',hostHealth:'not_checked',accountAcceptance:'NOT RUN',
 ...(journal.reason?{reason:journal.reason}:{}),
 ...(journal.updatedAt?{updatedAt:journal.updatedAt,observedAt:journal.updatedAt}:{}),
 operations:journal.operations.map(({id,status})=>({id,status}))};}
export function readDeploymentBackground(d){return projection(readJournal(d,scope(d)))}
export async function enableDeploymentBackground(d,{authorize=false}={},operations={}){
 if(authorize!==true)fail('background_start_and_login_authorization_required');
 const ops={...defaults,...operations},digest=scope(d),lock=path.join(d,'background.lock');
 let fd;try{fd=openPrivateFile(lock,0o600)}catch{fail('background_busy_or_interrupted_lock')}
 let journal;
 try{
  journal=readJournal(d,digest);
  if(journal.operations.some(x=>['running','uncertain'].includes(x.status)))fail('background_uncertain_requires_reconciliation');
  const state=ops.read(d);
  const hasHost=state.roles?.host!=='disabled';
  if(hasHost&&state.steps.find(x=>x.id==='host.doctor')?.status!=='succeeded')fail('successful_host_doctor_required');
  if(state.steps.some(x=>['uncertain','running'].includes(x.status)))fail('onboarding_uncertain_requires_reconciliation');
  journal.status='configuring';delete journal.reason;
  const persist=()=>{journal.updatedAt=new Date().toISOString();save(d,journal)};
  const mutate=async(id,call)=>{
   // Retain bounded history; never discard unresolved operations.
   const entry={id,status:'running'};journal.operations=[...journal.operations.slice(-29),entry];persist();
   let result;
   try{result=await call()}catch{entry.status='uncertain';journal.status='needs_attention';journal.reason='background_operation_uncertain_no_replay';persist();throw Error(journal.reason)}
   if(['uncertain','needs_attention','needs_owner_attention'].includes(result?.status)){
    entry.status='uncertain';journal.status='needs_attention';journal.reason='background_operation_uncertain_no_replay';persist();throw Error(journal.reason);
   }
   if(['blocked','not_implemented'].includes(result?.status)){
    entry.status='blocked';journal.status='needs_attention';journal.reason='background_operation_refused';persist();throw Error(journal.reason);
   }
   entry.status='succeeded';persist();return result;
  };
  persist();
  // Inspect both roles before stopping the working foreground Gateway.
  let host=hasHost?await ops.host(d,{action:'status',authorize:true}):null;
  if(hasHost&&(host.status!=='reported'||typeof host.installed!=='boolean'))fail('host_service_observation_unavailable');
  if(hasHost&&!['running','stopped','not_installed'].includes(host.state))fail(state.mode==='join-existing'?'host_service_not_running':'host_service_observation_unavailable');
  let gateway=state.mode==='create-local'?await ops.gateway(d,{action:'status'}):null;
  if(gateway&&gateway.status!=='not_installed'&&!['active','inactive'].includes(gateway.active))fail('gateway_service_observation_unavailable');
  if(gateway?.active==='active'&&state.gatewayRuntime.status==='running')fail('conflicting_gateway_ownership');
  const foreground=await ops.readForeground(d);
  if(foreground.status==='needs_attention'||foreground.status==='stopping')fail('foreground_owned_or_interrupted_do_not_take_over');
  if(foreground.status!=='not_running')await mutate('foreground.stop_owned',async()=>{
   const stopped=await ops.stopOwnedForeground(d);if(!['stopped','not_running'].includes(stopped.status))fail('foreground_stop_unconfirmed');return stopped;
  });
  if(state.mode==='create-local'){
   if(hasHost){
   const connection=await ops.hostConnection(d);
   if(connection?.status!=='observed'||typeof connection.online!=='boolean')fail('host_connection_observation_unavailable');
   if(host.state!=='running'&&connection.online){
    journal.status='needs_attention';journal.host='foreground';journal.hostConnection='exec_connected';
    journal.reason='foreground_host_handoff_required';persist();return projection(journal);
   }
   if(!['running','stopped','not_installed'].includes(host.state))fail('host_service_observation_unavailable');
   }
   if(gateway.status==='not_installed')gateway=await mutate('gateway.install',()=>ops.gateway(d,{action:'install',authorize:true}));
   if(state.gatewayRuntime.status==='running'){
    if(gateway.active==='active')fail('conflicting_gateway_ownership');
    const stopped=await mutate('gateway.stop_foreground',()=>ops.stopForeground(d));
    if(stopped.status!=='stopped')fail('foreground_gateway_stop_unconfirmed');
   }
   gateway=await ops.gateway(d,{action:'status'});
   if(gateway.active!=='active'){
    if(!['inactive'].includes(gateway.active))fail('gateway_service_observation_unavailable');
    await mutate('gateway.start',()=>ops.gateway(d,{action:'start',authorize:true}));
   }
   // Linux requires enable separately. Other adapters enable on explicit start.
   gateway=await ops.gateway(d,{action:'status'});
   if(gateway.enabled==='disabled')await mutate('gateway.enable',()=>ops.gateway(d,{action:'enable',authorize:true}));
   let verified=false;
   for(let attempt=0;attempt<20;attempt++){
    try{if((await ops.verifyGateway(d)).status==='gateway_verified'){verified=true;break}}catch{}
    await ops.sleep(250);
   }
   if(!verified)fail('persistent_gateway_connection_not_ready');
   gateway=await ops.gateway(d,{action:'status'});
   if(gateway.active!=='active'||!(gateway.pid>0)||!['enabled','default'].includes(gateway.enabled))fail('persistent_gateway_state_unconfirmed');
   journal.gateway='running';journal.gatewayConnection='verified';persist();
  }else journal.gateway='external';
  if(hasHost){
  if(!host.installed)await mutate('host.install',()=>ops.host(d,{action:'install',authorize:true}));
  host=await ops.host(d,{action:'status',authorize:true});
  if(host.status!=='reported'||!host.installed)fail('host_service_observation_unavailable');
  if(host.state!=='running'||host.persistence==='disabled')await mutate('host.start',()=>ops.host(d,{action:'start',authorize:true}));
  host=await ops.host(d,{action:'status',authorize:true});
  if(host.status!=='reported'||host.state!=='running'||host.persistence==='disabled')fail('host_service_not_running');
  journal.host='running';
  if(state.mode==='create-local'){
   let connected=false;
   for(let attempt=0;attempt<20;attempt++){
    if(hasHost)try{const connection=await ops.hostConnection(d);if(connection.status==='observed'&&connection.online===true){connected=true;break}}catch{}
    await ops.sleep(250);
   }
   journal.hostConnection=connected?'exec_connected':'not_connected';persist();
   if(!connected)fail('host_exec_connection_not_ready');
  }
  const desktop=await mutate('desktop.login_recovery',()=>ops.desktopRecovery(d,'install'));
  journal.desktop=desktop.status;
  if(desktop.status==='needs_attention')fail('desktop_login_recovery_not_ready');
  }else{journal.host='disabled';journal.hostConnection='not_applicable';journal.desktop='not_applicable';}
  journal.status='running';persist();return projection(journal);
 }catch(error){
  if(journal&&journal.status==='configuring'){
   journal.status='needs_attention';journal.reason='background_readiness_not_confirmed';journal.updatedAt=new Date().toISOString();save(d,journal);
  }
  // No credentials, native command output or filesystem paths in public errors.
  throw Error(/^[a-z][a-z0-9_]{1,100}$/.test(error?.message??'')?error.message:'background_operation_failed');
 }finally{fs.closeSync(fd);fs.unlinkSync(lock)}
}

// Refresh actual OS process observations without changing either service or journals.
export async function observeDeploymentBackground(d,operations={}){
 scope(d);
 const ops={desktopRecovery,read:readDeployment,plan:planDeployment,hostStatus:observeHostService,gateway:(d,o)=>controlDeploymentService(d,{role:'gateway',...o}),hostConnection:observeLocalHostConnection,...operations};
 const state=ops.read(d),hasHost=state.roles?.host!=='disabled';
 const result={schema:1,observation:'current',observedAt:new Date().toISOString(),
  startup:'current_user_login',systemBootWithoutLogin:'NOT CONFIGURED',
  host:'not_observed',gateway:state.mode==='create-local'?'not_observed':'external',
  gatewayConnection:'not_checked',hostConnection:'not_checked',hostHealth:'not_checked',accountAcceptance:'NOT RUN'};
 if(hasHost)try{
  const host=await ops.hostStatus({serviceConfigFile:ops.plan(d).service.configFile});
  result.host=host.status!=='reported'?'unknown':host.state==='running'?'running':host.installed===false?'not_installed':'not_running';
  result.hostPersistence=host.persistence??'unknown';
 }catch{result.host='unknown'}else{result.host='disabled';result.hostConnection='not_applicable'}
 if(state.mode==='create-local'){
  try{
   const gateway=await ops.gateway(d,{action:'status'});
   result.gateway=gateway.status==='not_installed'?'not_installed':gateway.active==='active'&&gateway.pid>0?'running':gateway.active==='inactive'?'not_running':'unknown';
   result.gatewayPersistence=gateway.enabled??'unknown';
  }catch{result.gateway='unknown'}
  if(hasHost)try{const connection=await ops.hostConnection(d);result.hostConnection=connection.status==='observed'?(connection.online?'exec_connected':'not_connected'):'unknown'}catch{result.hostConnection='unknown'}
 }
 if(hasHost)try{result.desktop=(await ops.desktopRecovery(d,'status')).status}catch{result.desktop='unknown'}else result.desktop='not_applicable';
 result.status=!['needs_attention','unknown'].includes(result.desktop)&&(!hasHost||result.host==='running')&&['running','external'].includes(result.gateway)&&(!hasHost||state.mode!=='create-local'||result.hostConnection==='exec_connected')?'running':'needs_attention';
 return result;
}
