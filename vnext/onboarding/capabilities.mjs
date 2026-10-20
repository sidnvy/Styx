// Owner-local capability changes reuse the enrolled identity, never a new invitation.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash,createPublicKey,sign,constants,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile,ensurePrivateDirectory} from '../host/private-storage.mjs';
import {activeRelease} from '../host/installer.mjs';
import {activeHostConfig} from '../host/launch.mjs';
import {validateDeployment} from './deployment-config.mjs';
import {assertMacPreviewContinuity,verifyMacPreviewApp} from '../host/macos-preview-trust.mjs';
import {capabilityPayload} from '../shared/enrollment-protocol.mjs';
import {ownerCommand} from '../gateway/enroll-admin.mjs';
import {readDeployment,controlDeploymentHostService} from './core.mjs';
import {observeHostService} from './service-lifecycle.mjs';
import {stopDeploymentForeground,readDeploymentForeground} from './foreground.mjs';
const assert=(ok,code)=>{if(!ok)throw Error(code)};
const hash=b=>createHash('sha256').update(b).digest('hex');
export function selectMacPreviewForCapabilities(registered,trustedOverride){
 const current=trustedOverride??registered;
 if(assertMacPreviewContinuity(registered,current).migrationRequired)throw Error('mac_preview_certificate_migration_required');
 return current;
}
function read(file){requirePrivateFile(file);assert(fs.statSync(file).size<=1048576,'capability_file_too_large');return JSON.parse(fs.readFileSync(file,'utf8'))}
function write(file,data){
 const temp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(temp,0o600);
 try{fs.writeFileSync(fd,JSON.stringify(data,null,2)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 try{fs.renameSync(temp,file)}finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}
 if(process.platform!=='win32'){const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}
}
function prepare(d,enable,trustedMacPreviewApp){
 const state=readDeployment(d),config=read(path.join(d,'deployment.json'));
 const selectedPreview=selectMacPreviewForCapabilities(config.host?.macPreviewApp,trustedMacPreviewApp);
 assert(state.mode==='create-local'&&config.mode==='create-local','local_owner_capability_change_only');
 assert(state.steps.some(s=>['host.pair','host.claim'].includes(s.id)&&s.status==='succeeded'),'paired_host_required');
 assert(!state.steps.some(s=>['running','uncertain'].includes(s.status)),'onboarding_uncertain_requires_reconciliation');
 const base=config.host.baseDir,device=path.join(base,'device'),hostFile=path.join(device,'host.json');
 const identity=read(path.join(device,'identity.json')),host=read(hostFile);
 requirePrivateFile(path.join(device,'identity.pem'));const key=fs.readFileSync(path.join(device,'identity.pem'),'utf8');
 const pub=createPublicKey(key);assert(hash(pub.export({type:'spki',format:'der'}))===identity.fingerprint&&host.host_id===identity.device_id,'capability_identity_mismatch');
 assert(host.token_file===path.join(device,'host.token'),'capability_host_token_binding_changed');requirePrivateFile(host.token_file);
 const owner=read(path.join(d,'gateway','owner.json'));
 assert(owner.gateway_url===config.gateway.url&&owner.gateway_ca_file===path.join(d,'gateway','certificate.pem')&&owner.admin_token_file===path.join(d,'gateway','admin.token'),'capability_owner_binding_changed');
 let computer;
 if(enable){
  const publisher=path.join(base,'publisher.pem');requirePrivateFile(publisher);
  const active=activeRelease(path.join(base,'install'),fs.readFileSync(publisher,'utf8'));assert(active,'signed_release_required');
  let binary=path.join(active.release_root,'bin',process.platform==='win32'?'cua-driver.exe':'cua-driver');
  if(process.platform==='darwin'){
   const preview=selectedPreview;
   if(trustedMacPreviewApp)assert(trustedMacPreviewApp.path==='/Applications/Styx.app','fixed_macos_preview_path_required');
   if(preview)verifyMacPreviewApp(preview);
   else{
    assert(/^[A-Z0-9]{10}$/.test(config.host.macTeamID??''),'verified_macos_app_required');
    execFileSync('/usr/bin/codesign',['--verify','--deep','--strict','-R',`=anchor apple generic and identifier "app.styx.host" and certificate leaf[subject.OU] = "${config.host.macTeamID}"`,'/Applications/Styx.app'],{stdio:'ignore',timeout:15000});
   }
   binary=path.join(preview?.path??'/Applications/Styx.app','Contents/MacOS/cua-driver');
  }
  const info=fs.lstatSync(binary);assert(info.isFile()&&!info.isSymbolicLink(),'regular_computer_binary_required');
  computer={enabled:true,binary,connections:1,...(process.platform==='darwin'?{socket:`/tmp/styx-cua-${process.getuid()}/cua.sock`}:{}),
   ...(process.platform==='linux'&&config.host.wayland===true?{env:{CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}}:{})};
 }
 return {identity,key,publicKey:pub.export({type:'spki',format:'pem'}),host,hostFile,computer,owner,serviceConfigFile:path.join(base,'service.json')};
}
function publicStatus(j){return {status:j.status,observation:'last_recorded',computer:j.computer??null,browser:j.browser??null,requestedComputer:j.requestedComputer,
 phase:j.phase,observedAt:j.updatedAt,...(j.transactionId?{transactionId:j.transactionId,rollbackAvailable:['complete','needs_reconciliation'].includes(j.phase)}:{}),...(j.requestedBrowser!==undefined?{requestedBrowser:j.requestedBrowser}:{}),foregroundRestartRequired:j.foregroundRestartRequired===true,nativePermissions:'not_checked',accountAcceptance:'NOT RUN',...(j.reason?{reason:j.reason}:{})}}
export function readDeploymentCapabilities(d){
 requirePrivateDirectory(d);const file=path.join(d,'capabilities.json');
 if(!fs.existsSync(file))return {status:'not_changed',computer:null,browser:null};
 const journal=read(file);assert(journal.schema===1&&journal.configSha256===hash(fs.readFileSync(path.join(d,'deployment.json'))),'capability_scope_changed');
 return publicStatus(journal);
}
export async function changeDeploymentCapabilities(d,{authorize=false,computer,browser}={},operations={}){
 if(browser!==undefined){
  assert(authorize===true&&typeof browser==='boolean','explicit_browser_capability_authorization_required');
  assert(computer===undefined||typeof computer==='boolean','explicit_desktop_capability_authorization_required');
  return changeBrowserCapabilities(d,{browser,computer},operations);
 }
 assert(authorize===true&&typeof computer==='boolean','explicit_desktop_capability_authorization_required');
 requirePrivateDirectory(d);
 const ops={prepare:(dir,enabled)=>prepare(dir,enabled,operations.trustedMacPreviewApp),owner:ownerCommand,hostStatus:observeHostService,hostControl:controlDeploymentHostService,stopOwnedForeground:stopDeploymentForeground,readForeground:readDeploymentForeground,...operations};
 const lock=path.join(d,'capabilities.lock');let fd;
 try{fd=openPrivateFile(lock,0o600)}catch{throw Error('capability_busy_or_interrupted_lock')}
 const file=path.join(d,'capabilities.json');let journal,scope,observed,wasRunning=false,foregroundRestartRequired=false;
 try{
  const digest=hash(fs.readFileSync(path.join(d,'deployment.json')));
  if(fs.existsSync(file)){
   const previous=read(file);assert(previous.configSha256===digest,'capability_scope_changed');
   assert(previous.status!=='running'&&previous.status!=='uncertain','capability_uncertain_requires_reconciliation');
  }
  const foreground=await ops.readForeground(d);
  assert(!['needs_attention','stopping'].includes(foreground.status),'foreground_owned_or_interrupted_do_not_take_over');
  scope=ops.prepare(d,computer);
  const host=await ops.hostStatus({serviceConfigFile:scope.serviceConfigFile});
  assert(host.status==='reported'&&['running','stopped','not_installed'].includes(host.state),'host_state_not_safe_for_capability_change');
  wasRunning=host.state==='running';
  const devices=await ops.owner(scope.owner,'devices');
  observed=devices.find(x=>x.device_id===scope.identity.device_id&&x.fingerprint===scope.identity.fingerprint&&x.status==='approved');
  assert(observed,'capability_device_not_approved');
  journal={schema:1,configSha256:digest,status:'running',phase:'prepared',requestedComputer:computer,computer:observed.capabilities.computer,foregroundRestartRequired};
  const persist=()=>{journal.updatedAt=new Date().toISOString();write(file,journal)};
  const update=async(enabled)=>{
   const body={device_id:scope.identity.device_id,fingerprint:scope.identity.fingerprint,generation:observed.generation,enable_computer:enabled,public_key_pem:scope.publicKey};
   body.signature=sign('sha256',Buffer.from(capabilityPayload(body)),{key:scope.key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
   const result=await ops.owner(scope.owner,'capabilities',[body]);
   assert(result.status==='updated'&&result.device_id===body.device_id&&result.fingerprint===body.fingerprint&&result.capabilities.computer===enabled&&typeof result.generation==='string','capability_reply_invalid');
   observed=result;journal.computer=enabled;persist();
  };
  if(foreground.status!=='not_running'){
   journal.phase='stop_owned_foreground';persist();
   const stopped=await ops.stopOwnedForeground(d);assert(['stopped','not_running'].includes(stopped.status),'foreground_stop_unconfirmed');
   journal.foregroundRestartRequired=stopped.foregroundRestartRequired===true;persist();
  }
  journal.phase='deny_computer';persist();await update(false);
  journal.phase='stop_host';persist();
  if(wasRunning){const stopped=await ops.hostControl(d,{action:'stop',authorize:true});assert(stopped.status==='reported'&&stopped.state==='stopped','host_stop_unconfirmed')}
  journal.phase='write_host';persist();
  const next={...scope.host};delete next.computer;if(computer)next.computer=scope.computer;
  write(scope.hostFile,next);
  if(computer){journal.phase='enable_computer';persist();await update(true)}
  journal.phase='restart_host';persist();
  if(wasRunning){const started=await ops.hostControl(d,{action:'start',authorize:true});assert(started.status==='reported'&&started.state==='running','host_restart_unconfirmed')}
  journal.status='updated';journal.phase='complete';persist();return publicStatus(journal);
 }catch(error){
  if(journal){
   if(journal.phase==='stop_owned_foreground'){
    journal.status='uncertain';journal.reason='foreground_stop_unconfirmed_requires_reconciliation';journal.foregroundRestartRequired=true;
    journal.updatedAt=new Date().toISOString();write(file,journal);throw Error(journal.reason);
   }
   // Fail closed locally even when a Gateway response was lost: no automatic
   // restart and no replay of a signed remote mutation with unknown outcome.
   let localStopped=!wasRunning;
   if(scope&&wasRunning){try{const s=await ops.hostControl(d,{action:'stop',authorize:true});localStopped=s.status==='reported'&&s.state==='stopped'}catch{}}
   if(scope){try{const safe={...scope.host};delete safe.computer;write(scope.hostFile,safe)}catch{localStopped=false}}
   // A compensating deny uses a newly observed revision, never replays the
   // uncertain enable. If the owner endpoint is unavailable, keep uncertainty.
   if(scope){try{
    const devices=await ops.owner(scope.owner,'devices');
    const current=devices.find(x=>x.device_id===scope.identity.device_id&&x.fingerprint===scope.identity.fingerprint&&x.status==='approved');
    if(current){
     if(current.capabilities.computer===false)journal.computer=false;
     else{
      const body={device_id:scope.identity.device_id,fingerprint:scope.identity.fingerprint,generation:current.generation,enable_computer:false,public_key_pem:scope.publicKey};
      body.signature=sign('sha256',Buffer.from(capabilityPayload(body)),{key:scope.key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
      const denied=await ops.owner(scope.owner,'capabilities',[body]);
      if(denied.status==='updated'&&denied.device_id===body.device_id&&denied.capabilities.computer===false)journal.computer=false;
     }
    }
   }catch{}}
   journal.status='uncertain';journal.localHostStopped=localStopped;
   journal.reason=localStopped?'capability_change_incomplete_host_stopped_no_replay':'capability_change_incomplete_inspect_local_state';
   journal.updatedAt=new Date().toISOString();write(file,journal);
  }
  throw Error(/^[a-z][a-z0-9_]{1,100}$/.test(error?.message??'')?error.message:'capability_change_failed');
 }finally{fs.closeSync(fd);fs.unlinkSync(lock)}
}

// Browser changes are deliberately offline transactions. They never disconnect
// live work, restart services, issue invitations or replace enrolled credentials.
const BROWSER_CHANGE='browser-capabilities-v1';
const encode=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
const privateBytes=file=>{assert(requirePrivateFile(file).size<=1048576,'capability_file_too_large');return fs.readFileSync(file)};
function atomicBytes(file,bytes){
 const temp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(temp);
 try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 try{fs.renameSync(temp,file);if(process.platform!=='win32'){const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}}finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}
}
function browserLocks(d,id,{recover=false}={}){
 const held=[];
 try{
  for(const name of ['advance.lock','capabilities.lock']){
   const file=path.join(d,name);
   if(fs.existsSync(file)&&recover){
    const old=read(file);assert(old.kind===BROWSER_CHANGE&&old.transactionId===id&&Number.isSafeInteger(old.pid)&&old.pid>0,'capability_foreign_management_lock');
    let absent=false;try{process.kill(old.pid,0)}catch(error){absent=error.code==='ESRCH'}assert(absent,'capability_management_owner_alive');
    fs.unlinkSync(file);
   }
   let fd;try{fd=openPrivateFile(file)}catch{throw Error('capability_busy_or_interrupted_lock')}
   const bytes=encode({schema:1,kind:BROWSER_CHANGE,transactionId:id,pid:process.pid}),info=fs.fstatSync(fd);
   fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);held.push({file,fd,bytes,info});
  }
  return ()=>{for(const item of held.reverse()){try{const st=requirePrivateFile(item.file);assert(st.ino===item.info.ino&&st.dev===item.info.dev&&fs.readFileSync(item.file).equals(item.bytes),'capability_management_lock_changed');fs.unlinkSync(item.file)}finally{fs.closeSync(item.fd)}}};
 }catch(error){for(const item of held.reverse()){fs.closeSync(item.fd);try{if(fs.readFileSync(item.file).equals(item.bytes))fs.unlinkSync(item.file)}catch{}}throw error}
}
function browserIdentity(d,config){
 assert(config.mode==='create-local'&&config.host&&absolute(config.host.baseDir),'local_owner_capability_change_only');
 const base=config.host.baseDir,device=path.join(base,'device');for(const directory of [base,device,path.join(base,'install')])requirePrivateDirectory(directory);
 const identity=read(path.join(device,'identity.json')),key=privateBytes(path.join(device,'identity.pem')),pub=createPublicKey(key),hostFile=path.join(device,'host.json');
 assert(hash(pub.export({type:'spki',format:'der'}))===identity.fingerprint,'capability_identity_mismatch');
 const owner=read(path.join(d,'gateway/owner.json'));
 assert(owner.gateway_url===config.gateway.url&&owner.gateway_ca_file===path.join(d,'gateway/certificate.pem')&&owner.admin_token_file===path.join(d,'gateway/admin.token'),'capability_owner_binding_changed');
 return {base,identity,key,publicKey:pub.export({type:'spki',format:'pem'}),owner,hostFile,serviceConfigFile:path.join(base,'service.json')};
}
function browserSnapshot(d,selection,ops){
 const configFile=path.join(d,'deployment.json'),stateFile=path.join(d,'state.json'),configBytes=privateBytes(configFile),config=JSON.parse(configBytes),state=read(stateFile);
 selectMacPreviewForCapabilities(config.host?.macPreviewApp,ops.trustedMacPreviewApp);
 validateDeployment(config,{checkNetwork:false});
 assert(state.schema===1&&state.mode===config.mode&&state.configSha256===hash(configBytes),'capability_scope_changed');
 assert(state.steps.some(s=>['host.pair','host.claim'].includes(s.id)&&s.status==='succeeded'),'paired_host_required');
 assert(!state.steps.some(s=>['running','uncertain'].includes(s.status))&&![...(state.maintenance??[]),...(state.gatewayMaintenance??[])].some(s=>['running','uncertain'].includes(s.status)),'onboarding_uncertain_requires_reconciliation');
 const scope=browserIdentity(d,config),host=read(scope.hostFile);
 assert(host.host_id===scope.identity.device_id&&host.token_file===path.join(scope.base,'device/host.token'),'capability_identity_mismatch');requirePrivateFile(host.token_file);
 const gateway=new URL(config.gateway.url);gateway.protocol='wss:';assert(new URL(host.gateway_ws_url).href===gateway.href,'capability_gateway_binding_changed');
 const profileRoot=path.join(scope.base,'browser');
 assert(!host.browser||host.browser.profileRoot===profileRoot,'browser_profile_binding_changed');
 const publisher=path.join(scope.base,'publisher.pem'),pem=privateBytes(publisher),publicKey=createPublicKey(pem);
 assert(publicKey.asymmetricKeyType==='ed25519'&&hash(publicKey.export({type:'spki',format:'der'}))===config.host.publisherSha256,'browser_publisher_binding_changed');
 const active=activeRelease(path.join(scope.base,'install'),pem);assert(active,'signed_release_required');
 const requestedComputer=selection.computer??host.computer?.enabled===true;
 let computer=host.computer;
 if(selection.computer===true&&host.computer?.enabled!==true)computer=ops.prepare(d,true).computer;
 if(selection.computer===false)computer=undefined;
 const desiredBrowser={...(config.host.browser??{}),enabled:selection.browser,headless:config.host.browser?.headless??host.browser?.headless??true};
 const browser={enabled:true,headless:desiredBrowser.headless,profileRoot,...(desiredBrowser.executablePath?{executablePath:desiredBrowser.executablePath}:{})};
 if(selection.browser){
  // This verifies the same signed closure selected by the real Host launcher.
  try{activeHostConfig({...host,browser},active.release_root)}catch{throw Error('browser_enabled_host_update_required')}
 }
 const files=[{name:'deployment',path:configFile},{name:'host',path:scope.hostFile},{name:'enrollment',path:path.join(scope.base,'enrollment.json')},{name:'state',path:stateFile}];
 for(const item of files)item.before=privateBytes(item.path);
 const enrollment=JSON.parse(files.find(x=>x.name==='enrollment').before);
 assert(enrollment.storage_dir===path.join(scope.base,'device')&&enrollment.gateway_url===config.gateway.url,'capability_enrollment_binding_changed');
 for(const name of ['background']){
  const file=path.join(d,name+'.json');if(!fs.existsSync(file))continue;
  const before=privateBytes(file),value=JSON.parse(before);
  assert(value.schema===1&&value.configSha256===state.configSha256,'capability_auxiliary_scope_changed');
  assert(!['configuring','uncertain'].includes(value.status)&&Array.isArray(value.operations)&&!value.operations.some(x=>['running','uncertain'].includes(x.status)),'capability_auxiliary_uncertain');
  files.push({name,path:file,before});
 }
 for(const step of state.steps.filter(x=>x.status==='succeeded'))for(const value of Object.values(step.evidence??{})){
  if(value&&typeof value==='object'&&absolute(value.path)&&typeof value.sha256==='string')assert(hash(privateBytes(value.path))===value.sha256,'capability_completed_evidence_changed');
 }
 const preserve=[path.join(scope.base,'device/identity.json'),path.join(scope.base,'device/identity.pem'),host.token_file,publisher,path.join(scope.base,'install/active.json'),scope.serviceConfigFile,path.join(d,'gateway/certificate.pem'),path.join(d,'gateway/owner.json'),ownerFile(scope.owner)];
 for(const optional of [host.gateway_ca_file,path.join(d,'gateway/private-key.pem'),path.join(d,'gateway/model.token'),path.join(d,'onboarding-plugin.json')])if(optional&&fs.existsSync(optional))preserve.push(optional);
 const preserved=preserve.map(file=>({path:file,sha256:hash(privateBytes(file))}));
 const profileIdentity=fs.existsSync(profileRoot)?(()=>{const info=requirePrivateDirectory(profileRoot);return {dev:info.dev,ino:info.ino}})():null;
 const nextConfig={...config,host:{...config.host,computer:requestedComputer,browser:desiredBrowser}};validateDeployment(nextConfig,{checkNetwork:false});
 const nextHost={...host};delete nextHost.computer;delete nextHost.browser;if(computer)nextHost.computer=computer;if(selection.browser)nextHost.browser=browser;
 const nextEnrollment={...enrollment,computer_requested:requestedComputer,browser_requested:selection.browser};delete nextEnrollment.browser_config;if(selection.browser)nextEnrollment.browser_config=browser;
 if(computer){nextEnrollment.computer_binary=computer.binary;if(computer.socket)nextEnrollment.computer_socket=computer.socket;if(computer.env)nextEnrollment.computer_env=computer.env}
 else for(const key of ['computer_binary','computer_socket','computer_env'])delete nextEnrollment[key];
 const after=new Map([['deployment',encode(nextConfig)],['host',encode(nextHost)],['enrollment',encode(nextEnrollment)]]),nextState=structuredClone(state);nextState.configSha256=hash(after.get('deployment'));
 for(const item of files)if(item.name==='background')after.set(item.name,encode({...JSON.parse(item.before),configSha256:nextState.configSha256,status:'needs_attention',reason:'capabilities_changed_reconnect_required'}));
 for(const step of nextState.steps)for(const value of Object.values(step.evidence??{}))if(value&&typeof value==='object'&&typeof value.path==='string'){
  const changed=files.find(item=>item.path===value.path);if(changed&&after.has(changed.name))value.sha256=hash(after.get(changed.name));
 }
 if(nextState.onboardingDecisions?.background?.configSha256===state.configSha256)nextState.onboardingDecisions.background.configSha256=nextState.configSha256;
 after.set('state',encode(nextState));
 for(const item of files)item.after=after.get(item.name);
 return {...scope,config,state,host,requestedComputer,requestedBrowser:selection.browser,profileRoot,profileIdentity,files,preserved,active,moduleFile:path.join(active.release_root,'packages/styx-browser-provider/prepare.mjs')};
}
const ownerFile=owner=>owner.admin_token_file;
function unchangedBrowserScope(scope,{allowAfter=false}={}){
 for(const file of scope.files){const actual=hash(privateBytes(file.path));assert(actual===hash(file.before)||allowAfter&&actual===hash(file.after),'capability_review_changed');}
 for(const item of scope.preserved)assert(hash(privateBytes(item.path))===item.sha256,'capability_preserved_identity_changed');
 if(scope.profileIdentity){const current=requirePrivateDirectory(scope.profileRoot);assert(current.dev===scope.profileIdentity.dev&&current.ino===scope.profileIdentity.ino,'browser_profile_binding_changed')}
}
async function quietBrowserScope(d,scope,ops){
 for(const name of ['foreground.lock','background.lock'])assert(!fs.existsSync(path.join(d,name)),'capability_active_management_owner');
 for(const name of ['.health-update-lock','.health-operation-lock','.health-recovery-guard'])assert(!fs.existsSync(path.join(scope.base,'install',name)),'capability_host_update_in_progress');
 for(const name of ['prepare.lock','prepare.recovery.lock'])assert(!fs.existsSync(path.join(scope.profileRoot,'runtime',name)),'capability_browser_preparation_in_progress');
 const foreground=await ops.readForeground(d);assert(foreground.status==='not_running','browser_capability_foreground_must_be_stopped');
 const host=await ops.hostStatus({serviceConfigFile:scope.serviceConfigFile});
 assert(host.status==='reported'&&['stopped','not_installed'].includes(host.state)&&(host.installed===false||host.persistence==='disabled'||host.persistence==='none'),'browser_capability_host_must_be_stopped');
 const rows=await ops.owner(scope.owner,'devices'),device=rows.find(x=>x.device_id===scope.identity.device_id&&x.fingerprint===scope.identity.fingerprint&&x.status==='approved');
 assert(device,'capability_device_not_approved');
 assert(device.online===false&&['exec','computer','browser'].every(lane=>device.connections?.[lane]===false),'browser_capability_all_connections_must_be_offline');
 assert(typeof device.capabilities?.browser==='boolean'&&typeof device.capabilities?.computer==='boolean','browser_capability_gateway_update_required');
 return device;
}
async function signedBrowserUpdate(scope,observed,selection,ops){
 const body={device_id:scope.identity.device_id,fingerprint:scope.identity.fingerprint,generation:observed.generation,enable_browser:selection.browser,...(selection.computer!==undefined?{enable_computer:selection.computer}:{}),public_key_pem:scope.publicKey};
 body.signature=sign('sha256',Buffer.from(capabilityPayload(body)),{key:scope.key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
 const result=await ops.owner(scope.owner,'capabilities',[body]);
 assert(result.status==='updated'&&result.device_id===body.device_id&&result.fingerprint===body.fingerprint&&result.capabilities.browser===selection.browser&&(selection.computer===undefined||result.capabilities.computer===selection.computer)&&typeof result.generation==='string','capability_reply_invalid');
 return result;
}
async function prepareSignedBrowser(scope){
 const api=await import(pathToFileURL(scope.moduleFile).href+'?sha256='+hash(privateBytes(scope.moduleFile)));
 assert(typeof api.prepareManagedBrowser==='function'&&typeof api.readManagedBrowser==='function','browser_enabled_host_update_required');
 ensurePrivateDirectory(scope.profileRoot);
 const result=await api.prepareManagedBrowser({profileRoot:scope.profileRoot,authorize:true});
 assert(result?.status==='prepared','browser_preparation_incomplete');
 return {status:'prepared',playwrightVersion:typeof result.playwright==='string'?result.playwright:null,readiness:'not_verified'};
}
function saveBrowserTransaction(d,scope,id,observed){
 const root=path.join(d,'capability-transactions');ensurePrivateDirectory(root);const directory=path.join(root,id);ensurePrivateDirectory(directory,{exclusive:true});
 const record={schema:1,kind:BROWSER_CHANGE,transactionId:id,base:scope.base,profileRoot:scope.profileRoot,profileIdentity:scope.profileIdentity,preserved:scope.preserved,prior:{computer:observed.capabilities.computer,browser:observed.capabilities.browser},requested:{computer:scope.requestedComputer,browser:scope.requestedBrowser},files:[]};
 for(const [index,file]of scope.files.entries()){
  atomicBytes(path.join(directory,index+'.before'),file.before);atomicBytes(path.join(directory,index+'.after'),file.after);
  record.files.push({name:file.name,path:file.path,beforeSha256:hash(file.before),afterSha256:hash(file.after)});
 }
 write(path.join(directory,'transaction.json'),record);return record;
}
function restoreBrowserFiles(scope){unchangedBrowserScope(scope,{allowAfter:true});for(const item of scope.files)atomicBytes(item.path,item.before)}
async function changeBrowserCapabilities(d,selection,operations){
 assert(absolute(d),'absolute_state_directory_required');requirePrivateDirectory(d);
 const id=randomBytes(16).toString('hex'),release=browserLocks(d,id),file=path.join(d,'capabilities.json');
 const ops={prepare:(dir,enabled)=>prepare(dir,enabled,operations.trustedMacPreviewApp),owner:ownerCommand,hostStatus:observeHostService,readForeground:readDeploymentForeground,prepareBrowser:prepareSignedBrowser,...operations};
 let scope,journal,attemptedRemote=false;
 const persist=()=>{journal.updatedAt=new Date().toISOString();write(file,journal)};
 try{
  if(fs.existsSync(file)){const prior=read(file);assert(prior.configSha256===hash(privateBytes(path.join(d,'deployment.json'))),'capability_scope_changed');assert(!['running','uncertain'].includes(prior.status),'capability_uncertain_requires_reconciliation')}
  scope=browserSnapshot(d,selection,ops);const observed=await quietBrowserScope(d,scope,ops);unchangedBrowserScope(scope);
  assert(observed.capabilities.browser===(scope.host.browser?.enabled===true)&&observed.capabilities.computer===(scope.host.computer?.enabled===true),'capability_host_gateway_disagree');
  scope.priorCapabilities={computer:observed.capabilities.computer,browser:observed.capabilities.browser};
  const record=saveBrowserTransaction(d,scope,id,observed);
  journal={schema:1,kind:BROWSER_CHANGE,transactionId:id,configSha256:hash(scope.files[0].before),status:'running',phase:'prepared',requestedComputer:scope.requestedComputer,requestedBrowser:selection.browser,computer:observed.capabilities.computer,browser:observed.capabilities.browser,foregroundRestartRequired:true};persist();
  if(selection.browser){journal.phase='prepare_browser';persist();journal.preparation=await ops.prepareBrowser(scope);unchangedBrowserScope(scope);}
  let current=await quietBrowserScope(d,scope,ops);unchangedBrowserScope(scope);
  assert(current.generation===observed.generation,'capability_revision_changed');
  journal.phase='write_configuration';persist();
  for(const item of scope.files)atomicBytes(item.path,item.after);
  journal.configSha256=hash(scope.files[0].after);journal.phase='approve_capabilities';persist();
  current=await quietBrowserScope(d,scope,ops);unchangedBrowserScope(scope,{allowAfter:true});assert(current.generation===observed.generation,'capability_revision_changed');
  attemptedRemote=true;
  const updated=await signedBrowserUpdate(scope,current,{browser:selection.browser,computer:scope.requestedComputer},ops);
  unchangedBrowserScope(scope,{allowAfter:true});journal.computer=updated.capabilities.computer;journal.browser=updated.capabilities.browser;
  journal.status='updated';journal.phase='complete';journal.rollbackAvailable=true;journal.previousCapabilities=record.prior;persist();return publicStatus(journal);
 }catch(error){
  if(journal&&scope){
   let restored=false;try{restoreBrowserFiles(scope);restored=true}catch{}
   if(attemptedRemote){
    // A lost response is reconciled with a fresh generation before a deny.
    // This never replays the uncertain enable and never auto-restores a grant.
    try{const now=await quietBrowserScope(d,scope,ops);const denied=await signedBrowserUpdate(scope,now,{browser:false,...(scope.requestedComputer!==scope.priorCapabilities.computer?{computer:false}:{})},ops);journal.browser=denied.capabilities.browser;journal.computer=denied.capabilities.computer}catch{}
   }
   // A surviving provider lock can own an unresolved installer child. Restoring
   // config does not prove that process has stopped; never erase its lock here.
   const preparationUnresolved=['prepare.lock','prepare.recovery.lock'].some(name=>fs.existsSync(path.join(scope.profileRoot,'runtime',name)));
   const safelyRestored=restored&&!attemptedRemote&&!preparationUnresolved;
   journal.configSha256=hash(privateBytes(path.join(d,'deployment.json')));journal.status=safelyRestored?'rolled_back':'uncertain';journal.phase=safelyRestored?'rolled_back':'needs_reconciliation';journal.reason=preparationUnresolved?'browser_preparation_owner_requires_reconciliation':safelyRestored?'browser_change_failed_configuration_restored':'browser_change_incomplete_no_automatic_restart';persist();
  }
  throw Error(/^[a-z][a-z0-9_]{1,100}$/.test(error?.message??'')?error.message:'browser_capability_change_failed');
 }finally{release()}
}

export async function rollbackDeploymentCapabilities(d,{authorize=false,transactionId}={},operations={}){
 assert(authorize===true&&/^[a-f0-9]{32}$/.test(transactionId??''),'explicit_capability_rollback_authorization_required');assert(absolute(d),'absolute_state_directory_required');requirePrivateDirectory(d);
 const file=path.join(d,'capabilities.json'),journal=read(file);assert(journal.kind===BROWSER_CHANGE&&journal.transactionId===transactionId&&journal.phase!=='rolled_back','capability_rollback_binding_changed');
 const release=browserLocks(d,transactionId,{recover:true}),ops={owner:ownerCommand,hostStatus:observeHostService,readForeground:readDeploymentForeground,...operations};
 const persist=()=>{journal.updatedAt=new Date().toISOString();write(file,journal)};
 try{
  const directory=path.join(d,'capability-transactions',transactionId);requirePrivateDirectory(directory);const record=read(path.join(directory,'transaction.json'));
  assert(record.kind===BROWSER_CHANGE&&record.transactionId===transactionId&&absolute(record.base)&&record.profileRoot===path.join(record.base,'browser')&&Array.isArray(record.files),'capability_rollback_record_invalid');
  const allowed={deployment:path.join(d,'deployment.json'),host:path.join(record.base,'device/host.json'),enrollment:path.join(record.base,'enrollment.json'),state:path.join(d,'state.json'),background:path.join(d,'background.json')};
  assert(record.files.length>=4&&record.files.length<=5&&new Set(record.files.map(x=>x.name)).size===record.files.length&&['deployment','host','enrollment','state'].every(n=>record.files.some(x=>x.name===n)),'capability_rollback_record_invalid');
  const files=record.files.map((entry,index)=>{assert(allowed[entry.name]===entry.path,'capability_rollback_record_invalid');const before=privateBytes(path.join(directory,index+'.before')),after=privateBytes(path.join(directory,index+'.after'));assert(hash(before)===entry.beforeSha256&&hash(after)===entry.afterSha256,'capability_rollback_backup_changed');return {...entry,before,after}});
  const config=JSON.parse(files.find(x=>x.name==='deployment').before);validateDeployment(config,{checkNetwork:false});assert(config.host.baseDir===record.base,'capability_rollback_record_invalid');
  const scope={...browserIdentity(d,config),files,preserved:record.preserved,profileRoot:record.profileRoot,profileIdentity:record.profileIdentity};
  unchangedBrowserScope(scope,{allowAfter:true});let observed=await quietBrowserScope(d,scope,ops);
  journal.phase='rollback';journal.status='running';persist();
  // Restore bytes before restoring an explicitly authorized previous grant;
  // any interrupted rollback remains blocked from automatic foreground start.
  restoreBrowserFiles(scope);journal.configSha256=hash(files.find(x=>x.name==='deployment').before);persist();
  observed=await quietBrowserScope(d,scope,ops);
  const result=await signedBrowserUpdate(scope,observed,record.prior,ops);
  unchangedBrowserScope(scope);journal.status='rolled_back';journal.phase='rolled_back';journal.computer=result.capabilities.computer;journal.browser=result.capabilities.browser;journal.reason='explicit_rollback_complete_reconnect_required';persist();return publicStatus(journal);
 }catch(error){journal.status='uncertain';journal.phase='needs_reconciliation';journal.reason='capability_rollback_incomplete_no_replay';journal.configSha256=hash(privateBytes(path.join(d,'deployment.json')));persist();throw error}
 finally{release()}
}
