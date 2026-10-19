// Owner-local capability changes reuse the enrolled identity, never a new invitation.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,sign,constants,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
import {activeRelease} from '../host/installer.mjs';
import {verifyMacPreviewApp} from '../host/macos-preview-trust.mjs';
import {capabilityPayload} from '../shared/enrollment-protocol.mjs';
import {ownerCommand} from '../gateway/enroll-admin.mjs';
import {readDeployment,controlDeploymentHostService} from './core.mjs';
import {observeHostService} from './service-lifecycle.mjs';
const assert=(ok,code)=>{if(!ok)throw Error(code)};
const hash=b=>createHash('sha256').update(b).digest('hex');
function read(file){requirePrivateFile(file);assert(fs.statSync(file).size<=1048576,'capability_file_too_large');return JSON.parse(fs.readFileSync(file,'utf8'))}
function write(file,data){
 const temp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(temp,0o600);
 try{fs.writeFileSync(fd,JSON.stringify(data,null,2)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 try{fs.renameSync(temp,file)}finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}
 if(process.platform!=='win32'){const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}
}
function prepare(d,enable,trustedMacPreviewApp){
 const state=readDeployment(d),config=read(path.join(d,'deployment.json'));
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
   const preview=trustedMacPreviewApp??config.host.macPreviewApp;
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
function publicStatus(j){return {status:j.status,observation:'last_recorded',computer:j.computer??null,requestedComputer:j.requestedComputer,
 phase:j.phase,observedAt:j.updatedAt,nativePermissions:'not_checked',accountAcceptance:'NOT RUN',...(j.reason?{reason:j.reason}:{})}}
export function readDeploymentCapabilities(d){
 requirePrivateDirectory(d);const file=path.join(d,'capabilities.json');
 if(!fs.existsSync(file))return {status:'not_changed',computer:null};
 return publicStatus(read(file));
}
export async function changeDeploymentCapabilities(d,{authorize=false,computer}={},operations={}){
 assert(authorize===true&&typeof computer==='boolean','explicit_desktop_capability_authorization_required');
 requirePrivateDirectory(d);
 const ops={prepare:(dir,enabled)=>prepare(dir,enabled,operations.trustedMacPreviewApp),owner:ownerCommand,hostStatus:observeHostService,hostControl:controlDeploymentHostService,...operations};
 const lock=path.join(d,'capabilities.lock');let fd;
 try{fd=openPrivateFile(lock,0o600)}catch{throw Error('capability_busy_or_interrupted_lock')}
 const file=path.join(d,'capabilities.json');let journal,scope,observed,wasRunning=false;
 try{
  const digest=hash(fs.readFileSync(path.join(d,'deployment.json')));
  if(fs.existsSync(file)){
   const previous=read(file);assert(previous.configSha256===digest,'capability_scope_changed');
   assert(previous.status!=='running'&&previous.status!=='uncertain','capability_uncertain_requires_reconciliation');
  }
  scope=ops.prepare(d,computer);
  const host=await ops.hostStatus({serviceConfigFile:scope.serviceConfigFile});
  assert(host.status==='reported'&&['running','stopped','not_installed'].includes(host.state),'host_state_not_safe_for_capability_change');
  wasRunning=host.state==='running';
  const devices=await ops.owner(scope.owner,'devices');
  observed=devices.find(x=>x.device_id===scope.identity.device_id&&x.fingerprint===scope.identity.fingerprint&&x.status==='approved');
  assert(observed,'capability_device_not_approved');
  journal={schema:1,configSha256:digest,status:'running',phase:'deny_computer',requestedComputer:computer,computer:observed.capabilities.computer};
  const persist=()=>{journal.updatedAt=new Date().toISOString();write(file,journal)};
  const update=async(enabled)=>{
   const body={device_id:scope.identity.device_id,fingerprint:scope.identity.fingerprint,generation:observed.generation,enable_computer:enabled,public_key_pem:scope.publicKey};
   body.signature=sign('sha256',Buffer.from(capabilityPayload(body)),{key:scope.key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
   const result=await ops.owner(scope.owner,'capabilities',[body]);
   assert(result.status==='updated'&&result.device_id===body.device_id&&result.fingerprint===body.fingerprint&&result.capabilities.computer===enabled&&typeof result.generation==='string','capability_reply_invalid');
   observed=result;journal.computer=enabled;persist();
  };
  persist();await update(false);
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
