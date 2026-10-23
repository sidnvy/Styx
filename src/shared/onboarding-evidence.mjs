import {deploymentConnectionHash} from './deployment-scope.mjs';
// Private execution evidence, never an account identity provider or an admin MCP API.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
const fail=code=>{throw Error(code)};
export const evidenceHash=value=>createHash('sha256').update(value).digest('hex');
export function privateEvidenceRead(file,maximumBytes=1024*1024){if(requirePrivateFile(file).size>maximumBytes)fail('acceptance_evidence_size_limit');return JSON.parse(fs.readFileSync(file,'utf8'));}
export function acceptanceFile(stateDir){return path.join(stateDir,'account-acceptance.json');}
// A network-independent, credential-free challenge. Reconstruct this exact URL
// when projecting it; no caller HTML, scripts, paths or remote URLs are accepted.
export function browserAcceptanceChallenge(nonce){
 if(!/^[a-f0-9]{32}$/.test(nonce??''))fail('invalid_browser_acceptance_nonce');
 const marker='STYX_BROWSER_'+nonce;
 const html='<!doctype html><html><head><title>Styx Browser acceptance</title></head><body><h1>'+marker+'</h1></body></html>';
 return {marker,url:'data:text/html;charset=utf-8,'+encodeURIComponent(html)};
}
export function browserAcceptanceVerified(record){return !record.browserRequired||record.browser?.navigated===true&&record.browser?.observed===true&&/^[a-f0-9]{64}$/.test(record.browser?.ownerHash??'');}
function browserResponseSections(result){
 const blocks=(result?.content??[]).filter(item=>item.type==='text'&&typeof item.text==='string');
 if(blocks.reduce((n,item)=>n+item.text.length,0)>131072)return new Map();
 const sections=new Map();
 for(const part of blocks.map(item=>item.text).join('\n').split(/^### /m).slice(1)){const i=part.indexOf('\n');if(i>0)sections.set(part.slice(0,i),part.slice(i+1).trim());}
 return sections;
}
function browserPageMatches(sections,record){return sections.get('Page')?.split('\n').includes('- Page URL: '+record.browserUrl)===true;}
function browserSnapshotMatches(sections,record){
 const snapshot=/^```yaml\n([\s\S]*)\n```$/.exec(sections.get('Snapshot')??'')?.[1];
 // The URL and generated code both contain the marker. Only the actual inline
 // accessibility snapshot heading proves it was read from page content.
 return snapshot?.split('\n').some(line=>line.startsWith('- heading "'+record.browserMarker+'" ')&&line.includes('[level=1]')&&/\[ref=(?:styx-[a-f0-9]{32}|(?:f\d+)?e\d+)\]/.test(line))===true;
}
export function acceptanceBinding(stateDir){
 requirePrivateDirectory(stateDir);
 const deploymentFile=path.join(stateDir,'deployment.json'),config=privateEvidenceRead(deploymentFile);
 if(config.mode!=='create-local'||!config.host)fail('acceptance_requires_owned_gateway_and_host');
 const identity=privateEvidenceRead(path.join(config.host.baseDir,'device/identity.json'));
 const host=privateEvidenceRead(path.join(config.host.baseDir,'device/host.json'));
 const database=privateEvidenceRead(path.join(stateDir,'gateway/enrollment/state.json'));
 const record=database.devices?.find(item=>item.id===identity.device_id&&item.fingerprint===identity.fingerprint&&item.status==='approved');
 if(!record||record.target?.id!==host.host_id||record.target.allowed!==true)fail('acceptance_device_not_approved');
 const certificate=path.join(stateDir,'gateway/certificate.pem');requirePrivateFile(certificate);
 const model=path.join(stateDir,'gateway/model.token');requirePrivateFile(model);
 return {config,host,target:record.target,binding:evidenceHash(JSON.stringify({configuration:deploymentConnectionHash(fs.readFileSync(deploymentFile)),certificate:evidenceHash(fs.readFileSync(certificate)),modelCredential:evidenceHash(fs.readFileSync(model)),device:identity.device_id,fingerprint:identity.fingerprint,generation:record.target.generation,desktop:record.target.computer?.enabled===true,...(record.target.browser?.enabled===true?{browser:true}:{})}))};
}
export function writeAcceptanceEvidence(stateDir,record){
 const file=acceptanceFile(stateDir),temp=file+'.'+randomBytes(8).toString('hex')+'.tmp';
 const fd=openPrivateFile(temp);try{fs.writeFileSync(fd,JSON.stringify(record,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd)}
 try{fs.renameSync(temp,file);if(process.platform!=='win32'){const directory=fs.openSync(stateDir,'r');try{fs.fsyncSync(directory)}finally{fs.closeSync(directory)}}}finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}
}
export function withAcceptanceLock(stateDir,operation){
 const file=path.join(stateDir,'account-acceptance.lock');let fd;
 try{fd=openPrivateFile(file)}catch{fail('acceptance_busy_or_interrupted')}
 const value=randomBytes(32).toString('hex'),identity=fs.fstatSync(fd);let initialized=false;
 try{fs.writeFileSync(fd,value);fs.fsyncSync(fd);initialized=true;return operation();}
 finally{try{if(initialized){const current=requirePrivateFile(file);if(current.ino!==identity.ino||current.dev!==identity.dev||fs.readFileSync(file,'utf8')!==value)fail('acceptance_lock_ownership_changed');fs.unlinkSync(file)}}finally{fs.closeSync(fd)}}
}
export function currentAcceptanceEvidence(stateDir){
 const ctx=acceptanceBinding(stateDir),record=privateEvidenceRead(acceptanceFile(stateDir),65536);
 if(record.schema!==1||!/^[a-f0-9]{32}$/.test(record.id??'')||!/^[a-f0-9]{32}$/.test(record.nonce??'')||record.binding!==ctx.binding)fail('acceptance_context_changed');
 if(!Number.isSafeInteger(record.expiresAt)||Date.now()>record.expiresAt&&record.targetChatConfirmation?.status!=='user_confirmed')fail('acceptance_expired');
 return {ctx,record};
}
function desktopActionScope(record,args,owner){
 const observed=record.desktop?.observed,who=evidenceHash(owner);
 if(!observed||observed.owner!==who||observed.pid!==record.desktopAppPid)return null;
 if(args.scope==='desktop'||args.target?.kind==='desktop')return null;
 const pid=args.target?.pid??args.pid,window=args.target?.window_id??args.window_id;
 if(pid!==undefined&&pid!==observed.pid||window!==undefined&&window!==observed.window)return null;
 const token=typeof args.element_token==='string'&&args.element_token.startsWith(observed.snapshot+':');
 if(!token&&(pid!==observed.pid||window!==observed.window))return null;
 return {owner:who,pid:observed.pid,window:observed.window};
}
// Execution proof is recorded only after production dispatch succeeds. A local
// before hook clears old DOM readback for a scoped Cua attempt; it cannot prove
// an action succeeded. Neither hook executes or replays any tool operation.
export function createAcceptanceObserver(stateDir){
 const observer=event=>{
  if(!fs.existsSync(acceptanceFile(stateDir)))return;
  try{withAcceptanceLock(stateDir,()=>{
   const {ctx,record}=currentAcceptanceEvidence(stateDir),{name,args,result,owner,target}=event;
   if(!target||target.id!==ctx.target.id||target.generation!==ctx.target.generation||typeof owner!=='string'||!owner)return;
   if(record.browserRequired&&['browser_navigate','browser_snapshot'].includes(name)){
    const who=evidenceHash(owner),sameDevice=args.environment_id===undefined||args.environment_id===ctx.target.id;
    if(!sameDevice||typeof event.operationId!=='string'||!event.operationId)return;
    if(event.phase==='before'){
     if(name==='browser_navigate'&&args.url===record.browserUrl&&Object.keys(args).every(key=>['url','environment_id'].includes(key))){
      record.browser={ownerHash:who,navigationAttempt:{id:event.operationId,ownerHash:who},navigated:false,observed:false};
     }else if(name==='browser_snapshot'&&Object.keys(args).every(key=>key==='environment_id')&&record.browser?.navigated===true&&record.browser.ownerHash===who){
      record.browser.snapshotAttempt={id:event.operationId,navigationId:record.browser.navigationAttempt.id,ownerHash:who};
     }else return;
    }else{
     if(result?.isError)return;
     const sections=browserResponseSections(result),browser=record.browser;
     if(!browser||browser.ownerHash!==who||!browserPageMatches(sections,record))return;
     if(name==='browser_navigate'&&args.url===record.browserUrl&&browser.navigationAttempt?.id===event.operationId){browser.navigated=true;browser.navigatedAt=Date.now();}
     else if(name==='browser_snapshot'&&Object.keys(args).every(key=>key==='environment_id')&&browser.navigated===true&&browser.snapshotAttempt?.id===event.operationId&&browser.snapshotAttempt.ownerHash===who&&browser.snapshotAttempt.navigationId===browser.navigationAttempt.id&&browserSnapshotMatches(sections,record)){browser.observed=true;browser.observedAt=Date.now();browser.source='authenticated_mcp_browser_result';}
     else return;
    }
    writeAcceptanceEvidence(stateDir,record);return;
   }
   if(event.phase==='before'){
    if(!record.desktopRequired||!['set_value','type_text'].includes(name)||!(args.value===record.desktopValue||args.text===record.desktopValue)||typeof event.operationId!=='string')return;
    const scope=desktopActionScope(record,args,owner);if(!scope)return;
    record.desktop={...record.desktop,actionAttempt:{...scope,id:event.operationId},actionVerified:false,readback:false,after:false};
    writeAcceptanceEvidence(stateDir,record);return;
   }
   if(result?.isError)return;
   const output=result?.structuredContent;
   if(name==='exec_command'&&args.cmd===record.command&&args.environment_id===ctx.target.id&&args.login===false&&args.tty!==true){
    record.execution={ownerHash:evidenceHash(owner),sessionId:output?.session_id??null,tail:typeof output?.output==='string'?output.output.slice(-256):''};
    if(output?.exit_code===0&&!output.session_id&&record.execution.tail.includes(record.marker))record.requestProof={status:'verified',at:Date.now(),environmentId:ctx.target.id,generation:ctx.target.generation,source:'authenticated_mcp_exec_result'};
   }else if(name==='write_stdin'&&record.execution?.sessionId===args.session_id&&record.execution.ownerHash===evidenceHash(owner)&&!args.chars){
    record.execution.tail=(record.execution.tail+(typeof output?.output==='string'?output.output:'')).slice(-256);
    if(output?.exit_code===0&&!output.session_id&&record.execution.tail.includes(record.marker))record.requestProof={status:'verified',at:Date.now(),environmentId:ctx.target.id,generation:ctx.target.generation,source:'authenticated_mcp_exec_result'};
   }else if(record.desktopRequired){
    const desktop=record.desktop??={},who=evidenceHash(owner);
    const observed=name==='get_window_state'&&Number.isSafeInteger(record.desktopAppPid)&&args.pid===record.desktopAppPid&&Number.isSafeInteger(args.window_id)&&/^s[0-9a-f]{8}$/.test(output?.snapshot_id??'')&&result?.content?.some(item=>item.type==='image')&&output?.screenshot_frame_valid!==false;
    if(observed){
     if(desktop.actionVerified===true&&desktop.actionOwner===who&&desktop.actionAttempt?.window===args.window_id)desktop.after=true;
     desktop.observed={owner:who,pid:args.pid,window:args.window_id,snapshot:output.snapshot_id};
    }
    if(['set_value','type_text'].includes(name)&&desktop.actionAttempt?.id===event.operationId&&desktop.actionAttempt?.owner===who&&desktopActionScope(record,args,owner)&&(args.value===record.desktopValue||args.text===record.desktopValue)){desktop.actionOwner=who;desktop.actionVerified=true;}
    record.desktop=desktop;
   }else return;
   writeAcceptanceEvidence(stateDir,record);
  })}catch{/* Evidence unavailable/busy is never success and must not replay work. */}
 };
 observer.before=event=>observer({...event,phase:'before'});
 return observer;
}
