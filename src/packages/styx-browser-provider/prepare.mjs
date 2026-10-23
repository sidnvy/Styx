// Host-local preparation of the pinned browser. Locks describe processes, not
// elapsed time: an interrupted spawn without enough evidence stays blocked.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash,randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile,openPrivateFile,writePrivateFile} from '../../host/private-storage.mjs';
import {BROWSER_CONTRACT} from './contract.mjs';
const require=createRequire(import.meta.url);
const posix=process.platform!=='win32';
const sameFile=(a,b)=>a.ino===b.ino&&a.dev===b.dev;
const validPid=value=>Number.isSafeInteger(value)&&value>0;
const hashFile=file=>{const digest=createHash('sha256'),fd=fs.openSync(file,'r'),buffer=Buffer.allocUnsafe(1024*1024);try{let n;while((n=fs.readSync(fd,buffer,0,buffer.length,null)))digest.update(buffer.subarray(0,n));return digest.digest('hex');}finally{fs.closeSync(fd);}};
const hostIdentity=()=>({name:os.hostname(),platform:process.platform,arch:process.arch,...(process.getuid?{uid:process.getuid()}:{})});
function rootRequired(profileRoot){if(typeof profileRoot!=='string'||!path.isAbsolute(profileRoot)||path.normalize(profileRoot)!==profileRoot)throw Error('private_browser_profile_root_required');}
function processState(pid,group=false){try{process.kill(group?-pid:pid,0);return 'present';}catch(error){return error.code==='ESRCH'?'absent':'unknown';}}
function checkBinding(file,identity){if(!sameFile(fs.lstatSync(file),identity))throw Error('browser_prepare_lock_changed');}
function writeJournal(fd,file,identity,record){const data=Buffer.from(JSON.stringify(record)+'\n');fs.writeSync(fd,data,0,data.length,0);fs.ftruncateSync(fd,data.length);fs.fsyncSync(fd);checkBinding(file,identity);}
function removeBoundFile(file,identity){checkBinding(file,identity);fs.unlinkSync(file);}

// Only these ordinary OS, proxy and CA settings reach the pinned Node CLI.
// In particular NODE_OPTIONS/NODE_PATH, loader variables, PWTEST_* and every
// user-supplied PLAYWRIGHT_* download/source override are deliberately absent.
export function browserPreparationEnvironment(cache,source=process.env){
  const allowed=new Set(['PATH','HOME','USER','LOGNAME','SHELL','TMPDIR','TMP','TEMP','LANG','LC_ALL','LC_CTYPE','TZ','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT','LOCALAPPDATA','APPDATA','PROGRAMDATA','PROGRAMFILES','PROGRAMFILES(X86)','SYSTEMDRIVE','USERPROFILE','HOMEDRIVE','HOMEPATH','USERNAME','USERDOMAIN','OS','PROCESSOR_ARCHITECTURE','NUMBER_OF_PROCESSORS','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','SSL_CERT_FILE','SSL_CERT_DIR','NODE_EXTRA_CA_CERTS']);
  return {...Object.fromEntries(Object.entries(source).filter(([key,value])=>allowed.has(key.toUpperCase())&&typeof value==='string')),PLAYWRIGHT_BROWSERS_PATH:cache};
}

function readJournal(file){
  requirePrivateFile(file);const fd=fs.openSync(file,'r');
  try{
    const identity=fs.fstatSync(fd);if(identity.size<1||identity.size>16384)throw Error('browser_prepare_recovery_unverified');
    const record=JSON.parse(fs.readFileSync(fd,'utf8'));checkBinding(file,identity);
    if(record.schema!==1||typeof record.transaction!=='string'||!/^[a-f0-9]{32}$/.test(record.transaction)||!validPid(record.owner?.pid)||JSON.stringify(record.host)!==JSON.stringify(hostIdentity())||!['owned','spawning','running','settled'].includes(record.phase))throw Error('browser_prepare_recovery_unverified');
    if(['owned','settled','spawning'].includes(record.phase)&&record.child!==null)throw Error('browser_prepare_recovery_unverified');
    if(record.phase==='running'&&(!validPid(record.child?.pid)||!['install','executable-path'].includes(record.child.command)||(posix&&record.child.processGroup!==record.child.pid)))throw Error('browser_prepare_recovery_unverified');
    return {record,identity};
  }catch(error){if(error.message==='browser_prepare_lock_changed')throw error;throw Error('browser_prepare_recovery_unverified');}
  finally{fs.closeSync(fd);}
}
// PID reuse is conservative: any process at the recorded PID blocks recovery.
function assertOwnerAbsent(record){const state=processState(record.owner.pid);if(state!=='absent')throw Error(state==='present'?'browser_prepare_owner_alive':'browser_prepare_recovery_unverified');}

// Explicit recovery never kills another process. The exclusive recovery claim
// prevents two recoverers from unlinking a newly acquired preparation lock.
// A crashed recovery claim, legacy empty lock, unrecorded spawn, foreign host,
// or Windows in-flight child needs external reconciliation; none is aged out.
export async function recoverManagedBrowserPreparation({profileRoot,authorize=false}={}){
  if(authorize!==true)throw Error('browser_prepare_authorization_required');rootRequired(profileRoot);
  const runtime=path.join(profileRoot,'runtime'),lock=path.join(runtime,'prepare.lock'),claim=path.join(runtime,'prepare.recovery.lock');
  if(fs.existsSync(claim))throw Error('browser_prepare_recovery_owned_or_interrupted');
  if(!fs.existsSync(lock))return {status:'not_locked'};
  requirePrivateDirectory(profileRoot);requirePrivateDirectory(runtime);
  let claimFd;
  try{claimFd=openPrivateFile(claim);}catch{throw Error('browser_prepare_recovery_owned_or_interrupted');}
  let claimIdentity;
  try{
    claimIdentity=fs.fstatSync(claimFd);
    writeJournal(claimFd,claim,claimIdentity,{schema:1,owner:{pid:process.pid},host:hostIdentity()});
    if(!fs.existsSync(lock))return {status:'not_locked'};
    const {record,identity}=readJournal(lock);assertOwnerAbsent(record);
    if(record.phase==='spawning')throw Error('browser_prepare_recovery_unverified_children');
    if(record.phase==='running'){
      if(!posix)throw Error('browser_prepare_recovery_unverified_children');
      const childState=processState(record.child.processGroup,true);
      if(childState!=='absent')throw Error(childState==='present'?'browser_prepare_child_alive':'browser_prepare_recovery_unverified_children');
    }
    assertOwnerAbsent(record);removeBoundFile(lock,identity);
    return {status:'recovered',transaction:record.transaction,phase:record.phase};
  }finally{try{if(claimIdentity)removeBoundFile(claim,claimIdentity);}finally{fs.closeSync(claimFd);}}
}

async function groupAbsent(pid){
  for(let attempt=0;attempt<40;attempt++){
    const state=processState(pid,true);if(state==='absent')return true;if(state==='unknown')return false;
    await new Promise(resolve=>setTimeout(resolve,50));
  }
  return false;
}
async function child(command,args,options,signal,transaction,kind){
  if(signal?.aborted)throw Error('browser_prepare_cancelled');
  try{transaction.mark('spawning',null);}catch(error){transaction.releasable=true;throw error;}
  let processChild;
  try{processChild=spawn(command,args,{...options,detached:posix,stdio:['ignore','pipe','pipe'],windowsHide:true});}
  catch{transaction.mark('settled',null);throw Error('browser_runtime_download_failed');}
  let output='',spawnError=false,timer;
  processChild.stdout.on('data',data=>{output=(output+data.toString()).slice(-8192);});processChild.stderr.resume();
  const completion=new Promise(resolve=>{processChild.once('error',()=>{spawnError=true;});processChild.once('close',code=>resolve(code));});
  const stop=signalName=>{try{if(posix&&validPid(processChild.pid))process.kill(-processChild.pid,signalName);else processChild.kill(signalName);}catch{ /* Exit evidence below decides whether the lock can be released. */ }};
  const abort=()=>{stop('SIGTERM');timer??=setTimeout(()=>stop('SIGKILL'),2000);timer.unref?.();};
  let journalError;
  try{if(validPid(processChild.pid))transaction.mark('running',{pid:processChild.pid,processGroup:posix?processChild.pid:null,command:kind});}
  catch(error){journalError=error;abort();}
  signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  let code;
  try{code=await completion;}finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  // POSIX descendants inherit the new group, so an exited CLI alone is not
  // enough. Windows failures retain the running journal: no job/tree proof.
  const quiescent=!validPid(processChild.pid)||(posix?await groupAbsent(processChild.pid):code===0);
  if(quiescent){transaction.releasable=true;transaction.mark('settled',null);}
  if(journalError)throw journalError;
  if(signal?.aborted)throw Error('browser_prepare_cancelled');
  if(!quiescent)throw Error('browser_prepare_child_exit_unverified');
  if(code!==0||spawnError)throw Error('browser_runtime_download_failed');
  return output;
}

export function readManagedBrowser(profileRoot){
  const runtime=path.join(profileRoot,'runtime'),receipt=path.join(runtime,'receipt.json');
  if(!fs.existsSync(receipt)){
    if(fs.existsSync(path.join(runtime,'prepare.recovery.lock')))return {status:'preparation_blocked',reason:'browser_prepare_recovery_owned_or_interrupted'};
    const lock=path.join(runtime,'prepare.lock');if(!fs.existsSync(lock))return {status:'not_prepared'};
    try{
      const {record}=readJournal(lock),ownerState=processState(record.owner.pid);
      const childState=record.phase==='running'?(posix?processState(record.child.processGroup,true):'unknown'):undefined;
      const reason=ownerState==='present'?'browser_prepare_owner_alive':ownerState==='unknown'?'browser_prepare_recovery_unverified':record.phase==='spawning'||childState==='unknown'?'browser_prepare_recovery_unverified_children':childState==='present'?'browser_prepare_child_alive':'browser_prepare_owned_or_interrupted';
      return {status:'preparation_blocked',reason,phase:record.phase,ownerState,...(childState?{childState}:{})};
    }catch{return {status:'preparation_blocked',reason:'browser_prepare_recovery_unverified'};}
  }
  const cache=path.join(runtime,'browsers');
  for(const dir of [profileRoot,runtime,cache])requirePrivateDirectory(dir);
  requirePrivateFile(receipt);const record=JSON.parse(fs.readFileSync(receipt,'utf8'));
  if(record.schema!==1||record.playwright!==BROWSER_CONTRACT.playwright||record.platform!==process.platform||record.arch!==process.arch||typeof record.executablePath!=='string'||!record.executablePath.startsWith(cache+path.sep)||!fs.statSync(record.executablePath).isFile()||!fs.realpathSync(record.executablePath).startsWith(fs.realpathSync(cache)+path.sep)||hashFile(record.executablePath)!==record.sha256)throw Error('browser_runtime_binding_changed');
  return {status:'prepared',executablePath:record.executablePath,playwright:record.playwright,sha256:record.sha256};
}
export async function prepareManagedBrowser({profileRoot,authorize=false,signal,recover=false}={}){
  if(authorize!==true)throw Error('browser_prepare_authorization_required');rootRequired(profileRoot);
  if(typeof recover!=='boolean')throw Error('invalid_browser_prepare_recovery');
  if(signal?.aborted)throw Error('browser_prepare_cancelled');
  ensurePrivateDirectory(profileRoot);
  if(fs.existsSync(path.join(profileRoot,'runtime','prepare.recovery.lock')))throw Error('browser_prepare_recovery_owned_or_interrupted');
  const existing=readManagedBrowser(profileRoot);if(existing.status==='prepared')return existing;
  const runtime=path.join(profileRoot,'runtime'),cache=path.join(runtime,'browsers');ensurePrivateDirectory(runtime);ensurePrivateDirectory(cache);
  const lock=path.join(runtime,'prepare.lock'),claim=path.join(runtime,'prepare.recovery.lock');let fd;
  if(fs.existsSync(claim))throw Error('browser_prepare_recovery_owned_or_interrupted');
  try{fd=openPrivateFile(lock);}catch{
    if(!recover)throw Error('browser_prepare_owned_or_interrupted');
    await recoverManagedBrowserPreparation({profileRoot,authorize:true});
    try{fd=openPrivateFile(lock);}catch{throw Error('browser_prepare_owned_or_interrupted');}
  }
  let identity,transaction;
  try{
    identity=fs.fstatSync(fd);
    const record={schema:1,transaction:randomBytes(16).toString('hex'),playwright:BROWSER_CONTRACT.playwright,host:hostIdentity(),owner:{pid:process.pid},phase:'owned',child:null};
    transaction={releasable:true,mark(phase,child){this.releasable=['owned','settled'].includes(phase);Object.assign(record,{phase,child});writeJournal(fd,lock,identity,record);}};
    transaction.mark('owned',null);
    if(fs.existsSync(claim))throw Error('browser_prepare_recovery_owned_or_interrupted');
    const packageFile=require.resolve('playwright/package.json'),packageRoot=path.dirname(packageFile),pkg=JSON.parse(fs.readFileSync(packageFile,'utf8'));
    if(pkg.version!==BROWSER_CONTRACT.playwright)throw Error('browser_runtime_version_mismatch');
    const env=browserPreparationEnvironment(cache);
    await child(process.execPath,[path.join(packageRoot,'cli.js'),'install','--no-shell','chromium'],{cwd:runtime,env},signal,transaction,'install');
    const script="const {chromium}=require('playwright');process.stdout.write(chromium.executablePath());";
    const executablePath=(await child(process.execPath,['-e',script],{cwd:path.dirname(fileURLToPath(import.meta.url)),env},signal,transaction,'executable-path')).trim();
    if(!executablePath.startsWith(cache+path.sep)||!fs.statSync(executablePath).isFile()||!fs.realpathSync(executablePath).startsWith(fs.realpathSync(cache)+path.sep))throw Error('managed_browser_executable_missing');
    const receipt={schema:1,playwright:BROWSER_CONTRACT.playwright,platform:process.platform,arch:process.arch,executablePath,sha256:hashFile(executablePath)};
    writePrivateFile(path.join(runtime,'receipt.json'),JSON.stringify(receipt,null,2)+'\n');return {status:'prepared',...receipt};
  }finally{try{if(identity&&transaction?.releasable)removeBoundFile(lock,identity);}finally{fs.closeSync(fd);}}
}
