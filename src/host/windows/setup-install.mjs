// Per-user side-by-side installation. Device state is owned by Core, outside this tree.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash,randomUUID} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
const kind='styx-windows-user-install',receiptName='installation.json';
const assert=(ok,message)=>{if(!ok)throw Error(message);};
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function regular(file,directory=false){const st=fs.lstatSync(file);assert(!st.isSymbolicLink()&&(directory?st.isDirectory():st.isFile()),'redirected_install_path');const a=fs.realpathSync(file),b=path.resolve(file);assert(process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b,'redirected_install_path');}
function inside(home,target){const r=path.relative(home,target);return !!r&&r!=='..'&&!r.startsWith('..'+path.sep)&&!path.isAbsolute(r);}
function targetRoot(root){assert(typeof root==='string'&&path.isAbsolute(root)&&path.normalize(root)===root&&inside(path.resolve(process.env.USERPROFILE??os.homedir()),root),'current_user_install_root_required');regular(path.dirname(root),true);}
function read(root){regular(root,true);regular(path.join(root,receiptName));const value=JSON.parse(fs.readFileSync(path.join(root,receiptName),'utf8'));assert(value.schema===1&&value.kind===kind&&value.root===root&&/^[a-f0-9]{64}$/.test(value.launcherSha256)&&Array.isArray(value.releases),'owned_installation_required');regular(path.join(root,'Styx.exe'));assert(hash(path.join(root,'Styx.exe'))===value.launcherSha256,'installed_launcher_changed');for(const release of value.releases)assert(/^[a-f0-9-]{36}$/.test(release.id)&&/^[a-f0-9]{64}$/.test(release.packageSha256),'invalid_installation_release');assert(value.releases.some(r=>r.id===value.current)&&(!value.previous||value.releases.some(r=>r.id===value.previous)),'invalid_installation_pointer');return value;}
function write(root,value){const file=path.join(root,receiptName),temp=path.join(root,'.installation-'+randomUUID()+'.tmp');fs.writeFileSync(temp,JSON.stringify(value,null,2)+'\n',{flag:'wx',mode:0o600});try{fs.renameSync(temp,file);}finally{if(fs.existsSync(temp))fs.unlinkSync(temp);}}
function acquireLock(root){
 const lock=path.join(root,'.setup.lock'),temp=path.join(root,'.setup-lock-'+randomUUID()+'.tmp');
 fs.writeFileSync(temp,JSON.stringify({schema:1,pid:process.pid,createdAt:new Date().toISOString()})+'\n',{flag:'wx',mode:0o600});
 try{fs.linkSync(temp,lock);return ()=>{regular(lock);assert(hash(lock)===hash(temp),'setup_lock_changed');fs.unlinkSync(lock);fs.unlinkSync(temp);};}
 catch(error){fs.unlinkSync(temp);if(error.code==='EEXIST')throw Error('another_setup_or_interrupted_setup');throw error;}
}
async function api(source){return import(pathToFileURL(path.join(source,'install-windows-preview.mjs')));}
async function verifyRelease(root,receipt,id,verifyPackage){const release=receipt.releases.find(r=>r.id===id);assert(release,'unknown_installation_release');const folder=path.join(root,'releases',id);regular(path.join(root,'releases'),true);regular(folder,true);assert(hash(path.join(folder,'windows-package.json'))===release.packageSha256,'installed_release_changed');await verifyPackage(folder,{installed:true});return folder;}
export async function installManaged(source,root,launcher,{onProgress}={}){
 targetRoot(root);regular(launcher);const {verifyPackage,installPreview}=await api(source);const manifest=await verifyPackage(source,{onProgress});assert(manifest.compiled===true,'native_compile_required_before_install');let launcherSha256=hash(launcher),previous;
 if(!fs.existsSync(root)){const initial=path.join(path.dirname(root),'.styx-initializing-'+randomUUID());fs.mkdirSync(initial,{mode:0o700});try{fs.mkdirSync(path.join(initial,'releases'),{mode:0o700});fs.copyFileSync(launcher,path.join(initial,'Styx.exe'),fs.constants.COPYFILE_EXCL);fs.writeFileSync(path.join(initial,'.setup-owner.json'),JSON.stringify({schema:1,kind,root,launcherSha256})+'\n',{flag:'wx',mode:0o600});fs.renameSync(initial,root);}finally{if(fs.existsSync(initial))fs.rmSync(initial,{recursive:true});}}
 regular(root,true);const ownerFile=path.join(root,'.setup-owner.json');regular(ownerFile);regular(path.join(root,'Styx.exe'));const owner=JSON.parse(fs.readFileSync(ownerFile,'utf8'));assert(owner.schema===1&&owner.kind===kind&&owner.root===root&&hash(path.join(root,'Styx.exe'))===owner.launcherSha256,'owned_installation_required');
 const releaseLock=acquireLock(root);
 try{
  if(fs.existsSync(path.join(root,receiptName))){previous=read(root);await verifyRelease(root,previous,previous.current,verifyPackage);}
  // Launcher protocol v1 is stable: retain the already-owned executable across compiler rebuilds.
  launcherSha256=owner.launcherSha256;regular(path.join(root,'releases'),true);
  const id=randomUUID(),folder=path.join(root,'releases',id);await installPreview(source,folder);const packageSha256=hash(path.join(folder,'windows-package.json'));
  const value={schema:1,kind,root,launcherSha256,current:id,previous:previous?.current??null,releases:[...(previous?.releases??[]),{id,packageSha256,installedAt:new Date().toISOString()}]};
  write(root,value);return {status:previous?'updated':'installed',root,current:id,previous:value.previous,statePreserved:true,restartRequired:!!previous};
 }finally{releaseLock();}
}
export async function rollbackManaged(source,root){targetRoot(root);regular(root,true);const releaseLock=acquireLock(root);
 try{const {verifyPackage}=await api(source),before=read(root);assert(before.previous,'previous_release_unavailable');await verifyRelease(root,before,before.previous,verifyPackage);const current=before.previous;write(root,{...before,current,previous:before.current});return {status:'rolled_back',root,current,previous:before.current,statePreserved:true,restartRequired:true};}finally{releaseLock();}}
export function managedStatus(root){targetRoot(root);if(!fs.existsSync(root))return {status:'not_installed',root};const value=read(root);return {status:'installed',root,current:value.current,previous:value.previous,rollbackAvailable:!!value.previous,statePreserved:true};}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const args=process.argv.slice(2),[operation,root,launcher]=args,source=fileURLToPath(new URL('../../../',import.meta.url));let result;
 if(operation==='install'&&root&&launcher&&args.length===3)result=await installManaged(source,root,launcher,{onProgress:progress=>console.log(JSON.stringify(progress))});
 else if(operation==='rollback'&&root&&args.length===2)result=await rollbackManaged(source,root);
 else if(operation==='status'&&root&&args.length===2)result=managedStatus(root);
 else throw Error('invalid_setup_arguments');console.log(JSON.stringify(result));
 }catch(error){console.error(JSON.stringify({status:'FAIL',reason:/^[a-z_]+$/.test(error.message??'')?error.message:'setup_operation_failed'}));process.exitCode=2;}
}
