// Windows App identity/staging adapter for the shared Core maintenance ticket.
// A current native parent and package consistency bind execution provenance;
// only the existing Host publisher authorizes the candidate payload itself.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {readHostPayloadMigration} from '../../onboarding/host-payload-migration.mjs';
import {observeWindowsNativeAppAuthority} from './native-app-authority.mjs';
import {requirePrivateFile,requirePrivatePaths} from '../private-storage.mjs';
const ROOT=fileURLToPath(new URL('../../../',import.meta.url));
const sha=b=>createHash('sha256').update(b).digest('hex'),hash=f=>sha(fs.readFileSync(f));
const assert=(v,m)=>{if(!v)throw Error(m)},digest=v=>/^[a-f0-9]{64}$/.test(v??''),id=v=>/^[a-f0-9]{32}$/.test(v??'');
const relative=s=>typeof s==='string'&&!path.posix.isAbsolute(s)&&!s.includes('\\')&&!s.includes(':')&&s.split('/').every(v=>v&&v!=='.'&&v!=='..');
function regular(file,directory=false){const s=fs.lstatSync(file);assert(!s.isSymbolicLink()&&(directory?s.isDirectory():s.isFile())&&fs.realpathSync(file).toLowerCase()===path.resolve(file).toLowerCase(),'handoff_windows_path_redirected');return s}
export function resolveWindowsHostPayloadHandoffApp({stateDir,config}={}, {resourceRoot=ROOT,platform=process.platform,observeApp=observeWindowsNativeAppAuthority}={}){
 assert(platform==='win32','handoff_windows_required');assert(path.isAbsolute(stateDir)&&config?.host,'handoff_windows_deployment_required');regular(resourceRoot,true);
 const manifestFile=path.join(resourceRoot,'windows-package.json'),runtimeFile=path.join(resourceRoot,'windows-runtime.json');regular(manifestFile);regular(runtimeFile);
 const manifest=JSON.parse(fs.readFileSync(manifestFile)),runtime=JSON.parse(fs.readFileSync(runtimeFile));
 assert(manifest.schema===1&&manifest.compiled===true&&Array.isArray(manifest.files)&&manifest.files.length>0&&manifest.files.length<=12000,'handoff_windows_package_invalid');
 const authority=observeApp(resourceRoot,runtime);assert(authority.source==='current_windows_native_app','handoff_windows_native_app_required');
 const names=new Set(),files=[];
 for(const member of manifest.files){assert(relative(member.path)&&digest(member.sha256)&&!names.has(member.path),'handoff_windows_package_invalid');names.add(member.path);const source=path.join(resourceRoot,...member.path.split('/'));regular(source);assert(hash(source)===member.sha256,'handoff_windows_package_changed');
  if(member.path.startsWith('vnext/')||['runtime/node.exe','StyxUpdater.exe','StyxPreview.exe','StyxPrivateStorage.exe'].includes(member.path))files.push({source,relative:member.path==='runtime/node.exe'?'node.exe':member.path,executable:member.path.endsWith('.exe')});
 }
 for(const name of ['windows-runtime.json','runtime/node.exe','StyxUpdater.exe','StyxPreview.exe','vnext/onboarding/cli.mjs','vnext/onboarding/host-payload-handoff.mjs'])assert(names.has(name),'handoff_windows_package_incomplete');
 assert(runtime.hostUpdater?.path==='StyxUpdater.exe'&&digest(runtime.hostUpdater.sha256)&&hash(path.join(resourceRoot,'StyxUpdater.exe'))===runtime.hostUpdater.sha256,'handoff_windows_updater_unverified');
 assert(runtime.artifacts?.bundle==='host-bundle'&&runtime.artifacts.publisherKeyFile==='publisher.pem'&&digest(runtime.artifacts.publisherSha256),'handoff_windows_candidate_invalid');
 const appPath=path.join(resourceRoot,'StyxPreview.exe');
 return {appPath,bundle:path.join(resourceRoot,'host-bundle'),identity:{source:'current_windows_native_app',nativeAppPid:authority.nativeAppPid,nativeAppGeneration:authority.nativeAppGeneration,packageSha256:hash(manifestFile),appSha256:hash(appPath),nodeSha256:hash(path.join(resourceRoot,'runtime/node.exe')),updaterSha256:runtime.hostUpdater.sha256},files:files.sort((a,b)=>a.relative.localeCompare(b.relative))};
}
export async function launchWindowsHostPayloadHandoff({stateDir,ticketId,mode='apply'}={}, {platform=process.platform,spawnProcess=spawn,pid=process.pid}={}){
 assert(platform==='win32'&&path.isAbsolute(stateDir)&&id(ticketId)&&['apply','rollback'].includes(mode),'handoff_windows_launch_invalid');
 const file=path.join(stateDir,'host-payload-handoff.json');requirePrivateFile(file);const ticket=JSON.parse(fs.readFileSync(file));
 assert(ticket.schema===1&&ticket.kind==='host-payload-handoff-v1'&&ticket.stateDir===stateDir&&ticket.ticketId===ticketId&&digest(ticket.runtimeManifestSha256),'handoff_windows_ticket_changed');
 if(mode==='apply')assert(ticket.ownerPid===pid&&ticket.status==='awaiting_exit'&&ticket.expiresAt>Date.now(),'handoff_windows_ticket_changed');
 else{const upgrade=readHostPayloadMigration({stateDir});assert(upgrade.handoffTicketId===ticketId&&upgrade.status!=='rolled_back'&&id(upgrade.transactionId),'handoff_windows_rollback_unbound');const current=resolveWindowsHostPayloadHandoffApp({stateDir,config:JSON.parse(fs.readFileSync(path.join(stateDir,'deployment.json')))});assert(current.appPath===ticket.appPath,'handoff_windows_app_changed');}
 const dir=path.join(path.dirname(stateDir),'host-payload-updaters',sha(stateDir).slice(0,16),ticketId),manifestFile=path.join(dir,'runtime-manifest.json');requirePrivateFile(manifestFile);assert(hash(manifestFile)===ticket.runtimeManifestSha256,'handoff_windows_runtime_changed');
 const files=JSON.parse(fs.readFileSync(manifestFile));assert(Array.isArray(files)&&files.length>0&&files.length<=12000,'handoff_windows_runtime_changed');
 for(let offset=0;offset<files.length;offset+=32){const block=files.slice(offset,offset+32);for(const item of block)assert(relative(item.relative)&&digest(item.sha256),'handoff_windows_runtime_changed');requirePrivatePaths(block.map(item=>({path:path.join(dir,...item.relative.split('/')),kind:'file'})));for(const item of block)assert(hash(path.join(dir,...item.relative.split('/')))===item.sha256,'handoff_windows_runtime_changed')}
 assert(files.some(f=>f.relative==='StyxUpdater.exe')&&files.some(f=>f.relative==='node.exe'),'handoff_windows_runtime_changed');
 if(mode==='rollback')assert(hash(ticket.appPath)===hash(path.join(dir,'StyxPreview.exe')),'handoff_windows_app_changed');
 const inputFile=path.join(dir,'input.json');requirePrivateFile(inputFile);const input=JSON.parse(fs.readFileSync(inputFile));assert(input.stateDir===stateDir&&input.ticketId===ticketId,'handoff_windows_input_changed');
 const env={...process.env};delete env.NODE_OPTIONS;delete env.NODE_PATH;delete env.STYX_NATIVE_RESOURCES;delete env.STYX_NATIVE_STATE;
 const child=spawnProcess(path.join(dir,'StyxUpdater.exe'),mode==='rollback'?['--rollback',String(pid)]:[],{cwd:dir,env,detached:true,stdio:'ignore',windowsHide:false});await new Promise((resolve,reject)=>{child.once('error',reject);child.once('spawn',resolve)});child.unref();return {status:'launched',ticketId};
}
