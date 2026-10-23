import fs from 'node:fs';
import {requirePrivateDirectory,requirePrivateFile,requirePrivatePaths,openPrivatePayloadFiles,createPrivatePayloadDirectories,ensurePrivateDirectory,openPrivateFile,writePrivateFile} from './private-storage.mjs';
import path from 'node:path';
import {
  createHash,createPublicKey,verify,randomBytes
} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const VERSION=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HEX=/^[a-f0-9]{64}$/;
const safeRel=name=>typeof name==='string' && name.length<240 &&
  !name.startsWith('/') && !name.startsWith('\\') &&
  name.split('/').every(p=>p&&p!=='.'&&p!=='..'&&p.indexOf('\\')<0&&p.indexOf(':')<0);
const hash=file=>{
  const h=createHash('sha256');
  h.update(fs.readFileSync(file));
  return h.digest('hex');
};
function assert(yes,reason){if(!yes)throw Error(reason)}
function existingInfo(file){try{return fs.lstatSync(file)}catch(error){if(error.code==='ENOENT')return null;throw error}}
function privateRoot(root,{create=false,bigint=false}={}) {
  assert(typeof root==='string'&&path.isAbsolute(root),'absolute_install_root_required');
  if(create)return ensurePrivateDirectory(root,{bigint});
  return requirePrivateDirectory(root);
}
function fileAtomic(dest,content){
  const temp=dest+'.new-'+randomBytes(8).toString('hex');
  try{requirePrivateFile(dest)}catch(error){if(error.code!=='ENOENT')throw error}
  writePrivateFile(temp,content);
  try{fs.renameSync(temp,dest)}
  catch(e){fs.rmSync(temp,{force:true});throw e}
}
// New files receive native private ownership before signed bytes are written.
// Copy through the exclusively created descriptor: COPYFILE_EXCL alone does
// not establish the current SID as Owner for an elevated Windows process.
function copyPrivate(source,destination,mode=0o600){
  const input=fs.openSync(source,'r');let output;
  try{
    output=openPrivateFile(destination,mode);
    const block=Buffer.allocUnsafe(1024*1024);
    let count;
    while((count=fs.readSync(input,block,0,block.length,null))>0){
      let written=0;
      while(written<count)written+=fs.writeSync(output,block,written,count-written);
    }
    fs.fsyncSync(output);
  }finally{fs.closeSync(input);if(output!==undefined)fs.closeSync(output)}
}
function privateSubdirectory(root,directory){
  const relative=path.relative(root,directory);
  assert(relative===''||!relative.startsWith('..'+path.sep)&&relative!=='..'&&!path.isAbsolute(relative),'invalid_private_release_directory');
  requirePrivateDirectory(root);
  let current=root;
  for(const part of relative.split(path.sep).filter(Boolean)){
    current=path.join(current,part);ensurePrivateDirectory(current);
  }
}
const list=(root)=>{
  const names=[];
  function walk(dir,rel=''){
    for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
      const r=rel?rel+'/'+entry.name:entry.name;
      if(entry.isSymbolicLink())throw Error('archive_symlink_forbidden');
      if(entry.isDirectory())walk(path.join(dir,entry.name),r);
      else if(entry.isFile()) names.push(r);
      else throw Error('nonregular_release_member');
    }
  }
  walk(root);
  return names.sort();
};
export function verifySignedRelease(sourceDir,publicKeyPem,{platform=process.platform,
  arch=process.arch}={}) {
  assert(typeof sourceDir==='string'&&path.isAbsolute(sourceDir),'absolute_bundle_dir_required');
  const packageStat=fs.lstatSync(sourceDir);
  assert(packageStat.isDirectory()&&!packageStat.isSymbolicLink(),
    'bundle_dir_not_regular');
  const mpath=path.join(sourceDir,'manifest.json');
  const sigpath=path.join(sourceDir,'manifest.sig');
  const manifestRaw=fs.readFileSync(mpath);
  const signatureRaw=fs.readFileSync(sigpath,'utf8').trim();
  assert(/^[A-Za-z0-9_-]{80,100}$/.test(signatureRaw),'invalid_manifest_signature');
  const publicKey=createPublicKey(publicKeyPem);
  assert(publicKey.asymmetricKeyType==='ed25519','invalid_release_signing_key');
  assert(verify(null,manifestRaw,publicKey,Buffer.from(signatureRaw,'base64url')),
    'release_signature_untrusted');
  const manifest=JSON.parse(manifestRaw.toString('utf8'));
  assert(manifest.schema===1 && VERSION.test(manifest.version??'') &&
    manifest.platform===platform && manifest.arch===arch &&
    Array.isArray(manifest.files) && manifest.files.length>0 &&
    manifest.files.length<=4096,'invalid_release_manifest');
  const files=new Set();
  for(const entry of manifest.files){
    assert(entry&&safeRel(entry.path)&&HEX.test(entry.sha256??'') &&
      Number.isSafeInteger(entry.size)&&entry.size>=0&&
      typeof entry.executable==='boolean','invalid_release_file_entry');
    assert(!files.has(entry.path),'duplicate_release_member');
    files.add(entry.path);
    const resolved=path.join(sourceDir,...entry.path.split('/'));
    const stat=fs.lstatSync(resolved);
    assert(stat.isFile()&&!stat.isSymbolicLink()&&stat.size===entry.size,
      'release_file_metadata_mismatch');
    assert(hash(resolved)===entry.sha256,'release_file_hash_mismatch');
  }
  const actual=list(sourceDir);
  const expected=[...files,'manifest.json','manifest.sig'].sort();
  assert(JSON.stringify(actual)===JSON.stringify(expected),
    'unexpected_release_members');
  return {version:manifest.version,platform,arch,manifest,sha256:sha256(manifestRaw)};
}
function sha256(data){return createHash('sha256').update(data).digest('hex')}
const sameIdentity=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
// This optimization copies only publisher-signed PUBLIC release payloads, never
// credentials. Authorization is local to this synchronous staging invocation.
// Fresh directories receive explicit private ownership; empty payload files
// receive native-ID-bound ownership/DACLs in batches. Every real DACL is still
// checked in bounded batches before any generation becomes visible.
function privateWindowsStage(temp,parents){
 const bindings=new Map();
 const inspect=(file,kind)=>{const info=fs.lstatSync(file,{bigint:true});assert(!info.isSymbolicLink()&&(kind==='directory'?info.isDirectory():info.isFile()),'stage_path_not_regular');return info;};
 const remember=(file,kind,expected)=>{assert(!bindings.has(file),'stage_path_already_bound');assert(expected&&sameIdentity(expected,inspect(file,kind)),'stage_path_identity_changed');bindings.set(file,{path:file,kind,info:expected});};
 const check=entry=>{assert(sameIdentity(entry.info,inspect(entry.path,entry.kind)),'stage_path_identity_changed');};
 for(const item of [...parents,temp])remember(item.path,'directory',item.info);
 const parentPaths=parents.map(x=>x.path);temp=temp.path;
 const checkAncestors=directory=>{
  for(const file of parentPaths)check(bindings.get(file));
  let current=directory;
  for(;;){const entry=bindings.get(current);assert(entry?.kind==='directory','stage_parent_not_owned');check(entry);if(current===temp)break;current=path.dirname(current);}
 };
 const prepareDirectories=payloads=>{
  const levels=new Map();
  for(const item of payloads){
   let folder=path.dirname(item.destination);
   const relative=path.relative(temp,folder);assert(relative===''||!relative.startsWith('..'+path.sep)&&relative!=='..'&&!path.isAbsolute(relative),'invalid_private_release_directory');
   while(folder!==temp){const depth=path.relative(temp,folder).split(path.sep).length;if(!levels.has(depth))levels.set(depth,new Set());levels.get(depth).add(folder);folder=path.dirname(folder);}
  }
  for(const depth of [...levels.keys()].sort((a,b)=>a-b)){
   const folders=[...levels.get(depth)].sort();
   for(let offset=0;offset<folders.length;offset+=32){
    const group=folders.slice(offset,offset+32);for(const folder of group)checkAncestors(path.dirname(folder));
    const created=createPrivatePayloadDirectories(group);
    for(const item of created){checkAncestors(path.dirname(item.path));remember(item.path,'directory',item.info);}
   }
  }
 };
 const copyBatch=payloads=>{
  for(const item of payloads)checkAncestors(path.dirname(item.destination));
  const outputs=openPrivatePayloadFiles(payloads.map(item=>({path:item.destination,mode:item.mode??0o600})));
  try{
   for(let index=0;index<outputs.length;index++){
    const output=outputs[index],item=payloads[index],destination=item.destination;
    const created=fs.fstatSync(output.fd,{bigint:true});remember(destination,'file',created);
    checkAncestors(path.dirname(destination));check(bindings.get(destination));
    const input=fs.openSync(item.source,'r');
    try{
     const block=Buffer.allocUnsafe(1024*1024);let count;
     while((count=fs.readSync(input,block,0,block.length,null))>0){let written=0;while(written<count){const n=fs.writeSync(output.fd,block,written,count-written);assert(n>0,'stage_write_failed');written+=n;}}
     fs.fsyncSync(output.fd);assert(sameIdentity(created,fs.fstatSync(output.fd,{bigint:true})),'stage_path_identity_changed');check(bindings.get(destination));checkAncestors(path.dirname(destination));
    }finally{fs.closeSync(input);}
   }
  }finally{for(const output of outputs)fs.closeSync(output.fd);}
 };
 const entries=()=>[...bindings.values()];
 const ownedTreeMatches=folder=>{
  for(const child of fs.readdirSync(folder,{withFileTypes:true})){
   const file=path.join(folder,child.name),entry=bindings.get(file);if(!entry)return false;check(entry);
   if(entry.kind==='directory'&&!ownedTreeMatches(file))return false;
  }return true;
 };
 return {prepareDirectories,copyBatch,canRemove(){
  try{
   for(const file of [...parentPaths,temp])check(bindings.get(file));
   return ownedTreeMatches(temp);
  }catch{return false;}
 },validate(){
  const all=entries();for(const entry of all)check(entry);assert(ownedTreeMatches(temp),'stage_unknown_member');
  for(let offset=0;offset<all.length;){
   // Windows environment payloads also have a character limit; keep both the
   // existing 32-path bound and the existing private-path JSON bound intact.
   let end=Math.min(offset+32,all.length),batch=all.slice(offset,end);
   while(JSON.stringify(batch.map(x=>x.path)).length>16384&&end>offset+1)batch=all.slice(offset,--end);
   for(const entry of batch)check(entry);
   requirePrivatePaths(batch.map(({path,kind})=>({path,kind})));
   for(const entry of batch)check(entry);offset=end;
  }
  for(const entry of all)check(entry);assert(ownedTreeMatches(temp),'stage_unknown_member');
 },checkBindings(){for(const entry of entries())check(entry);assert(ownedTreeMatches(temp),'stage_unknown_member');}};
}
export function stageSignedRelease({sourceDir,installRoot,publicKeyPem,
  platform=process.platform,arch=process.arch}) {
  const receipt=verifySignedRelease(sourceDir,publicKeyPem,{platform,arch});
  const rootInfo=privateRoot(installRoot,{create:true,bigint:process.platform==='win32'});
  // Stable launcher and its verification helper are supplied by the trusted
  // local Styx installer executable, NEVER accepted from unsigned bundle
  // contents. They are not an alternative unsigned update path.
  for(const filename of ['private-storage.mjs','installer.mjs','launch.mjs']) {
    const destShim=path.join(installRoot,filename);
    const existing=existingInfo(destShim);
    if(!existing){
      const sourceShim=fileURLToPath(new URL('./'+filename,import.meta.url));
      copyPrivate(sourceShim,destShim);
    } else {
      assert(existing.isFile()&&!existing.isSymbolicLink(),
        'invalid_installer_shim');
      requirePrivateFile(destShim);
    }
  }
  const releases=path.join(installRoot,'releases');
  const releasesInfo=ensurePrivateDirectory(releases,{bigint:process.platform==='win32'});
  const dest=path.join(releases,receipt.version);
  if(existingInfo(dest)){
    requirePrivateDirectory(dest);
    const existing=verifySignedRelease(dest,publicKeyPem,{platform,arch});
    assert(existing.sha256===receipt.sha256,'existing_release_conflict');
    return {status:'already_staged',version:receipt.version};
  }
  const temp=path.join(releases,'.stage-'+randomBytes(8).toString('hex'));
  const tempInfo=ensurePrivateDirectory(temp,{exclusive:true,bigint:process.platform==='win32'});
  let windowsStage;
  try{
    if(process.platform==='win32'){
      windowsStage=privateWindowsStage({path:temp,info:tempInfo},[{path:installRoot,info:rootInfo},{path:releases,info:releasesInfo}]);
      const payloads=[...receipt.manifest.files.map(entry=>({source:path.join(sourceDir,...entry.path.split('/')),destination:path.join(temp,...entry.path.split('/')),mode:entry.executable?0o700:0o600})),
        ...['manifest.json','manifest.sig'].map(name=>({source:path.join(sourceDir,name),destination:path.join(temp,name),mode:0o600}))];
      windowsStage.prepareDirectories(payloads);
      for(let offset=0;offset<payloads.length;offset+=32)windowsStage.copyBatch(payloads.slice(offset,offset+32));
      windowsStage.validate();
    }else{
      for(const entry of receipt.manifest.files){
        const from=path.join(sourceDir,...entry.path.split('/')),to=path.join(temp,...entry.path.split('/'));
        privateSubdirectory(temp,path.dirname(to));copyPrivate(from,to,entry.executable?0o700:0o600);
      }
      copyPrivate(path.join(sourceDir,'manifest.json'),path.join(temp,'manifest.json'));
      copyPrivate(path.join(sourceDir,'manifest.sig'),path.join(temp,'manifest.sig'));
    }
    verifySignedRelease(temp,publicKeyPem,{platform,arch});
    windowsStage?.checkBindings();
    fs.renameSync(temp,dest);
  }catch(e){
    // POSIX behavior is unchanged. On Windows an unknown/replaced child or
    // root never authorizes recursive deletion of a foreign tree.
    if(process.platform!=='win32'||windowsStage?.canRemove())fs.rmSync(temp,{recursive:true,force:true});
    throw e;
  }
  return {status:'staged',version:receipt.version};
}
function readPointer(installRoot) {
  const activeFile=path.join(installRoot,'active.json');
  if(!fs.existsSync(activeFile)){
    // A dangling link is an existing foreign destination, never a fresh pointer.
    try{fs.lstatSync(activeFile);throw Error('invalid_active_pointer')}catch(error){if(error.code!=='ENOENT')throw error}
    return null;
  }
  requirePrivateFile(activeFile);
  const data=JSON.parse(fs.readFileSync(activeFile,'utf8'));
  assert(data.schema===1&&VERSION.test(data.version??'')&&
    (data.previous===null||data.previous===undefined||
      VERSION.test(data.previous)),'invalid_active_pointer');
  return data;
}
// This locally run updater only refreshes the stable bootstrap shim from
// publisher-signed, already-staged payloads. Never copy a mutable Git
// workspace launcher directly into an active Host install.
export function refreshVerifiedBootstrap(installRoot,publicKeyPem,version,
  options={}) {
  privateRoot(installRoot);
  assert(VERSION.test(version??''),'invalid_bootstrap_version');
  const releaseRoot=path.join(installRoot,'releases',version);
  const verified=verifySignedRelease(releaseRoot,publicKeyPem,options);
  const signed=new Set(verified.manifest.files.map(e=>e.path));
  const runtime=verified.platform==='win32'?'bin/node.exe':'bin/node';
  const helper='host/private-storage.mjs';
  const installerSource=signed.has('host/installer.mjs')
    ?fs.readFileSync(path.join(releaseRoot,'host/installer.mjs'),'utf8'):'';
  assert(signed.has(helper)||!installerSource.includes('./private-storage.mjs'),
    'signed_bootstrap_payload_missing');
  const bootstrap=[...(signed.has(helper)?[helper]:[]),'host/installer.mjs','host/launch.mjs',
    ...(signed.has(runtime)?[runtime]:[])];
  assert(bootstrap.every(name=>signed.has(name)),'signed_bootstrap_payload_missing');
  if(verified.platform==='win32')assert(signed.has(runtime),'signed_windows_node_missing');
  // Preflight ALL destinations before writing any shim. Windows can lock the
  // running executable; runtime changes require a stopped-service/offline switch.
  if(verified.platform==='win32' && signed.has(runtime)){
    const dest=path.join(installRoot,'node.exe');
    const st=existingInfo(dest);
    if(st){
      assert(st.isFile()&&!st.isSymbolicLink(),'untrusted_bootstrap_destination');
      requirePrivateFile(dest);
      assert(hash(dest)===hash(path.join(releaseRoot,runtime)),
        'windows_node_runtime_requires_offline_switch');
    }
  }
  const staged=[];
  try {
    for(const name of bootstrap){
      const dest=path.join(installRoot,path.basename(name));
      const st=existingInfo(dest);
      if(st){
        assert(st.isFile()&&!st.isSymbolicLink(),
          'untrusted_bootstrap_destination');
        requirePrivateFile(dest);
      }
      if(name===runtime && verified.platform==='win32' && st)continue;
      const tmp=dest+'.signed-'+randomBytes(8).toString('hex');
      copyPrivate(path.join(releaseRoot,name),tmp,name===runtime?0o700:0o600);
      staged.push([tmp,dest]);
    }
    // Update verifier first: the older launch shim can safely import the
    // backward-compatible signed new installer even if interrupted here.
    for(const [src,dest] of staged) fs.renameSync(src,dest);
    return {status:'bootstrap_refreshed',version,
      verified_manifest_sha256:verified.sha256,
      shims:bootstrap.map(name=>path.basename(name))};
  }catch(e){
    for(const [src] of staged)fs.rmSync(src,{force:true});
    throw e;
  }
}

export function activeRelease(installRoot,publicKeyPem,{platform=process.platform,
  arch=process.arch}={}) {
  privateRoot(installRoot);
  const data=readPointer(installRoot);
  if(!data)return null;
  const verifyResult=verifySignedRelease(
    path.join(installRoot,'releases',data.version),publicKeyPem,{platform,arch});
  assert(verifyResult.sha256===data.manifest_sha256,'active_release_hash_changed');
  return {version:data.version,previous:data.previous??null,
    release_root:path.join(installRoot,'releases',data.version)};
}
export function activateRelease(installRoot,version,publicKeyPem,options={}) {
  privateRoot(installRoot);
  assert(VERSION.test(version??''),'invalid_version');
  const checked=verifySignedRelease(path.join(installRoot,'releases',version),
    publicKeyPem,options);
  const previous=activeRelease(installRoot,publicKeyPem,options);
  const pointer={schema:1,version,
    previous:previous?.version===version ? previous.previous??null:
      previous?.version??null,
    manifest_sha256:checked.sha256,activated_at:new Date().toISOString()};
  fileAtomic(path.join(installRoot,'active.json'),JSON.stringify(pointer,null,2)+'\n');
  return {status:'activated',version,previous:pointer.previous};
}
export function rollbackRelease(installRoot,publicKeyPem,options={}) {
  privateRoot(installRoot);
  // Recovery must work even when the currently active build was corrupted
  // after activation. Verify the PREVIOUS signed build before selecting it.
  const previous=readPointer(installRoot);
  assert(previous?.previous,'no_rollback_generation');
  const target=previous.previous;
  const checked=verifySignedRelease(path.join(installRoot,'releases',target),
    publicKeyPem,options);
  fileAtomic(path.join(installRoot,'active.json'),JSON.stringify({
    schema:1,version:target,previous:previous.version,
    manifest_sha256:checked.sha256,
    activated_at:new Date().toISOString(),rolled_back:true
  },null,2)+'\n');
  return {status:'rolled_back',version:target};
}
// Retain active and one previous signed generation, never delete unknown
// directories or symlinks. Preview mode is the default.
export function pruneVerifiedReleases(installRoot,publicKeyPem,{
  dryRun=true,platform=process.platform,arch=process.arch
}={}) {
  privateRoot(installRoot);
  const active=activeRelease(installRoot,publicKeyPem,{platform,arch});
  assert(active?.version,'no_active_release');
  const keep=new Set([active.version,active.previous].filter(Boolean));
  const folder=path.join(installRoot,'releases');
  const removals=[];
  for(const entry of fs.readdirSync(folder,{withFileTypes:true})) {
    const name=entry.name;
    assert(entry.isDirectory() && !entry.isSymbolicLink() && VERSION.test(name),
      'unexpected_release_dir');
    if(keep.has(name))continue;
    verifySignedRelease(path.join(folder,name),publicKeyPem,{platform,arch});
    removals.push(name);
  }
  if(!dryRun)for(const name of removals)
    fs.rmSync(path.join(folder,name),{recursive:true,force:false});
  return {status:dryRun?'dry_run':'pruned',
    keep:[...keep],removed:dryRun?[]:removals,
    planned:removals};
}
// Service managers need a stable runtime outside prunable release generations.
// When a release contains Node, accept only the verified stable copy or that
// exact signed generation. This validates selection; no files/services mutate.
export function verifiedServiceNode({installRoot,publicKeyPem,nodeBinary,
  platform=process.platform,arch=process.arch}={}) {
  const active=activeRelease(installRoot,publicKeyPem,{platform,arch});
  assert(active,'no_active_release');
  const checked=verifySignedRelease(active.release_root,publicKeyPem,{platform,arch});
  const name=platform==='win32'?'node.exe':'node';
  const entry=checked.manifest.files.find(e=>e.path==='bin/'+name);
  if(!entry){
    assert(platform!=='win32','signed_windows_node_missing');
    return nodeBinary??process.execPath;
  }
  assert(entry.executable,'signed_node_not_executable');
  const stable=path.join(installRoot,name);
  const generation=path.join(active.release_root,'bin',name);
  const selected=nodeBinary??stable;
  assert(selected===stable||selected===generation,'node_runtime_outside_signed_install');
  const st=fs.lstatSync(selected);
  assert(st.isFile()&&!st.isSymbolicLink()&&st.size===entry.size&&
    hash(selected)===entry.sha256,'service_node_hash_mismatch');
  return selected;
}
// This is a PLAN only; it never installs/enables OS startup services.
export function servicePlan({installRoot,configFile,nodeBinary,
  platform=process.platform,publicKeyFile}) {
  nodeBinary??=platform==='win32'?path.join(installRoot,'node.exe'):process.execPath;
  assert(path.isAbsolute(installRoot)&&path.isAbsolute(configFile) &&
    path.isAbsolute(nodeBinary)&&path.isAbsolute(publicKeyFile),
    'absolute_service_paths_required');
  const argv=[nodeBinary,path.join(installRoot,'launch.mjs'),
    installRoot,configFile,publicKeyFile];
  const serviceName='StyxPilot-Host';
  if(platform==='darwin') return {status:'NOT_INSTALLED',
    manager:'launchd-user',label:'app.styx.host',
    args:argv,runAtLoad:true,keepAlive:true};
  if(platform==='win32')return {status:'NOT_INSTALLED',
    manager:'windows-interactive-task',taskName:serviceName,
    logonType:'InteractiveToken',runLevel:'Limited',args:argv};
  if(platform==='linux')return {status:'NOT_INSTALLED',
    manager:'systemd-user',unitName:'styx-host.service',args:argv,
    restart:'on-failure'};
  throw Error('unsupported_platform');
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [action,installRoot,other,publicKeyFile]=process.argv.slice(2);
  try{
    if(!['stage','activate','rollback','active','refresh-bootstrap',
      'prune-preview','prune'].includes(action)||
      !installRoot||!publicKeyFile)throw Error('install_usage_invalid');
    const key=fs.readFileSync(path.resolve(publicKeyFile),'utf8');
    const result=action==='stage'
      ?stageSignedRelease({sourceDir:path.resolve(other),installRoot:path.resolve(installRoot),
        publicKeyPem:key})
      :action==='activate'
        ?activateRelease(path.resolve(installRoot),other,key)
        :action==='rollback'
          ?rollbackRelease(path.resolve(installRoot),key)
        :action==='refresh-bootstrap'
          ?refreshVerifiedBootstrap(path.resolve(installRoot),key,other)
        :action==='prune-preview'||action==='prune'
          ?pruneVerifiedReleases(path.resolve(installRoot),key,
              {dryRun:action==='prune-preview'})
          :activeRelease(path.resolve(installRoot),key);
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch(e){process.stderr.write('Styx installer: '+e.message+'\n');process.exitCode=2}
}
