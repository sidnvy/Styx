// Local staged-release activation only. Never starts/restarts services, runs
// shell commands, refreshes bootstrap, retries probes or steals stale locks.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {activeRelease,activateRelease,verifySignedRelease} from './installer.mjs';

const assert=(ok,reason)=>{if(!ok)throw Error(reason)};
const digest=b=>createHash('sha256').update(b).digest('hex');
function snapshot(file){
  try{
    const st=fs.lstatSync(file);
    assert(st.isFile()&&!st.isSymbolicLink(),'update_pointer_not_regular');
    return fs.readFileSync(file);
  }catch(e){if(e.code==='ENOENT')return null;throw e}
}
const same=(a,b)=>a===null?b===null:b!==null&&a.equals(b);
function bootstrapCompatible(installRoot,checked){
  const runtime=checked.platform==='win32'?'node.exe':'node';
  const required=['host/installer.mjs','host/launch.mjs'];
  const bundled=checked.manifest.files.find(e=>e.path==='bin/'+runtime);
  if(checked.platform==='win32')assert(bundled,'signed_windows_node_missing');
  if(bundled)required.push('bin/'+runtime);
  for(const name of required){
    const signed=checked.manifest.files.find(e=>e.path===name);
    assert(signed,'signed_bootstrap_payload_missing');
    const dest=path.join(installRoot,path.basename(name));
    const st=fs.lstatSync(dest);
    assert(st.isFile()&&!st.isSymbolicLink()&&st.size===signed.size&&
      digest(fs.readFileSync(dest))===signed.sha256,
      name==='bin/'+runtime?'runtime_requires_offline_switch':'bootstrap_requires_offline_switch');
  }
}

// The callback is executable local operator code, never a model-authored shell
// string or remote configuration. It must honor AbortSignal and return true
// only for an observed healthy candidate. Callback errors/output are not logged.
export async function activateHealthyRelease({installRoot,version,publicKeyPem,
  checkHealth,timeoutMs=10000,platform=process.platform,arch=process.arch}={}){
  assert(typeof checkHealth==='function','trusted_health_callback_required');
  assert(Number.isInteger(timeoutMs)&&timeoutMs>=1&&timeoutMs<=60000,'invalid_health_timeout');
  assert(typeof installRoot==='string'&&path.isAbsolute(installRoot),'absolute_install_root_required');
  assert(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(version??''),'invalid_version');
  const rootStat=fs.lstatSync(installRoot);
  assert(rootStat.isDirectory()&&!rootStat.isSymbolicLink()&&
    (process.platform==='win32'||(rootStat.uid===process.getuid()&&!(rootStat.mode&0o077))),
    'private_install_root_required');
  const options={platform,arch};
  const releaseRoot=path.join(installRoot,'releases',version);
  // Invalid publishers cannot cause a health callback or acquire a local lock.
  let checked=verifySignedRelease(releaseRoot,publicKeyPem,options);
  const lock=path.join(installRoot,'.health-update-lock');
  try{fs.mkdirSync(lock,{mode:0o700})}
  catch(e){if(e.code==='EEXIST')throw Error('health_update_in_progress');throw e}
  const owner=randomBytes(16).toString('hex');
  let timer,keepLock=false,ownerWritten=false;
  const controller=new AbortController();
  try{
    fs.writeFileSync(path.join(lock,'owner'),owner,{flag:'wx',mode:0o600});
    ownerWritten=true;
    const pointer=path.join(installRoot,'active.json');
    const before=snapshot(pointer);
    const previous=activeRelease(installRoot,publicKeyPem,options);
    bootstrapCompatible(installRoot,checked);
    if(previous)bootstrapCompatible(installRoot,
      verifySignedRelease(previous.release_root,publicKeyPem,options));
    const context=Object.freeze({version,releaseRoot,manifestSha256:checked.sha256,
      previousVersion:previous?.version??null,signal:controller.signal});
    const started=performance.now();
    const probe=Promise.resolve().then(()=>checkHealth(context)).then(
      ok=>ok===true?'healthy':'probe_rejected',()=> 'probe_failed');
    const timeout=new Promise(resolve=>{timer=setTimeout(()=>{
      controller.abort();resolve('probe_timeout');
    },timeoutMs)});
    let result=await Promise.race([probe,timeout]);
    if(performance.now()-started>=timeoutMs)result='probe_timeout';
    keepLock=result==='probe_timeout';
    clearTimeout(timer);
    // Never overwrite a pointer changed by another actor, even after failure.
    assert(same(before,snapshot(pointer)),'active_pointer_changed_during_health');
    if(result!=='healthy')return {status:'retained',version:previous?.version??null,
      candidate:version,reason:result,lock_retained:keepLock};
    checked=verifySignedRelease(releaseRoot,publicKeyPem,options);
    assert(checked.sha256===context.manifestSha256,'candidate_changed_during_health');
    bootstrapCompatible(installRoot,checked);
    if(previous)bootstrapCompatible(installRoot,
      verifySignedRelease(previous.release_root,publicKeyPem,options));
    // No await between final compare and the existing atomic pointer writer.
    assert(same(before,snapshot(pointer)),'active_pointer_changed_during_health');
    const receipt=activateRelease(installRoot,version,publicKeyPem,options);
    return {...receipt,health:'PASS',candidate_manifest_sha256:checked.sha256};
  }finally{
    clearTimeout(timer);
    controller.abort();
    // No automatic stale-lock recovery after process death. A trusted local
    // operator must inspect uncertain probe outcomes before releasing that lock.
    if(!ownerWritten){fs.rmdirSync(lock)}
    else if(!keepLock&&fs.readFileSync(path.join(lock,'owner'),'utf8')===owner){
      fs.unlinkSync(path.join(lock,'owner'));fs.rmdirSync(lock);
    }
  }
}
