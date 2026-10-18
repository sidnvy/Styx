import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {ensurePrivateDirectory} from '../private-storage.mjs';
import {stageSignedRelease,activateRelease,activeRelease} from '../installer.mjs';
import {updateServiceRelease,recoverServiceUpdate,inspectServiceUpdate} from '../service-update.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-update-transaction-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const installRoot=path.join(root,'installed');ensurePrivateDirectory(installRoot);
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const publicKeyPem=publicKey.export({type:'spki',format:'pem'});
  const runtime=process.platform==='win32'?'node.exe':'node';
  function make(version){
    const source=path.join(root,version);fs.mkdirSync(path.join(source,'host'),{recursive:true});
    fs.mkdirSync(path.join(source,'bin'));
    const files=['host/private-storage.mjs','host/installer.mjs','host/launch.mjs','bin/'+runtime].map(name=>{
      const bytes=Buffer.from('// signed '+version+' '+name+'\n');fs.writeFileSync(path.join(source,name),bytes);
      return {path:name,size:bytes.length,sha256:sha(bytes),executable:name.startsWith('bin/')};
    });
    const raw=JSON.stringify({schema:1,version,platform:process.platform,arch:process.arch,files});
    fs.writeFileSync(path.join(source,'manifest.json'),raw);
    fs.writeFileSync(path.join(source,'manifest.sig'),sign(null,Buffer.from(raw),privateKey).toString('base64url'));
    stageSignedRelease({sourceDir:source,installRoot,publicKeyPem});
    return source;
  }
  make('old');make('candidate');make('other');
  // Trusted test setup installs initial signed stable bytes, never executes them.
  for(const name of ['private-storage.mjs','installer.mjs','launch.mjs'])
    fs.copyFileSync(path.join(installRoot,'releases','old','host',name),path.join(installRoot,name));
  fs.copyFileSync(path.join(installRoot,'releases','old','bin',runtime),path.join(installRoot,runtime));
  for(const name of ['private-storage.mjs','installer.mjs','launch.mjs',runtime])
    fs.chmodSync(path.join(installRoot,name),0o600);
  activateRelease(installRoot,'old',publicKeyPem);
  const pointer=path.join(installRoot,'active.json'),before=fs.readFileSync(pointer,'utf8');
  return {root,installRoot,publicKeyPem,pointer,before,runtime,
    args:{installRoot,publicKeyPem,version:'candidate'}};
}
function callbacks(events,{health=true}={}){return {
  stopService:async ctx=>{assert.equal(ctx.restartInhibitionRequired,true);events.push('stop:'+ctx.version);return true},
  startService:async ctx=>{events.push('start:'+ctx.version);return true},
  checkHealth:async ctx=>{events.push('health:'+ctx.version);return ctx.version==='candidate'?health:true}
};}

test('offline transaction switches signed bootstrap/runtime and checks service after switch',async t=>{
  const f=fixture(t),events=[];
  const result=await updateServiceRelease({...f.args,...callbacks(events)});
  assert.equal(result.status,'activated');
  assert.deepEqual(events,['stop:old','start:candidate','health:candidate']);
  assert.equal(activeRelease(f.installRoot,f.publicKeyPem).version,'candidate');
  assert.equal(fs.readFileSync(path.join(f.installRoot,f.runtime),'utf8'),'// signed candidate bin/'+f.runtime+'\n');
  assert.equal(inspectServiceUpdate({...f.args,transactionId:result.transactionId}).phase,'activated');
  assert.equal(fs.existsSync(path.join(f.installRoot,'.health-update-lock')),false);
});
test('known failed post-switch health restores exact prior pointer and signed stable bytes then checks old service',async t=>{
  const f=fixture(t),events=[];
  const result=await updateServiceRelease({...f.args,...callbacks(events,{health:false})});
  assert.equal(result.status,'rolled_back');
  assert.deepEqual(events,['stop:old','start:candidate','health:candidate',
    'stop:candidate','start:old','health:old']);
  assert.equal(fs.readFileSync(f.pointer,'utf8'),f.before);
  assert.equal(fs.readFileSync(path.join(f.installRoot,f.runtime),'utf8'),'// signed old bin/'+f.runtime+'\n');
});
test('uncertain start retains durable phase and lock; explicit recovery observes stopped and never replays start',async t=>{
  const f=fixture(t),events=[];let finish;
  const result=await updateServiceRelease({...f.args,...callbacks(events),timeoutMs:10,
    startService:ctx=>{events.push('start:'+ctx.version);return new Promise(resolve=>{finish=resolve})}});
  assert.equal(result.status,'needs_recovery');assert.equal(result.reason,'callback_timeout');
  assert.equal(result.phase,'start_intent');
  await assert.rejects(updateServiceRelease({...f.args,...callbacks([]),version:'other'}),/health_update_in_progress/);
  await assert.rejects(recoverServiceUpdate({...f.args,transactionId:'0'.repeat(32),confirmStopped:async()=>true}),/ENOENT|ownership/);
  const refused=await recoverServiceUpdate({...f.args,transactionId:result.transactionId,confirmStopped:async()=>false});
  assert.equal(refused.status,'needs_recovery');
  const recovered=await recoverServiceUpdate({...f.args,transactionId:result.transactionId,confirmStopped:async()=>true});
  assert.equal(recovered.status,'recovered_stopped');assert.equal(fs.readFileSync(f.pointer,'utf8'),f.before);
  finish(true);await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(events,['stop:old','start:candidate']);
  assert.equal(fs.readFileSync(f.pointer,'utf8'),f.before);
});
test('callback errors never leak secrets and leave inspection evidence without retry',async t=>{
  const f=fixture(t);let calls=0;
  const result=await updateServiceRelease({...f.args,...callbacks([]),stopService:()=>{calls++;throw Error('secret-token /private/path')}});
  assert.equal(result.status,'needs_recovery');assert.equal(result.reason,'callback_failed');assert.equal(calls,1);
  assert.doesNotMatch(JSON.stringify(inspectServiceUpdate({...f.args,transactionId:result.transactionId})),/secret-token|private\/path/);
});
test('concurrent legacy activation or changed stable bootstrap is never clobbered',async t=>{
  for(const change of ['pointer','bootstrap']){
    const f=fixture(t);
    const result=await updateServiceRelease({...f.args,...callbacks([]),checkHealth:()=>{
      if(change==='pointer')activateRelease(f.installRoot,'other',f.publicKeyPem);
      else fs.appendFileSync(path.join(f.installRoot,'launch.mjs'),'foreign-change');
      return false;
    }});
    assert.equal(result.status,'needs_recovery');
    if(change==='pointer'){
      assert.equal(activeRelease(f.installRoot,f.publicKeyPem).version,'other');
      await assert.rejects(recoverServiceUpdate({...f.args,transactionId:result.transactionId,confirmStopped:async()=>true}),/active_pointer_changed/);
    }else assert.match(fs.readFileSync(path.join(f.installRoot,'launch.mjs'),'utf8'),/foreign-change/);
  }
});
test('candidate and previous signatures are checked before service callbacks',async t=>{
  for(const version of ['old','candidate']){
    const f=fixture(t);let calls=0;
    fs.appendFileSync(path.join(f.installRoot,'releases',version,'host/launch.mjs'),'tamper');
    await assert.rejects(updateServiceRelease({...f.args,...callbacks([]),stopService:()=>{calls++;return true}}),/release_file_/);
    assert.equal(calls,0);assert.equal(fs.existsSync(path.join(f.installRoot,'.health-update-lock')),false);
  }
});

test('persisted switch intent can recover partial signed file replacement without replay',async t=>{
  const f=fixture(t);
  const pending=await updateServiceRelease({...f.args,...callbacks([]),startService:()=>{throw Error('uncertain')}});
  const record=inspectServiceUpdate({...f.args,transactionId:pending.transactionId});
  // Simulate a crash after switch-intent, some file renames and pointer rename
  // but before switched receipt. Recovery is read-only observation, not resume.
  const file=path.join(f.installRoot,'update-transactions',pending.transactionId+'.json');
  record.phase='switch_intent';record.expectedPointer=record.originalPointer;
  fs.writeFileSync(file,JSON.stringify(record),{mode:0o600});
  fs.copyFileSync(path.join(f.installRoot,'releases','old','host/launch.mjs'),path.join(f.installRoot,'launch.mjs'));
  const refused=await recoverServiceUpdate({...f.args,transactionId:pending.transactionId,confirmStopped:async()=>false});
  assert.equal(refused.status,'needs_recovery');
  const recovered=await recoverServiceUpdate({...f.args,transactionId:pending.transactionId,confirmStopped:async()=>true});
  assert.equal(recovered.status,'recovered_stopped');
  assert.equal(fs.readFileSync(f.pointer,'utf8'),f.before);
});
test('recovery refuses changed prior signature, wrong transaction owner and modified stable bytes',async t=>{
  for(const change of ['previous','owner','stable']){
    const f=fixture(t);
    const result=await updateServiceRelease({...f.args,...callbacks([]),startService:()=>{throw Error('uncertain')}});
    if(change==='previous')fs.appendFileSync(path.join(f.installRoot,'releases','old','host/launch.mjs'),'tamper');
    if(change==='owner')fs.writeFileSync(path.join(f.installRoot,'.health-update-lock','owner'),'0'.repeat(32));
    if(change==='stable')fs.appendFileSync(path.join(f.installRoot,'launch.mjs'),'tamper');
    let observations=0;
    const args={...f.args,transactionId:result.transactionId,confirmStopped:()=>{observations++;return true}};
    if(change==='stable')assert.equal((await recoverServiceUpdate(args)).status,'needs_recovery');
    else await assert.rejects(recoverServiceUpdate(args),/release_file_|update_ownership_changed/);
    if(change!=='stable')assert.equal(observations,0);
    assert.equal(activeRelease(f.installRoot,f.publicKeyPem).version,'candidate');
  }
});
test('blocking late callback does not evade timeout or trigger an automatic restart',async t=>{
  const f=fixture(t);let starts=0;
  const result=await updateServiceRelease({...f.args,...callbacks([]),timeoutMs:1,
    stopService:()=>{const until=performance.now()+5;while(performance.now()<until){};return true},
    startService:()=>{starts++;return true}});
  assert.equal(result.status,'needs_recovery');assert.equal(result.reason,'callback_timeout');assert.equal(starts,0);
});


test('killed updater leaves durable start intent; recovery never invokes an old service callback',
  {timeout:90000},async t=>{
  const f=fixture(t);
  const moduleURL=new URL('../service-update.mjs',import.meta.url).href;
  const code=`import {updateServiceRelease} from ${JSON.stringify(moduleURL)};
    await updateServiceRelease({...${JSON.stringify(f.args)},
      stopService:async()=>true,
      startService:async()=>{process.stdout.write('awaiting-owner\\n');await new Promise(()=>{})},
      checkHealth:async()=>true});`;
  const child=spawn(process.execPath,['--input-type=module','-e',code],{stdio:['ignore','pipe','pipe']});
  t.after(()=>{if(child.exitCode===null)child.kill('SIGKILL')});
  const exited=once(child,'exit');
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('child_start_intent_not_observed')),60000);
    let output='';
    child.stdout.on('data',bytes=>{output+=bytes;if(output.includes('awaiting-owner')){clearTimeout(timer);resolve()}});
    child.once('error',e=>{clearTimeout(timer);reject(e)});
    child.once('exit',()=>{clearTimeout(timer);if(!output.includes('awaiting-owner'))reject(Error('child_exited_before_intent'))});
  });
  child.kill('SIGKILL');await exited;
  const transactionId=fs.readdirSync(path.join(f.installRoot,'update-transactions'))[0].replace('.json','');
  assert.equal(inspectServiceUpdate({...f.args,transactionId}).phase,'start_intent');
  const result=await recoverServiceUpdate({...f.args,transactionId,confirmStopped:async()=>true});
  assert.equal(result.status,'recovered_stopped');assert.equal(fs.readFileSync(f.pointer,'utf8'),f.before);
});


test('unconfirmed stop or durable restart inhibition never switches pointer, bootstrap or starts',async t=>{
  const f=fixture(t);let starts=0;
  const result=await updateServiceRelease({...f.args,...callbacks([]),
    stopService:ctx=>{assert.equal(ctx.restartInhibitionRequired,true);return false},
    startService:()=>{starts++;return true}});
  assert.equal(result.status,'needs_recovery');assert.equal(result.phase,'stop_intent');
  assert.equal(starts,0);assert.equal(fs.readFileSync(f.pointer,'utf8'),f.before);
  assert.equal(fs.readFileSync(path.join(f.installRoot,f.runtime),'utf8'),'// signed old bin/'+f.runtime+'\n');
  const recovered=await recoverServiceUpdate({...f.args,transactionId:result.transactionId,
    confirmStopped:ctx=>{assert.equal(ctx.restartInhibitionRequired,true);return true}});
  assert.equal(recovered.status,'recovered_stopped');assert.equal(starts,0);
});
