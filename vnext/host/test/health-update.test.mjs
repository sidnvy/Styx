import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {activateHealthyRelease} from '../health-update.mjs';
import {stageSignedRelease,activateRelease,activeRelease} from '../installer.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(t,{platform=process.platform}={}){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-health-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519');
  const pem=publicKey.export({type:'spki',format:'pem'});
  const installRoot=path.join(root,'installed'),options={platform,arch:process.arch};
  function make(version,{runtime='same-runtime',bootstrap}={}){
    const sourceDir=path.join(root,'source-'+version);
    fs.mkdirSync(path.join(sourceDir,'host'),{recursive:true});
    fs.mkdirSync(path.join(sourceDir,'bin'));
    const bytes={
      'host/private-storage.mjs':fs.readFileSync(fileURLToPath(new URL('../private-storage.mjs',import.meta.url))),
      'host/installer.mjs':fs.readFileSync(fileURLToPath(new URL('../installer.mjs',import.meta.url))),
      'host/launch.mjs':Buffer.from(bootstrap??fs.readFileSync(fileURLToPath(new URL('../launch.mjs',import.meta.url)))) ,
      ['bin/'+(platform==='win32'?'node.exe':'node')]:Buffer.from(runtime)
    };
    const files=Object.entries(bytes).map(([name,b])=>{
      fs.writeFileSync(path.join(sourceDir,name),b);
      return {path:name,size:b.length,sha256:sha(b),executable:name.startsWith('bin/')};
    });
    const raw=JSON.stringify({schema:1,version,...options,files});
    fs.writeFileSync(path.join(sourceDir,'manifest.json'),raw);
    fs.writeFileSync(path.join(sourceDir,'manifest.sig'),sign(null,Buffer.from(raw),privateKey).toString('base64url'));
    stageSignedRelease({sourceDir,installRoot,publicKeyPem:pem,...options});
  }
  make('old');make('candidate');make('other');
  fs.writeFileSync(path.join(installRoot,platform==='win32'?'node.exe':'node'),'same-runtime');
  activateRelease(installRoot,'old',pem,options);
  const pointer=path.join(installRoot,'active.json');
  const before=fs.readFileSync(pointer);
  const args={installRoot,version:'candidate',publicKeyPem:pem,...options};
  return {root,installRoot,pem,options,pointer,before,args,make};
}
test('healthy signed candidate activates once and retains prior signed version',async t=>{
  const f=fixture(t);let calls=0;
  const result=await activateHealthyRelease({...f.args,checkHealth:async c=>{
    calls++;assert.equal(c.previousVersion,'old');assert.equal(c.version,'candidate');
    assert.deepEqual(fs.readFileSync(f.pointer),f.before);return true;
  }});
  assert.equal(result.status,'activated');assert.equal(calls,1);
  assert.equal(activeRelease(f.installRoot,f.pem,f.options).previous,'old');
});
test('rejection, exception and bounded timeout preserve exact previous pointer without retries',async t=>{
  for(const probe of [()=>false,()=>{throw Error('secret-token')},()=>new Promise(()=>{})]){
    const f=fixture(t);let calls=0;
    const result=await activateHealthyRelease({...f.args,timeoutMs:20,checkHealth:c=>{calls++;return probe(c)}});
    assert.equal(result.status,'retained');assert.equal(calls,1);
    assert.deepEqual(fs.readFileSync(f.pointer),f.before);
    assert.ok(!JSON.stringify(result).includes('secret-token'));
  }
});
test('invalid signature and tampered signed payload refuse before health',async t=>{
  const f=fixture(t);let calls=0;
  const {publicKey}=generateKeyPairSync('ed25519');
  await assert.rejects(activateHealthyRelease({...f.args,publicKeyPem:publicKey.export({type:'spki',format:'pem'}),checkHealth:()=>{calls++;return true}}),/signature_untrusted/);
  fs.appendFileSync(path.join(f.installRoot,'releases','candidate','host/launch.mjs'),'tamper');
  await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>{calls++;return true}}),/metadata_mismatch/);
  assert.equal(calls,0);assert.deepEqual(fs.readFileSync(f.pointer),f.before);
});
test('simultaneous gated updates fail closed and failure does not activate either candidate',async t=>{
  const f=fixture(t);let release,entered;
  const ready=new Promise(r=>{entered=r});
  const first=activateHealthyRelease({...f.args,checkHealth:()=>{entered();return new Promise(r=>{release=r})}});
  await ready;
  await assert.rejects(activateHealthyRelease({...f.args,version:'other',checkHealth:()=>true}),/update_in_progress/);
  release(false);assert.equal((await first).status,'retained');
  assert.deepEqual(fs.readFileSync(f.pointer),f.before);
});
test('external activation during health is detected and never overwritten or rolled back',async t=>{
  const f=fixture(t);
  await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>{
    activateRelease(f.installRoot,'other',f.pem,f.options);return false;
  }}),/pointer_changed/);
  assert.equal(activeRelease(f.installRoot,f.pem,f.options).version,'other');
});
test('candidate corruption during successful health leaves exact previous pointer',async t=>{
  const f=fixture(t);
  await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>{
    fs.appendFileSync(path.join(f.installRoot,'releases','candidate','host/launch.mjs'),'tamper');return true;
  }}),/metadata_mismatch/);
  assert.deepEqual(fs.readFileSync(f.pointer),f.before);
});
test('Windows runtime change and bootstrap upgrade require offline switch before health',async t=>{
  for(const change of [{runtime:'new-runtime'},{bootstrap:'new-bootstrap'}]){
    const f=fixture(t,{platform:'win32'});f.make('upgrade',change);let calls=0;
    const shim=fs.readFileSync(path.join(f.installRoot,'launch.mjs'));
    await assert.rejects(activateHealthyRelease({...f.args,version:'upgrade',checkHealth:()=>{calls++;return true}}),/requires_offline_switch/);
    assert.equal(calls,0);assert.deepEqual(fs.readFileSync(f.pointer),f.before);
    assert.deepEqual(fs.readFileSync(path.join(f.installRoot,'launch.mjs')),shim);
    assert.equal(fs.readFileSync(path.join(f.installRoot,'node.exe'),'utf8'),'same-runtime');
  }
});
test('timed-out probe retains lock and late success cannot replay or activate',async t=>{
  const f=fixture(t);let finish;
  const result=await activateHealthyRelease({...f.args,timeoutMs:15,checkHealth:()=>new Promise(r=>{finish=r})});
  assert.equal(result.reason,'probe_timeout');assert.equal(result.lock_retained,true);
  finish(true);await new Promise(r=>setImmediate(r));
  assert.deepEqual(fs.readFileSync(f.pointer),f.before);
  await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>true}),/update_in_progress/);
});
test('first-install health failure preserves absence of active pointer',async t=>{
  const f=fixture(t);fs.unlinkSync(f.pointer);
  const result=await activateHealthyRelease({...f.args,checkHealth:()=>false});
  assert.equal(result.version,null);assert.equal(fs.existsSync(f.pointer),false);
});
test('stale lock is never stolen and a malformed pointer cannot invoke health',async t=>{
  const f=fixture(t);let calls=0;
  const lock=path.join(f.installRoot,'.health-update-lock');fs.mkdirSync(lock);
  await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>{calls++;return true}}),/update_in_progress/);
  fs.rmdirSync(lock);fs.writeFileSync(f.pointer,'invalid pointer');
  await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>{calls++;return true}}));
  assert.equal(calls,0);assert.equal(fs.readFileSync(f.pointer,'utf8'),'invalid pointer');
  assert.equal(fs.existsSync(lock),false);
});
test('previous signed payload corruption blocks a successful probe from committing',async t=>{
  const f=fixture(t);
  await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>{
    fs.appendFileSync(path.join(f.installRoot,'releases','old','host/launch.mjs'),'tamper');return true;
  }}),/metadata_mismatch/);
  assert.deepEqual(fs.readFileSync(f.pointer),f.before);
});

test('stable signed private-storage dependency is verified before and after health',async t=>{
  for(const during of [false,true]){
    const f=fixture(t);let calls=0;
    const helper=path.join(f.installRoot,'private-storage.mjs');
    if(!during)fs.appendFileSync(helper,'// changed');
    await assert.rejects(activateHealthyRelease({...f.args,checkHealth:()=>{
      calls++;fs.appendFileSync(helper,'// changed during probe');return true;
    }}),/bootstrap_requires_offline_switch/);
    assert.equal(calls,during?1:0);
    assert.deepEqual(fs.readFileSync(f.pointer),f.before);
  }
});
