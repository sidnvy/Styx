import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  createHash,generateKeyPairSync,sign,randomBytes
} from 'node:crypto';
import {
  verifySignedRelease,stageSignedRelease,activateRelease,activeRelease,
  rollbackRelease,servicePlan,refreshVerifiedBootstrap,pruneVerifiedReleases
} from '../installer.mjs';
import {launchActive} from '../launch.mjs';

function sha(data){return createHash('sha256').update(data).digest('hex')}
async function fixture(t) {
  const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'styx-signed-install-'));
  t.after(()=>fs.rm(tmp,{recursive:true,force:true}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519',{
    publicKeyEncoding:{type:'spki',format:'pem'},
    privateKeyEncoding:{type:'pkcs8',format:'pem'}
  });
  const installRoot=path.join(tmp,'installed');
  async function make(version,options={}) {
    const source=path.join(tmp,'bundle-'+version);
    await fs.mkdir(path.join(source,'host'),{recursive:true});
    await fs.mkdir(path.join(source,'bin'),{recursive:true});
    const files={
      'host/connect.mjs':options.code??"process.stdout.write('STYX_LAUNCH_OK\\n')",
      'bin/codex':'codex-pinned-0.163.0',
      'bin/cua':'cua-pinned-0.36.0'
    };
    if(options.bootstrap){
      for(const f of ['host/installer.mjs','host/launch.mjs']){
        files[f]=await fs.readFile(new URL('../'+f.split('/')[1],import.meta.url),'utf8');
      }
    }
    for(const [name,contents] of Object.entries(files))
      await fs.writeFile(path.join(source,name),contents);
    const manifest={
      schema:1,version,platform:options.platform??process.platform,
      arch:process.arch,
      files:Object.entries(files).map(([name,content])=>({
        path:name,sha256:sha(content),size:Buffer.byteLength(content),
        executable:name==='bin/codex'||name==='bin/cua'
      }))
    };
    const raw=JSON.stringify(manifest)+'\n';
    const signature=sign(null,Buffer.from(raw),privateKey).toString('base64url');
    await fs.writeFile(path.join(source,'manifest.json'),raw);
    await fs.writeFile(path.join(source,'manifest.sig'),signature+'\n');
    return {source,manifest};
  }
  return {tmp,privateKey,publicKey,installRoot,make};
}

test('signed offline staging, version activation and safe rollback',async t=>{
  const f=await fixture(t);
  const v1=await f.make('0.1.0-pilot1');
  const checked=verifySignedRelease(v1.source,f.publicKey);
  assert.equal(checked.version,'0.1.0-pilot1');
  const one=stageSignedRelease({sourceDir:v1.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey});
  assert.equal(one.status,'staged');
  assert.equal(stageSignedRelease({sourceDir:v1.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey}).status,'already_staged');
  assert.equal((await fs.stat(path.join(f.installRoot,'launch.mjs'))).isFile(),true);
  assert.equal(activateRelease(f.installRoot,'0.1.0-pilot1',
    f.publicKey).previous,null);
  const v2=await f.make('0.1.0-pilot2');
  stageSignedRelease({sourceDir:v2.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey});
  const switched=activateRelease(f.installRoot,'0.1.0-pilot2',f.publicKey);
  assert.equal(switched.previous,'0.1.0-pilot1');
  assert.equal(activeRelease(f.installRoot,f.publicKey).version,'0.1.0-pilot2');
  const rolled=rollbackRelease(f.installRoot,f.publicKey);
  assert.equal(rolled.version,'0.1.0-pilot1');
  assert.equal(activeRelease(f.installRoot,f.publicKey).version,'0.1.0-pilot1');
});
test('unsigned changes, extra binaries and wrong signing key cannot stage',async t=>{
  const f=await fixture(t);
  const v=await f.make('0.2.0-test');
  const {publicKey}=generateKeyPairSync('ed25519',{
    publicKeyEncoding:{format:'pem',type:'spki'},
    privateKeyEncoding:{format:'pem',type:'pkcs8'}
  });
  assert.throws(()=>verifySignedRelease(v.source,publicKey),/release_signature_untrusted/);
  const outsider=path.join(f.tmp,'unlisted.js');
  await fs.writeFile(outsider,'unlisted');
  let hasSymlink=false;
  try {
    await fs.symlink(outsider,path.join(v.source,'extra.js'));
    hasSymlink=true;
  }catch(e){
    if(!['EPERM','EACCES','ENOTSUP'].includes(e.code))throw e;
  }
  if(hasSymlink){
    assert.throws(()=>verifySignedRelease(v.source,f.publicKey),/archive_symlink_forbidden/);
    await fs.unlink(path.join(v.source,'extra.js'));
  }
  await fs.writeFile(path.join(v.source,'bin/cua'),'compromised');
  assert.throws(()=>stageSignedRelease({sourceDir:v.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey}),/release_file_(hash|metadata)_mismatch/);
  await fs.writeFile(path.join(v.source,'bin/cua'),'cua-pinned-0.36.0');
  await fs.writeFile(path.join(v.source,'unlisted.js'),'malware');
  assert.throws(()=>verifySignedRelease(v.source,f.publicKey),
    /unexpected_release_members/);
});
test('platform mismatch and nonempty existing release fail closed',async t=>{
  const f=await fixture(t);
  const v=await f.make('0.3.0-pilot');
  assert.throws(()=>verifySignedRelease(v.source,f.publicKey,{
    platform:process.platform==='win32'?'linux':'win32'}),/invalid_release_manifest/);
  stageSignedRelease({sourceDir:v.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey});
  await fs.writeFile(path.join(f.installRoot,'releases','0.3.0-pilot',
    'host/connect.mjs'),'tampered');
  assert.throws(()=>stageSignedRelease({sourceDir:v.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey}),/release_file_(hash|metadata)_mismatch/);
});
test('rollback works even if the just-activated release is damaged',async t=>{
  const f=await fixture(t);
  for(const version of ['0.1.0-alpha1','0.1.0-alpha2']){
    const v=await f.make(version);
    stageSignedRelease({sourceDir:v.source,installRoot:f.installRoot,
      publicKeyPem:f.publicKey});
    activateRelease(f.installRoot,version,f.publicKey);
  }
  await fs.writeFile(path.join(f.installRoot,'releases','0.1.0-alpha2',
    'host/connect.mjs'),'damaged_after_activation');
  assert.throws(()=>activeRelease(f.installRoot,f.publicKey),
    /release_file_(hash|metadata)_mismatch/);
  assert.equal(rollbackRelease(f.installRoot,f.publicKey).version,'0.1.0-alpha1');
  assert.equal(activeRelease(f.installRoot,f.publicKey).version,'0.1.0-alpha1');
});
test('stable launcher verifies active generation before executing signed code',async t=>{
  const f=await fixture(t);
  const v=await f.make('0.1.0-launch');
  stageSignedRelease({sourceDir:v.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey});
  activateRelease(f.installRoot,v.manifest.version,f.publicKey);
  const config=path.join(f.tmp,'host.json');
  const key=path.join(f.tmp,'trusted-ed25519.pem');
  await fs.writeFile(config,JSON.stringify({
    host_id:'signed-launch-fixture',
    exec:{binary:'/untrusted/binary',cwd:f.tmp}
  })+'\n',{mode:0o600});
  await fs.writeFile(key,f.publicKey,{mode:0o600});
  const result=await launchActive({
    installRoot:f.installRoot,hostConfigFile:config,trustPublicKeyFile:key
  });
  assert.equal(result.exit_code,0);
  assert.equal(result.version,'0.1.0-launch');
  await fs.writeFile(path.join(f.installRoot,'releases','0.1.0-launch',
    'host/connect.mjs'),'unsigned_and_untrusted_mutation');
  await assert.rejects(launchActive({
    installRoot:f.installRoot,hostConfigFile:config,trustPublicKeyFile:key
  }),/release_file_(hash|metadata)_mismatch/);
});
test('service plans never mutate OS startup state',async t=>{
  const f=await fixture(t);
  for(const [platform,manager] of [
    ['darwin','launchd-user'],['linux','systemd-user'],
    ['win32','windows-interactive-task']
  ]){
    const planned=servicePlan({platform,installRoot:f.installRoot,
      configFile:path.join(f.tmp,'host.json'),
      publicKeyFile:path.join(f.tmp,'trust.pub')});
    assert.equal(planned.status,'NOT_INSTALLED');
    assert.equal(planned.manager,manager);
    assert.ok(planned.args.every(x=>path.isAbsolute(x)));
  }
  assert.equal((await fs.readdir(f.tmp)).filter(x=>x.includes('service')).length,0);
});

test('stable bootstrap can only be refreshed using a publisher-signed bundled shim',
  async t=>{
  const f=await fixture(t);
  const bare=await f.make('0.1.0-bare');
  stageSignedRelease({sourceDir:bare.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey});
  assert.throws(()=>refreshVerifiedBootstrap(f.installRoot,f.publicKey,
    '0.1.0-bare'),/signed_bootstrap_payload_missing/);
  const full=await f.make('0.1.0-full',{bootstrap:true});
  stageSignedRelease({sourceDir:full.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey});
  const receipt=refreshVerifiedBootstrap(f.installRoot,f.publicKey,'0.1.0-full');
  assert.equal(receipt.status,'bootstrap_refreshed');
  for(const name of ['launch.mjs','installer.mjs']){
    assert.equal(await fs.readFile(path.join(f.installRoot,name),'utf8'),
      await fs.readFile(path.join(full.source,'host',name),'utf8'));
  }
  await fs.writeFile(path.join(f.installRoot,'releases','0.1.0-full',
    'host/launch.mjs'),'not-trusted');
  assert.throws(()=>refreshVerifiedBootstrap(f.installRoot,f.publicKey,
    '0.1.0-full'),/release_file_(hash|metadata)_mismatch/);
});

test('an intentional launcher termination is not reported as a crash',
  {skip:process.platform==='win32',timeout:9000},async t=>{
  const f=await fixture(t);
  const v=await f.make('0.1.0-term',{
    code:"process.on('SIGTERM',()=>process.exit(1));setInterval(()=>{},1000)"
  });
  stageSignedRelease({sourceDir:v.source,installRoot:f.installRoot,
    publicKeyPem:f.publicKey});
  activateRelease(f.installRoot,'0.1.0-term',f.publicKey);
  const config=path.join(f.tmp,'stop-config.json');
  const key=path.join(f.tmp,'publisher.pub');
  await fs.writeFile(config,JSON.stringify({exec:{cwd:f.tmp}}),{mode:0o600});
  await fs.writeFile(key,f.publicKey,{mode:0o600});
  const signal=new AbortController();
  const result=launchActive({installRoot:f.installRoot,hostConfigFile:config,
    trustPublicKeyFile:key,signal:signal.signal});
  await new Promise(resolve=>setTimeout(resolve,180));
  signal.abort();
  const outcome=await result;
  assert.equal(outcome.expected_stop,true);
  assert.equal(outcome.version,'0.1.0-term');
});

test('signed release retention keeps exactly active and previous, with preview first',
  async t=>{
  const f=await fixture(t);
  for(const version of ['pilot-a','pilot-b','pilot-c']){
    const bundle=await f.make(version);
    stageSignedRelease({sourceDir:bundle.source,installRoot:f.installRoot,
      publicKeyPem:f.publicKey});
    activateRelease(f.installRoot,version,f.publicKey);
  }
  const preview=pruneVerifiedReleases(f.installRoot,f.publicKey);
  assert.equal(preview.status,'dry_run');
  assert.deepEqual(preview.planned,['pilot-a']);
  assert.deepEqual(preview.keep,['pilot-c','pilot-b']);
  assert.deepEqual((await fs.readdir(path.join(f.installRoot,'releases'))).sort(),
    ['pilot-a','pilot-b','pilot-c']);
  const cleaned=pruneVerifiedReleases(f.installRoot,f.publicKey,{dryRun:false});
  assert.deepEqual(cleaned.removed,['pilot-a']);
  assert.deepEqual((await fs.readdir(path.join(f.installRoot,'releases'))).sort(),
    ['pilot-b','pilot-c']);
  assert.equal(activeRelease(f.installRoot,f.publicKey).version,'pilot-c');
  assert.equal(rollbackRelease(f.installRoot,f.publicKey).version,'pilot-b');
});

test('an unknown unsigned release blocks deletion of any old release',
  async t=>{
  const f=await fixture(t);
  for(const version of ['safe-a','safe-b','safe-c']){
    const bundle=await f.make(version);
    stageSignedRelease({sourceDir:bundle.source,installRoot:f.installRoot,
      publicKeyPem:f.publicKey});
    activateRelease(f.installRoot,version,f.publicKey);
  }
  const extra=path.join(f.installRoot,'releases','untrusted-build');
  await fs.mkdir(extra);
  await fs.writeFile(path.join(extra,'unknown'), 'do-not-touch');
  assert.throws(()=>pruneVerifiedReleases(f.installRoot,f.publicKey,
    {dryRun:false}),/ENOENT|unexpected_release_members|invalid_manifest/);
  assert.equal((await fs.readdir(path.join(f.installRoot,'releases')))
    .includes('safe-a'),true);
  assert.equal((await fs.readFile(path.join(extra,'unknown'),'utf8')),'do-not-touch');
});
