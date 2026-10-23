import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import childProcess from 'node:child_process';
import {once} from 'node:events';
import {syncBuiltinESMExports} from 'node:module';
import {fileURLToPath} from 'node:url';
import {createHash,randomBytes} from 'node:crypto';
import {ensurePrivateDirectory,writePrivateFile} from '../../../host/private-storage.mjs';
import {BROWSER_CONTRACT} from '../contract.mjs';
import {browserPreparationEnvironment,prepareManagedBrowser,readManagedBrowser,recoverManagedBrowserPreparation} from '../prepare.mjs';
const realSpawn=childProcess.spawn;
const posix=process.platform!=='win32';
const packageRoot=fileURLToPath(new URL('../',import.meta.url));
function fixture(t){
  // All fixture writes stay inside this independent worktree and are removed.
  const root=path.join(packageRoot,'.prepare-test-'+randomBytes(12).toString('hex'));ensurePrivateDirectory(root,{exclusive:true});
  const profileRoot=path.join(root,'profiles'),runtime=path.join(profileRoot,'runtime'),cache=path.join(runtime,'browsers');
  for(const dir of [profileRoot,runtime,cache])ensurePrivateDirectory(dir);
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  return {root,profileRoot,runtime,cache,lock:path.join(runtime,'prepare.lock'),claim:path.join(runtime,'prepare.recovery.lock')};
}
const hostIdentity=()=>({name:os.hostname(),platform:process.platform,arch:process.arch,...(process.getuid?{uid:process.getuid()}:{})});
function journal(pid,phase='owned',child=null){return {schema:1,transaction:'a'.repeat(32),playwright:BROWSER_CONTRACT.playwright,host:hostIdentity(),owner:{pid},phase,child};}
function writeLock(f,record){writePrivateFile(f.lock,typeof record==='string'?record:JSON.stringify(record));}
async function exitedPid(){const child=realSpawn(process.execPath,['-e',''],{stdio:'ignore'});const pid=child.pid;await once(child,'close');return pid;}
function mockSpawn(t,handler){t.mock.method(childProcess,'spawn',handler);syncBuiltinESMExports();return ()=>{t.mock.restoreAll();syncBuiltinESMExports();};}
function fakeSuccessfulInstall(t,f,onSpawn=()=>{}){
  const executablePath=path.join(f.cache,'fixture-browser');
  return mockSpawn(t,(command,args,options)=>{
    assert.equal(command,process.execPath);assert.equal(options.env.PLAYWRIGHT_BROWSERS_PATH,f.cache);assert.equal(options.detached,posix);
    let script;
    if(args[1]==='install'){
      assert.deepEqual(args.slice(1),['install','--no-shell','chromium']);
      assert.match(args[0],/playwright[/\\]cli\.js$/);
      writePrivateFile(executablePath,'fixture-browser-only-not-executed',{mode:0o700});script='';
    }else{assert.equal(args[0],'-e');script='process.stdout.write('+JSON.stringify(executablePath)+')';}
    const child=realSpawn(command,['-e',script],options);onSpawn(child,args,options);return child;
  });
}

test('preparation environment preserves OS/proxy/CA settings and drops injection/download overrides',()=>{
  const env=browserPreparationEnvironment('/private/cache',{PATH:'/usr/bin',HOME:'/private/home',SystemRoot:'C:\\Windows',HTTPS_PROXY:'http://proxy.invalid',NO_PROXY:'localhost',NODE_EXTRA_CA_CERTS:'/private/ca.pem',SSL_CERT_FILE:'/private/ca.pem',NODE_OPTIONS:'--require injected',NODE_PATH:'/injected',NODE_TLS_REJECT_UNAUTHORIZED:'0',LD_PRELOAD:'/injected',DYLD_INSERT_LIBRARIES:'/injected',PLAYWRIGHT_DOWNLOAD_HOST:'https://override.invalid',PLAYWRIGHT_CHROMIUM_DOWNLOAD_HOST:'https://override.invalid',PLAYWRIGHT_BROWSERS_PATH:'/foreign',PWTEST_CLI_IS_UNDER_TEST:'1'});
  assert.deepEqual(env,{PATH:'/usr/bin',HOME:'/private/home',SystemRoot:'C:\\Windows',HTTPS_PROXY:'http://proxy.invalid',NO_PROXY:'localhost',NODE_EXTRA_CA_CERTS:'/private/ca.pem',SSL_CERT_FILE:'/private/ca.pem',PLAYWRIGHT_BROWSERS_PATH:'/private/cache'});
});

test('authorization is required for preparation and recovery; an already aborted call spawns nothing',async t=>{
  const f=fixture(t);let spawned=0;const restore=mockSpawn(t,()=>{spawned++;throw Error('must_not_spawn');});
  try{
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot}),/browser_prepare_authorization_required/);
    await assert.rejects(recoverManagedBrowserPreparation({profileRoot:f.profileRoot}),/browser_prepare_authorization_required/);
    const abort=new AbortController();abort.abort();
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true,signal:abort.signal}),/browser_prepare_cancelled/);
    assert.equal(spawned,0);assert.equal(fs.existsSync(f.lock),false);assert.deepEqual(readManagedBrowser(f.profileRoot),{status:'not_prepared'});
  }finally{restore();}
});

test('old mtime does not authorize taking a live preparer lock',async t=>{
  const f=fixture(t);writeLock(f,journal(process.pid));fs.utimesSync(f.lock,1,1);const original=fs.readFileSync(f.lock,'utf8');
  assert.equal(readManagedBrowser(f.profileRoot).reason,'browser_prepare_owner_alive');
  await assert.rejects(recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_owner_alive/);
  await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true,recover:true}),/browser_prepare_owner_alive/);
  assert.equal(fs.readFileSync(f.lock,'utf8'),original);assert.equal(fs.existsSync(f.claim),false);
});

test('authorized recovery removes an identified dead preparer without using time',async t=>{
  const f=fixture(t);writeLock(f,journal(await exitedPid(),'settled'));
  assert.equal(readManagedBrowser(f.profileRoot).status,'preparation_blocked');
  assert.equal(readManagedBrowser(f.profileRoot).ownerState,'absent');
  assert.deepEqual(await recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true}),{status:'recovered',transaction:'a'.repeat(32),phase:'settled'});
  assert.equal(fs.existsSync(f.lock),false);assert.equal(fs.existsSync(f.claim),false);
  assert.deepEqual(readManagedBrowser(f.profileRoot),{status:'not_prepared'});
});

test('legacy, partial, foreign-host and unrecorded spawn locks remain blocked',async t=>{
  const f=fixture(t),dead=await exitedPid();
  for(const record of ['', '{', {...journal(dead),host:{...hostIdentity(),name:'unverified-other-host'}},journal(dead,'spawning')]){
    writeLock(f,record);const bytes=fs.readFileSync(f.lock);
    await assert.rejects(recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_recovery_unverified/);
    assert.deepEqual(fs.readFileSync(f.lock),bytes);assert.equal(readManagedBrowser(f.profileRoot).status,'preparation_blocked');assert.equal(fs.existsSync(f.claim),false);fs.unlinkSync(f.lock);
  }
});

test('a recovery claim is never stolen, including after its creator is absent',async t=>{
  const f=fixture(t);writeLock(f,journal(await exitedPid()));writePrivateFile(f.claim,JSON.stringify({owner:{pid:await exitedPid()}}));
  assert.equal(readManagedBrowser(f.profileRoot).reason,'browser_prepare_recovery_owned_or_interrupted');
  await assert.rejects(recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_recovery_owned_or_interrupted/);
  assert.equal(fs.existsSync(f.lock),true);assert.equal(fs.existsSync(f.claim),true);
});

test('a surviving POSIX download process group prevents recovery after preparer exit',{skip:!posix},async t=>{
  const f=fixture(t),dead=await exitedPid();
  const child=realSpawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'}),closed=once(child,'close');
  t.after(async()=>{if(child.exitCode===null&&child.signalCode===null)process.kill(-child.pid,'SIGKILL');await closed;});
  await once(child,'spawn');writeLock(f,journal(dead,'running',{pid:child.pid,processGroup:child.pid,command:'install'}));
  assert.equal(readManagedBrowser(f.profileRoot).reason,'browser_prepare_child_alive');
  await assert.rejects(recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_child_alive/);
  process.kill(-child.pid,'SIGTERM');await closed;
  assert.equal((await recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true})).status,'recovered');
});

test('Windows interrupted child tracking remains blocked without a process-tree proof',{skip:posix},async t=>{
  const f=fixture(t),dead=await exitedPid();writeLock(f,journal(dead,'running',{pid:dead,processGroup:null,command:'install'}));
  await assert.rejects(recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_recovery_unverified_children/);
  assert.equal(fs.existsSync(f.lock),true);
});

test('explicit recover re-enters a dead transaction and produces a reusable pinned receipt',async t=>{
  const f=fixture(t);writeLock(f,journal(await exitedPid()));let spawned=0;
  const restore=fakeSuccessfulInstall(t,f,()=>{spawned++;});
  try{
    const prepared=await prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true,recover:true});
    assert.equal(prepared.status,'prepared');assert.equal(prepared.playwright,BROWSER_CONTRACT.playwright);assert.equal(spawned,2);assert.equal(fs.existsSync(f.lock),false);
    const receipt=readManagedBrowser(f.profileRoot);assert.equal(receipt.executablePath,prepared.executablePath);assert.equal(receipt.sha256,prepared.sha256);
    assert.equal((await prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true})).status,'prepared');assert.equal(spawned,2,'receipt reuse does not run the installer again');
    writePrivateFile(f.claim,'unknown recovery');
    assert.equal(readManagedBrowser(f.profileRoot).status,'prepared','the existing valid receipt remains readable');
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true,recover:true}),/browser_prepare_recovery_owned_or_interrupted/);
    assert.equal(spawned,2);fs.unlinkSync(f.claim);
    fs.appendFileSync(prepared.executablePath,'changed');assert.throws(()=>readManagedBrowser(f.profileRoot),/browser_runtime_binding_changed/);
  }finally{restore();}
});

test('an existing receipt cannot point through a cache symlink to an external file',{skip:!posix},t=>{
  const f=fixture(t),external=path.join(f.root,'external-browser'),executablePath=path.join(f.cache,'linked-browser');writePrivateFile(external,'outside');fs.symlinkSync(external,executablePath);
  writePrivateFile(path.join(f.runtime,'receipt.json'),JSON.stringify({schema:1,playwright:BROWSER_CONTRACT.playwright,platform:process.platform,arch:process.arch,executablePath,sha256:createHash('sha256').update('outside').digest('hex')}));
  assert.throws(()=>readManagedBrowser(f.profileRoot),/browser_runtime_binding_changed/);
});

test('abort waits for the owned child and releases only a verified quiescent lock',async t=>{
  const f=fixture(t),abort=new AbortController();let download;
  const restore=mockSpawn(t,(command,args,options)=>{assert.equal(args[1],'install');download=realSpawn(command,['-e','setInterval(()=>{},1000)'],options);download.once('spawn',()=>abort.abort());return download;});
  try{
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true,signal:abort.signal}),/browser_prepare_cancelled/);
    assert.ok(download.exitCode!==null||download.signalCode!==null);assert.equal(fs.existsSync(path.join(f.runtime,'receipt.json')),false);
    if(posix){assert.equal(fs.existsSync(f.lock),false);assert.throws(()=>process.kill(-download.pid,0),error=>error.code==='ESRCH');}
    else{assert.equal(readManagedBrowser(f.profileRoot).status,'preparation_blocked');assert.equal(fs.existsSync(f.lock),true);}
  }finally{restore();if(download&&download.exitCode===null&&download.signalCode===null){download.kill('SIGKILL');await once(download,'close');}}
});

test('a lock cleanup failure still closes its fd and preserves recovery evidence',async t=>{
  const f=fixture(t),restore=fakeSuccessfulInstall(t,f),realUnlink=fs.unlinkSync,realOpen=fs.openSync,realClose=fs.closeSync;let lockFd,fdClosed=false;
  t.mock.method(fs,'openSync',(file,...args)=>{const fd=realOpen(file,...args);if(file===f.lock)lockFd=fd;return fd;});
  t.mock.method(fs,'closeSync',fd=>{if(fd===lockFd)fdClosed=true;return realClose(fd);});
  t.mock.method(fs,'unlinkSync',file=>{if(file===f.lock)throw Error('injected_lock_cleanup_failure');return realUnlink(file);});
  try{
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true}),/injected_lock_cleanup_failure/);
    assert.equal(fdClosed,true);assert.equal(fs.existsSync(f.lock),true);assert.equal(JSON.parse(fs.readFileSync(f.lock,'utf8')).phase,'settled');
  }finally{restore();}
});


test('an unsuccessful installer leaves no receipt and releases its quiescent transaction',async t=>{
  const f=fixture(t),restore=mockSpawn(t,(command,args,options)=>realSpawn(command,['-e',"process.stderr.write('private diagnostic');process.exit(7)"],options));
  try{
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true}),error=>error.message==='browser_runtime_download_failed');
    assert.equal(fs.existsSync(f.lock),!posix);assert.equal(fs.existsSync(path.join(f.runtime,'receipt.json')),false);
    if(!posix)assert.equal(readManagedBrowser(f.profileRoot).status,'preparation_blocked');
  }finally{restore();}
});

test('cleanup never removes a replacement lock and still closes the original fd',async t=>{
  const f=fixture(t),replacement=journal(process.pid),realOpen=fs.openSync,realClose=fs.closeSync;let replaced=false,lockFd,fdClosed=false;
  const restore=fakeSuccessfulInstall(t,f,()=>{
    if(replaced)return;replaced=true;fs.unlinkSync(f.lock);writePrivateFile(f.lock,JSON.stringify(replacement));
  });
  t.mock.method(fs,'openSync',(file,...args)=>{const fd=realOpen(file,...args);if(file===f.lock&&lockFd===undefined)lockFd=fd;return fd;});
  t.mock.method(fs,'closeSync',fd=>{if(fd===lockFd)fdClosed=true;return realClose(fd);});
  try{
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_lock_changed/);
    assert.equal(fdClosed,true);assert.deepEqual(JSON.parse(fs.readFileSync(f.lock,'utf8')),replacement);
  }finally{restore();}
});


test('a recovery claim without a main lock blocks both recovery and fresh preparation',async t=>{
  const f=fixture(t);writePrivateFile(f.claim,JSON.stringify({owner:{pid:await exitedPid()}}));let spawned=0;
  const restore=mockSpawn(t,()=>{spawned++;throw Error('must_not_spawn');});
  try{
    assert.equal(readManagedBrowser(f.profileRoot).reason,'browser_prepare_recovery_owned_or_interrupted');
    await assert.rejects(recoverManagedBrowserPreparation({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_recovery_owned_or_interrupted/);
    for(const recover of [false,true])await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true,recover}),/browser_prepare_recovery_owned_or_interrupted/);
    assert.equal(spawned,0);assert.equal(fs.existsSync(f.lock),false);assert.equal(fs.existsSync(f.claim),true);
  }finally{restore();}
});

test('preparation rechecks a recovery claim after recording its newly acquired lock',async t=>{
  const f=fixture(t),realSync=fs.fsyncSync;let spawned=0,injected=false;
  t.mock.method(fs,'fsyncSync',fd=>{
    realSync(fd);
    if(!injected&&fs.existsSync(f.lock)){
      injected=true;const claimFd=fs.openSync(f.claim,'wx',0o600);fs.writeSync(claimFd,'unknown recovery');fs.closeSync(claimFd);
    }
  });
  const restore=mockSpawn(t,()=>{spawned++;throw Error('must_not_spawn');});
  try{
    await assert.rejects(prepareManagedBrowser({profileRoot:f.profileRoot,authorize:true}),/browser_prepare_recovery_owned_or_interrupted/);
    assert.equal(spawned,0);assert.equal(fs.existsSync(f.lock),false);assert.equal(fs.existsSync(f.claim),true);
  }finally{restore();}
});
