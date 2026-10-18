import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile} from '../../shared/private-file.mjs';
import {initLocalIdentity} from '../enroll.mjs';
const windows=process.platform==='win32';
function fixture(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-private-storage-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  return root;
}
function broad(folder){
  if(windows)execFileSync('icacls.exe',[folder,'/grant','*S-1-1-0:(OI)(CI)(F)'],
    {windowsHide:true,stdio:'ignore',timeout:7000});
  else fs.chmodSync(folder,0o755);
}
function config(storage){return {gateway_url:'https://invalid.example',storage_dir:storage,
  label:'private-test',cwd:process.cwd(),exec_binary:process.execPath,
  shell:windows?'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe':'/bin/sh'};}

test('new native private directory removes broad inheritance before secret creation',t=>{
  const root=fixture(t);broad(root);
  const state=path.join(root,'new-state');
  ensurePrivateDirectory(state);
  assert.ok(requirePrivateDirectory(state).isDirectory());
  const secret=path.join(state,'test-only.txt');
  fs.writeFileSync(secret,'not-a-real-secret',{mode:0o600});
  assert.ok(requirePrivateFile(secret).isFile());
  assert.doesNotThrow(()=>ensurePrivateDirectory(state));
});
test('existing broad native state is rejected unchanged before writing identity keys',t=>{
  const root=fixture(t),state=path.join(root,'existing');fs.mkdirSync(state);broad(state);
  assert.throws(()=>initLocalIdentity(config(state)),/private_directory_(permissions|acl_not_owner_only)/);
  assert.deepEqual(fs.readdirSync(state),[]);
  assert.throws(()=>requirePrivateDirectory(state),/private_directory_(permissions|acl_not_owner_only)/);
});
test('native enrollment rejects a broadened existing private identity file',t=>{
  const root=fixture(t),state=path.join(root,'device');
  initLocalIdentity(config(state));
  const key=path.join(state,'identity.pem');
  if(windows)execFileSync('icacls.exe',[key,'/grant','*S-1-1-0:(R)'],
    {windowsHide:true,stdio:'ignore',timeout:7000});
  else fs.chmodSync(key,0o644);
  assert.throws(()=>initLocalIdentity(config(state)),/private_file_(permissions|acl_not_owner_only)/);
});
test('private directory creation rejects symlinks and never creates missing parents',t=>{
  const root=fixture(t),state=path.join(root,'real');ensurePrivateDirectory(state);
  const link=path.join(root,'alias');
  fs.symlinkSync(state,link,windows?'junction':'dir');
  assert.throws(()=>ensurePrivateDirectory(link),/private_directory_not_regular/);
  const missing=path.join(root,'missing','state');
  assert.throws(()=>ensurePrivateDirectory(missing),/ENOENT/);
  assert.equal(fs.existsSync(path.dirname(missing)),false);
  const foreign=windows?null:fs.realpathSync('/etc');
  if(foreign&&fs.statSync(foreign).uid!==process.getuid())
    assert.throws(()=>requirePrivateDirectory(foreign),/private_directory_owner_mismatch/);
});

test('Gateway refuses broad existing enrollment state before writing tokens or database',async t=>{
  const {EnrollmentController}=await import('../../gateway/enrollment.mjs');
  const {TargetRegistry}=await import('../../gateway/registry.mjs');
  const root=fixture(t),privateRoot=path.join(root,'owner');ensurePrivateDirectory(privateRoot);
  const admin=path.join(privateRoot,'admin.test');fs.writeFileSync(admin,'a'.repeat(48),{mode:0o600});
  const state=path.join(root,'existing-gateway');fs.mkdirSync(state);broad(state);
  assert.throws(()=>new EnrollmentController({rootDir:state,adminTokenFile:admin,
    registry:new TargetRegistry({version:1,targets:[]})}),
    /private_directory_(permissions|acl_not_owner_only)/);
  assert.deepEqual(fs.readdirSync(state),[]);
});

test('foreign Windows directory owner is rejected without changing ownership',
  {skip:!windows},t=>{
  const root=fixture(t),state=path.join(root,'foreign-owner');ensurePrivateDirectory(state);
  try{execFileSync('icacls.exe',[state,'/setowner','*S-1-5-32-544'],
    {windowsHide:true,stdio:'ignore',timeout:7000})}
  catch{t.skip('scratch owner reassignment unavailable to this Windows account');return}
  assert.throws(()=>ensurePrivateDirectory(state),/private_directory_acl_not_owner_only/);
});
