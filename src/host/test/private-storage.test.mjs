import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile,openPrivateFile,writePrivateFile} from '../../shared/private-file.mjs';
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
  writePrivateFile(secret,'not-a-real-secret');
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
  const admin=path.join(privateRoot,'admin.test');writePrivateFile(admin,'a'.repeat(48));
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

test('exclusive private file has verified ownership before its first secret byte',t=>{
 const root=fixture(t),dir=path.join(root,'owned');ensurePrivateDirectory(dir);
 const file=path.join(dir,'secret'),fd=openPrivateFile(file);
 try{
  assert.equal(fs.fstatSync(fd).size,0);assert.ok(requirePrivateFile(file).isFile());
  assert.equal(fs.fstatSync(fd,{bigint:true}).ino,fs.lstatSync(file,{bigint:true}).ino);
  fs.writeFileSync(fd,'new-private-secret');fs.fsyncSync(fd);
 }finally{fs.closeSync(fd);}
 assert.equal(fs.readFileSync(file,'utf8'),'new-private-secret');assert.ok(requirePrivateFile(file).isFile());
});
test('new private file helpers refuse existing files and unsafe modes without changing content',t=>{
 const root=fixture(t),dir=path.join(root,'owned');ensurePrivateDirectory(dir);const file=path.join(dir,'existing');writePrivateFile(file,'keep-original');
 const before=fs.lstatSync(file,{bigint:true});
 assert.throws(()=>openPrivateFile(file),/EEXIST/);assert.throws(()=>writePrivateFile(file,'replacement'),/EEXIST/);
 assert.equal(fs.readFileSync(file,'utf8'),'keep-original');assert.equal(fs.lstatSync(file,{bigint:true}).ino,before.ino);
 assert.throws(()=>openPrivateFile(path.join(dir,'unsafe'),0o666),/creation_mode_invalid/);assert.equal(fs.existsSync(path.join(dir,'unsafe')),false);
});
test('private file creation rejects a broad existing parent before creating a file',t=>{
 const root=fixture(t),dir=path.join(root,'broad-parent');ensurePrivateDirectory(dir);broad(dir);
 const file=path.join(dir,'never-created');assert.throws(()=>writePrivateFile(file,'secret'),/private_directory_(permissions|acl_not_owner_only)/);assert.equal(fs.existsSync(file),false);
});
test('exclusive private directory creation rejects existing state without reuse or takeover',t=>{
 const root=fixture(t),dir=path.join(root,'lock');ensurePrivateDirectory(dir,{exclusive:true});assert.ok(requirePrivateDirectory(dir).isDirectory());
 const before=fs.lstatSync(dir,{bigint:true});assert.throws(()=>ensurePrivateDirectory(dir,{exclusive:true}),/EEXIST/);assert.equal(fs.lstatSync(dir,{bigint:true}).ino,before.ino);assert.deepEqual(fs.readdirSync(dir),[]);
});
test('existing Windows foreign-owner private file is rejected and never repaired by exclusive creation',{skip:!windows},t=>{
 const root=fixture(t),dir=path.join(root,'owned');ensurePrivateDirectory(dir);const file=path.join(dir,'foreign-file');writePrivateFile(file,'retain-foreign-file');
 try{execFileSync('icacls.exe',[file,'/setowner','*S-1-5-32-544'],{windowsHide:true,stdio:'ignore',timeout:30000});}
 catch{t.skip('scratch owner reassignment unavailable');return;}
 assert.throws(()=>requirePrivateFile(file),/private_file_acl_not_owner_only/);assert.throws(()=>openPrivateFile(file),/EEXIST/);assert.equal(fs.readFileSync(file,'utf8'),'retain-foreign-file');assert.throws(()=>requirePrivateFile(file),/private_file_acl_not_owner_only/);
});
