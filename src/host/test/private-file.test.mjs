import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {requirePrivateFile} from '../../shared/private-file.mjs';

const windows=process.platform==='win32';
async function fixture(t){
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'styx-private-credential-test-'));
  t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const file=path.join(dir,'owned-secret.test');
  await fs.writeFile(file,'test-only-no-real-credential',{mode:0o600});
  if(windows){
    // Restrict THIS scratch test file, never the user's profile or an
    // existing Styx credential. SIDs avoid locale-dependent NTAccount names.
    const sidScript='[Security.Principal.WindowsIdentity]::GetCurrent().User.Value';
    const sid=execFileSync('powershell.exe',[
      '-NoProfile','-NonInteractive','-Command',sidScript
    ],{encoding:'utf8',windowsHide:true,timeout:7000}).trim();
    assert.match(sid,/^S-1-/);
    execFileSync('icacls.exe',[file,'/inheritance:r'],
      {windowsHide:true,stdio:'ignore',timeout:7000});
    execFileSync('icacls.exe',[file,'/grant:r','*'+sid+':(F)'],
      {windowsHide:true,stdio:'ignore',timeout:7000});
  }
  return {dir,file};
}

test('native per-user credential permission verification accepts the owner',async t=>{
  const {file}=await fixture(t);
  assert.ok(requirePrivateFile(file).isFile());
});
test('world-readable credentials are rejected on Windows ACL and Unix mode',async t=>{
  const {file}=await fixture(t);
  if(windows){
    execFileSync('icacls.exe',[file,'/grant','*S-1-1-0:(R)'],
      {windowsHide:true,stdio:'ignore',timeout:7000});
    assert.throws(()=>requirePrivateFile(file),/private_file_acl_not_owner_only/);
  }else {
    await fs.chmod(file,0o644);
    assert.throws(()=>requirePrivateFile(file),/private_file_permissions/);
  }
});
test('symbolic-link secret files are never trusted',async t=>{
  const {dir,file}=await fixture(t);
  const link=path.join(dir,'symbolic-secret-link');
  try{await fs.symlink(file,link);}
  catch(e){
    if(windows && ['EPERM','EACCES','ENOTSUP'].includes(e.code)){
      t.skip('symlink creation unavailable under this Windows account');return;
    }
    throw e;
  }
  assert.throws(()=>requirePrivateFile(link),/private_file_not_regular/);
});
test('private credentials reject relative paths, directories and foreign native ownership',async t=>{
  const {dir}=await fixture(t);
  assert.throws(()=>requirePrivateFile('relative-secret'),/private_file_absolute_path_required/);
  assert.throws(()=>requirePrivateFile(dir),/private_file_not_regular/);
  if(!windows){
    const info=await fs.stat('/etc/passwd');
    if(info.uid!==process.getuid())
      assert.throws(()=>requirePrivateFile('/etc/passwd'),/private_file_owner_mismatch/);
  }
});
