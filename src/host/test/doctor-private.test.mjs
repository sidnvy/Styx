import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {doctor} from '../doctor.mjs';
import {ensurePrivateDirectory} from '../private-storage.mjs';

const windows=process.platform==='win32';
function setup(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-doctor-private-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const privateDir=path.join(root,'private');ensurePrivateDirectory(privateDir);
  const token=path.join(privateDir,'token');fs.writeFileSync(token,'t'.repeat(48),{mode:0o600});
  const config={host_id:'test',gateway_ws_url:'wss://example.invalid',token_file:token,
    exec:{binary:process.execPath,cwd:root}};
  return {root,privateDir,token,config};
}
function broaden(file){
  if(windows)execFileSync('icacls.exe',[file,'/grant','*S-1-1-0:(R)'],
    {windowsHide:true,timeout:30000,stdio:'ignore'});
  else fs.chmodSync(file,0o644);
}
for(const auth of ['bearer','mtls'])test('Doctor blocks broad '+auth+' credentials before runtime probes',async t=>{
  const {privateDir,token,config}=setup(t);
  if(auth==='mtls'){
    delete config.token_file;
    config.client_key_file=token;
    config.client_cert_file=path.join(privateDir,'cert');
    fs.writeFileSync(token,'-----BEGIN PRIVATE KEY-----\ntest-only\n',{mode:0o600});
    fs.writeFileSync(config.client_cert_file,'-----BEGIN CERTIFICATE-----\ntest-only\n');
  }
  broaden(token);
  const report=await doctor(config);
  assert.equal(report.status,'blocked');
  assert.ok(report.blockers.includes('host_credential_unavailable'));
  assert.equal(report.checks.runtime_probe,'not_run_preflight_blocked');
  assert.equal(report.checks.executor_version,null);
  assert.equal(JSON.stringify(report).includes(token),false);
});
test('Doctor rejects symlink credential paths before reading or executing',async t=>{
  const {root,token,config}=setup(t);
  const link=path.join(root,'link');
  try{fs.symlinkSync(token,link)}catch(e){
    if(windows&&['EPERM','EACCES','ENOTSUP'].includes(e.code)){
      t.skip('symlink creation unavailable for this native account');return;
    }throw e;
  }
  const report=await doctor({...config,token_file:link});
  assert.ok(report.blockers.includes('host_credential_unavailable'));
  assert.equal(report.checks.runtime_probe,'not_run_preflight_blocked');
});
test('Doctor signed-selection error cannot fall back to unsigned paths',async t=>{
  const {root,config}=setup(t);
  const report=await doctor(config,{installRoot:path.join(root,'missing-install')});
  assert.ok(report.blockers.includes('signed_install_unavailable'));
  assert.equal(report.checks.runtime_probe,'not_run_preflight_blocked');
  assert.equal(report.checks.executor_version,null);
});
