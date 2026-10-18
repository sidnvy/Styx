import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {verify,createPublicKey,constants} from 'node:crypto';
import {initLocalIdentity} from '../enroll.mjs';
import {joinPayload} from '../../gateway/enrollment.mjs';

test('native device identity is device-local, stable and cryptographically bound',
  async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'styx-identity-native-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  await fs.chmod(root,0o700);
  const config={
    gateway_url:'https://gateway.example.invalid',
    storage_dir:root,label:'test-host',
    cwd:process.cwd(),
    shell:process.platform==='win32'
      ?'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
      :'/bin/sh',
    exec_binary:process.execPath,
    computer_requested:false
  };
  const first=initLocalIdentity(config);
  const second=initLocalIdentity(config);
  assert.equal(first.device_id,second.device_id);
  assert.match(first.fingerprint,/^[a-f0-9]{64}$/);
  const priv=await fs.readFile(path.join(root,'identity.pem'),'utf8');
  assert.match(priv,/BEGIN PRIVATE KEY/);
  const {sign}=await import('node:crypto');
  const payload={
    invitation:'a'.repeat(48),
    device_id:first.device_id,
    label:config.label,platform:process.platform,
    cwd:config.cwd,shell:config.shell,
    computer_requested:false,
    public_key_pem:first.public_key_pem
  };
  const signature=sign('sha256',Buffer.from(joinPayload(payload)),{
    key:priv,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  });
  assert.equal(verify('sha256',Buffer.from(joinPayload(payload)),{
    key:createPublicKey(first.public_key_pem),
    padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  },signature),true);
  assert.equal(verify('sha256',Buffer.from(joinPayload({...payload,label:'attacker'})),{
    key:createPublicKey(first.public_key_pem),
    padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  },signature),false);
  if(process.platform!=='win32'){
    const st=await fs.stat(path.join(root,'identity.pem'));
    assert.equal(st.mode&0o077,0);
  }
});
