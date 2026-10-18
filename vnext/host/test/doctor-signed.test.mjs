import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
import {stageSignedRelease,activateRelease} from '../installer.mjs';
import {doctor} from '../doctor.mjs';

const unix=process.platform==='linux'||process.platform==='darwin';
const sha=b=>createHash('sha256').update(b).digest('hex');

test('Doctor checks an actually signed active Host, not untrusted enrollment binary paths',
  {skip:!unix,timeout:18000},async t=>{
  const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'styx-doctor-installed-'));
  t.after(()=>fs.rm(tmp,{recursive:true,force:true}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519',{
    publicKeyEncoding:{format:'pem',type:'spki'},
    privateKeyEncoding:{format:'pem',type:'pkcs8'}
  });
  const source=path.join(tmp,'bundle');
  await fs.mkdir(path.join(source,'bin'),{recursive:true});
  const exe={
    'bin/codex':'#!/bin/sh\nprintf "codex-cli 0.163.0\\n"\n',
    'bin/cua-driver':'#!/bin/sh\nprintf "cua-driver 0.36.0\\n"\n'
  };
  for(const [name,script] of Object.entries(exe)){
    const dest=path.join(source,...name.split('/'));
    await fs.writeFile(dest,script,{mode:0o700});
    await fs.chmod(dest,0o700);
  }
  const manifest={schema:1,version:'0.1.0-signed',platform:process.platform,
    arch:process.arch,files:Object.entries(exe).map(([name,script])=>({
      path:name,sha256:sha(script),size:Buffer.byteLength(script),executable:true
    }))};
  const raw=JSON.stringify(manifest)+'\n';
  await fs.writeFile(path.join(source,'manifest.json'),raw);
  await fs.writeFile(path.join(source,'manifest.sig'),
    sign(null,Buffer.from(raw),privateKey).toString('base64url')+'\n');
  const installRoot=path.join(tmp,'install');
  stageSignedRelease({sourceDir:source,installRoot,publicKeyPem:publicKey});
  activateRelease(installRoot,'0.1.0-signed',publicKey);
  const token=path.join(tmp,'host.token');
  await fs.writeFile(token,randomBytes(48).toString('base64url')+'\n',
    {mode:0o600});
  const pub=path.join(tmp,'publisher.pub');
  await fs.writeFile(pub,publicKey);
  const config={
    host_id:'pilot',gateway_ws_url:'wss://test.example.invalid',
    token_file:token,
    exec:{binary:'/untrusted/not-real',cwd:tmp},
    computer:{enabled:true,binary:'/another/untrusted/path',connections:1,
      env:{CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}}
  };
  const d=await doctor(config,{installRoot,trustPublicKeyFile:pub});
  assert.equal(d.status,'ready_for_exec');
  assert.equal(d.checks.signed_install.publisher_verified,true);
  assert.equal(d.checks.signed_install.version,'0.1.0-signed');
  assert.equal(d.checks.executor_version,'codex-cli 0.163.0');
  assert.equal(d.checks.computer_version,'cua-driver 0.36.0');
  const baseline=await doctor(config);
  assert.ok(baseline.blockers.includes('codex_executor_unavailable'));
  await fs.writeFile(path.join(installRoot,'releases','0.1.0-signed','bin','codex'),
    '#!/bin/sh\nprintf "codex-cli 999.0\\n"\n');
  const damaged=await doctor(config,{installRoot,trustPublicKeyFile:pub});
  assert.equal(damaged.status,'blocked');
  assert.ok(damaged.blockers.includes('signed_install_unavailable'));
});
test('Doctor never accepts only one of the trusted installed-release parameters',
  async()=>{
    const report=await doctor({}, {installRoot:'/nonexistent'});
    assert.ok(report.blockers.includes('signed_install_unavailable'));
    assert.ok(report.blockers.includes('invalid_host_configuration'));
  });
