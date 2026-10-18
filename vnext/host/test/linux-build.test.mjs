import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {generateKeyPairSync} from 'node:crypto';
import {buildLinuxRelease} from '../build-linux-release.mjs';
import {verifySignedRelease} from '../installer.mjs';

const linux=process.platform==='linux'&&process.arch==='x64';
test('Linux signed Host bundle uses only reviewed source and pinned runtime versions',
  {skip:!linux},async t=>{
  const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'styx-bundle-test-'));
  t.after(()=>fs.rm(tmp,{recursive:true,force:true}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519',{
    publicKeyEncoding:{type:'spki',format:'pem'},
    privateKeyEncoding:{type:'pkcs8',format:'pem'}
  });
  const keyPath=path.join(tmp,'publisher-key.pem');
  await fs.writeFile(keyPath,privateKey,{mode:0o600});
  await fs.chmod(keyPath,0o600);
  const codex=path.join(tmp,'codex');
  const cua=path.join(tmp,'cua-driver');
  await fs.writeFile(codex,'#!/bin/sh\nprintf "codex-cli 0.163.0\\n"\n',{mode:0o700});
  await fs.writeFile(cua,'#!/bin/sh\nprintf "cua-driver 0.36.0\\n"\n',{mode:0o700});
  const destination=path.join(tmp,'bundle');
  const result=buildLinuxRelease({destination,version:'0.1.0-linuxtest',
    privateKeyFile:keyPath,codexBinary:codex,cuaBinary:cua});
  assert.equal(result.version,'0.1.0-linuxtest');
  assert.ok(result.files>10);
  const checked=verifySignedRelease(destination,publicKey);
  assert.ok(checked.manifest.files.some(f=>f.path==='host/connect.mjs'));
  assert.ok(checked.manifest.files.some(f=>f.path==='host/computer.mjs'));
  assert.ok(checked.manifest.files.some(f=>f.path==='node_modules/ws/package.json'));
  assert.ok(checked.manifest.files.some(f=>f.path==='bin/codex'));
  assert.ok(checked.manifest.files.some(f=>f.path==='bin/cua-driver'));
  assert.ok(!checked.manifest.files.some(f=>f.path.endsWith('identity.pem')));
  assert.ok(!checked.manifest.files.some(f=>f.path.includes('secret')));
  const actual=(await fs.readdir(destination)).sort();
  assert.deepEqual(actual,['bin','host','licenses','manifest.json','manifest.sig',
    'node_modules','packages','shared']);
  assert.throws(()=>buildLinuxRelease({destination,version:'0.1.0-linuxtest',
    privateKeyFile:keyPath,codexBinary:codex,cuaBinary:cua}),
    /release_destination_must_be_empty/);
  await fs.writeFile(cua,'#!/bin/sh\nprintf "cua-driver 0.37.0\\n"\n',{mode:0o700});
  assert.throws(()=>buildLinuxRelease({destination:path.join(tmp,'bad-bundle'),
    version:'0.1.0-linuxtest',privateKeyFile:keyPath,
    codexBinary:codex,cuaBinary:cua}),/unsupported_pinned_binary_version/);
});
