import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {generateKeyPairSync} from 'node:crypto';
import {buildHostRelease} from '../build-host-release.mjs';
import {verifySignedRelease} from '../installer.mjs';

test('portable signed Host bundle builds on the native macOS or Linux publisher',
  {skip:process.platform==='win32',timeout:15000},async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'styx-native-package-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519',{
    privateKeyEncoding:{type:'pkcs8',format:'pem'},
    publicKeyEncoding:{type:'spki',format:'pem'}
  });
  const key=path.join(root,'private-publisher.pem');
  await fs.writeFile(key,privateKey,{mode:0o600});
  await fs.chmod(key,0o600);
  const codex=path.join(root,'codex'),cua=path.join(root,'cua-driver');
  await fs.writeFile(codex,'#!/bin/sh\necho codex-cli 0.163.0\n',{mode:0o700});
  await fs.writeFile(cua,'#!/bin/sh\necho cua-driver 0.36.0\n',{mode:0o700});
  await fs.chmod(codex,0o700);await fs.chmod(cua,0o700);
  const destination=path.join(root,'bundle');
  const receipt=buildHostRelease({destination,version:'0.1.0-portable',
    privateKeyFile:key,codexBinary:codex,cuaBinary:cua});
  assert.equal(receipt.platform,process.platform);
  assert.equal(receipt.arch,process.arch);
  assert.ok(receipt.files>=20);
  const verified=verifySignedRelease(destination,publicKey);
  for(const file of ['bin/codex','bin/cua-driver','host/installer.mjs',
    'host/launch.mjs','shared/private-file.mjs','node_modules/ws/package.json',
    'licenses/cua-LICENSE','licenses/codex-LICENSE','licenses/codex-NOTICE',
    'licenses/styx-LICENSE','licenses/provenance.json']){
    assert.ok(verified.manifest.files.some(x=>x.path===file),file);
  }
  // The signed payload must actually resolve every local runtime import.
  execFileSync(process.execPath,['--input-type=module','--eval',
    'await import('+JSON.stringify(pathToFileURL(path.join(destination,'host/connect.mjs')).href)+')'],
    {timeout:7000,stdio:'pipe'});
  if(process.env.STYX_TEST_NODE_BINARY){
    const runtimeBundle=path.join(root,'bundle-node');
    buildHostRelease({destination:runtimeBundle,version:'0.1.0-with-node',
      privateKeyFile:key,codexBinary:codex,cuaBinary:cua,nodeBinary:process.env.STYX_TEST_NODE_BINARY});
    const runtime=verifySignedRelease(runtimeBundle,publicKey);
    assert.equal(runtime.manifest.upstream.node,'22.23.3');
    for(const name of ['bin/node','licenses/node-LICENSE','provenance/node.json'])
      assert.ok(runtime.manifest.files.some(x=>x.path===name));
    assert.equal(execFileSync(path.join(runtimeBundle,'bin/node'),['--version'],{encoding:'utf8'}).trim(),'v22.23.3');
    await fs.appendFile(path.join(runtimeBundle,'bin/node'),'tampered');
    assert.throws(()=>verifySignedRelease(runtimeBundle,publicKey),/metadata_mismatch|hash_mismatch/);
  }
  assert.throws(()=>buildHostRelease({destination:path.join(root,'wrong-platform'),
    version:'0.1.0-bad',privateKeyFile:key,codexBinary:codex,cuaBinary:cua,
    platform:process.platform==='darwin'?'linux':'darwin'
  }),/native_build_platform_required/);
});
