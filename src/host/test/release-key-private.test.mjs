import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import {buildHostRelease} from '../build-host-release.mjs';
import {ensurePrivateDirectory} from '../private-storage.mjs';

test('publisher rejects a broad private signing key before probing binaries or writing bundle',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-signing-private-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const dir=path.join(root,'private');ensurePrivateDirectory(dir);
  const key=path.join(dir,'publisher.key');
  fs.writeFileSync(key,generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
  if(process.platform==='win32')execFileSync('icacls.exe',[key,'/grant','*S-1-1-0:(R)'],
    {stdio:'ignore',windowsHide:true,timeout:30000});
  else fs.chmodSync(key,0o644);
  const destination=path.join(root,'bundle');
  assert.throws(()=>buildHostRelease({destination,version:'test-private',privateKeyFile:key,
    codexBinary:path.join(root,'missing-codex'),cuaBinary:path.join(root,'missing-cua')}),
    /release_signing_key_permissions/);
  assert.equal(fs.existsSync(destination),false);
});
