import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import {generateKeyPairSync} from 'node:crypto';
import {buildHostRelease} from '../build-host-release.mjs';
import {verifySignedRelease} from '../installer.mjs';
const installed=fs.existsSync(fileURLToPath(new URL('../../packages/styx-browser-provider/node_modules/@playwright/mcp/package.json',import.meta.url)));

test('optional signed Browser runtime resolves without the publisher source checkout',{skip:process.platform==='win32'||!installed,timeout:20000},async t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-browser-release-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519',{privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
  const key=path.join(root,'publisher.pem'),codex=path.join(root,'codex'),cua=path.join(root,'cua');fs.writeFileSync(key,privateKey,{mode:0o600});
  fs.writeFileSync(codex,'#!/bin/sh\necho codex-cli 0.163.0\n',{mode:0o700});fs.writeFileSync(cua,'#!/bin/sh\necho cua-driver 0.36.0\n',{mode:0o700});
  const destination=path.join(root,'release');buildHostRelease({destination,version:'browser-test',privateKeyFile:key,codexBinary:codex,cuaBinary:cua,browserRuntime:true});
  const signed=verifySignedRelease(destination,publicKey);assert.equal(signed.manifest.upstream.browserMcp,'0.0.83');
  for(const file of ['host/browser.mjs','packages/styx-browser-provider/prepare.mjs','packages/styx-browser-provider/node_modules/@playwright/mcp/package.json','packages/styx-browser-provider/node_modules/playwright-core/lib/coreBundle.js'])assert.ok(signed.manifest.files.some(f=>f.path===file),file);
  const workspace=path.join(root,'workspace');fs.mkdirSync(workspace,{mode:0o700});
  const source=pathToFileURL(path.join(destination,'packages/styx-browser-provider/host.mjs')).href;
  const output=execFileSync(process.execPath,['--input-type=module','--eval',`const {HostBrowserSupervisor}=await import(${JSON.stringify(source)});const host=new HostBrowserSupervisor({browser:{enabled:true,headless:true,profileRoot:${JSON.stringify(path.join(root,'profiles'))}},cwd:${JSON.stringify(workspace)}});const server=host.createServer();await server.close();await host.close();console.log('browser-signed-runtime-ok');`],{cwd:root,encoding:'utf8',timeout:7000});
  assert.match(output,/browser-signed-runtime-ok/);
  assert.equal(signed.manifest.files.some(f=>f.path.includes('runtime/browsers/')),false,'browser binary is prepared locally by the controlled runtime, not copied from a user profile');
});
