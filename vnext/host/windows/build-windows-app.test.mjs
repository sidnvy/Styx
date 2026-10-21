import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {buildWindowsApp} from '../build-windows-app.mjs';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(t,{type='ed25519'}={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-windows-builder-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const sourceRoot=path.join(dir,'source');for(const rel of ['host/windows','assets/brand','node_modules/@modelcontextprotocol/sdk'])fs.mkdirSync(path.join(sourceRoot,rel),{recursive:true});
 for(const name of ['Styx.cs','SessionProbe.cs','build.ps1'])fs.writeFileSync(path.join(sourceRoot,'host/windows',name),'source fixture');
 fs.writeFileSync(path.join(sourceRoot,'assets/brand/styx-logo.png'),'image fixture');fs.writeFileSync(path.join(sourceRoot,'node_modules/@modelcontextprotocol/sdk/package.json'),'{}');
 const nodeBinary=path.join(dir,'node.exe');fs.writeFileSync(nodeBinary,'MZ-format-fixture');fs.writeFileSync(path.join(dir,'LICENSE'),'Node license fixture');fs.writeFileSync(path.join(dir,'node-provenance.json'),'{"upstream":"fixture, not verified"}');
 const {privateKey,publicKey}=generateKeyPairSync(type,type==='rsa'?{modulusLength:2048}:{}),pem=publicKey.export({type:'spki',format:'pem'});const publisherKeyFile=path.join(dir,'publisher.pem');fs.writeFileSync(publisherKeyFile,pem);
 const hostBundle=path.join(dir,'bundle');fs.mkdirSync(hostBundle);const bytes=Buffer.from('signed public fixture');fs.writeFileSync(path.join(hostBundle,'payload'),bytes);
 const manifest=Buffer.from(JSON.stringify({schema:1,version:'0.1.0-fixture',platform:'win32',arch:'x64',files:[{path:'payload',sha256:digest(bytes),size:bytes.length,executable:false}]}));fs.writeFileSync(path.join(hostBundle,'manifest.json'),manifest);fs.writeFileSync(path.join(hostBundle,'manifest.sig'),sign(type==='ed25519'?null:'sha256',manifest,privateKey).toString('base64url'));
 return {dir,pem,publicKey,config:{sourceRoot,output:path.join(dir,'output'),nodeBinary,hostBundle,publisherKeyFile,publisherSha256:digest(publicKey.export({format:'der',type:'spki'}))}};
}
test('Windows package uses Core SPKI DER fingerprint and verifies signed release',t=>{const f=fixture(t),r=buildWindowsApp(f.config);assert.equal(r.signedHostBundleIncluded,true);assert.equal(r.nodeValidation,'windows_executable_format_check_only');assert.equal(r.nodeUpstreamVerification,'not_performed_by_this_builder');assert.deepEqual(r.nodeNoticesIncluded,['LICENSE','node-provenance.json']);assert.equal(fs.readFileSync(path.join(f.config.output,'runtime/LICENSE'),'utf8'),'Node license fixture');});
test('PEM-byte fingerprint is rejected before creating output',t=>{const f=fixture(t);f.config.publisherSha256=digest(f.pem);assert.throws(()=>buildWindowsApp(f.config),/publisher_pin_mismatch/);assert.equal(fs.existsSync(f.config.output),false);});
test('tampered signed release is rejected before creating output',t=>{const f=fixture(t);fs.appendFileSync(path.join(f.config.hostBundle,'payload'),'tampered');assert.throws(()=>buildWindowsApp(f.config),/release_file_metadata_mismatch/);assert.equal(fs.existsSync(f.config.output),false);});
test('non-Ed25519 publisher is rejected',t=>{const f=fixture(t,{type:'rsa'});assert.throws(()=>buildWindowsApp(f.config),/invalid_release_signing_key/);assert.equal(fs.existsSync(f.config.output),false);});
