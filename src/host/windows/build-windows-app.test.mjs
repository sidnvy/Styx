import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {buildWindowsApp} from '../build-windows-app.mjs';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(t){
 const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-windows-builder-')));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const sourceRoot=path.join(dir,'source'),sourceFiles=['host/windows/Styx.cs','host/windows/SessionProbe.cs','host/windows/PrivateStorage.cs','assets/brand/styx-logo.png'];
 for(const name of sourceFiles){const file=path.join(sourceRoot,...name.split('/'));fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,'public source fixture');}
 const {privateKey,publicKey}=generateKeyPairSync('ed25519'),publisherKeyFile=path.join(dir,'publisher.pem');fs.writeFileSync(publisherKeyFile,publicKey.export({type:'spki',format:'pem'}));
 return {dir,privateKey,sourceFiles,config:{sourceRoot,output:path.join(dir,'output'),publisherKeyFile,publisherSha256:digest(publicKey.export({type:'spki',format:'der'}))}};
}
function nativeFixture(t){
 const f=fixture(t),payloadDir=path.join(f.dir,'native-payload');fs.mkdirSync(payloadDir);const pe=Buffer.alloc(256);pe.write('MZ');pe.writeUInt32LE(128,60);pe.write('PE\0\0',128,'binary');pe.writeUInt16LE(0x8664,132);pe.writeUInt16LE(2,148);pe.writeUInt16LE(2,150);pe.writeUInt16LE(0x20b,152);
 const bytes={'bin/styx.exe':pe,'LICENSE':Buffer.from('test license'),'source-inputs.json':Buffer.from('{"fixture":true}')};
 const files=Object.entries(bytes).map(([name,data])=>{const file=path.join(payloadDir,...name.split('/'));fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,data);return {path:name,size:data.length,sha256:digest(data),executable:name==='bin/styx.exe'};});
 const manifest={schema:2,runtime_format:'native_rust_v1',component:'styx',scope:'runtime_candidate',minimum_reader:'native_runtime_migrated_v1',target:'x86_64-pc-windows-msvc',version:'0.4.0-native-fixture',entrypoint:'bin/styx.exe',source:{revision:'a'.repeat(40),inputs_sha256:digest(bytes['source-inputs.json'])},contracts:{control:1,management_state:2},files,external_workers:[]};
 const publish=()=>{const raw=Buffer.from(JSON.stringify(manifest));fs.writeFileSync(path.join(payloadDir,'manifest.json'),raw);fs.writeFileSync(path.join(payloadDir,'manifest.sig'),sign(null,raw,f.privateKey));};publish();
 return {...f,payloadDir,manifest,publish,nativeConfig:{sourceRoot:f.config.sourceRoot,sourceFiles:f.sourceFiles,output:f.config.output,compile:false,nativeRuntime:{payloadDir,publisherFile:f.config.publisherKeyFile,expectedPublisher:f.config.publisherSha256}}};
}
test('native staging retains exact C08 bytes and fixed Rust bootstrap without a Node Core closure',t=>{
 const f=nativeFixture(t),before=fs.readFileSync(path.join(f.payloadDir,'manifest.json')),result=buildWindowsApp(f.nativeConfig),out=f.nativeConfig.output;
 assert.equal(result.runtimeFormat,'native_rust_v1');assert.equal(result.installer,'NOT_IMPLEMENTED_NATIVE_INSTALLER');assert.equal(result.packageAuthenticity,'unsigned_preview_consistency_only_not_os_signature_or_initial_cli_authentication');
 const runtime=JSON.parse(fs.readFileSync(path.join(out,'windows-runtime.json')));assert.deepEqual(runtime.nativeRuntime,{schema:1,cli:'native/bin/styx.exe',cliSha256:f.manifest.files[0].sha256,payload:'native',manifestSha256:digest(before),publisher:'native-publisher.pem',publisherSpkiSha256:f.nativeConfig.nativeRuntime.expectedPublisher});assert.equal(Object.hasOwn(runtime,'node'),false);
 for(const file of ['vnext','runtime/node.exe','host-bundle','install-windows-preview.mjs','Install-StyxPreview.cmd','StyxUpdater.exe'])assert.equal(fs.existsSync(path.join(out,...file.split('/'))),false,file);
 assert.deepEqual(fs.readFileSync(path.join(out,'native/manifest.json')),before);assert.deepEqual(fs.readFileSync(path.join(f.payloadDir,'manifest.json')),before);
 const catalog=JSON.parse(fs.readFileSync(path.join(out,'windows-package.json')));for(const member of catalog.files){const data=fs.readFileSync(path.join(out,...member.path.split('/')));assert.equal(digest(data),member.sha256);assert.equal(data.length,member.size);}
});
test('native staging refuses foreign target, unexpected member and source overlap before publishing an output',t=>{
 const f=nativeFixture(t);f.manifest.target='x86_64-unknown-linux-gnu';f.publish();assert.throws(()=>buildWindowsApp(f.nativeConfig),/native_windows_c08_runtime_required/);assert.equal(fs.existsSync(f.nativeConfig.output),false);
 f.manifest.target='x86_64-pc-windows-msvc';f.publish();fs.writeFileSync(path.join(f.payloadDir,'unexpected.txt'),'not in original signed closure');assert.throws(()=>buildWindowsApp(f.nativeConfig),/native_member_hash|native_inventory_not_exact/);assert.equal(fs.existsSync(f.nativeConfig.output),false);fs.unlinkSync(path.join(f.payloadDir,'unexpected.txt'));
 const original=fs.readFileSync(path.join(f.payloadDir,'manifest.json'));assert.throws(()=>buildWindowsApp({...f.nativeConfig,output:path.join(f.payloadDir,'new-output')}),/native_input_output_overlap/);assert.deepEqual(fs.readFileSync(path.join(f.payloadDir,'manifest.json')),original);assert.equal(fs.existsSync(path.join(f.payloadDir,'new-output')),false);
});

test('missing native selection never silently falls back to Node management',()=>{assert.throws(()=>buildWindowsApp({}),/native_runtime_required_for_product_app/);});

// Package compatibility only; the fixture PE is never executed or installed.
test('native staging preserves declared migrated readers and refuses unknown versions',t=>{
 for(const reader of ['native_runtime_migrated_v2','native_runtime_migrated_v3']){
  const f=nativeFixture(t);f.manifest.minimum_reader=reader;f.publish();
  const original=fs.readFileSync(path.join(f.payloadDir,'manifest.json'));
  buildWindowsApp(f.nativeConfig);
  assert.deepEqual(fs.readFileSync(path.join(f.nativeConfig.output,'native/manifest.json')),original);
 }
 const f=nativeFixture(t);f.manifest.minimum_reader='native_runtime_migrated_v4';f.publish();
 assert.throws(()=>buildWindowsApp(f.nativeConfig),/native_windows_c08_runtime_required/);
 assert.equal(fs.existsSync(f.nativeConfig.output),false);
});
