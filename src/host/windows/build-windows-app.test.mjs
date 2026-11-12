import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {buildWindowsApp,createNativeOutputDirectory,windowsNativeOutputCommand} from '../build-windows-app.mjs';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(t){
 const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-windows-builder-')));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const sourceRoot=path.join(dir,'source'),sourceFiles=['host/windows/Styx.cs','host/windows/SessionProbe.cs','host/windows/PrivateStorage.cs','assets/brand/styx-logo.png','assets/brand/styx-custom-mcp-icon.png'];
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
 assert.deepEqual(fs.readFileSync(path.join(out,'styx-custom-mcp-icon.png')),fs.readFileSync(path.join(f.nativeConfig.sourceRoot,'assets/brand/styx-custom-mcp-icon.png')));
});
test('native staging refuses foreign target, unexpected member and source overlap before publishing an output',t=>{
 const f=nativeFixture(t);f.manifest.target='x86_64-unknown-linux-gnu';f.publish();assert.throws(()=>buildWindowsApp(f.nativeConfig),/native_windows_c08_runtime_required/);assert.equal(fs.existsSync(f.nativeConfig.output),false);
 f.manifest.target='x86_64-pc-windows-msvc';f.publish();fs.writeFileSync(path.join(f.payloadDir,'unexpected.txt'),'not in original signed closure');assert.throws(()=>buildWindowsApp(f.nativeConfig),/native_member_hash|native_inventory_not_exact/);assert.equal(fs.existsSync(f.nativeConfig.output),false);fs.unlinkSync(path.join(f.payloadDir,'unexpected.txt'));
 const original=fs.readFileSync(path.join(f.payloadDir,'manifest.json'));assert.throws(()=>buildWindowsApp({...f.nativeConfig,output:path.join(f.payloadDir,'new-output')}),/native_input_output_overlap/);assert.deepEqual(fs.readFileSync(path.join(f.payloadDir,'manifest.json')),original);assert.equal(fs.existsSync(path.join(f.payloadDir,'new-output')),false);
});

test('missing native selection never silently falls back to Node management',()=>{assert.throws(()=>buildWindowsApp({}),/native_runtime_required_for_product_app/);});

test('fresh native output refuses existing directories and files without changing their contents',t=>{
 const parent=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-output-'));t.after(()=>fs.rmSync(parent,{recursive:true,force:true}));
 const existing=path.join(parent,'existing'),file=path.join(parent,'existing-file');fs.mkdirSync(existing,{mode:0o750});fs.writeFileSync(path.join(existing,'keep.txt'),'preserve directory');fs.writeFileSync(file,'preserve file');
 const before=fs.statSync(existing),parentMode=fs.statSync(parent).mode;
 assert.throws(()=>createNativeOutputDirectory(existing));assert.throws(()=>createNativeOutputDirectory(file));
 assert.equal(fs.readFileSync(path.join(existing,'keep.txt'),'utf8'),'preserve directory');assert.equal(fs.readFileSync(file,'utf8'),'preserve file');
 assert.equal(fs.statSync(existing).ino,before.ino);assert.equal(fs.statSync(existing).mode,before.mode);assert.equal(fs.statSync(parent).mode,parentMode);
 const fresh=path.join(parent,"New output ' 中文");createNativeOutputDirectory(fresh);assert.equal(fs.statSync(fresh).isDirectory(),true);
 if(process.platform!=='win32')assert.equal(fs.statSync(fresh).mode&0o777,0o700);
});

test('Windows private directory command preserves path text without PowerShell evaluation',()=>{
 const output="D:\\Build output\\' 中文 $(not-a-command)",command=windowsNativeOutputCommand(output,'C:\\Windows');
 assert.equal(command.executable,'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
 assert.deepEqual(command.args.slice(0,3),['-NoProfile','-NonInteractive','-EncodedCommand']);
 const script=Buffer.from(command.args[3],'base64').toString('utf16le'),encoded=script.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/)?.[1];
 assert.equal(Buffer.from(encoded,'base64').toString('utf8'),output);assert.equal(script.includes('$(not-a-command)'),false);
 assert.throws(()=>windowsNativeOutputCommand('relative-output'),/absolute_package_paths_required/);
});

test('Windows fresh native output is private at creation and children inherit only the approved principals',{skip:process.platform!=='win32'},t=>{
 const parent=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-private-output-'));t.after(()=>fs.rmSync(parent,{recursive:true,force:true}));
 const output=path.join(parent,'New output 中文'),b64=value=>Buffer.from(value,'utf8').toString('base64');
 const ps=script=>execFileSync(windowsNativeOutputCommand(output).executable,['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from("$ErrorActionPreference='Stop';"+script,'utf16le').toString('base64')],{encoding:'utf8',windowsHide:true}).trim();
 // Only this test's new temporary parent is made broadly writable. Production
 // creation must exclude that inherited ACE without ever rewriting the parent.
 const before=ps(`$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64(parent)}'));$a=[IO.Directory]::GetAccessControl($p);$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow));[IO.Directory]::SetAccessControl($p,$a);[IO.Directory]::GetAccessControl($p).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)`);
 createNativeOutputDirectory(output);const child=path.join(output,'child');fs.mkdirSync(child);fs.writeFileSync(path.join(child,'file.txt'),'private inherited child');
 const result=JSON.parse(ps(`$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64(parent)}'));$o=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64(output)}'));$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$allowed=@($sid,'S-1-5-18','S-1-5-32-544');foreach($path in @($o,(Join-Path $o 'child'),(Join-Path $o 'child\\file.txt'))){$a=Get-Acl -LiteralPath $path;if($a.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid){throw 'owner_changed'};if($path -eq $o -and !$a.AreAccessRulesProtected){throw 'root_inherits_parent'};$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($rules.Count -ne 3){throw 'rule_count_changed'};foreach($r in $rules){if($r.IdentityReference.Value -notin $allowed -or $r.AccessControlType -ne 'Allow' -or $r.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl){throw 'unexpected_access'}}};@{parentDacl=[IO.Directory]::GetAccessControl($p).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access);privateInheritance=$true}|ConvertTo-Json -Compress`));
 assert.equal(result.privateInheritance,true);assert.equal(result.parentDacl,before);
 // A competing creator wins the name; the exclusive native API refuses it.
 assert.throws(()=>createNativeOutputDirectory(output),/native_private_output_creation_failed/);assert.equal(ps(`$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64(parent)}'));[IO.Directory]::GetAccessControl($p).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)`),before);
});

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
