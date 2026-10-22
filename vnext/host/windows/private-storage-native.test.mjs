import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import * as native from '../private-storage.mjs';
import * as original from '../private-storage.mjs?powershell-comparison';

test('native Windows ACL adapter preserves rejection and observes changed permissions without a cache', {skip:process.platform!=='win32'}, t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-acl-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const helper=path.join(root,'StyxPrivateStorage.exe');
 execFileSync(path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),[
  '/nologo','/warn:4','/warnaserror+','/target:exe','/optimize+','/reference:System.Web.Extensions.dll',
  '/out:'+helper,fileURLToPath(new URL('./PrivateStorage.cs',import.meta.url))],{windowsHide:true,stdio:'pipe'});
 const pin=createHash('sha256').update(fs.readFileSync(helper)).digest('hex');
 const state=path.join(root,'private');original.ensurePrivateDirectory(state);
 const file=path.join(state,'normal-文件.txt');original.writePrivateFile(file,'test-only');
 let deep=state;while(deep.length<280){deep=path.join(deep,'long-path-segment');fs.mkdirSync(deep);}
 const long=path.join(deep,'long.txt'),short=path.join(state,'short.txt');original.writePrivateFile(short,'long-path-test');fs.renameSync(short,long);
 for(const f of [file,long])assert.ok(original.requirePrivateFile(f).isFile());
 assert.throws(()=>native.configureWindowsAclHelper(helper,'0'.repeat(64)),/private_acl_helper_changed/);
 native.configureWindowsAclHelper(helper,pin);
 for(const f of [file,long])assert.ok(native.requirePrivateFile(f).isFile());
 assert.ok(native.requirePrivateDirectory(state).isDirectory());
 const everyone=path.join(state,'everyone.txt');original.writePrivateFile(everyone,'keep');assert.ok(native.requirePrivateFile(everyone).isFile());
 execFileSync('icacls.exe',[everyone,'/grant','*S-1-1-0:(R)'],{windowsHide:true,stdio:'ignore'});
 for(const implementation of [original,native])assert.throws(()=>implementation.requirePrivateFile(everyone),/acl_not_owner_only/);
 // A previously accepted path is checked again after its ACL changes.
 execFileSync('icacls.exe',[path.toNamespacedPath(long),'/grant','*S-1-1-0:(R)'],{windowsHide:true,stdio:'ignore'});
 for(const implementation of [original,native])assert.throws(()=>implementation.requirePrivateFile(long),/acl_not_owner_only/);
 // Owner policy is narrower than the allow-list: Administrators is a valid
 // ACE principal, but never a substitute for this user's ownership.
 const foreign=path.join(state,'foreign.txt');original.writePrivateFile(foreign,'test-only');
 try{
  execFileSync('icacls.exe',[foreign,'/setowner','*S-1-5-32-544'],{windowsHide:true,stdio:'ignore'});
  for(const implementation of [original,native])assert.throws(()=>implementation.requirePrivateFile(foreign),/acl_not_owner_only/);
 }catch(error){if(error.status)t.diagnostic('Foreign-owner reassignment unavailable to this test token');else throw error;}
 // Verify empty and null DACL semantics using only new test-owned fixtures.
 for(const [name,dacl,accepted] of [['empty','D:',true],['null','D:NO_ACCESS_CONTROL',false]]){
  const candidate=path.join(state,name+'.txt');original.writePrivateFile(candidate,'test-only');
  const script="$ErrorActionPreference='Stop';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$acl=New-Object Security.AccessControl.FileSecurity;$acl.SetSecurityDescriptorSddlForm('O:'+$sid+$env:STYX_TEST_DACL);[IO.File]::SetAccessControl($env:STYX_TEST_FILE,$acl)";
  execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{windowsHide:true,stdio:'pipe',env:{...process.env,STYX_TEST_FILE:candidate,STYX_TEST_DACL:dacl}});
  try{for(const implementation of [original,native]){
   if(accepted)assert.ok(implementation.requirePrivateFile(candidate).isFile());
   else assert.throws(()=>implementation.requirePrivateFile(candidate),/acl_not_owner_only/);
  }}finally{
   // The owner retains WRITE_DAC even with an empty DACL; restore only our file
   // so cleanup does not require elevation or leave an inaccessible fixture.
   execFileSync('icacls.exe',[candidate,'/reset'],{windowsHide:true,stdio:'ignore'});
  }
 }
 const link=path.join(root,'junction');fs.symlinkSync(state,link,'junction');
 assert.throws(()=>native.requirePrivateDirectory(link),/not_regular/);
 // Mutating this test-owned executable must fail closed, not select PowerShell.
 fs.appendFileSync(helper,'changed');
 assert.throws(()=>native.requirePrivateFile(file),/acl_not_owner_only/);
 assert.ok(original.requirePrivateFile(file).isFile());
});
