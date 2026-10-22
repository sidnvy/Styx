import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
test('Windows native installer admission holds package mutex and observes running resources',{skip:process.platform!=='win32'},t=>{
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'styx-install-admission-'));t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
  const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),gate=path.join(temp,'gate.exe'),harness=path.join(temp,'test.exe');
  const compile=args=>execFileSync(csc,['/nologo','/warn:4','/warnaserror+','/target:exe','/reference:System.Web.Extensions.dll',...args],{windowsHide:true,stdio:'pipe'});
  compile(['/out:'+gate,path.join(here,'InstallGate.cs')]);
  compile(['/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/main:InstallCoordinationTest','/out:'+harness,path.join(here,'../Styx.cs'),path.join(here,'InstallCoordinationTest.cs')]);
  execFileSync(harness,[path.join(temp,'Programs Styx 中文'),gate],{windowsHide:true,timeout:30000,stdio:'pipe'});
});
