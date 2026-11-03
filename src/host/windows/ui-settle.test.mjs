// Actual Rust-shaped Core/WinForms observation race; not native Host acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
test('a failed mutation invalidates its old read, then observation resumes without erasing draft or feedback',{skip:process.platform!=='win32'},t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ui-settle-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const resources=path.join(root,'resources');fs.mkdirSync(resources);
 fs.copyFileSync(path.join(here,'../../assets/brand/styx-logo.png'),path.join(resources,'styx-logo.png'));
 const exe=path.join(root,'UiSettleTest.exe'),csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
 const built=spawnSync(csc,['/nologo','/warn:4','/warnaserror+','/define:STYX_QUIT_TEST','/target:exe','/main:StyxNative.QuitLifecycleTest','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll','/out:'+exe,path.join(here,'Styx.cs'),path.join(here,'QuitLifecycleTest.cs')],{encoding:'utf8',windowsHide:true});
 assert.equal(built.status,0,built.stdout+built.stderr);
 const dir=path.join(root,'race'),run=spawnSync(exe,[resources,dir,'observe-mutation'],{encoding:'utf8',timeout:30000,windowsHide:true});
 assert.equal(run.status,0,fs.existsSync(path.join(dir,'failure.txt'))?fs.readFileSync(path.join(dir,'failure.txt'),'utf8'):run.error||run.stderr);
 assert.equal(JSON.parse(fs.readFileSync(path.join(dir,'result.json'),'utf8')).status,'PASS');
});
