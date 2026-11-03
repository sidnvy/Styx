// Actual Windows processes/stdio/WinForms custody; no Host, Gateway or desktop
// admission is fabricated. The test-only constructor is absent from App builds.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
test('original Quit custody joins owned work, preserves uncertainty and refuses duplicate profile owners',{skip:process.platform!=='win32'},t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-quit-regression-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const resources=path.join(root,'resources');fs.mkdirSync(resources);
 fs.copyFileSync(path.join(here,'../../assets/brand/styx-logo.png'),path.join(resources,'styx-logo.png'));
 const exe=path.join(root,'QuitLifecycleTest.exe'),csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
 const built=spawnSync(csc,['/nologo','/warn:4','/warnaserror+','/define:STYX_QUIT_TEST','/target:exe','/main:StyxNative.QuitLifecycleTest','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll','/out:'+exe,path.join(here,'Styx.cs'),path.join(here,'QuitLifecycleTest.cs')],{encoding:'utf8',windowsHide:true});
 assert.equal(built.status,0,built.stdout+built.stderr);
 for(const mode of ['idle','active','disconnected','slow','busy','failed','startup-failed','crashed','lost','reservation','observe','dispose','bootstrap','capability-draft']){
  const dir=path.join(root,mode),run=spawnSync(exe,[resources,dir,mode],{encoding:'utf8',timeout:60000,windowsHide:true});
  assert.equal(run.status,0,`${mode}: ${fs.existsSync(path.join(dir,'failure.txt'))?fs.readFileSync(path.join(dir,'failure.txt'),'utf8'):run.error||run.stderr}`);
  const result=JSON.parse(fs.readFileSync(path.join(dir,'result.json'),'utf8'));assert.equal(result.status,'PASS');
  if(mode==='reservation')continue;
  assert.equal(result.coreExit,['failed','startup-failed','crashed'].includes(mode)?101:0);
  assert.equal(result.quitStatus,'ready_to_exit');
  assert.equal(result.calls,mode==='busy'?'2':['failed','startup-failed','crashed'].includes(mode)?'0':'1');
 }
});
