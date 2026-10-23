import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
// Exercise the production WinForms state machine and controls against a delayed
// protocol fixture. This is a UI regression, not native Host/update acceptance.
test('a failed mutation resumes an invalidated settings read without replay or lost feedback',{skip:process.platform!=='win32'},t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ui-settle-'));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.mkdirSync(path.join(root,'runtime'));fs.copyFileSync(process.execPath,path.join(root,'runtime/node.exe'));
 fs.writeFileSync(path.join(root,'windows-runtime.json'),JSON.stringify({node:{sha256:crypto.createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex')}}));
 fs.copyFileSync(path.join(here,'../../assets/brand/styx-logo.png'),path.join(root,'styx-logo.png'));
 fs.mkdirSync(path.join(root,'vnext/host/windows'),{recursive:true});
 fs.writeFileSync(path.join(root,'vnext/host/windows/core-bridge.mjs'),`
 import readline from 'node:readline';import fs from 'node:fs';import path from 'node:path';
 let reads=0,updates=0;const mode=fs.readFileSync(path.join(process.env.STYX_NATIVE_STATE,'mode'),'utf8');
 for await(const line of readline.createInterface({input:process.stdin})){
  const request=JSON.parse(line);let result={},ok=true;
  if(request.operation==='status'){reads++;await new Promise(r=>setTimeout(r,150));
   if(reads>1&&mode==='read-fails')ok=false;
   result=mode.startsWith('auto-')?{status:{nativeStartup:{status:'reconciliation_required',reason:'host_payload_update_required',automaticUpdate:mode==='auto-fails'}}}:reads>1&&mode==='recovery'?{componentRecovery:{status:'interrupted'}}:{status:{deployment:{mode:'create-local'}},session:{}};
  }else if(request.operation==='runtimeUpgradePrepare'){updates++;ok=false;}
  else if(request.operation==='counts')result={reads,updates};
  process.stdout.write(JSON.stringify({id:request.id,ok,result,error:'fixture_failure'})+'\\n');
 }
 `);
 const exe=path.join(root,'UiSettleTest.exe'),compiler=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
 const built=spawnSync(compiler,['/nologo','/warnaserror+','/target:winexe','/main:StyxNative.UiSettleTest','/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:System.Web.Extensions.dll',`/out:${exe}`,path.join(here,'Styx.cs'),path.join(here,'UiSettleTest.cs')],{encoding:'utf8'});
 assert.equal(built.status,0,built.stdout+built.stderr);
 for(const mode of ['success','read-fails','recovery','auto-fails','auto-blocked']){
  const state=path.join(root,mode);fs.mkdirSync(state);fs.writeFileSync(path.join(state,'mode'),mode);const receipt=path.join(state,'receipt');
  const run=spawnSync(exe,[root,state,mode,receipt],{timeout:15000,encoding:'utf8'});
  assert.equal(run.status,0,`${mode}: ${fs.existsSync(receipt)?fs.readFileSync(receipt,'utf8'):run.error||run.stderr}`);
  assert.equal(fs.readFileSync(receipt,'utf8'),'PASS');
 }
});
