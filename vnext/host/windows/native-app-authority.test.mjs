import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {observeWindowsNativeAppAuthority} from './native-app-authority.mjs';
const generation='638900000000000000';
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-app-authority-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const manifest={};
 for(const [field,name] of [['desktopApp','StyxPreview.exe'],['desktopProbe','StyxSessionProbe.exe']]){
  fs.writeFileSync(path.join(root,name),'synthetic identity contract fixture: '+name);
  manifest[field]={path:name,sha256:createHash('sha256').update(fs.readFileSync(path.join(root,name))).digest('hex')};
 }
 const report={schema:1,status:'available',sessionId:2,interactive:true,windowStation:'WinSta0',inputDesktop:'Default',computerAcceptance:'NOT RUN',app:{pid:123,executablePath:path.join(root,'StyxPreview.exe'),sessionId:2,startTimeUtcTicks:generation}};
 const observe=(value=report,options={})=>observeWindowsNativeAppAuthority(root,manifest,{platform:'win32',parentPid:123,run:()=>JSON.stringify(value),...options});
 return {root,manifest,report,observe};
}
test('synthetic pinned process contract binds only the kernel parent identity, never Cua acceptance',t=>{
 const f=fixture(t);let called=false;
 const value=f.observe(f.report,{run:(file,args,options)=>{
  called=true;assert.equal(file,path.join(f.root,'StyxSessionProbe.exe'));assert.deepEqual(args,['--app-pid','123']);
  assert.equal(options.windowsHide,true);assert.equal(options.timeout,5000);assert.equal(options.maxBuffer,8192);assert.deepEqual(options.stdio,['ignore','pipe','ignore']);
  assert.ok(Object.keys(options.env).every(key=>['SystemRoot','WINDIR','TEMP','TMP'].includes(key)));return JSON.stringify(f.report);
 }});
 assert.equal(called,true);assert.deepEqual(value,{source:'current_windows_native_app',nativeAppPid:123,nativeAppGeneration:generation});
 assert.equal(value.computerAcceptance,undefined);assert.equal(value.accessibility,undefined);
 // The production default comes from Node's kernel-supplied ppid, not manifest
 // metadata, a descriptor, or an environment-supplied purported App identity.
 const original=process.env.STYX_NATIVE_PARENT_PID;process.env.STYX_NATIVE_PARENT_PID='999';t.after(()=>{if(original===undefined)delete process.env.STYX_NATIVE_PARENT_PID;else process.env.STYX_NATIVE_PARENT_PID=original;});
 const report={...f.report,app:{...f.report.app,pid:process.ppid}};
 assert.equal(observeWindowsNativeAppAuthority(f.root,{...f.manifest,parentPid:999},{platform:'win32',run:(_file,args)=>{assert.deepEqual(args,['--app-pid',String(process.ppid)]);return JSON.stringify(report);}}).nativeAppPid,process.ppid);
});
test('App and probe must both match fixed package filenames and hashes before the native query',t=>{
 const f=fixture(t);
 for(const field of ['desktopApp','desktopProbe'])for(const patch of [undefined,{...f.manifest[field],path:'../alternate.exe'},{...f.manifest[field],path:'/alternate.exe'},{...f.manifest[field],sha256:'f'.repeat(64)}]){
  let ran=false;const manifest={...f.manifest,[field]:patch};
  assert.deepEqual(observeWindowsNativeAppAuthority(f.root,manifest,{platform:'win32',parentPid:123,run:()=>{ran=true;return JSON.stringify(f.report);}}),{source:'not_observed'});
  assert.equal(ran,false,field+' must be checked before execution');
 }
 assert.deepEqual(f.observe(f.report,{platform:'linux',run:()=>{throw Error('must not query');}}),{source:'not_observed'});
 for(const parentPid of [0,-1,1.5,2147483648,'123'])assert.deepEqual(f.observe(f.report,{parentPid}),{source:'not_observed'});
 assert.deepEqual(observeWindowsNativeAppAuthority('relative',f.manifest,{platform:'win32',parentPid:123}),{source:'not_observed'});
});
test('native readiness alone, foreign App identity, locks and missing generations fail closed',t=>{
 const f=fixture(t);
 const invalid=[
  {...f.report,app:undefined},{...f.report,schema:2},{...f.report,status:'session_unavailable'},
  {...f.report,sessionId:0},{...f.report,interactive:false},{...f.report,windowStation:'Service-0'},{...f.report,inputDesktop:'Winlogon'},
  ...[{pid:999},{sessionId:3},{executablePath:path.join(f.root,'Other.exe')},{executablePath:'StyxPreview.exe'},
   {startTimeUtcTicks:undefined},{startTimeUtcTicks:638900000000000000},{startTimeUtcTicks:'000638900000000000000'},{startTimeUtcTicks:'-1'},{startTimeUtcTicks:'1.2'},{startTimeUtcTicks:'9'.repeat(20)},{startTimeUtcTicks:'3155378975999999999'}].map(app=>({...f.report,app:{...f.report.app,...app}}))
 ];
 for(const report of invalid)assert.deepEqual(f.observe(report),{source:'not_observed'},JSON.stringify(report));
 for(const run of [()=>{throw Error('process access denied');},()=>'',()=>'{',()=>Buffer.from(JSON.stringify(f.report)),()=>'x'.repeat(8193)])assert.deepEqual(f.observe(f.report,{run}),{source:'not_observed'});
});
test('a reused parent PID cannot bind a process started after this Core',t=>{
 const f=fixture(t),newStart=(621355968000000000n+BigInt(Date.now()+60000)*10000n).toString();
 assert.deepEqual(f.observe({...f.report,app:{...f.report.app,startTimeUtcTicks:newStart}}),{source:'not_observed'});
});
test('redirected or changed package files cannot acquire App authority',t=>{
 const f=fixture(t),app=path.join(f.root,'StyxPreview.exe'),probe=path.join(f.root,'StyxSessionProbe.exe');
 const copy=path.join(f.root,'Other.exe');fs.copyFileSync(app,copy);
 assert.deepEqual(f.observe({...f.report,app:{...f.report.app,executablePath:copy}}),{source:'not_observed'},'a byte-identical executable at another path is a different App');
 assert.deepEqual(f.observe(f.report,{run:()=>{fs.writeFileSync(app,'replaced during probe');return JSON.stringify(f.report);}}),{source:'not_observed'});
 fs.copyFileSync(copy,app);
 const originalProbe=fs.readFileSync(probe);fs.unlinkSync(probe);fs.writeFileSync(path.join(f.root,'probe-copy.exe'),originalProbe);try{fs.symlinkSync(path.join(f.root,'probe-copy.exe'),probe);}catch(error){if(process.platform==='win32'&&['EPERM','EACCES'].includes(error.code)){t.diagnostic('Symbolic file checks skipped: this Windows test process cannot create symlinks');return;}throw error;}
 assert.deepEqual(f.observe(),{source:'not_observed'},'a symlinked probe must not execute');
 fs.unlinkSync(probe);fs.writeFileSync(probe,originalProbe);fs.unlinkSync(app);fs.symlinkSync(copy,app);
 assert.deepEqual(f.observe(),{source:'not_observed'},'a symlinked App must not bind');
});
