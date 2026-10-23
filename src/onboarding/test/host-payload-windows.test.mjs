import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {observeWindowsHostPayloadAbsence as observe} from '../host-payload-windows.mjs';
const scope={installRoot:'C:\\Users\\Sid\\Test\\host\\install',hostConfigFile:'C:\\Users\\Sid\\Test\\host\\device\\host.json',stateDir:'C:\\Users\\Sid\\Test\\state',hostServiceTaskName:'StyxPilot-Upgrade123',appPath:'C:\\Users\\Sid\\Test\\app\\Styx.exe'};
const options={platform:'win32',pid:123,execPath:'C:\\Program Files\\nodejs\\node.exe'};
test('absence requires strict native response and invokes only fixed read-only PowerShell',()=>{
 let script;const r=observe(scope,{...options,run:(command,args,opts)=>{assert.equal(command,'powershell.exe');assert.deepEqual(args.slice(0,4),['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand']);assert.equal(opts.windowsHide,true);script=Buffer.from(args[4],'base64').toString('utf16le');return '{"schema":1,"status":"absent","reason":""}';}});
 assert.equal(r.status,'absent');assert.equal(r.mutation,'NONE');assert(script.includes('Get-ScheduledTask'));assert(script.includes('Win32_Service'));assert(script.includes('GetOwnerSid'));assert(!/Stop-Process|Stop-Service|Disable-ScheduledTask|Unregister-ScheduledTask/.test(script));
});
test('native task, process, independent-runtime and uncertain states remain blocked without diagnostic leakage',()=>{
 for(const reason of ['native_service_definition_present','native_owned_process_present','independent_updater_runtime_required','native_updater_identity_unverified','native_process_observation_unknown','native_observation_unavailable']){
  const r=observe(scope,{...options,run:()=>JSON.stringify({schema:1,status:'blocked',reason,commandLine:'private-token'})});assert.equal(r.reason,reason);assert(!JSON.stringify(r).includes('private-token'));
 }
 for(const raw of ['{}','[]','no json','{"schema":1,"status":"absent"}','{"schema":1,"status":"blocked","reason":"secret-token"}'])assert.equal(observe(scope,{...options,run:()=>raw}).reason,'native_observation_unavailable');
 assert.equal(observe(scope,{...options,run:()=>{throw Error('private-token')}}).reason,'native_observation_unavailable');
});
test('scope rejects path aliases, UNC/network and foreign labels before observation',()=>{
 const opts={...options,run:()=>{throw Error('unexpected native call')}};
 for(const changes of [{installRoot:'C:\\'},{stateDir:'C:\\Users\\Sid\\Test\\..\\state'},{stateDir:'\\\\server\\share\\state'},{hostServiceTaskName:'Foreign-Host'},{hostServiceTaskName:'StyxPilot-abc;whoami'},{appPath:'relative.exe'}])assert.equal(observe({...scope,...changes},opts).reason,'native_scope_invalid');
 assert.equal(observe(scope,{...opts,platform:'linux'}).reason,'windows_native_observation_required');
 assert.equal(observe(scope,{...opts,pid:0}).reason,'native_scope_invalid');
});

// Real native process observations: the updater sibling must not look like a
// live Host, while exact and nested arguments (including spaces) still block.
test('native absence distinguishes updater siblings from owned path components',{skip:process.platform!=='win32'},async t=>{
 const base=fs.mkdtempSync(path.join(os.tmpdir(),'Styx absence boundary '));
 t.after(()=>fs.rmSync(base,{recursive:true,force:true}));
 const host=path.join(base,'host');const native={installRoot:path.join(host,'install'),hostConfigFile:path.join(host,'device/host.json'),stateDir:path.join(base,'deployment'),hostServiceTaskName:'StyxPilot-Boundary'+process.pid,appPath:path.join(base,'app/Styx.exe')};
 const cases=[[host+'-payload-updaters\\node.exe','absent'],[host+'-archive','absent'],[host,'blocked'],[path.join(host,'install/node.exe'),'blocked'],[host.replaceAll('\\','/'),'blocked'],[native.hostConfigFile,'blocked'],[native.appPath,'blocked']];
 for(const [argument,status] of cases){
  const child=spawn(process.execPath,['-e',"process.stdout.write('ready');setTimeout(()=>{},60000)",argument],{stdio:['ignore','pipe','ignore'],windowsHide:true});
  try{await once(child.stdout,'data');const observed=observe(native);assert.equal(observed.status,status,JSON.stringify({argument,observed}));if(status==='blocked')assert.equal(observed.reason,'native_owned_process_present');}
  finally{child.kill();await once(child,'exit');}
 }
});
