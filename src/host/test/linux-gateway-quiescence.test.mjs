import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {observeLinuxGatewayProcesses} from '../linux-gateway-quiescence.mjs';
const linux={skip:process.platform!=='linux'};
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-linux-quiescence-')),installRoot=path.join(root,'install'),stateDir=path.join(root,'deployment');for(const dir of [installRoot,stateDir])fs.mkdirSync(dir,{mode:0o700});t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return {root,installRoot,stateDir};}
function binary(f,source='/usr/bin/sleep',name='node'){const file=path.join(f.installRoot,name);fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.copyFileSync(source,file);fs.chmodSync(file,0o700);return file;}
function proc({args=['/unrelated/program'],exeError='EACCES',cmdlineError,raw,state='S'}={}){
 const fail=code=>{throw Object.assign(Error(code),{code})},tail=Array(20).fill('0');tail[0]=state;tail[19]='1234';
 const bytes=raw??Buffer.from(args.join('\0')+'\0');
 return {readdirSync:()=>['987654321'],statSync:()=>({uid:process.getuid()}),readFileSync(file,encoding){if(file.endsWith('/stat'))return '987654321 (owned fixture) '+tail.join(' ');if(cmdlineError)fail(cmdlineError);return encoding?bytes.toString():bytes},readlinkSync(){if(exeError)fail(exeError);return '/unrelated/program'}};
}
const noProcesses={readdirSync:()=>[]};
async function stopped(child){if(child.exitCode!==null||child.signalCode!==null)return;const closed=once(child,'close');child.kill('SIGTERM');await closed;}
test('actual installed Node is busy independently of argv; nontruncating probes preserve inode bytes and metadata',linux,async t=>{
 const f=fixture(t),node=binary(f,process.execPath),before={sha256:hash(node),size:fs.statSync(node).size,mtimeMs:fs.statSync(node).mtimeMs,ctimeMs:fs.statSync(node).ctimeMs};
 const observe=()=>observeLinuxGatewayProcesses(f,{filesystem:noProcesses});
 assert.equal(observe().executableInodes.length,1);
 const child=spawn(node,['-e',"process.stdout.write('ready');setInterval(()=>{},1000)"],{stdio:['ignore','pipe','pipe']});t.after(()=>stopped(child));await once(child.stdout,'data');
 assert.throws(observe,/gateway_runtime_process_still_running/);
 await stopped(child);
 // Process close can precede the kernel's final mm/exe reference release.
 // Keep refusing until a real non-writing open succeeds.
 const deadline=Date.now()+2000;for(;;){try{assert.equal(observe().executableInodes.length,1);break}catch(error){if(error.message!=='gateway_runtime_process_still_running'||Date.now()>=deadline)throw error;await new Promise(resolve=>setTimeout(resolve,10))}}
 const after={sha256:hash(node),size:fs.statSync(node).size,mtimeMs:fs.statSync(node).mtimeMs,ctimeMs:fs.statSync(node).ctimeMs};assert.deepEqual(after,before);
});
test('kernel checks cover retained generation executable inodes as well as the stable Node',linux,async t=>{
 const f=fixture(t);binary(f);const older=binary(f,'/usr/bin/sleep','releases/old/bin/node'),child=spawn(older,['60'],{stdio:'ignore'});t.after(()=>stopped(child));await once(child,'spawn');
 assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem:noProcesses}),/gateway_runtime_process_still_running/);await stopped(child);
 assert.equal(observeLinuxGatewayProcesses(f,{filesystem:noProcesses}).executableInodes.length,2);
});
test('inaccessible exe is resolved only with complete unrelated argv and independently excluded current inodes',linux,t=>{
 const f=fixture(t);binary(f);const observed=observeLinuxGatewayProcesses(f,{filesystem:proc()});
 assert.deepEqual(observed.inaccessibleExecutablePids,[987654321]);assert.equal(observed.executableInodes.length,1);assert.equal(observed.continuousExclusion,false);
 for(const filesystem of [proc({cmdlineError:'EACCES'}),proc({raw:Buffer.from('/truncated')}),proc({raw:Buffer.alloc(0)}),proc({exeError:'EIO'}),proc({exeError:'ENOENT'})])assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem}),/gateway_process_quiescence_unknown/);
});
test('external interpreters or renamed/deleted runtimes still require a complete unrelated argument observation',linux,t=>{
 const f=fixture(t);binary(f);
 for(const args of [['/outside/node','/outside/runner.mjs',f.stateDir],['/outside/node',f.installRoot+'/releases/old/app/onboarding/gateway-signed-runner.mjs']])assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem:proc({args})}),/gateway_runtime_process_still_running/);
 assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem:proc({cmdlineError:'EACCES'})}),/gateway_process_quiescence_unknown/);
 const liveThreads=proc({raw:Buffer.alloc(0),state:'Z'}),readDir=liveThreads.readdirSync;liveThreads.readdirSync=file=>file.endsWith('/task')?['987654321','987654322']:readDir(file);assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem:liveThreads}),/gateway_process_quiescence_unknown/);
});
test('unknown executable inventory, inaccessible probes, or changing PID identity cannot become an offline claim',linux,t=>{
 const f=fixture(t),node=binary(f);fs.chmodSync(node,0o500);assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem:noProcesses}),/gateway_process_quiescence_unknown/);fs.chmodSync(node,0o700);
 const filesystem=proc(),read=filesystem.readFileSync;let scans=0;filesystem.readFileSync=(file,encoding)=>{const value=read(file,encoding);if(file.endsWith('/stat')&&++scans===2)return value.replace(/1234$/,'1235');return value};assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem}),/gateway_process_quiescence_unknown/);
 fs.symlinkSync(node,path.join(f.installRoot,'unknown-link'));assert.throws(()=>observeLinuxGatewayProcesses(f,{filesystem:noProcesses}),/gateway_process_quiescence_unknown/);
});
