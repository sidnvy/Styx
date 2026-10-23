import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {observeLinuxHostPayloadAbsence} from '../../onboarding/host-payload-linux.mjs';
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-linux-offline-')),stateDir=path.join(root,'state'),base=path.join(root,'host'),installRoot=path.join(base,'install'),hostConfigFile=path.join(base,'device/host.json'),units=path.join(root,'units');
 for(const dir of [stateDir,base,installRoot,path.dirname(hostConfigFile),units])fs.mkdirSync(dir,{mode:0o700});
 fs.writeFileSync(hostConfigFile,'{}',{mode:0o600});fs.writeFileSync(path.join(stateDir,'deployment.json'),JSON.stringify({mode:'join-existing',host:{baseDir:base}}),{mode:0o600});
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));let observed=0;
 const input={stateDir,installRoot,hostConfigFile,hostServiceUnitName:'styx-isolated-test.service'};
 const run=(bin,args)=>bin.endsWith('systemd-analyze')?units+'\n':'LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nMainPID=0\nFragmentPath=\n';
 return {root,base,units,input,options:{platform:'linux',home:root,run,observeProcesses(scope){observed++;assert.equal(scope.stateDir,stateDir)}},observed:()=>observed};
}
test('only uninstalled and unloaded service plus observed kernel process absence qualifies',t=>{
 const f=fixture(t),r=observeLinuxHostPayloadAbsence(f.input,f.options);assert.equal(r.status,'absent');assert.equal(f.observed(),1);assert.equal(r.mutation,'NONE');assert.equal(r.pointInTime,true);
});
test('disabled installed service, queued activation and unreachable manager never qualify',t=>{
 const f=fixture(t);for(const text of ['LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled\nMainPID=0\n','LoadState=not-found\nActiveState=activating\nSubState=auto-restart\nMainPID=0\n',''])assert.equal(observeLinuxHostPayloadAbsence(f.input,{...f.options,run:()=>text}).status,'blocked');
 assert.equal(observeLinuxHostPayloadAbsence(f.input,{...f.options,run(){throw Error('offline')}}).status,'blocked');assert.equal(f.observed(),0);
});
test('fresh unit file is detected even before systemd daemon-reload',t=>{
 const f=fixture(t);fs.writeFileSync(path.join(f.units,f.input.hostServiceUnitName),'[Service]\n');assert.equal(observeLinuxHostPayloadAbsence(f.input,f.options).reason,'native_service_definition_present');assert.equal(f.observed(),0);
});
test('combined Host and Gateway installed runtimes are independently observed',t=>{
 const f=fixture(t),gateway=path.join(f.root,'gateway');fs.writeFileSync(path.join(f.input.stateDir,'deployment.json'),JSON.stringify({mode:'create-local',host:{baseDir:f.base},gateway:{runtime:{baseDir:gateway}}}),{mode:0o600});
 const seen=[];assert.equal(observeLinuxHostPayloadAbsence(f.input,{...f.options,observeProcesses:x=>seen.push(x.installRoot)}).status,'absent');assert.deepEqual(seen,[f.input.installRoot,path.join(gateway,'install')]);
});
test('process refusal and unknown observation remain unavailable, without killing processes',t=>{
 const f=fixture(t);for(const [error,reason] of [['gateway_runtime_process_still_running','native_owned_process_present'],['gateway_process_quiescence_unknown','native_observation_unavailable']])assert.equal(observeLinuxHostPayloadAbsence(f.input,{...f.options,observeProcesses(){throw Error(error)}}).reason,reason);
 assert.equal(observeLinuxHostPayloadAbsence({...f.input,gatewayServiceUnitName:'styx-foreign.service'},f.options).reason,'gateway_service_name_mismatch');
 assert.equal(observeLinuxHostPayloadAbsence({...f.input,hostConfigFile:'/unrelated'},f.options).reason,'native_scope_invalid');
});
