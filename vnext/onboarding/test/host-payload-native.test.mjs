import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {observeMacHostPayloadAbsence} from '../host-payload-native.mjs';

function fixture(t){
 const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-absence-'))),uid=process.getuid();t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const scope={installRoot:path.join(home,'host/install'),hostConfigFile:path.join(home,'host/device/host.json'),stateDir:path.join(home,'deployment'),hostServiceLabel:'app.styx.host.fixture'};
 const calls=[];const run=(command,args)=>{calls.push([command,args]);if(command==='/bin/launchctl')throw Object.assign(Error('missing'),{status:113,stderr:'Could not find service'});if(command==='/bin/ps')return `${uid} 123 1 /usr/bin/login\n`;throw Error('unexpected_command')};
 return {home,uid,scope,calls,options:{home,uid,platform:'darwin',run},run};
}
test('observes only fixed native reads; absent requires every service and process check',t=>{
 const f=fixture(t),r=observeMacHostPayloadAbsence(f.scope,f.options);assert.equal(r.status,'absent');assert.equal(r.mutation,'NONE');assert.equal(r.pointInTime,true);
 assert.equal(f.calls.filter(([cmd])=>cmd==='/bin/launchctl').length,9);assert.deepEqual(f.calls.at(-1),['/bin/ps',['-ww','-axo','uid=,pid=,ppid=,command=']]);
});
test('installed recovery job blocks even if disabled or unloaded, including dangling symlink',t=>{
 const f=fixture(t),dir=path.join(f.home,'Library/LaunchAgents');fs.mkdirSync(dir,{recursive:true});const file=path.join(dir,'app.styx.desktop-login.plist');fs.symlinkSync(path.join(f.home,'absent'),file);
 assert.equal(observeMacHostPayloadAbsence(f.scope,f.options).reason,'native_service_definition_present');assert.equal(f.calls.length,0);
});
test('loaded Host, Gateway or App recovery job blocks without exposing launchctl output',t=>{
 for(const target of ['app.styx.host.fixture','app.styx.gateway.','app.styx.desktop-login']){
  const f=fixture(t);const r=observeMacHostPayloadAbsence(f.scope,{...f.options,run:(cmd,args)=>cmd==='/bin/launchctl'&&args[1].includes(target)?'secretToken must not escape':f.run(cmd,args)});
  assert.equal(r.reason,'native_service_loaded');assert(!JSON.stringify(r).includes('secretToken'));
 }
});
test('unknown launchctl responses and inaccessible domains never mean absent',t=>{
 for(const error of [{status:1,stderr:'Operation not permitted'},{status:113,stderr:'Could not find domain'},{status:1,stderr:'Could not find service'},{code:'ETIMEDOUT'}]){
  const f=fixture(t);assert.equal(observeMacHostPayloadAbsence(f.scope,{...f.options,run:()=>{throw Object.assign(Error('private diagnostic'),error)}}).reason,'native_service_observation_unknown');
 }
});
test('running App, orphaned Host, legacy Gateway and host configuration references block; no argv leaks',t=>{
 const f=fixture(t);
 for(const command of [f.scope.installRoot+'/releases/v1/bin/codex',f.scope.installRoot+'/releases/v1/bin/cua-driver','/Applications/Styx.app/Contents/MacOS/Styx','/usr/bin/node gateway-runner.mjs '+f.scope.stateDir,'/usr/bin/node --config '+f.scope.hostConfigFile,'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir='+path.dirname(f.scope.installRoot)+'/browser/profile']){
  const r=observeMacHostPayloadAbsence(f.scope,{...f.options,run:(cmd,args)=>cmd==='/bin/ps'?`${f.uid} 321 1 ${command} --token hidden-value\n`:f.run(cmd,args)});
  assert.equal(r.reason,'native_owned_process_present');assert.deepEqual(r.pids,[321]);assert(!JSON.stringify(r).includes('hidden-value'));
 }
});
test('empty, truncated or malformed process observation blocks, unrelated users do not count as our processes',t=>{
 const f=fixture(t);for(const output of ['',`${f.uid} 123\n`,`${f.uid} 123 1 /usr/bin/login\ntruncated\n`])assert.equal(observeMacHostPayloadAbsence(f.scope,{...f.options,run:(cmd,args)=>cmd==='/bin/ps'?output:f.run(cmd,args)}).reason,'native_process_observation_unknown');
 assert.equal(observeMacHostPayloadAbsence(f.scope,{...f.options,run:(cmd,args)=>cmd==='/bin/ps'?`${f.uid} 123 1 /usr/bin/login\n${f.uid+1} 124 1 ${f.scope.installRoot}/node\n`:f.run(cmd,args)}).status,'absent');
});
test('scope rejects wrong platform, label, UID, aliases and mismatched Gateway identity before native commands',t=>{
 const f=fixture(t),expected='app.styx.gateway.'+createHash('sha256').update(f.scope.stateDir).digest('hex').slice(0,12);
 assert.equal(observeMacHostPayloadAbsence({...f.scope,gatewayServiceLabel:expected},f.options).status,'absent');
 for(const bad of [{gatewayServiceLabel:'styx-gateway-wrong.service'},{hostServiceLabel:'../../escape'},{installRoot:'/'},{stateDir:f.scope.stateDir+'/../deployment'}])assert.equal(observeMacHostPayloadAbsence({...f.scope,...bad},f.options).status,'blocked');
 assert.equal(observeMacHostPayloadAbsence(f.scope,{...f.options,platform:'linux'}).reason,'macos_native_observation_required');assert.equal(observeMacHostPayloadAbsence(f.scope,{...f.options,uid:0}).reason,'native_scope_invalid');
});
