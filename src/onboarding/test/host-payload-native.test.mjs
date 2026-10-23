import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {readDeploymentAppLoginBinding} from '../app-lifecycle.mjs';
import {macLoginRecoveryPlan} from '../macos-login-recovery.mjs';
import {observeMacHostPayloadAbsence} from '../host-payload-native.mjs';

function fixture(t){
 const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-absence-'))),uid=process.getuid();t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const scope={installRoot:path.join(home,'host/install'),hostConfigFile:path.join(home,'host/device/host.json'),stateDir:path.join(home,'deployment'),hostServiceLabel:'app.styx.host.fixture'};
 fs.mkdirSync(scope.installRoot,{recursive:true});
 const calls=[];const run=(command,args)=>{calls.push([command,args]);if(command==='/bin/launchctl')throw Object.assign(Error('missing'),{status:113,stderr:'Could not find service'});if(command==='/bin/ps')return `${uid} 123 1 /usr/bin/login\n`;throw Error('unexpected_command')};
 return {home,uid,scope,calls,options:{home,uid,platform:'darwin',run},run};
}
test('observes only fixed native reads; absent requires every service and process check',t=>{
 const f=fixture(t),r=observeMacHostPayloadAbsence(f.scope,f.options);assert.equal(r.status,'absent');assert.equal(r.mutation,'NONE');assert.equal(r.pointInTime,true);
 assert.equal(f.calls.filter(([cmd])=>cmd==='/bin/launchctl').length,9);assert.deepEqual(f.calls.at(-1),['/bin/ps',['-ww','-axo','uid=,pid=,ppid=,command=']]);
});
test('only native-verified current independent updater is exempt; parent and other Host PIDs remain blocked',t=>{
 const f=fixture(t),pid=456,exe=fs.realpathSync(process.execPath),options={...f.options,pid,execPath:exe};
 const runFor=rows=>(cmd,args)=>cmd==='/bin/ps'?(args.includes('-p')?`${f.uid} ${exe}\n`:rows):f.run(cmd,args);
 const self=`${f.uid} ${pid} 1 ${exe} updater.mjs --state ${f.scope.stateDir}\n`;
 assert.equal(observeMacHostPayloadAbsence(f.scope,{...options,run:runFor(self)}).status,'absent');
 for(const row of [`${f.uid} 457 ${pid} ${f.scope.installRoot}/bin/codex\n`,`${f.uid} 458 1 /bin/sh runner ${f.scope.stateDir}\n`]){
  const r=observeMacHostPayloadAbsence(f.scope,{...options,run:runFor(self+row)});assert.equal(r.reason,'native_owned_process_present');assert.equal(r.processCount,1);
 }
 assert.equal(observeMacHostPayloadAbsence(f.scope,{...options,run:(cmd,args)=>cmd==='/bin/ps'?(args.includes('-p')?`${f.uid+1} ${exe}`:self):f.run(cmd,args)}).reason,'native_updater_identity_unverified');
 const inside=path.join(f.scope.installRoot,'node');fs.writeFileSync(inside,'not executable');
 assert.equal(observeMacHostPayloadAbsence(f.scope,{...options,execPath:inside,run:runFor(self)}).reason,'independent_updater_runtime_required');
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

function ownedLogin(t){
 const f=fixture(t),appPath=path.join(f.home,'Styx.app'),file=path.join(f.home,'Library/LaunchAgents/app.styx.desktop-login.plist');
 fs.mkdirSync(f.scope.stateDir,{mode:0o700});fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.mkdirSync(appPath);
 fs.writeFileSync(path.join(f.scope.stateDir,'deployment.json'),JSON.stringify({host:{macPreviewApp:{path:appPath,cdhash:'a'.repeat(40)}}}),{mode:0o600});
 fs.writeFileSync(file,macLoginRecoveryPlan({appPath,logDir:path.join(f.scope.stateDir,'login-recovery-logs')})[0].plist,{mode:0o600});
 let disabled=false;const run=(cmd,args)=>cmd==='/bin/launchctl'&&args[0]==='print-disabled'?'disabled services = {\n "app.styx.desktop-login" => '+disabled+'\n}':f.run(cmd,args);
 const options={...f.options,run,verifyApp:value=>value};
 const binding=readDeploymentAppLoginBinding(f.scope.stateDir,{operations:options});
 return {...f,file,options,scope:{...f.scope,appPath,desktopLoginBinding:binding},disable:()=>{disabled=true}};
}
test('only exact authoritative unloaded login definition is preserved; loaded job remains blocked',t=>{
 const f=ownedLogin(t),before=fs.readFileSync(f.file),r=observeMacHostPayloadAbsence(f.scope,f.options);
 assert.equal(r.status,'absent');assert.equal(r.services,'owned_login_definition_preserved_all_jobs_unloaded');assert.deepEqual(fs.readFileSync(f.file),before);
 for(const domain of ['gui/'+f.uid,'user/'+f.uid,'system']){
  const loaded=observeMacHostPayloadAbsence(f.scope,{...f.options,run:(cmd,args)=>cmd==='/bin/launchctl'&&args[0]==='print'&&args[1]===domain+'/app.styx.desktop-login'?'state = running':f.options.run(cmd,args)});
  assert.equal(loaded.reason,'native_service_loaded');assert.equal(loaded.serviceLabel,'app.styx.desktop-login');
 }
 assert.equal(observeMacHostPayloadAbsence({...f.scope,desktopLoginBinding:undefined},f.options).reason,'native_service_definition_present');
 assert(f.calls.every(([cmd,args])=>cmd!=='/bin/launchctl'||['print','print-disabled'].includes(args[0])));
});
test('login exception cannot be manufactured and refuses definition, preference, signature or existence drift',t=>{
 const f=ownedLogin(t),original=fs.readFileSync(f.file);
 fs.appendFileSync(f.file,'<!-- foreign -->');assert.equal(observeMacHostPayloadAbsence(f.scope,f.options).status,'blocked');
 const forged={...f.scope.desktopLoginBinding,sha256:createHash('sha256').update(fs.readFileSync(f.file)).digest('hex')};assert.equal(observeMacHostPayloadAbsence({...f.scope,desktopLoginBinding:forged},f.options).status,'blocked');fs.writeFileSync(f.file,original);
 assert.equal(observeMacHostPayloadAbsence(f.scope,{...f.options,verifyApp:()=>{throw Error('signature invalid')}}).status,'blocked');
 fs.unlinkSync(f.file);assert.equal(observeMacHostPayloadAbsence(f.scope,f.options).status,'blocked');
 const missing=readDeploymentAppLoginBinding(f.scope.stateDir,{operations:f.options});fs.writeFileSync(f.file,original,{mode:0o600});assert.equal(observeMacHostPayloadAbsence({...f.scope,desktopLoginBinding:missing},f.options).status,'blocked');
 f.disable();assert.equal(observeMacHostPayloadAbsence(f.scope,f.options).status,'blocked');
 const disabled=readDeploymentAppLoginBinding(f.scope.stateDir,{operations:f.options});assert.equal(observeMacHostPayloadAbsence({...f.scope,desktopLoginBinding:disabled},f.options).status,'absent');
});
