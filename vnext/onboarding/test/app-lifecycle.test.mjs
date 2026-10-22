import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {readDeploymentAppLifecycle,controlDeploymentAppLifecycle,readDeploymentAppLoginBinding} from '../app-lifecycle.mjs';
import {macLoginRecoveryPlan} from '../macos-login-recovery.mjs';
const label='app.styx.desktop-login';
function fixture(t,{registered=true,missingState=false}={}){
 const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-app-lifecycle-')));
 t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const stateDir=path.join(home,'state'),appPath=path.join(home,'Styx.app'),cdhash='a'.repeat(40),calls=[],verified=[],jobs=new Map(),disabled=new Map();
 fs.mkdirSync(appPath);fs.mkdirSync(path.join(home,'Library/LaunchAgents'),{recursive:true});
 if(!missingState){
  fs.mkdirSync(stateDir,{mode:0o700});
  if(registered)fs.writeFileSync(path.join(stateDir,'deployment.json'),JSON.stringify({host:{macPreviewApp:{path:appPath,cdhash}},preserveIdentity:'original'}),{mode:0o600});
 }
 const uid=process.getuid(),gui='gui/'+uid;
 const run=(bin,args)=>{
  calls.push([bin,args]);if(bin==='/usr/bin/codesign')return '';
  const [op,target]=args;
  if(op==='print'&&target===gui)return 'session = Aqua';
  if(op==='print'){
   if(jobs.has(target))return jobs.get(target);
   const error=Error();error.stderr='Could not find specified service';throw error;
  }
  if(op==='print-disabled')return 'disabled services = {\n'+[...disabled].map(([name,value])=>' "'+name+'" => '+value).join('\n')+'\n}';
  if(op==='enable'||op==='disable')disabled.set(path.basename(target),op==='disable');
  if(op==='bootstrap'){
   const expected=macLoginRecoveryPlan({appPath,logDir:path.join(stateDir,'login-recovery-logs')})[0];
   jobs.set(gui+'/'+label,'state = running\n pid = 42\n path = '+args[2]+'\n arguments = {\n'+expected.args.map(arg=>' '+arg).join('\n')+'\n }\n');
  }
  if(op==='bootout')jobs.delete(target);
  return '';
 };
 const operations={platform:'darwin',home,uid,run,verifyApp:value=>{
  verified.push(value);
  if(value.path!==appPath||value.cdhash!==cdhash)throw Error('adhoc_preview_identity_mismatch');
  return {...value,trust:'test_fixture'};
 }};
 const trusted={trustedAppPath:appPath,operations},cli={operations};
 const mutate=(action,enabled,context=trusted)=>controlDeploymentAppLifecycle(stateDir,{action,authorize:true,...(enabled===undefined?{}:{enabled})},context);
 return {stateDir,appPath,cdhash,home,calls,verified,jobs,disabled,gui,operations,trusted,cli,mutate};
}
const mutationCalls=f=>f.calls.filter(([bin,args])=>bin==='/bin/launchctl'&&!['print','print-disabled'].includes(args[0]));

test('fresh trusted App status is read-only, without creating deployment or service state',t=>{
 const f=fixture(t,{missingState:true});
 const state=readDeploymentAppLifecycle(f.stateDir,f.trusted);
 assert.equal(state.status,'not_installed');assert.equal(state.loginAtStartup,'not_installed');
 assert.equal(fs.existsSync(f.stateDir),false);assert.deepEqual(mutationCalls(f),[]);
});
test('CLI re-verifies authoritative registered identity; native path must match registration',t=>{
 const f=fixture(t);
 assert.equal(readDeploymentAppLifecycle(f.stateDir,f.cli).source,'verified_deployment_identity');
 assert.equal(f.verified.length,1);
 assert.throws(()=>readDeploymentAppLifecycle(f.stateDir,{...f.trusted,trustedAppPath:'/other/Styx.app'}),/registered_path_changed/);
 const file=path.join(f.stateDir,'deployment.json');
 fs.writeFileSync(file,JSON.stringify({host:{macPreviewApp:{path:f.appPath,cdhash:'b'.repeat(40)}}}));
 assert.throws(()=>readDeploymentAppLifecycle(f.stateDir,f.cli),/identity_mismatch/);
 assert.deepEqual(mutationCalls(f),[]);
});
test('trusted native path still verifies the persisted certificate before launchd changes',t=>{
 const f=fixture(t),file=path.join(f.stateDir,'deployment.json');
 const registration={path:f.appPath,cdhash:f.cdhash,certificateSha1:'b'.repeat(40),certificateSha256:'c'.repeat(64)};
 fs.writeFileSync(file,JSON.stringify({host:{macPreviewApp:registration}}));
 let observed={...registration,cdhash:'d'.repeat(40)};
 const verified=[],operations={...f.operations,verifyApp:value=>{verified.push(value);return observed}};
 const trusted={...f.trusted,operations};
 assert.equal(readDeploymentAppLifecycle(f.stateDir,trusted).source,'verified_native_launch');
 assert.deepEqual(verified,[registration]);
 for(const value of [{path:f.appPath,cdhash:'d'.repeat(40)},{...observed,certificateSha256:'e'.repeat(64)}]){
  observed=value;assert.throws(()=>f.mutate('login',true,trusted),/registered_certificate_changed/);
 }
 const throwing={...trusted,operations:{...operations,verifyApp:()=>{throw Error('actual_certificate_mismatch')}}};
 assert.throws(()=>f.mutate('quit',undefined,throwing),/actual_certificate_mismatch/);
 assert.deepEqual(mutationCalls(f),[]);
 assert.deepEqual(JSON.parse(fs.readFileSync(file)).host.macPreviewApp,registration);
});
test('login preference uses observed launchd override, not plist existence',t=>{
 const f=fixture(t),file=path.join(f.stateDir,'deployment.json'),original=fs.readFileSync(file);
 let state=f.mutate('login',true);
 assert.equal(state.loginAtStartup,'enabled');assert.equal(state.running,true);
 state=f.mutate('login',false);
 assert.equal(state.installed,true);assert.equal(state.running,false);assert.equal(state.loginAtStartup,'disabled');
 f.disabled.delete(label);
 assert.equal(readDeploymentAppLifecycle(f.stateDir,f.trusted).loginAtStartup,'enabled');
 assert.deepEqual(fs.readFileSync(file),original);
});
test('unobservable or malformed startup overrides remain unknown',t=>{
 const f=fixture(t);f.mutate('login',true);
 for(const output of ['not a launchctl disabled-services response','disabled services = {\n "'+label+'" => perhaps\n}']){
  const operations={...f.operations,run:(bin,args)=>args[0]==='print-disabled'?output:f.operations.run(bin,args)};
  assert.equal(readDeploymentAppLifecycle(f.stateDir,{...f.trusted,operations}).loginAtStartup,'unknown');
 }
 const operations={...f.operations,run:(bin,args)=>{if(args[0]==='print-disabled')throw Error('transport error');return f.operations.run(bin,args)}};
 assert.equal(readDeploymentAppLifecycle(f.stateDir,{...f.trusted,operations}).loginAtStartup,'unknown');
});
test('Quit suspends App recovery, keeps enabled login intent and independent jobs',t=>{
 const f=fixture(t);f.mutate('login',true);
 for(const other of ['app.styx.gateway','app.styx.host','app.styx.bieber-tunnel'])f.jobs.set(f.gui+'/'+other,'independently owned');
 f.calls.length=0;
 const state=f.mutate('quit');
 assert.equal(state.currentSessionRecovery,'suspended');assert.equal(state.loginAtStartup,'enabled');
 assert.equal(state.running,false);assert.equal(f.jobs.size,3);
 assert.deepEqual(mutationCalls(f).map(x=>x[1]),[['bootout',f.gui+'/'+label]]);
 assert.equal(f.mutate('login',true).running,true);
});
test('fresh unregistered Quit proves absence and never silently skips an orphan loaded App',t=>{
 const f=fixture(t,{missingState:true});
 const result=f.mutate('quit',undefined,f.cli);
 assert.equal(result.currentSessionRecovery,'absent');assert.equal(result.status,'not_running');
 assert.equal(fs.existsSync(f.stateDir),false);assert.deepEqual(mutationCalls(f),[]);
 f.jobs.set(f.gui+'/'+label,'state = running\n pid = 42');
 assert.throws(()=>f.mutate('quit',undefined,f.cli),/loaded_app_not_owned/);
 assert.throws(()=>f.mutate('quit'),/loaded_app_not_owned/);
 assert.deepEqual(mutationCalls(f),[]);
});
test('matching private plist does not authorize changing a foreign loaded job',t=>{
 const f=fixture(t);f.mutate('login',true);
 f.jobs.set(f.gui+'/'+label,f.jobs.get(f.gui+'/'+label).replace(' /usr/bin/open',' /usr/bin/other'));
 f.calls.length=0;
 for(const [action,enabled] of [['quit',undefined],['login',true],['login',false]])assert.throws(()=>f.mutate(action,enabled),/loaded_app_not_owned/);
 assert.deepEqual(mutationCalls(f),[]);
});
test('CLI cannot manufacture App registration; mutations reject user-supplied trust or operations',t=>{
 const f=fixture(t,{registered:false});
 assert.throws(()=>f.mutate('login',true,f.cli),/verified_app_required/);
 for(const options of [{action:'quit'},{authorize:true,action:'quit',trustedAppPath:f.appPath},{authorize:true,action:'quit',operations:{}},{authorize:true,action:'login',enabled:'true'},{authorize:true,action:'quit',enabled:false}]){
  assert.throws(()=>controlDeploymentAppLifecycle(f.stateDir,options,f.trusted),/authorization_required|action_invalid/);
 }
 assert.deepEqual(mutationCalls(f),[]);
});
test('symlinked or public deployment registration is rejected without native mutations',t=>{
 const f=fixture(t),file=path.join(f.stateDir,'deployment.json');
 fs.chmodSync(file,0o644);assert.throws(()=>f.mutate('quit'),/private_file_permissions/);
 fs.chmodSync(file,0o600);fs.renameSync(file,file+'.original');fs.symlinkSync(file+'.original',file);
 assert.throws(()=>f.mutate('quit'),/private_file_not_regular/);
 assert.deepEqual(mutationCalls(f),[]);
});
test('missing GUI or unknown job observation is never treated as stopped',t=>{
 const f=fixture(t,{missingState:true});
 for(const run of [()=>{throw Error('no GUI session')},(bin,args)=>{if(args[0]==='print'&&args[1]!==f.gui)throw Error('unknown transport');return f.operations.run(bin,args)}]){
  assert.throws(()=>f.mutate('quit',undefined,{operations:{...f.operations,run}}),/no GUI session|observation_unknown/);
 }
 assert.deepEqual(mutationCalls(f),[]);
});

test('login binding is authoritative, read-only and stable across normal Quit',t=>{
 const f=fixture(t),absent=readDeploymentAppLoginBinding(f.stateDir,f.cli);
 assert.equal(absent.installed,false);f.mutate('login',true);
 f.calls.length=0;const before=readDeploymentAppLoginBinding(f.stateDir,f.cli);
 assert.equal(before.installed,true);assert.equal(before.appPath,f.appPath);assert.equal(before.disabledOverride,false);assert.equal(before.loginPreference,'enabled');assert.equal(before.loaded,undefined);assert.match(before.sha256,/^[a-f0-9]{64}$/);assert.deepEqual(mutationCalls(f),[]);
 f.mutate('quit');f.calls.length=0;assert.deepEqual(readDeploymentAppLoginBinding(f.stateDir,f.cli),before);assert.deepEqual(mutationCalls(f),[]);
 f.disabled.delete(label);assert.equal(readDeploymentAppLoginBinding(f.stateDir,f.cli).disabledOverride,null);
 f.disabled.set(label,true);assert.equal(readDeploymentAppLoginBinding(f.stateDir,f.cli).loginPreference,'disabled');
});
test('login binding rejects changed or redirected definitions, unknown preferences and unverified App',t=>{
 const f=fixture(t);f.mutate('login',true);const file=path.join(f.home,'Library/LaunchAgents',label+'.plist'),original=fs.readFileSync(file);f.calls.length=0;
 fs.appendFileSync(file,'<!-- changed -->');assert.throws(()=>readDeploymentAppLoginBinding(f.stateDir,f.cli),/login_definition_changed/);fs.writeFileSync(file,original);
 const badSignature={operations:{...f.operations,verifyApp:()=>{throw Error('signature_invalid')}}};assert.throws(()=>readDeploymentAppLoginBinding(f.stateDir,badSignature),/signature_invalid/);
 for(const text of ['unavailable','disabled services = {\n "app.styx.desktop-login" => unknown\n}', 'disabled services = {\n "app.styx.desktop-login" => false\n "app.styx.desktop-login" => unknown\n}'])assert.throws(()=>readDeploymentAppLoginBinding(f.stateDir,{operations:{...f.operations,run:(bin,args)=>args[0]==='print-disabled'?text:f.operations.run(bin,args)}}),/preference_unknown/);
 fs.renameSync(file,file+'.original');fs.symlinkSync(file+'.original',file);assert.throws(()=>readDeploymentAppLoginBinding(f.stateDir,f.cli),/not_regular/);fs.unlinkSync(file);fs.linkSync(file+'.original',file);assert.throws(()=>readDeploymentAppLoginBinding(f.stateDir,f.cli),/definition_untrusted/);fs.unlinkSync(file);fs.renameSync(file+'.original',file);
 fs.renameSync(path.dirname(file),path.dirname(file)+'.original');fs.symlinkSync(path.dirname(file)+'.original',path.dirname(file));assert.throws(()=>readDeploymentAppLoginBinding(f.stateDir,f.cli),/directory_untrusted/);
 assert.deepEqual(mutationCalls(f),[]);
});
