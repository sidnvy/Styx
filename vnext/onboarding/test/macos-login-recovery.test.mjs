import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {macLoginRecoveryPlan,controlMacLoginRecovery} from '../macos-login-recovery.mjs';
function fixture(t){
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'styx-login-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 fs.mkdirSync(path.join(home,'Library','LaunchAgents'),{recursive:true});
 const appPath=path.join(home,'Styx.app');fs.mkdirSync(appPath);
 const config={appPath,logDir:path.join(home,'logs')},calls=[],loaded=new Set(),definitions=new Map();
 const run=(bin,args)=>{
  calls.push([bin,args]);if(bin==='/usr/bin/codesign')return '';
  const [op,target]=args;
  if(op==='print'&&target==='gui/'+process.getuid())return 'session = Aqua';
  if(op==='print'){if(loaded.has(target))return definitions.get(target)??'state = running\n pid = 42';const e=Error();e.stderr='Could not find service';throw e;}
  if(op==='bootstrap'){
   const label=path.basename(args[2],'.plist');loaded.add(target+'/'+label);
   const plan=macLoginRecoveryPlan(config).find(e=>e.label===label);
   definitions.set(target+'/'+label,'state = running\n pid = 42\n path = '+args[2]+'\n arguments = {\n'+plan.args.map(arg=>'  '+arg).join('\n')+'\n }\n');
  }
  if(op==='bootout')loaded.delete(target);
  return '';
 };
 let elapsed=0;const waits=[];
 return {home,config,calls,loaded,definitions,waits,elapsed:()=>elapsed,opts:{home,platform:'darwin',uid:process.getuid(),run,authorize:true,now:()=>elapsed,wait:ms=>{waits.push(ms);elapsed+=ms}}};
}
test('LaunchServices wait; throttled recovery for all exits; Aqua login only',()=>{
 const [app,tunnel]=macLoginRecoveryPlan({logDir:'/tmp/log & dir',tunnelRoot:'/tmp/tunnel root'});
 assert.deepEqual(app.args,['/usr/bin/open','-W','-g','/Applications/Styx.app']);
 for(const p of [app,tunnel]){assert.match(p.plist,/<key>KeepAlive<\/key><true\/>/);assert.match(p.plist,/<integer>15<\/integer>/);assert.match(p.plist,/<string>Aqua<\/string>/);assert.match(p.plist,/log &amp; dir/);assert.doesNotMatch(p.plist,/NetworkState|SuccessfulExit|api.key|Bearer/);}
 assert.ok(tunnel.args.includes('/tmp/tunnel root/profiles/bieber.yaml'));
});
test('repeatable install; stop, start, uninstall only owned definitions',t=>{
 const f=fixture(t);assert.equal(controlMacLoginRecovery(f.config,{...f.opts,action:'install'}).services[0].running,true);
 controlMacLoginRecovery(f.config,{...f.opts,action:'install'});assert.equal(f.calls.filter(x=>x[1][0]==='bootstrap').length,1);
 assert.equal(controlMacLoginRecovery(f.config,{...f.opts,action:'stop'}).services[0].loaded,false);
 controlMacLoginRecovery(f.config,{...f.opts,action:'start'});assert.equal(f.loaded.size,1);
 assert.equal(controlMacLoginRecovery(f.config,{...f.opts,action:'uninstall'}).services[0].installed,false);
});
test('reject absent authorization or foreign definitions before mutation',t=>{
 const f=fixture(t);
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,authorize:false,action:'install'}),/authorization/);
 fs.writeFileSync(path.join(f.home,'Library/LaunchAgents/app.styx.desktop-login.plist'),'foreign',{mode:0o600});
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'install'}),/definition_mismatch/);
 assert.equal(f.calls.some(x=>['disable','enable','bootstrap'].includes(x[1][0])),false);
});
test('no GUI login or unknown transport is not an absent job; reject unsafe paths',t=>{
 const f=fixture(t);assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,run:()=>{throw Error('no gui domain')}}),/no gui domain/);
 for(const logDir of ['relative','/tmp/../etc','/tmp/line\nbreak'])assert.throws(()=>macLoginRecoveryPlan({logDir}),/invalid_path/);
});

test('explicit Quit unloads current recovery, preserves legacy plist and next-login preference',t=>{
 const f=fixture(t);
 controlMacLoginRecovery(f.config,{...f.opts,action:'install'});
 const file=path.join(f.home,'Library/LaunchAgents/app.styx.desktop-login.plist');
 const legacyBytes=fs.readFileSync(file);
 // Existing v1 KeepAlive definitions need no replacement or reinstall. They
 // retain identity, launch arguments and on-disk next-login behavior verbatim.
 assert.match(legacyBytes.toString(),/<key>KeepAlive<\/key><true\/>/);
 f.calls.length=0;
 const result=controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'});
 assert.equal(result.currentSessionRecovery,'suspended');
 assert.equal(result.loginPreference,'unchanged');
 assert.equal(result.services[0].installed,true);
 assert.equal(result.services[0].loaded,false);
 assert.deepEqual(fs.readFileSync(file),legacyBytes);
 assert.deepEqual(f.calls.filter(x=>x[1][0]!=='print').map(x=>x[1][0]),['bootout']);
 // Repeated Quit is harmless; explicit start restores current-session recovery.
 controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'});
 assert.equal(f.calls.filter(x=>x[1][0]==='bootout').length,1);
 assert.equal(controlMacLoginRecovery(f.config,{...f.opts,action:'start'}).services[0].loaded,true);
});
test('Quit neither installs absent recovery nor changes independently managed jobs',t=>{
 const f=fixture(t),independent='gui/'+process.getuid()+'/app.styx.independent-cli';
 f.loaded.add(independent);
 const result=controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'});
 assert.equal(result.services[0].installed,false);
 assert.equal(f.loaded.has(independent),true);
 assert.equal(f.calls.some(x=>x[1][0]!=='print'),false);
});
test('Quit requires authorization and rejects a live job with foreign argv even when plist matches',t=>{
 const f=fixture(t);
 controlMacLoginRecovery(f.config,{...f.opts,action:'install'});
 f.calls.length=0;
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,authorize:false,action:'suspend'}),/authorization/);
 const target='gui/'+process.getuid()+'/app.styx.desktop-login';
 const original=f.definitions.get(target);
 f.definitions.set(target,original.replace('  /usr/bin/open','  /usr/bin/other'));
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'}),/loaded_definition_mismatch/);
 assert.equal(f.loaded.has(target),true);
 assert.equal(f.calls.some(x=>x[1][0]!=='print'),false);
});
test('Quit fails closed for a changed loaded source path or unobservable loaded definition',t=>{
 const f=fixture(t);
 controlMacLoginRecovery(f.config,{...f.opts,action:'install'});
 f.calls.length=0;
 const target='gui/'+process.getuid()+'/app.styx.desktop-login';
 const original=f.definitions.get(target);
 for(const definition of [original.replace(' path = ',' path = /other'),'state = running\n pid = 42']){
  f.definitions.set(target,definition);
  assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'}),/loaded_definition_mismatch/);
 }
 assert.equal(f.calls.some(x=>x[1][0]!=='print'),false);
});
test('Quit refuses an orphan loaded job and never reports unconfirmed unload as success',t=>{
 const f=fixture(t),target='gui/'+process.getuid()+'/app.styx.desktop-login';
 f.loaded.add(target);
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'}),/unowned_loaded_job/);
 f.loaded.delete(target);
 controlMacLoginRecovery(f.config,{...f.opts,action:'install'});
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'suspend',run:(bin,args)=>{
  if(args[0]==='bootout')return ''; // Simulate launchd failing to complete unload.
  return f.opts.run(bin,args);
 }}),/unload_unconfirmed/);
 assert.equal(f.loaded.has(target),true);
});

test('suspending previously stopped recovery does not enable next-login startup',t=>{
 const f=fixture(t);
 controlMacLoginRecovery(f.config,{...f.opts,action:'install'});
 controlMacLoginRecovery(f.config,{...f.opts,action:'stop'});
 f.calls.length=0;
 const result=controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'});
 assert.equal(result.loginPreference,'unchanged');
 assert.equal(result.services[0].loaded,false);
 assert.equal(f.calls.some(x=>x[1][0]!=='print'),false);
});
test('a foreign tunnel definition refuses the whole explicit plan before unloading the App',t=>{
 const f=fixture(t);
 f.config.tunnelRoot=path.join(f.home,'tunnel');
 for(const e of macLoginRecoveryPlan(f.config)){
  const file=path.join(f.home,'Library/LaunchAgents',e.label+'.plist');
  fs.writeFileSync(file,e.plist,{mode:0o600});
  f.opts.run('/bin/launchctl',['bootstrap','gui/'+process.getuid(),file]);
 }
 const tunnel='gui/'+process.getuid()+'/app.styx.bieber-tunnel';
 f.definitions.set(tunnel,f.definitions.get(tunnel).replace('  run','  other-mode'));
 f.calls.length=0;
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'suspend'}),/loaded_definition_mismatch/);
 assert.equal(f.loaded.size,2);
 assert.equal(f.calls.some(x=>x[1][0]!=='print'),false);
});


test('fresh login install creates only the missing private LaunchAgents directory',t=>{
 const f=fixture(t),dir=path.join(f.home,'Library/LaunchAgents');fs.rmdirSync(dir);
 assert.equal(controlMacLoginRecovery(f.config,{...f.opts,action:'status'}).services[0].installed,false);
 assert.equal(fs.existsSync(dir),false); // Read-only observation must not create it.
 const result=controlMacLoginRecovery(f.config,{...f.opts,action:'install'});
 assert.equal(result.services[0].running,true);
 assert.equal(fs.lstatSync(dir).mode&0o777,0o700);
 assert.equal(fs.lstatSync(path.join(dir,'app.styx.desktop-login.plist')).mode&0o777,0o600);
});
test('login install refuses unsafe existing Library or LaunchAgents instead of repairing them',t=>{
 for(const unsafe of ['writable-library','symlink-library','writable-launch-agents','symlink-launch-agents']){
  const f=fixture(t),library=path.join(f.home,'Library'),dir=path.join(library,'LaunchAgents');
  const target=unsafe.endsWith('library')?library:dir;
  if(unsafe.startsWith('writable'))fs.chmodSync(target,0o777);
  else{fs.renameSync(target,target+'.original');fs.symlinkSync(target+'.original',target);}
  assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'install'}),/untrusted_launch_directory/);
  assert.equal(f.calls.some(x=>['disable','enable','bootstrap'].includes(x[1][0])),false);
  assert.equal(fs.existsSync(path.join(dir,'app.styx.desktop-login.plist')),false);
  assert.equal(fs.existsSync(f.config.logDir),false);
 }
});

for(const action of ['suspend','stop','uninstall'])test(`${action} waits for native bootout settlement exactly once and keeps definition until confirmed`,t=>{
 const f=fixture(t);controlMacLoginRecovery(f.config,{...f.opts,action:'install'});
 const target='gui/'+process.getuid()+'/app.styx.desktop-login',file=path.join(f.home,'Library/LaunchAgents/app.styx.desktop-login.plist'),original=fs.readFileSync(file);f.calls.length=0;
 let bootout=false,postReads=0;const timeouts=[];
 const run=(bin,args,options)=>{
  if(args[0]==='bootout'){bootout=true;f.calls.push([bin,args]);return '';}
  if(bootout&&args[0]==='print'&&args[1]===target&&options.timeout<=5000){
   timeouts.push(options.timeout);assert.deepEqual(fs.readFileSync(file),original);
   if(++postReads===4)f.loaded.delete(target);
  }
  return f.opts.run(bin,args,options);
 };
 const result=controlMacLoginRecovery(f.config,{...f.opts,action,run});
 assert.equal(result.services[0].loaded,false);assert.equal(result.services[0].installed,action!=='uninstall');assert.equal(f.elapsed(),300);
 assert.equal(f.calls.filter(x=>x[1][0]==='bootout').length,1);assert.deepEqual(timeouts.slice(0,4),[5000,4900,4800,4700]);
 assert.deepEqual(f.calls.filter(x=>x[1][0]!=='print').map(x=>x[1][0]),action==='suspend'?['bootout']:['disable','bootout']);
 if(action!=='uninstall')assert.deepEqual(fs.readFileSync(file),original);
});
test('native unload deadline retains definition and does not retry bootout or kill when job remains loaded',t=>{
 const f=fixture(t);controlMacLoginRecovery(f.config,{...f.opts,action:'install'});f.calls.length=0;
 const file=path.join(f.home,'Library/LaunchAgents/app.styx.desktop-login.plist'),original=fs.readFileSync(file);
 assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'uninstall',run:(bin,args,options)=>{if(args[0]==='bootout'){f.calls.push([bin,args]);return ''}return f.opts.run(bin,args,options)}}),/unload_unconfirmed/);
 assert.equal(f.elapsed(),5000);assert.equal(f.waits.length,50);assert.deepEqual(fs.readFileSync(file),original);assert.equal(f.loaded.size,1);
 assert.equal(f.calls.filter(x=>x[1][0]==='bootout').length,1);assert(f.calls.every(([bin])=>bin==='/bin/launchctl'));
});
test('unknown or foreign definition during settlement fails immediately without deleting or reissuing commands',t=>{
 for(const failure of ['unknown','foreign-job','changed-file']){
  const f=fixture(t);controlMacLoginRecovery(f.config,{...f.opts,action:'install'});f.calls.length=0;
  const file=path.join(f.home,'Library/LaunchAgents/app.styx.desktop-login.plist');let bootout=false;
  const run=(bin,args,options)=>{
   if(args[0]==='bootout'){f.calls.push([bin,args]);bootout=true;if(failure==='changed-file')fs.appendFileSync(file,'<!-- changed -->');return '';}
   if(bootout&&args[0]==='print'){
    if(failure==='unknown')throw Object.assign(Error('unknown'),{stderr:'Permission denied'});
    if(failure==='foreign-job')return 'path = /foreign/entry.plist\n arguments = {\n /usr/bin/other\n }';
   }
   return f.opts.run(bin,args,options);
  };
  assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action:'uninstall',run}),/observation_unknown|loaded_definition_mismatch|existing_definition_mismatch/);
  assert.equal(f.waits.length,0);assert(fs.existsSync(file));assert.equal(f.calls.filter(x=>x[1][0]==='bootout').length,1);
 }
});
test('stop and uninstall reject foreign loaded argv before changing future login preference',t=>{
 for(const action of ['stop','uninstall']){
  const f=fixture(t);controlMacLoginRecovery(f.config,{...f.opts,action:'install'});const target='gui/'+process.getuid()+'/app.styx.desktop-login';
  f.definitions.set(target,f.definitions.get(target).replace('  /usr/bin/open','  /usr/bin/foreign'));f.calls.length=0;
  assert.throws(()=>controlMacLoginRecovery(f.config,{...f.opts,action}),/loaded_definition_mismatch/);assert(f.calls.every(x=>x[1][0]==='print'));
 }
});
