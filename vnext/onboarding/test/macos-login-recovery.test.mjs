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
 const config={appPath,logDir:path.join(home,'logs')},calls=[],loaded=new Set();
 const run=(bin,args)=>{
  calls.push([bin,args]);if(bin==='/usr/bin/codesign')return '';
  const [op,target]=args;
  if(op==='print'&&target==='gui/'+process.getuid())return 'session = Aqua';
  if(op==='print'){if(loaded.has(target))return 'state = running\n pid = 42';const e=Error();e.stderr='Could not find service';throw e;}
  if(op==='bootstrap')loaded.add(target+'/'+path.basename(args[2],'.plist'));
  if(op==='bootout')loaded.delete(target);
  return '';
 };
 return {home,config,calls,loaded,opts:{home,platform:'darwin',uid:process.getuid(),run,authorize:true}};
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
