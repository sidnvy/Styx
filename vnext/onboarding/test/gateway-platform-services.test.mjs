import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
import {platformGatewayPlan,platformGatewayDefinition,platformGatewayService,launchdEnablement} from '../gateway-platform-services.mjs';
const descriptor=platform=>{const stateDir=platform==='win32'?'C:\\Users\\Owner\\Styx State':'/Users/owner/Styx State';return {stateDir,nodeBinary:platform==='win32'?'C:\\Styx Runtime\\node.exe':'/Users/owner/Styx Runtime/node',runner:platform==='win32'?'C:\\Styx Source\\gateway-runner.mjs':'/Users/owner/Styx Source/gateway-runner.mjs',identityHash:createHash('sha256').update(stateDir).digest('hex')}};
test('fixed per-user identity is bound to the full verified state path hash',()=>{
 for(const platform of ['darwin','win32']){const d=descriptor(platform),p=platformGatewayPlan(d,{platform});assert.ok(p.name.endsWith(d.identityHash.slice(0,12)));assert.ok(p.marker.endsWith(d.identityHash));assert.equal(p.systemBootWithoutLogin,'NOT CONFIGURED');assert.equal(p.startEnablesStartup,true);assert.throws(()=>platformGatewayPlan({...d,identityHash:'0'.repeat(64)},{platform}),/identity_mismatch/)}
});
test('unsupported platform, relative/traversal/newline and extra command fields are refused',()=>{
 assert.throws(()=>platformGatewayPlan(descriptor('darwin'),{platform:'linux'}));
 for(const platform of ['darwin','win32'])for(const patch of [{runner:'relative'},{nodeBinary:'bad\ncommand'},{command:'arbitrary'},{stateDir:platform==='win32'?'C:\\x\\..\\y':'/a/../b'}])assert.throws(()=>platformGatewayPlan({...descriptor(platform),...patch},{platform}));
});
test('macOS XML escapes legal path characters and contains a fixed argv rather than shell expansion',()=>{
 const d=descriptor('darwin');d.runner='/Users/owner/a "quote" & <tag> $(touch ignored).mjs';const plan=platformGatewayDefinition(d,{platform:'darwin'});
 assert.ok(plan.plist.includes('&quot;quote&quot; &amp; &lt;tag&gt; $(touch ignored).mjs'));assert.ok(plan.plist.includes('<key>ProgramArguments</key><array>'));assert.ok(!plan.plist.includes('/bin/sh'));assert.ok(plan.plist.includes('<!-- '+plan.marker+' -->'));
});
test('Windows script enforces owner, exact one action, interactive limited logon, disabled registration and fixed operations',()=>{
 const script=platformGatewayDefinition(descriptor('win32'),{platform:'win32'}).powershell;
 for(const part of ["$t.Description -ne $marker","$who -ne $sid","$t.Principal.RunLevel -ne 'Limited'",'@($t.Actions).Count -ne 1','$t.Actions.Execute -cne $d.nodeBinary','$t.Actions.Arguments -cne $arguments','$t.Actions.WorkingDirectory -cne $d.stateDir','New-ScheduledTaskSettingsSet -Disable','-LogonType Interactive -RunLevel Limited',"$session -eq 0",'STYX_GATEWAY_SERVICE_JSON'])assert.ok(script.includes(part),part);
 assert.ok(!script.includes('Invoke-Expression'));assert.ok(!script.includes('ExecutionPolicy'));assert.ok(!script.includes('SYSTEM -'));
 assert.ok(script.indexOf('Disable-ScheduledTask -TaskName $name')<script.indexOf('Stop-ScheduledTask -TaskName $name'));
});
test('invalid verbs or absent user authorization never execute a native command',()=>{
 let calls=0;for(const request of [{action:'restart',authorize:true},{action:'install'},{action:'start',authorize:false},{action:'uninstall',authorize:'yes'}])assert.throws(()=>platformGatewayService({...request,descriptor:descriptor('darwin')},{run(){calls++}}));assert.equal(calls,0);
});

test('launchd enablement accepts actual current macOS words and older Boolean rows',()=>{
 const name='app.styx.gateway.123';for(const [native,expected] of [['disabled','disabled'],['enabled','enabled'],['true','disabled'],['false','enabled'],['unrecognized','unknown']])assert.equal(launchdEnablement('\t"'+name+'" => '+native+'\n',name),expected);
 assert.equal(launchdEnablement('"other" => disabled',name),'default');
});

// Explicit native acceptance only; ordinary CI never registers a service.
test('opt-in isolated native per-user Gateway manager lifecycle',{
 skip:!['darwin','win32'].includes(process.platform)||process.env.STYX_RUN_GATEWAY_PLATFORM_NATIVE!=='1',timeout:90000
},async t=>{
 const root=path.join(os.tmpdir(),'styx-gateway-owned-'+randomBytes(8).toString('hex'));ensurePrivateDirectory(root);
 const stateDir=path.join(root,'private state');ensurePrivateDirectory(stateDir);const runner=path.join(root,'owned runner.mjs');fs.writeFileSync(runner,'setInterval(()=>{},1000);\n',{mode:0o600});
 const d={stateDir,nodeBinary:fs.realpathSync(process.execPath),runner,identityHash:createHash('sha256').update(stateDir).digest('hex')};const p=platformGatewayPlan(d);
 let attempted=false,clean=false;const call=action=>platformGatewayService({action,authorize:true,descriptor:d});
 const observe=async active=>{const end=Date.now()+10000;let s;do{s=call('status');if(s.active===active)return s;await new Promise(r=>setTimeout(r,200))}while(Date.now()<end);assert.fail('native state not observed')};
 try{
  assert.equal(call('status').status,'not_installed');attempted=true;const install=call('install');assert.equal(install.active,'inactive');assert.equal(install.enabled,'disabled');
  assert.equal(call('enable').enabled,'enabled');assert.equal(call('disable').enabled,'disabled');call('start');assert.ok((await observe('active')).pid>0);
  call('stop');assert.equal((await observe('inactive')).enabled,'disabled');assert.equal(call('uninstall').status,'uninstalled_state_preserved');assert.equal(call('status').status,'not_installed');clean=true;
  t.diagnostic('exact owned service '+p.name+' lifecycle and cleanup PASS; pinned runtime/Gateway protocol health NOT RUN');
 }finally{
  if(attempted&&!clean){try{call('uninstall');clean=true}catch{t.diagnostic('retain private fixture for exact owned service '+p.name+' inspection')}}
  if(clean||!attempted)fs.rmSync(root,{recursive:true,force:true});
 }
});
