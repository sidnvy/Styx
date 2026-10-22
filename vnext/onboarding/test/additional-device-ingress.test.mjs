import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import https from 'node:https';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {syncBuiltinESMExports} from 'node:module';
import {GatewayDeviceIngress} from '../../gateway/device-ingress.mjs';
import {ownerCommand} from '../../gateway/enroll-admin.mjs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {createDeployment,advanceDeployment,stopDeploymentGateway,createDeploymentPairingLink,prepareDeploymentDeviceIngress,recoverDeploymentDeviceIngress,readDeploymentDeviceIngressSetup,closeDeploymentPairingWindow,verifyDeviceIngress,localGatewayAddresses,listDeploymentPending,approveDeploymentPending} from '../core.mjs';
import {requestEnrollment} from '../../host/enroll.mjs';
import {recoverAdditionalDeviceIngress} from '../device-ingress-setup.mjs';
import {acceptPairingLink} from '../pairing-links.mjs';
import {deploymentConnectionHash} from '../../shared/deployment-scope.mjs';
import {startForegroundObservation,observeForegroundOwner} from '../foreground-observation.mjs';
const digest=value=>createHash('sha256').update(value).digest('hex');
const host=localGatewayAddresses()[0];
async function freePort(address){const server=net.createServer();await new Promise(resolve=>server.listen(0,address,resolve));const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
async function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-additional-entry-')),state=path.join(root,'deployment'),port=await freePort('127.0.0.1');
 const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl'},host:{bundle:path.join(root,'not-prepared-bundle'),publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'not-prepared-host'),label:'Core integration fixture',computer:false}};
 const input=path.join(root,'input.json');fs.writeFileSync(input,JSON.stringify(config),{mode:0o600});createDeployment(input,{stateDir:state});
 const cleanups=[];t.after(async()=>{for(const cleanup of cleanups)await cleanup();await stopDeploymentGateway(state);fs.rmSync(root,{recursive:true,force:true})});
 await advanceDeployment(state,{authorize:['gateway.prepare','gateway.start','gateway.verify']});
 const gateway=path.join(state,'gateway'),preserved=['private-key.pem','certificate.pem','model.token','admin.token','runtime.json','owner.json'].map(name=>[path.join(gateway,name),fs.readFileSync(path.join(gateway,name))]);
 return {root,state,config,preserved,cleanup:fn=>cleanups.push(fn)};
}
function get(url,ca){return new Promise((resolve,reject)=>{const req=https.get(url,{ca:fs.readFileSync(ca),agent:false},res=>{res.resume();res.on('end',()=>resolve(res.statusCode))});req.on('error',reject)})}
const options={skip:process.platform!=='linux'||!host,timeout:30000};
test('Core and CLI close legacy primary invitations instead of reporting an unchanged invitation as closed',options,async t=>{
 const f=await fixture(t),owner=JSON.parse(fs.readFileSync(path.join(f.state,'gateway/owner.json')));
 const database=path.join(f.state,'gateway/enrollment/state.json');
 for(const viaCLI of [false,true]){
  const invitation=await ownerCommand(owner,'invite',['600']);
  assert.equal(JSON.parse(fs.readFileSync(database)).invitations.at(-1).used,false);
  if(viaCLI){
   const child=spawn(process.execPath,[fileURLToPath(new URL('../cli.mjs',import.meta.url)),'pairing-close',f.state,'--authorize'],{stdio:['ignore','pipe','pipe']});
   let output='';child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>output+=chunk);
   assert.equal((await once(child,'close'))[0],0,output);assert.equal(JSON.parse(output).pairing.status,'closed');
  }else assert.equal((await closeDeploymentPairingWindow(f.state,{authorize:true})).pairing.status,'closed');
  assert.equal(JSON.parse(fs.readFileSync(database)).invitations.at(-1).used,true);
  await assert.rejects(requestEnrollment({gateway_url:f.config.gateway.url,gateway_ca_file:owner.gateway_ca_file,storage_dir:path.join(f.root,'rejected-'+viaCLI),label:'Closed invitation',cwd:f.root,shell:'/bin/sh',exec_binary:'/not-executed/exec',computer_requested:false},invitation.invitation),/invitation_expired_or_used/);
 }
 for(const [name,bytes] of f.preserved)assert.deepEqual(fs.readFileSync(name),bytes);
});
test('Core adds actual LAN TLS without changing primary identity, live observation scope or confirmation identity',options,async t=>{
 const f=await fixture(t),file=path.join(f.state,'deployment.json'),before=fs.readFileSync(file),scope=deploymentConnectionHash(before);
 fs.writeFileSync(path.join(f.state,'foreground.lock'),'fixture-owned-observer',{mode:0o600});
 const observer=await startForegroundObservation({stateDir:f.state,configurationHash:scope,projection:()=>({schema:1,status:'connected',host:'foreground',gateway:'foreground',execConnection:'connected',desktopConnection:'not_requested',browserConnection:'not_requested'})});
 f.cleanup(async()=>{await observer.close();fs.unlinkSync(path.join(f.state,'foreground.lock'))});
 const link=await createDeploymentPairingLink(f.state,{authorize:true,listenHost:host}),configured=JSON.parse(fs.readFileSync(file));
 assert.equal(new URL(configured.gateway.url).hostname,'127.0.0.1');assert.equal(deploymentConnectionHash(fs.readFileSync(file)),scope);
 assert.equal((await observeForegroundOwner(f.state)).observation,'authenticated_foreground_owner');
 assert.equal((await observeForegroundOwner(f.state)).status,'connected');
 for(const [name,bytes] of f.preserved)assert.deepEqual(fs.readFileSync(name),bytes);
 const imported=path.join(f.root,'joining');const joined=acceptPairingLink(link.link,{stateDir:imported,approvedGatewayOrigin:link.origin,approvedCaSha256:link.caSha256});
 assert.equal(joined.origin,configured.gateway.deviceIngress.url);assert.equal(await get(new URL('/styx/enroll/join',link.origin),path.join(imported,'gateway-ca.pem')),405);
 assert.equal(await get(new URL('/mcp',link.origin),path.join(imported,'gateway-ca.pem')),404);
 const requested=await requestEnrollment({gateway_url:link.origin,gateway_ca_file:path.join(imported,'gateway-ca.pem'),storage_dir:path.join(f.root,'joining-identity'),label:'Joining integration fixture',cwd:f.root,shell:'/bin/sh',exec_binary:'/not-executed/exec',computer_requested:false},fs.readFileSync(path.join(imported,'invitation'),'utf8').trim());
 const pending=await listDeploymentPending(f.state,{authorize:true});assert.equal(pending.length,1);assert.equal(pending[0].comparison_code,requested.comparison_code);
 await approveDeploymentPending(f.state,{authorize:true,requestId:pending[0].request_id,fingerprint:pending[0].fingerprint});
 const renewed=await createDeploymentPairingLink(f.state,{authorize:true});assert.equal(renewed.origin,link.origin);assert.equal(renewed.caSha256,link.caSha256);
 await closeDeploymentPairingWindow(f.state,{authorize:true});assert.equal(await get(new URL('/styx/enroll/join',link.origin),path.join(imported,'gateway-ca.pem')),405);
 const db=fs.readFileSync(path.join(f.state,'gateway/enrollment/state.json'));
 await recoverDeploymentDeviceIngress(f.state,{authorize:true,action:'rollback'});
 assert.deepEqual(fs.readFileSync(file),before);assert.deepEqual(fs.readFileSync(path.join(f.state,'gateway/enrollment/state.json')),db,'rollback must not erase approval');
 assert.equal(await get(new URL('/styx/enroll/pending',f.config.gateway.url),path.join(f.state,'gateway/certificate.pem')),401);
 assert.equal((await observeForegroundOwner(f.state)).status,'connected');
 assert.equal(fs.readdirSync(path.join(f.state,'device-ingress-transactions')).length,2);
});
test('a failed real listen retains a recoverable desired configuration and explicit retry reuses TLS identity',options,async t=>{
 const f=await fixture(t),occupied=net.createServer();await new Promise(resolve=>occupied.listen(0,host,resolve));const port=occupied.address().port;
 t.after(()=>{if(occupied.listening)occupied.close()});
 await assert.rejects(prepareDeploymentDeviceIngress(f.state,{authorize:true,listenHost:host,port}));
 assert.equal(readDeploymentDeviceIngressSetup(f.state).status,'needs_reconciliation');const entry=JSON.parse(fs.readFileSync(path.join(f.state,'deployment.json'))).gateway.deviceIngress;
 const certificate=path.join(f.state,'gateway/device-ingress',entry.generation,'certificate.pem'),before=digest(fs.readFileSync(certificate));
 assert.equal(await get(new URL('/styx/enroll/pending',f.config.gateway.url),path.join(f.state,'gateway/certificate.pem')),401);
 await new Promise(resolve=>occupied.close(resolve));await recoverDeploymentDeviceIngress(f.state,{authorize:true,action:'retry'});
 assert.equal(readDeploymentDeviceIngressSetup(f.state).status,'applied');assert.equal(digest(fs.readFileSync(certificate)),before);
 assert.equal(await get(new URL('/styx/enroll/join',entry.url),certificate),405);
 await recoverDeploymentDeviceIngress(f.state,{authorize:true,action:'rollback'});
});
test('a real process dying during preflight leaves an explicitly recoverable claim before any shared configuration changes',options,async t=>{
 const f=await fixture(t),config=fs.readFileSync(path.join(f.state,'deployment.json')),state=fs.readFileSync(path.join(f.state,'state.json'));
 const module=fileURLToPath(new URL('../device-ingress-setup.mjs',import.meta.url));
 const script='import {pathToFileURL} from "node:url";const {prepareAdditionalDeviceIngress}=await import(pathToFileURL(process.argv[1]));await prepareAdditionalDeviceIngress(process.argv[2],{authorize:true},{command:async()=>process.exit(77)});';
 const child=spawn(process.execPath,['--input-type=module','-e',script,module,f.state],{stdio:'ignore'});const [code]=await once(child,'exit');assert.equal(code,77);
 assert.equal(readDeploymentDeviceIngressSetup(f.state).status,'preparing');
 await recoverDeploymentDeviceIngress(f.state,{authorize:true,action:'rollback'});
 assert.deepEqual(fs.readFileSync(path.join(f.state,'deployment.json')),config);assert.deepEqual(fs.readFileSync(path.join(f.state,'state.json')),state);
 for(const name of ['device-ingress.lock','advance.lock','background.lock','capabilities.lock','onboarding-plugin.lock','account-acceptance.lock'])assert.equal(fs.existsSync(path.join(f.state,name)),false);
});

async function until(predicate){
 const deadline=Date.now()+10000;
 while(!predicate()){if(Date.now()>deadline)throw Error('concurrent ingress recovery barrier timed out');await new Promise(resolve=>setTimeout(resolve,5));}
}
test('two actual recoverers cannot delete each other claims or both restore/dispatch to the owner',options,async t=>{
 const f=await fixture(t),setupURL=new URL('../device-ingress-setup.mjs',import.meta.url).href,ownerURL=new URL('../../gateway/enroll-admin.mjs',import.meta.url).href;
 const children=[];f.cleanup(async()=>{for(const child of children)if(child.exitCode===null){child.kill('SIGKILL');await once(child,'close')}});
 const crashed=path.join(f.root,'crashed-prepare.mjs');
 fs.writeFileSync(crashed,`import fs from 'node:fs';import path from 'node:path';import {prepareAdditionalDeviceIngress} from ${JSON.stringify(setupURL)};import {ownerCommand} from ${JSON.stringify(ownerURL)};
const state=process.argv[2],listenHost=process.argv[3],owner=JSON.parse(fs.readFileSync(path.join(state,'gateway/owner.json')));
await prepareAdditionalDeviceIngress(state,{authorize:true,listenHost},{command:async(op,input)=>{if(op==='enable')process.exit(77);return ownerCommand(owner,op==='status'?'ingress-status':'ingress-prepare',op==='status'?[]:[JSON.stringify(input)]);}});`,{mode:0o600});
 const installer=spawn(process.execPath,[crashed,f.state,host],{stdio:['ignore','pipe','pipe']});children.push(installer);
 let failure='';installer.stderr.on('data',chunk=>failure+=chunk);assert.equal((await once(installer,'close'))[0],77,failure);
 const journal=JSON.parse(fs.readFileSync(path.join(f.state,'device-ingress-setup.json'))),generation=journal.descriptor.generation;
 assert.equal(journal.phase,'listen');assert.equal(JSON.parse(fs.readFileSync(path.join(f.state,'advance.lock'))).pid,installer.pid);
 const worker=path.join(f.root,'recover-worker.mjs'),go=path.join(f.root,'go'),finish=path.join(f.root,'finish');
 fs.writeFileSync(worker,`import fs from 'node:fs';import path from 'node:path';import {recoverAdditionalDeviceIngress} from ${JSON.stringify(setupURL)};import {ownerCommand} from ${JSON.stringify(ownerURL)};
const root=process.argv[2],state=process.argv[3],owner=JSON.parse(fs.readFileSync(path.join(state,'gateway/owner.json')));
fs.writeFileSync(path.join(root,'ready-'+process.pid),'ready');while(!fs.existsSync(path.join(root,'go')))await new Promise(resolve=>setTimeout(resolve,2));
try{const result=await recoverAdditionalDeviceIngress(state,{authorize:true,action:'retry'},{command:async(op,input)=>{
fs.appendFileSync(path.join(root,'calls-'+process.pid),op+'\\n');
if(op==='status'){fs.writeFileSync(path.join(root,'entered-'+process.pid),'owned');while(!fs.existsSync(path.join(root,'finish')))await new Promise(resolve=>setTimeout(resolve,2));}
const names={status:'ingress-status',prepare:'ingress-prepare',enable:'ingress-enable'};
return ownerCommand(owner,names[op],op==='status'?[]:op==='prepare'?[JSON.stringify(input)]:[input.generation]);}});console.log(JSON.stringify(result));}
catch(error){console.log(JSON.stringify({error:error.message}));process.exitCode=2;}`,{mode:0o600});
 const completed=[];
 const launch=()=>{
  const child=spawn(process.execPath,[worker,f.root,f.state],{stdio:['ignore','pipe','pipe']});children.push(child);let stdout='',stderr='';
  child.stdout.on('data',chunk=>stdout+=chunk);child.stderr.on('data',chunk=>stderr+=chunk);
  return new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>{const result={code,stdout,stderr};completed.push(result);resolve(result)})});
 };
 const runs=[launch(),launch()];await until(()=>fs.readdirSync(f.root).filter(name=>name.startsWith('ready-')).length===2);fs.writeFileSync(go,'start');
 await until(()=>fs.readdirSync(f.root).some(name=>name.startsWith('entered-'))&&completed.length===1);
 const entrants=fs.readdirSync(f.root).filter(name=>name.startsWith('entered-'));assert.equal(entrants.length,1);
 const ownerPid=Number(entrants[0].slice('entered-'.length)),guard=path.join(f.state,'device-ingress-recovery.lock');
 const guardBytes=fs.readFileSync(guard),primary=path.join(f.state,'device-ingress.lock'),primaryBytes=fs.readFileSync(primary),config=path.join(f.state,'deployment.json'),configuration=fs.readFileSync(config),inode=fs.statSync(config).ino;
 assert.equal(JSON.parse(guardBytes).pid,ownerPid);assert.equal(JSON.parse(primaryBytes).pid,ownerPid);
 assert.match(completed[0].stdout,/device_ingress_recovery_guard_requires_inspection/);
 await assert.rejects(prepareDeploymentDeviceIngress(f.state,{authorize:true}),/device_ingress_recovery_guard_requires_inspection/);
 await assert.rejects(recoverDeploymentDeviceIngress(f.state,{authorize:true,action:'rollback'}),/device_ingress_recovery_guard_requires_inspection/);
 assert.deepEqual(fs.readFileSync(guard),guardBytes);assert.deepEqual(fs.readFileSync(primary),primaryBytes);assert.equal(fs.statSync(config).ino,inode);assert.deepEqual(fs.readFileSync(config),configuration);
 assert.equal(readDeploymentDeviceIngressSetup(f.state).reason,'device_ingress_recovery_guard_requires_inspection');
 fs.writeFileSync(finish,'release');const results=await Promise.all(runs);assert.deepEqual(results.map(result=>result.code).sort(),[0,2],JSON.stringify(results));
 assert.equal(JSON.parse(results.find(result=>result.code===0).stdout).status,'applied');
 assert.deepEqual(fs.readdirSync(f.root).filter(name=>name.startsWith('calls-')),['calls-'+ownerPid]);
 assert.equal(fs.readFileSync(path.join(f.root,'calls-'+ownerPid),'utf8'),'status\nprepare\nenable\n');
 assert.equal(fs.existsSync(guard),false);assert.equal(fs.existsSync(primary),false);
 assert.equal(await get(new URL('/styx/enroll/join',journal.descriptor.url),path.join(f.state,'gateway/device-ingress',generation,'certificate.pem')),405);
 await recoverDeploymentDeviceIngress(f.state,{authorize:true,action:'rollback'});
});

test('leftover empty, unknown or dead-owner recovery guards stay untouched and block prepare and recovery',options,async t=>{
 const f=await fixture(t),guard=path.join(f.state,'device-ingress-recovery.lock'),config=fs.readFileSync(path.join(f.state,'deployment.json'));
 for(const content of ['', 'unknown owner\n', JSON.stringify({schema:1,kind:'additional-device-ingress-v1',transactionId:'a'.repeat(32),pid:2147483647,token:'b'.repeat(64)})]){
  fs.writeFileSync(guard,content,{mode:0o600});
  await assert.rejects(prepareDeploymentDeviceIngress(f.state,{authorize:true}),/device_ingress_recovery_guard_requires_inspection/);
  await assert.rejects(recoverDeploymentDeviceIngress(f.state,{authorize:true,action:'rollback'}),/device_ingress_recovery_guard_requires_inspection/);
  const status=readDeploymentDeviceIngressSetup(f.state);assert.equal(status.status,'needs_reconciliation');assert.equal(status.reason,'device_ingress_recovery_guard_requires_inspection');
  assert.equal(fs.readFileSync(guard,'utf8'),content);assert.deepEqual(fs.readFileSync(path.join(f.state,'deployment.json')),config);assert.equal(fs.existsSync(path.join(f.state,'device-ingress.lock')),false);
  fs.unlinkSync(guard); // Test-created inspection artifact, never product recovery.
 }
});


test('a replaced shared claim stops recovery before its next owner command and is never unlinked',options,async t=>{
 const f=await fixture(t),occupied=net.createServer();await new Promise(resolve=>occupied.listen(0,host,resolve));
 try{await assert.rejects(prepareDeploymentDeviceIngress(f.state,{authorize:true,listenHost:host,port:occupied.address().port}))}finally{await new Promise(resolve=>occupied.close(resolve))}
 const journalFile=path.join(f.state,'device-ingress-setup.json'),journalBytes=fs.readFileSync(journalFile),journal=JSON.parse(journalBytes),file=path.join(f.state,'capabilities.lock'),calls=[];
 let replacementBytes;
 await assert.rejects(recoverAdditionalDeviceIngress(f.state,{authorize:true,action:'retry'},{command:async operation=>{
  calls.push(operation);assert.equal(operation,'status');replacementBytes=fs.readFileSync(file);const replacement=file+'.replacement';fs.writeFileSync(replacement,replacementBytes,{mode:0o600});fs.renameSync(replacement,file);
  return {supported:true,status:'prepared',generation:journal.descriptor.generation};
 }}),/device_ingress_lock_changed/);
 assert.deepEqual(calls,['status']);assert.deepEqual(fs.readFileSync(file),replacementBytes);assert.deepEqual(fs.readFileSync(journalFile),journalBytes);
 assert.equal(fs.existsSync(path.join(f.state,'device-ingress-recovery.lock')),false);
 for(const [name,bytes] of f.preserved)assert.deepEqual(fs.readFileSync(name),bytes);
});

test('rollback cancels a startup retry before prepared material exists and never reopens its revoked entry',options,async t=>{
 const f=await fixture(t);await prepareDeploymentDeviceIngress(f.state,{authorize:true,listenHost:host});
 const journal=JSON.parse(fs.readFileSync(path.join(f.state,'device-ingress-setup.json'))),descriptor=journal.descriptor,owner=JSON.parse(fs.readFileSync(path.join(f.state,'gateway/owner.json')));
 await ownerCommand(owner,'ingress-disable',[descriptor.generation]);
 // Model only the temporarily absent interface observation. The descriptor,
 // key/certificate, Core journal, localhost listener and subsequent observation
 // are real; no network interface or service is changed by this test.
 const manager=new GatewayDeviceIngress({gateway:{relay:{attach(){},detach(){}}},enrollment:{now:Date.now,closePairingWindow(){}},restoreRetryIntervalsMs:[20]});f.cleanup(()=>manager.close());
 const networkInterfaces=os.networkInterfaces;let initial;
 try{os.networkInterfaces=()=>({});syncBuiltinESMExports();initial=await manager.restore(descriptor)}finally{os.networkInterfaces=networkInterfaces;syncBuiltinESMExports()}
 assert.equal(initial.status,'failed');assert.equal(initial.generation,undefined);assert.equal(initial.recovery.generation,descriptor.generation);assert.equal(initial.recovery.status,'waiting');assert.equal(manager.prepared,null);
 const calls=[],result=await recoverAdditionalDeviceIngress(f.state,{authorize:true,action:'rollback'},{command:async(operation,input)=>{calls.push(operation);if(operation==='status')return manager.status();if(operation==='disable')return manager.disable(input);throw Error('unexpected_rollback_operation')}});
 assert.equal(result.status,'rolled_back');assert.deepEqual(calls,['status','disable']);assert.equal(JSON.parse(fs.readFileSync(path.join(f.state,'deployment.json'))).gateway.deviceIngress,undefined);
 await new Promise(resolve=>setTimeout(resolve,120));assert.equal(manager.status().status,'absent');assert.equal(manager.status().recovery,undefined);assert.equal(manager.restoreTimer,null);assert.equal(manager.server,null);
 await assert.rejects(get(new URL('/styx/enroll/join',descriptor.url),descriptor.tlsCertificateFile),/ECONNREFUSED/);
 assert.equal(await get(new URL('/styx/enroll/pending',f.config.gateway.url),path.join(f.state,'gateway/certificate.pem')),401);
 for(const [file,bytes] of f.preserved)assert.deepEqual(fs.readFileSync(file),bytes);
});

test('rollback refuses foreign or unidentifiable retry ownership instead of relying on a failed phase',options,async t=>{
 const f=await fixture(t);await prepareDeploymentDeviceIngress(f.state,{authorize:true,listenHost:host});
 const journal=JSON.parse(fs.readFileSync(path.join(f.state,'device-ingress-setup.json'))),generation=journal.descriptor.generation,configuration=fs.readFileSync(path.join(f.state,'deployment.json'));
 for(const state of [
  {status:'failed'},
  {status:'failed',recovery:{status:'waiting'}},
  {status:'failed',generation,recovery:{status:'waiting',generation:'foreign-generation'}},
  {status:'failed',generation:'foreign-generation',recovery:{status:'waiting',generation}},
  {status:'prepared',generation:'foreign-generation'},
  {status:'absent',recovery:{status:'waiting',generation:'foreign-generation'}}
 ]){
  const calls=[];await assert.rejects(recoverAdditionalDeviceIngress(f.state,{authorize:true,action:'rollback'},{command:async operation=>{calls.push(operation);assert.equal(operation,'status');return {supported:true,...state}}}),/device_ingress_runtime_generation_changed/);
  assert.deepEqual(calls,['status']);assert.deepEqual(fs.readFileSync(path.join(f.state,'deployment.json')),configuration);
 }
 for(const [file,bytes] of f.preserved)assert.deepEqual(fs.readFileSync(file),bytes);
});

test('joining Core verifies the real restricted device listener without accessing owner routes', {skip:!host},async t=>{
 const f=await fixture(t);await prepareDeploymentDeviceIngress(f.state,{authorize:true,listenHost:host});
 const configured=JSON.parse(fs.readFileSync(path.join(f.state,'deployment.json'))),entry=configured.gateway.deviceIngress;
 const cert=path.join(f.state,'gateway/device-ingress',entry.generation,'certificate.pem');
 const input=path.join(f.root,'probe-input.json'),state=path.join(f.root,'probe-join');
 fs.writeFileSync(input,JSON.stringify({schema:1,mode:'join-existing',gateway:{url:entry.url,caFile:cert},host:{...f.config.host,baseDir:path.join(f.root,'probe-host')}}),{mode:0o600});
 createDeployment(input,{stateDir:state});
 const database=path.join(f.state,'gateway/enrollment/state.json');
 const before=fs.existsSync(database)?fs.readFileSync(database):null;
 assert.equal(await get(new URL('/styx/enroll/pending',entry.url),cert),404);
 const observed=await verifyDeviceIngress(state,{url:entry.url,expectedCertificateSha256:entry.certificateSha256});
 assert.equal(observed.status,'ingress_endpoint_verified');assert.equal(observed.enrollment,'unauthenticated_join_route_observed_without_mutation');
 assert.equal(observed.tls.certificate.sha256,entry.certificateSha256);assert.equal(observed.remoteUsable,false);
 if(before)assert.deepEqual(fs.readFileSync(database),before);else assert.equal(fs.existsSync(database),false);
});
