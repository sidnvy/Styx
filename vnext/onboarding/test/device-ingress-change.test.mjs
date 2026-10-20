import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync,X509Certificate,createPrivateKey} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {planDeviceIngressChange,applyDeviceIngressChange,rollbackDeviceIngressChange} from '../device-ingress-change.mjs';
import {readGatewayDeployment} from '../gateway-deployment-reader.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const write=(file,value)=>fs.writeFileSync(file,Buffer.isBuffer(value)||typeof value==='string'?value:JSON.stringify(value,null,2)+'\n',{mode:0o600});
const read=file=>JSON.parse(fs.readFileSync(file));
const hostIdentity=generateKeyPairSync('rsa',{modulusLength:3072}),tlsIdentity=generateKeyPairSync('rsa',{modulusLength:2048});
const target='192.0.2.10'; // Documentation-only address: tests never bind this IP.
const locks=['advance.lock','background.lock','capabilities.lock','onboarding-plugin.lock','account-acceptance.lock'];
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ingress-change-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const d=path.join(root,'deployment'),base=path.join(root,'host'),gateway=path.join(d,'gateway');
 for(const dir of [d,base,gateway,path.join(base,'device'),path.join(gateway,'enrollment'),path.join(gateway,'enrollment/tokens')])fs.mkdirSync(dir,{mode:0o700});
 const key=path.join(gateway,'private-key.pem'),cert=path.join(gateway,'certificate.pem');
 write(key,tlsIdentity.privateKey.export({type:'pkcs8',format:'pem'}));
 const certPem=execFileSync('/usr/bin/openssl',['req','-x509','-key',key,'-days','2','-subj','/CN=Styx original fixture','-addext','subjectAltName=IP:127.0.0.1'],{encoding:'utf8',stdio:['ignore','pipe','pipe']});write(cert,certPem);
 const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:38729',openssl:'/usr/bin/openssl',listenHost:'127.0.0.1'},host:{baseDir:base,bundle:path.join(root,'bundle'),publisherKeyFile:path.join(base,'publisher.pem'),publisherSha256:'a'.repeat(64),label:'fixture',computer:false}};
 const runtime={schema:1,url:config.gateway.url,listenHost:'127.0.0.1',tlsCertificateFile:cert,tlsPrivateKeyFile:key,modelTokenFile:path.join(gateway,'model.token'),adminTokenFile:path.join(gateway,'admin.token'),enrollmentDir:path.join(gateway,'enrollment'),catalogFile:path.join(gateway,'targets.json')};
 write(path.join(d,'deployment.json'),config);write(path.join(gateway,'runtime.json'),runtime);write(path.join(gateway,'owner.json'),{gateway_url:config.gateway.url,gateway_ca_file:cert,admin_token_file:runtime.adminTokenFile});
 write(runtime.modelTokenFile,'fixture-model-credential-not-for-network');write(runtime.adminTokenFile,'fixture-admin-credential-not-for-network');write(runtime.catalogFile,{version:1,targets:[]});
 const id='styx-'+ '1'.repeat(24),fingerprint=sha(hostIdentity.publicKey.export({type:'spki',format:'der'}));
 write(path.join(base,'device/identity.json'),{device_id:id,fingerprint});write(path.join(base,'device/identity.pem'),hostIdentity.privateKey.export({type:'pkcs8',format:'pem'}));write(path.join(base,'device/host.token'),'fixture-host-token');
 write(path.join(base,'device/host.json'),{host_id:id,gateway_ws_url:config.gateway.url.replace('https:','wss:')+'/',gateway_ca_file:path.join(base,'gateway-ca.pem'),token_file:path.join(base,'device/host.token'),exec:{binary:'/fixture/codex'},computer:{enabled:false}});
 write(path.join(base,'gateway-ca.pem'),certPem);write(path.join(base,'enrollment.json'),{gateway_url:config.gateway.url,gateway_ca_file:path.join(base,'gateway-ca.pem'),storage_dir:path.join(base,'device'),label:'fixture'});
 write(path.join(base,'service.json'),{unitName:'styx-host.service'});write(path.join(base,'publisher.pem'),'fixture-publisher');
 write(path.join(gateway,'enrollment/state.json'),{version:1,invitations:[],pending:[{status:'claimed',device_id:id}],devices:[{id,fingerprint,status:'approved',target:{id}}]});write(path.join(gateway,'enrollment/tokens',id+'.token'),'fixture-approved-token');
 const evidence=file=>({path:file,sha256:sha(fs.readFileSync(file))});
 const state={schema:1,mode:'create-local',configSha256:sha(fs.readFileSync(path.join(d,'deployment.json'))),steps:[
  {id:'gateway.prepare',status:'succeeded',evidence:{runtime:evidence(path.join(gateway,'runtime.json')),certificate:evidence(cert),ownerConfiguration:evidence(path.join(gateway,'owner.json'))}},
  {id:'gateway.start',status:'succeeded',evidence:{url:config.gateway.url}},{id:'gateway.verify',status:'succeeded',evidence:{status:'gateway_verified'}},
  {id:'host.prepare',status:'succeeded',evidence:{enrollmentConfiguration:evidence(path.join(base,'enrollment.json')),serviceConfiguration:evidence(path.join(base,'service.json'))}},
  {id:'host.pair',status:'succeeded',evidence:{device_id:id}},{id:'host.doctor',status:'succeeded',evidence:{status:'ready'}},
  {id:'host.service.status',status:'succeeded'}]};
 state.onboardingDecisions={background:{choice:'foreground',configSha256:state.configSha256}};write(path.join(d,'state.json'),state);
 write(path.join(d,'background.json'),{schema:1,configSha256:state.configSha256,status:'not_configured',operations:[]});write(path.join(d,'capabilities.json'),{schema:1,configSha256:state.configSha256,status:'completed'});
 let reservations=0;
 // Injected OS observations are transaction-unit evidence only. There are no
 // service changes, no actual interface assignment, and no listening socket.
 const adapters={addresses:()=>[target],observeGateway:async()=>({service:'not_installed',processes:'none'}),observeHost:async()=>({status:'reported',installed:false,state:'not_installed'}),reservePorts:async()=>{reservations++;return async()=>{reservations--}}};
 return {d,base,root,gateway,key,cert,config,state,id,adapters,plan:()=>planDeviceIngressChange(d,{listenHost:target},adapters),reserved:()=>reservations};
}
test('review is read-only, binds every derived file, makes TLS identity and network exposure explicit',t=>{
 const f=fixture(t),before=fs.readFileSync(f.key),plan=f.plan();
 assert.equal(plan.status,'reviewable');assert.equal(plan.changes.length,10);assert.equal(plan.remoteUsable,false);
 assert.equal(plan.tls.identityChange,'certificate_reissued_same_private_key');assert.notEqual(plan.tls.beforeSha256,plan.tls.afterSha256);
 assert.equal(plan.networkScope,'single_owned_interface_address_all_sources_with_styx_authentication');
 assert.ok(plan.preserved.some(item=>item.path===f.key));assert.ok(plan.preserved.some(item=>item.path.endsWith('/identity.pem')));
 assert.deepEqual(fs.readFileSync(f.key),before);assert.equal(fs.existsSync(path.join(f.d,'ingress-changes')),false);
 assert.equal(JSON.stringify(plan).includes('PRIVATE KEY'),false);assert.equal(JSON.stringify(plan).includes('fixture-host-token'),false);
});
test('offline apply and byte-exact rollback preserve keys, pairing, capabilities and identities',async t=>{
 const f=fixture(t),plan=f.plan(),before=plan.changes.map(file=>[file.path,fs.readFileSync(file.path)]),preserved=plan.preserved.map(file=>[file.path,fs.readFileSync(file.path)]);
 const result=await applyDeviceIngressChange(f.d,{plan,authorize:true},f.adapters);
 assert.equal(result.status,'configured_unverified');assert.equal(result.remoteReachability,'NOT VERIFIED');assert.equal(result.accountAcceptance,'REQUIRED AGAIN');assert.equal(f.reserved(),0);
 const gateway=readGatewayDeployment(f.d);assert.equal(gateway.config.gateway.listenHost,target);assert.equal(gateway.runtime.url,plan.origin);
 const certificate=new X509Certificate(fs.readFileSync(f.cert));assert.equal(certificate.checkIP(target),target);assert.equal(certificate.checkPrivateKey(createPrivateKey(fs.readFileSync(f.key))),true);
 assert.equal(read(path.join(f.base,'device/host.json')).gateway_ws_url,plan.origin.replace('https:','wss:')+'/');
 assert.equal(read(path.join(f.base,'enrollment.json')).gateway_url,plan.origin);assert.deepEqual(fs.readFileSync(path.join(f.base,'gateway-ca.pem')),fs.readFileSync(f.cert));
 const state=read(path.join(f.d,'state.json'));assert.equal(state.steps.find(step=>step.id==='host.pair').evidence.device_id,f.id);assert.equal(state.steps.find(step=>step.id==='gateway.verify').status,'pending');assert.equal(state.onboardingDecisions.background.configSha256,state.configSha256);
 for(const [file,value] of preserved)assert.deepEqual(fs.readFileSync(file),value);
 const rolled=await rollbackDeviceIngressChange(f.d,{transactionId:result.transactionId,authorize:true},f.adapters);assert.equal(rolled.status,'rolled_back');assert.equal(f.reserved(),0);
 for(const [file,value] of [...before,...preserved])assert.deepEqual(fs.readFileSync(file),value);
 for(const lock of locks)assert.equal(fs.existsSync(path.join(f.d,lock)),false);
 await assert.rejects(rollbackDeviceIngressChange(f.d,{transactionId:result.transactionId,authorize:true},f.adapters),/not_rollbackable/);
});
test('wildcard, loopback, unowned IP, plan tampering and changed protected bytes are rejected',async t=>{
 const f=fixture(t);
 for(const listenHost of ['0.0.0.0','127.0.0.1','192.0.2.11','::'])assert.throws(()=>planDeviceIngressChange(f.d,{listenHost},f.adapters),/exact_owned_ipv4/);
 const plan=f.plan();await assert.rejects(applyDeviceIngressChange(f.d,{plan:{...plan,origin:'https://evil.example'},authorize:true},f.adapters),/reviewed_plan_changed/);
 write(path.join(f.base,'device/host.token'),'changed');await assert.rejects(applyDeviceIngressChange(f.d,{plan,authorize:true},f.adapters),/reviewed_plan_changed/);
 assert.equal(fs.existsSync(path.join(f.d,'ingress-changes')),false);
});
test('approved remote devices, unfinished pairing and configured chat are explicit blockers',async t=>{
 for(const scenario of ['remote','pairing','tunnel','plugin']){
  const f=fixture(t),dbFile=path.join(f.gateway,'enrollment/state.json'),db=read(dbFile);
  if(scenario==='remote'){db.devices.push({id:'other',fingerprint:'b'.repeat(64),status:'approved'});write(dbFile,db)}
  if(scenario==='pairing'){db.invitations.push({used:false,exp:Date.now()+60000});write(dbFile,db)}
  if(scenario==='tunnel'){fs.mkdirSync(path.join(f.d,'tunnel'),{mode:0o700});write(path.join(f.d,'tunnel/connection.json'),{tunnelId:'fixture'})}
  if(scenario==='plugin')write(path.join(f.d,'onboarding-plugin.json'),{presentation:{name:'preserve me'}});
  const plan=f.plan();assert.equal(plan.status,'blocked');await assert.rejects(applyDeviceIngressChange(f.d,{plan,authorize:true},f.adapters),/plan_blocked/);
 }
});
test('running, installed, unknown services or foreground ownership block before file changes',async t=>{
 const f=fixture(t),plan=f.plan(),before=fs.readFileSync(path.join(f.d,'deployment.json'));
 for(const observeGateway of [async()=>({service:'running',processes:'none'}),async()=>undefined])await assert.rejects(applyDeviceIngressChange(f.d,{plan,authorize:true},{...f.adapters,observeGateway}),/gateway_quiescence/);
 await assert.rejects(applyDeviceIngressChange(f.d,{plan,authorize:true},{...f.adapters,observeHost:async()=>({status:'reported',installed:true,state:'stopped'})}),/host_quiescence/);
 write(path.join(f.d,'foreground.lock'),'independent owner');await assert.rejects(applyDeviceIngressChange(f.d,{plan,authorize:true},f.adapters),/foreground_or_tunnel_owner/);
 assert.deepEqual(fs.readFileSync(path.join(f.d,'deployment.json')),before);assert.equal(f.reserved(),0);
});
test('partial apply retains locks and explicit rollback restores exact originals',async t=>{
 const f=fixture(t),plan=f.plan(),before=plan.changes.map(file=>[file.path,fs.readFileSync(file.path)]);let writes=0;
 await assert.rejects(applyDeviceIngressChange(f.d,{plan,authorize:true},{...f.adapters,replaceManagedFile:(file,data)=>{if(++writes===3)throw Error('injected interrupted write');write(file,data)}}),/uncertain_explicit_rollback/);
 assert.equal(read(path.join(f.d,'ingress-changes',plan.reviewSha256,'journal.json')).status,'uncertain');
 for(const lock of locks)assert.equal(fs.existsSync(path.join(f.d,lock)),true);
 const result=await rollbackDeviceIngressChange(f.d,{transactionId:plan.reviewSha256,authorize:true},f.adapters);assert.equal(result.status,'rolled_back');
 for(const [file,value] of before)assert.deepEqual(fs.readFileSync(file),value);
 for(const lock of locks)assert.equal(fs.existsSync(path.join(f.d,lock)),false);
});
test('rollback refuses foreign changes and cannot erase a preserved pairing update',async t=>{
 const f=fixture(t),plan=f.plan();await applyDeviceIngressChange(f.d,{plan,authorize:true},f.adapters);
 const file=path.join(f.gateway,'enrollment/state.json'),db=read(file);db.devices[0].status='revoked';write(file,db);
 await assert.rejects(rollbackDeviceIngressChange(f.d,{transactionId:plan.reviewSha256,authorize:true},f.adapters),/preserved_identity_or_credentials_changed/);
 assert.equal(read(file).devices[0].status,'revoked');
});
test('failed rollback preflight after completed apply releases its new locks for safe retry',async t=>{
 const f=fixture(t),plan=f.plan();await applyDeviceIngressChange(f.d,{plan,authorize:true},f.adapters);
 await assert.rejects(rollbackDeviceIngressChange(f.d,{transactionId:plan.reviewSha256,authorize:true},{...f.adapters,observeGateway:async()=>({service:'running',processes:'some'})}),/gateway_quiescence/);
 for(const lock of locks)assert.equal(fs.existsSync(path.join(f.d,lock)),false);
 assert.equal((await rollbackDeviceIngressChange(f.d,{transactionId:plan.reviewSha256,authorize:true},f.adapters)).status,'rolled_back');
});

test('expired invitations and handshakes remain preserved without granting new trust',t=>{
 const f=fixture(t),file=path.join(f.gateway,'enrollment/state.json'),db=read(file);
 db.invitations.push({used:false,exp:1});db.pending.push({status:'pending',exp:1},{status:'approved',claim_expires_at:1});write(file,db);
 const before=fs.readFileSync(file),plan=f.plan();assert.equal(plan.status,'reviewable');assert.deepEqual(fs.readFileSync(file),before);
});
test('Gateway-only change does not create or configure a Host',async t=>{
 const f=fixture(t),configFile=path.join(f.d,'deployment.json'),config=read(configFile),runtimeRoot=path.join(f.root,'gateway-runtime');
 delete config.host;config.gateway.runtime={baseDir:runtimeRoot,bundle:path.join(f.root,'runtime-bundle'),publisherKeyFile:path.join(f.root,'gateway-publisher.pem'),publisherSha256:'c'.repeat(64)};
 write(configFile,config);const stateFile=path.join(f.d,'state.json'),state=read(stateFile);state.configSha256=sha(fs.readFileSync(configFile));state.steps=state.steps.filter(step=>!step.id.startsWith('host.'));state.steps.unshift({id:'gateway.runtime.prepare',status:'succeeded'});write(stateFile,state);
 for(const name of ['background','capabilities']){const file=path.join(f.d,name+'.json'),value=read(file);value.configSha256=state.configSha256;write(file,value)}
 write(path.join(f.gateway,'enrollment/state.json'),{version:1,invitations:[],pending:[],devices:[]});
 const originalHost=fs.readFileSync(path.join(f.base,'device/host.json')),plan=f.plan();assert.equal(plan.changes.some(file=>file.name.startsWith('host')),false);
 await applyDeviceIngressChange(f.d,{plan,authorize:true},f.adapters);assert.equal(read(configFile).host,undefined);assert.deepEqual(fs.readFileSync(path.join(f.base,'device/host.json')),originalHost);
 await rollbackDeviceIngressChange(f.d,{transactionId:plan.reviewSha256,authorize:true},f.adapters);
});
