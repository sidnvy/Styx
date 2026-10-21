import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import WebSocket from 'ws';
import {once} from 'node:events';
import {createHash,createPublicKey,generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
import {main} from '../cli.mjs';
import {ownerCommand} from '../../gateway/enroll-admin.mjs';
import {createDeployment,readDeployment,planDeployment,advanceDeployment,startDeploymentGateway,stopDeploymentGateway,validateDeployment,controlDeploymentHostService,createDeploymentPairingLink,listDeploymentPending,approveDeploymentPending,localGatewayAddresses,readDeploymentDevices,revokeDeploymentDevice,setLocalDeploymentDefault,setDeploymentDefault,readDeploymentBrowser,prepareDeploymentBrowser} from '../core.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
async function fixture(t,{browserPreparationModule}={}){
 const root=path.join(os.tmpdir(),'styx-onboarding-'+randomUUID());ensurePrivateDirectory(root);t.after(async()=>{const d=path.join(root,'deployment');if(fs.existsSync(d))await stopDeploymentGateway(d);fs.rmSync(root,{recursive:true,force:true});});
 const server=net.createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;await new Promise(r=>server.close(r));
 const bundle=path.join(root,'bundle');fs.mkdirSync(bundle);fs.mkdirSync(path.join(bundle,'host'));fs.mkdirSync(path.join(bundle,'bin'));
 const {publicKey,privateKey}=generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
 const exe=process.platform==='win32'?'.exe':'';const contents={};
 for(const f of ['private-storage.mjs','installer.mjs','launch.mjs'])contents['host/'+f]=fs.readFileSync(new URL('../../host/'+f,import.meta.url));
 for(const f of ['enroll.mjs','doctor.mjs','setup-native.mjs','linux-service.mjs','macos-launchagent.mjs','macos-native-launcher.mjs','windows-task.ps1'])contents['host/'+f]=Buffer.from('// signed test payload; never executed');
 contents['bin/node'+exe]=fs.readFileSync(process.execPath);for(const f of ['codex','cua-driver'])contents['bin/'+f+exe]=Buffer.from('test bytes never executed');
 if(browserPreparationModule){fs.mkdirSync(path.join(bundle,'packages/styx-browser-provider'),{recursive:true});contents['packages/styx-browser-provider/prepare.mjs']=Buffer.from(browserPreparationModule);}
 const manifest={schema:1,version:'0.1.0-test',platform:process.platform,arch:process.arch,files:Object.entries(contents).map(([name,b])=>{fs.writeFileSync(path.join(bundle,name),b);return {path:name,sha256:sha(b),size:b.length,executable:name.startsWith('bin/')};})};
 const raw=JSON.stringify(manifest);fs.writeFileSync(path.join(bundle,'manifest.json'),raw);fs.writeFileSync(path.join(bundle,'manifest.sig'),sign(null,Buffer.from(raw),privateKey).toString('base64url'));
 const publisherKeyFile=path.join(root,'publisher.pem');fs.writeFileSync(publisherKeyFile,publicKey);
 const config={schema:1,mode:'create-local',pairingMode:'manual',gateway:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl'},host:{bundle,publisherKeyFile,publisherSha256:sha(createPublicKey(publicKey).export({type:'spki',format:'der'})),baseDir:path.join(root,'host'),label:'Onboarding test',computer:false}};
 const configFile=path.join(root,'input.json');fs.writeFileSync(configFile,JSON.stringify(config),{mode:0o600});const stateDir=path.join(root,'deployment');
 return {root,config,configFile,stateDir};
}
const steps=s=>Object.fromEntries(s.steps.map(x=>[x.id,x]));
test('unified workflow uses actual TLS enrollment and separate explicit owner approval', {skip:process.platform!=='linux',timeout:30000},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 assert.equal(planDeployment(f.stateDir).service.status,'not_checked');
 let s=await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare','host.invite','host.request','host.claim']});
 assert.equal(steps(s)['host.request'].status,'succeeded');assert.equal(steps(s)['host.claim'].status,'awaiting_approval');
 const pending=steps(s)['host.request'].evidence;assert.match(pending.fingerprint,/^[a-f0-9]{64}$/);
 assert.equal(fs.existsSync(path.join(f.config.host.baseDir,'device/host.json')),false);
 const owner=JSON.parse(fs.readFileSync(path.join(f.stateDir,'gateway/owner.json')));
 await ownerCommand(owner,'approve',[pending.request_id,pending.fingerprint]);
 s=await advanceDeployment(f.stateDir,{authorize:['host.claim']});assert.equal(steps(s)['host.claim'].status,'succeeded');
 assert.equal(steps(s)['host.claim'].evidence.status,'ready_to_connect');
 const host=JSON.parse(fs.readFileSync(path.join(f.config.host.baseDir,'device/host.json')));assert.equal(host.gateway_ws_url,f.config.gateway.url.replace('https:','wss:')+'/');assert.equal(host.computer,undefined);
 const publicOutput=JSON.stringify(s);for(const name of ['model.token','admin.token']){const token=fs.readFileSync(path.join(f.stateDir,'gateway',name),'utf8').trim();assert.equal(publicOutput.includes(token),false);}
 assert.notEqual(fs.readFileSync(path.join(f.stateDir,'gateway/model.token'),'utf8'),fs.readFileSync(path.join(f.stateDir,'gateway/admin.token'),'utf8'));
 assert.equal(readDeployment(f.stateDir).accountAcceptance,'NOT RUN');
 const before=fs.readFileSync(path.join(f.stateDir,'state.json'),'utf8');await advanceDeployment(f.stateDir,{authorize:['host.claim']});assert.equal(fs.readFileSync(path.join(f.stateDir,'state.json'),'utf8'),before);
});
test('explicit authorization, strict schema, owner-private inputs and evidence prevent replay',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);assert.throws(()=>validateDeployment({...f.config,command:'arbitrary'}),/invalid_configuration_fields/);
 assert.throws(()=>validateDeployment({...f.config,gateway:{...f.config.gateway,url:'https://user:secret@127.0.0.1:12345'}}));
 createDeployment(f.configFile,{stateDir:f.stateDir});assert.throws(()=>createDeployment(f.configFile,{stateDir:f.stateDir}),/already_exists/);
 let s=await advanceDeployment(f.stateDir,{authorize:[]});assert.equal(steps(s)['gateway.prepare'].status,'pending');
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['shell.exec']}),/unknown_authorized_step/);
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare']});
 fs.appendFileSync(path.join(f.stateDir,'gateway/runtime.json'),' ');
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['gateway.start']}),/completed_step_evidence_changed/);
 assert.equal(steps(readDeployment(f.stateDir))['gateway.start'].status,'pending');
});
test('interrupted side effects and simultaneous advances never replay uncertain operations',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 const stateFile=path.join(f.stateDir,'state.json');let raw=JSON.parse(fs.readFileSync(stateFile));raw.steps[0].status='running';fs.writeFileSync(stateFile,JSON.stringify(raw),{mode:0o600});
 assert.equal(steps(readDeployment(f.stateDir))['gateway.prepare'].status,'uncertain');
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['gateway.prepare']}),/uncertain_step/);
 fs.writeFileSync(path.join(f.stateDir,'advance.lock'),'locked',{mode:0o600});
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['gateway.prepare']}),/onboarding_busy_or_interrupted_lock/);
 assert.equal(fs.existsSync(path.join(f.stateDir,'gateway')),false);
});
test('join-existing cannot create local Gateway or accept arbitrary setup fields',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);const c={...f.config,mode:'join-existing',gateway:{url:'https://verified.styx.test'}};fs.writeFileSync(f.configFile,JSON.stringify(c));
 const s=createDeployment(f.configFile,{stateDir:f.stateDir});assert.equal(s.steps.some(x=>x.id.startsWith('gateway.')),false);
 assert.throws(()=>validateDeployment({...c,host:{...c.host,args:['unsafe']}}),/invalid_configuration_fields/);
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['gateway.prepare']}),/unknown_authorized_step/);
});

test('concurrent gateway start is serialized and stopped runtime differs from successful journal',{skip:process.platform!=='linux',timeout:15000},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare']});
 const first=advanceDeployment(f.stateDir,{authorize:['gateway.start']});
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['gateway.start']}),/onboarding_busy_or_interrupted_lock/);
 const s=await first;assert.equal(s.gatewayRuntime.status,'running');
 await stopDeploymentGateway(f.stateDir);const stopped=readDeployment(f.stateDir);
 assert.equal(steps(stopped)['gateway.start'].status,'succeeded');assert.equal(stopped.gatewayRuntime.status,'not_owned_by_current_process');
});
test('signed preparation failure records uncertainty and refuses resume without replay',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);const c={...f.config,mode:'join-existing',gateway:{url:'https://verified.styx.test'},host:{...f.config.host,publisherSha256:'0'.repeat(64)}};
 fs.writeFileSync(f.configFile,JSON.stringify(c));createDeployment(f.configFile,{stateDir:f.stateDir});
 const before=await main(['status',f.stateDir]);
 assert.equal(before.roles.gateway,'external');assert.equal(before.roles.deviceIngress,'not_hosted');
 assert.equal(before.steps.some(x=>x.id.startsWith('gateway.')),false);
 assert.equal(fs.existsSync(path.join(f.stateDir,'gateway')),false);
 const s=await advanceDeployment(f.stateDir,{authorize:['host.prepare']});assert.equal(steps(s)['host.prepare'].status,'uncertain');
 assert.equal(fs.existsSync(f.config.host.baseDir),false);await assert.rejects(advanceDeployment(f.stateDir,{authorize:['host.prepare']}),/uncertain_step/);
});

test('CLI accepts only fixed workflow commands and returns persisted redacted status',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);const created=await main(['create',f.configFile,f.stateDir]);assert.equal(created.mode,'create-local');
 assert.equal(created.roles.gateway,'local');assert.equal(created.roles.deviceIngress,'loopback_only');
 assert.deepEqual((await main(['plan',f.stateDir])).roles,created.roles);
 assert.deepEqual(await main(['status',f.stateDir]),created);
 await assert.rejects(main(['exec',f.stateDir,'whoami']),/usage_/);
});

test('explicit owner-local pairing avoids invitation shuttle and bounded shutdown closes a live Host websocket',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const f=await fixture(t);delete f.config.pairingMode;fs.writeFileSync(f.configFile,JSON.stringify(f.config));createDeployment(f.configFile,{stateDir:f.stateDir});
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare']});
 assert.equal(readDeployment(f.stateDir).steps.some(x=>x.id==='host.pair'),true);
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['host.pair']}),/invalid_configuration_fields/);
 assert.equal(steps(readDeployment(f.stateDir))['host.pair'].status,'pending');
 const ownerApproval={approve:true,...planDeployment(f.stateDir).ownerPairingScope};
 const s=await advanceDeployment(f.stateDir,{authorize:['host.pair'],ownerApproval});
 assert.equal(steps(s)['host.pair'].status,'succeeded');assert.equal(steps(s)['host.pair'].evidence.status,'ready_to_connect');
 await setLocalDeploymentDefault(f.stateDir);const devices=await readDeploymentDevices(f.stateDir);assert.equal(devices.length,1);assert.equal(devices[0].is_default,true);await assert.rejects(setDeploymentDefault(f.stateDir,{authorize:false,deviceId:devices[0].device_id}),/explicit_default/);
 assert.equal(fs.existsSync(path.join(f.stateDir,'invitation')),false);
 const host=JSON.parse(fs.readFileSync(path.join(f.config.host.baseDir,'device/host.json')));
 const token=fs.readFileSync(host.token_file,'utf8').trim();
 const ws=new WebSocket(host.gateway_ws_url+'styx/hosts/'+host.host_id+'/exec',{ca:fs.readFileSync(path.join(f.stateDir,'gateway/certificate.pem')),headers:{Authorization:'Bearer '+token}});
 await once(ws,'open');
 const observed=await readDeploymentDevices(f.stateDir);
 assert.equal(observed[0].is_local,true);assert.equal(observed[0].online,true);assert.equal(observed[0].connections.exec,true);
 const closed=once(ws,'close');const started=Date.now();
 await stopDeploymentGateway(f.stateDir);await closed;assert.ok(Date.now()-started<5000);assert.equal(ws.readyState,WebSocket.CLOSED);
 assert.equal(readDeployment(f.stateDir).gatewayRuntime.status,'not_owned_by_current_process');
});

test('CLI scoped local approval flag performs real pairing and verification evidence stays SDK scoped',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const f=await fixture(t);delete f.config.pairingMode;fs.writeFileSync(f.configFile,JSON.stringify(f.config));await main(['create',f.configFile,f.stateDir]);
 const setup=await main(['advance',f.stateDir,'gateway.prepare','gateway.start','gateway.verify','host.prepare']);
 assert.equal((await main(['gateway-service',f.stateDir,'status'])).status,'not_installed');
 assert.equal(steps(setup)['gateway.verify'].evidence.scope,'sdk_gateway');assert.equal(steps(setup)['gateway.verify'].evidence.account_acceptance,'NOT RUN');
 await assert.rejects(main(['advance',f.stateDir,'host.doctor','--approve-local-device']),/owner_approval_requires/);
 const paired=await main(['advance',f.stateDir,'host.pair','--approve-local-device']);assert.equal(steps(paired)['host.pair'].status,'succeeded');
});

test('Host service actions require explicit fixed authorization and a successful recorded doctor before mutation',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 const plan=planDeployment(f.stateDir);assert.deepEqual(plan.steps.slice(-3).map(s=>s.id),['host.service.install','host.service.start','host.service.status']);
 await assert.rejects(controlDeploymentHostService(f.stateDir,{action:'install'}),/explicit_fixed_host_service_authorization_required/);
 await assert.rejects(controlDeploymentHostService(f.stateDir,{action:'exec',authorize:true}),/explicit_fixed_host_service_authorization_required/);
 await assert.rejects(controlDeploymentHostService(f.stateDir,{action:'install',authorize:true}),/successful_host_doctor_required/);
 assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),false);
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.stateDir,'state.json'))).maintenance,undefined);
});
test('generated service configuration is journal-bound before any service action',{skip:process.platform!=='linux',timeout:15000},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 const s=await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare']});
 assert.match(steps(s)['host.prepare'].evidence.serviceConfiguration.sha256,/^[a-f0-9]{64}$/);
 fs.appendFileSync(path.join(f.config.host.baseDir,'service.json'),' ');
 await assert.rejects(controlDeploymentHostService(f.stateDir,{action:'status',authorize:true}),/completed_step_evidence_changed/);
});

test('CLI fixed Host and Gateway service verbs refuse missing mutation authority before adapters run',async()=>{
 for(const kind of ['host-service','gateway-service']){
  await assert.rejects(main([kind,'/not-a-deployment','start']),/explicit_fixed_service_authorization_required/);
  await assert.rejects(main([kind,'/not-a-deployment','exec','--authorize']),/explicit_fixed_service_authorization_required/);
  await assert.rejects(main([kind,'/not-a-deployment','status','--shell']),/explicit_fixed_service_authorization_required/);
 }
});

test('owner pairing link joins a fresh second deployment with explicit origin, CA and fingerprint approval',{skip:process.platform!=='linux',timeout:25000},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify']});
 await assert.rejects(createDeploymentPairingLink(f.stateDir,{authorize:false}),/explicit_owner_link_authorization_required/);
 const reopened=await import('../core.mjs?reopened-owner-ui');
 const issued=await reopened.createDeploymentPairingLink(f.stateDir,{authorize:true});assert.equal(issued.remoteUsable,false);assert.equal(issued.reachability,'loopback_only');
 const {inspectPairingLink,acceptPairingLink}=await import('../pairing-links.mjs');
 const preview=inspectPairingLink(issued.link),privateJoin=path.join(f.root,'join-material');
 acceptPairingLink(issued.link,{stateDir:privateJoin,approvedGatewayOrigin:preview.origin,approvedCaSha256:preview.caSha256});
 const material=JSON.parse(fs.readFileSync(path.join(privateJoin,'pairing.json')));
 const joinConfig={...f.config,mode:'join-existing',gateway:{url:material.gatewayOrigin,caFile:material.gatewayCaFile},host:{...f.config.host,baseDir:path.join(f.root,'second-host'),label:'Second device'},invitationFile:material.invitationFile};
 const joinInput=path.join(f.root,'join-input.json'),joinState=path.join(f.root,'join-deployment');fs.writeFileSync(joinInput,JSON.stringify(joinConfig),{mode:0o600});createDeployment(joinInput,{stateDir:joinState});
 let joined=await advanceDeployment(joinState,{authorize:['host.prepare','host.request','host.claim']});assert.equal(steps(joined)['host.claim'].status,'awaiting_approval');
 await assert.rejects(listDeploymentPending(f.stateDir,{authorize:false}),/explicit_owner_pending_authorization_required/);
 const pending=await reopened.listDeploymentPending(f.stateDir,{authorize:true});assert.equal(pending.length,1);assert.equal(pending[0].label,'Second device');
 assert.equal(pending[0].comparison_code,steps(joined)['host.request'].evidence.comparison_code);assert.match(pending[0].comparison_code,/^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$/);
 const approved={authorize:true,requestId:pending[0].request_id,fingerprint:pending[0].fingerprint};
 await assert.rejects(approveDeploymentPending(f.stateDir,{...approved,fingerprint:'0'.repeat(64)}),/pending_identity_or_capability_mismatch/);
 await assert.rejects(approveDeploymentPending(f.stateDir,{...approved,enableComputer:true}),/pending_identity_or_capability_mismatch/);
 assert.equal((await reopened.approveDeploymentPending(f.stateDir,approved)).status,'approved');
 joined=await advanceDeployment(joinState,{authorize:['host.claim']});assert.equal(steps(joined)['host.claim'].status,'succeeded');
 const secret=fs.readFileSync(material.invitationFile,'utf8').trim();for(const state of [readDeployment(f.stateDir),joined]){assert.equal(JSON.stringify(state).includes(secret),false);assert.equal(JSON.stringify(state).includes(issued.link),false);}
});

test('network exposure requires explicit authorization and an exact owned IPv4 interface without binding LAN', {skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);assert.equal(validateDeployment(f.config).gateway.listenHost,undefined);
 const network=address=>({...f.config,gateway:{...f.config.gateway,url:'https://'+address+':18765',listenHost:address,allowRemoteHosts:true}});
 for(const address of ['0.0.0.0','203.0.113.111','::','gateway.example'])assert.throws(()=>validateDeployment(network(address)));
 assert.throws(()=>validateDeployment({...f.config,gateway:{...f.config.gateway,listenHost:'192.0.2.11',allowRemoteHosts:true}}),/gateway_url_must_match_exact_bind_ip/);
 for(const address of localGatewayAddresses()){
  assert.equal(validateDeployment(network(address)).gateway.listenHost,address);
  const missing=network(address);delete missing.gateway.allowRemoteHosts;assert.throws(()=>validateDeployment(missing),/explicit_owned_network_interface_required/);
 }
 // Configuration validation is the only operation: no LAN listener or deployment is created.
 assert.equal(fs.existsSync(f.stateDir),false);
});

test('uncertain workflow and maintenance service mutations share one guard while status and stop remain available',{skip:process.platform!=='linux',timeout:15000},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare']});
 const stateFile=path.join(f.stateDir,'state.json');
 // Explicit journal fixtures model already-completed preconditions; this test
 // never claims native Doctor success and never reaches a native mutation.
 const original=JSON.parse(fs.readFileSync(stateFile));
 for(const step of original.steps)if(!step.id.startsWith('host.service.'))step.status='succeeded';
 const workflow=structuredClone(original);workflow.steps.find(s=>s.id==='host.service.install').status='succeeded';workflow.steps.find(s=>s.id==='host.service.start').status='uncertain';
 fs.writeFileSync(stateFile,JSON.stringify(workflow),{mode:0o600});
 for(const action of ['install','start'])await assert.rejects(controlDeploymentHostService(f.stateDir,{action,authorize:true}),/uncertain_service_action_requires_manual_reconciliation/);
 assert.equal(readDeployment(f.stateDir).hostServiceMaintenance.hasUncertainMutation,true);
 for(const action of ['status','stop']){const result=await controlDeploymentHostService(f.stateDir,{action,authorize:true});assert.equal(result.status,'blocked');}
 // The adapter rejects the absent Host config before native commands; reaching
 // this bounded result confirms recovery reads/stops were not guard-blocked.
 for(const action of ['install','start']){
  const maintenance=structuredClone(original);maintenance.maintenance=[{action:'start',status:'uncertain',at:new Date().toISOString()}];
  if(action==='start')maintenance.steps.find(s=>s.id==='host.service.install').status='succeeded';
  fs.writeFileSync(stateFile,JSON.stringify(maintenance),{mode:0o600});
  await assert.rejects(advanceDeployment(f.stateDir,{authorize:['host.service.'+action]}),/uncertain_service_action_requires_manual_reconciliation/);
  assert.equal(steps(readDeployment(f.stateDir))['host.service.'+action].status,'pending');
 }
 // An interrupted read-only status is not an uncertain native mutation.
 const readOnly=structuredClone(original);readOnly.maintenance=[{action:'status',status:'running',at:new Date().toISOString()}];readOnly.steps.find(s=>s.id==='host.service.status').status='running';
 fs.writeFileSync(stateFile,JSON.stringify(readOnly),{mode:0o600});
 assert.equal(readDeployment(f.stateDir).hostServiceMaintenance.hasUncertainMutation,false);
});
test('CLI owner pairing workflow stores invitation privately and never prints its secret',async t=>{
 const f=await fixture(t);delete f.config.pairingMode;fs.writeFileSync(f.configFile,JSON.stringify(f.config));createDeployment(f.configFile,{stateDir:f.stateDir});
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify']});
 const output=path.join(f.root,'join-link');const summary=await main(['pairing-link',f.stateDir,output,'--authorize']);
 const link=fs.readFileSync(output,'utf8').trim();assert.match(link,/^styx:\/\/join#/);assert.equal(summary.link,undefined);assert.equal(JSON.stringify(summary).includes(link),false);assert.equal(fs.statSync(output).mode&0o077,0);
 const preview=await main(['inspect-link',output]);const approval=path.join(f.root,'link-approval.json'),importDir=path.join(f.root,'imported');fs.writeFileSync(approval,JSON.stringify({stateDir:importDir,approvedGatewayOrigin:preview.origin,approvedCaSha256:preview.caSha256}),{mode:0o600});
 const accepted=await main(['accept-link',output,approval,'--authorize']);assert.equal(accepted.status,'pairing_material_saved');assert.equal(fs.existsSync(path.join(importDir,'invitation')),true);
 assert.deepEqual(await main(['pending',f.stateDir,'--authorize']),[]);assert.deepEqual(await main(['devices',f.stateDir]),[]);
 await assert.rejects(main(['pairing-link',f.stateDir,output,'--authorize']),/fresh_private_output_required/);
});

test('Host evidence damage cannot block independent Gateway startup or owner operations',async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare']});
 await stopDeploymentGateway(f.stateDir);fs.appendFileSync(path.join(f.config.host.baseDir,'service.json'),'unsigned local drift');
 assert.equal((await startDeploymentGateway(f.stateDir)).status,'running');
 assert.deepEqual(await listDeploymentPending(f.stateDir,{authorize:true}),[]);
 await assert.rejects(controlDeploymentHostService(f.stateDir,{action:'status',authorize:true}),/completed_step_evidence_changed/);
});


test('CLI Browser intent reaches explicit owner approval and local Host config without desktop setup',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const f=await fixture(t);delete f.config.pairingMode;f.config.host.browser={enabled:true};fs.writeFileSync(f.configFile,JSON.stringify(f.config));
 const created=await main(['create',f.configFile,f.stateDir]);assert.equal(created.roles.browser,'requested');assert.equal(created.roles.computer,'disabled');assert.equal(created.roles.readiness,'not_inferred');
 const plan=await main(['plan',f.stateDir]);assert.equal(plan.ownerPairingScope.enableBrowser,true);
 await main(['advance',f.stateDir,'gateway.prepare','gateway.start','gateway.verify','host.prepare']);
 const enrollment=JSON.parse(fs.readFileSync(path.join(f.config.host.baseDir,'enrollment.json')));assert.equal(enrollment.browser_requested,true);assert.equal(enrollment.browser_config.headless,true);assert.equal(enrollment.browser_config.profileRoot,path.join(f.config.host.baseDir,'browser'));
 const ownerApproval={approve:true,...plan.ownerPairingScope};delete ownerApproval.enableBrowser;
 await assert.rejects(advanceDeployment(f.stateDir,{authorize:['host.pair'],ownerApproval}),/explicit_scoped_owner_approval_required/);
 const paired=await main(['advance',f.stateDir,'host.pair','--approve-local-device']);assert.equal(steps(paired)['host.pair'].status,'succeeded');
 const host=JSON.parse(fs.readFileSync(path.join(f.config.host.baseDir,'device/host.json')));assert.deepEqual(host.browser,enrollment.browser_config);assert.equal(host.computer,undefined);
 assert.equal((await readDeploymentDevices(f.stateDir))[0].browser,true);assert.equal((await main(['status',f.stateDir])).roles.readiness,'not_inferred');
});
test('Core validates the bounded Browser intent and does not accept caller-supplied profiles',async t=>{
 const f=await fixture(t);
 for(const browser of [{enabled:true,profileRoot:'/foreign'},{enabled:true,binary:'/foreign'},{enabled:true,headless:'yes'},{enabled:true,executablePath:'relative'}])assert.throws(()=>validateDeployment({...f.config,host:{...f.config.host,browser}}));
 assert.equal(validateDeployment({...f.config,host:{...f.config.host,browser:{enabled:false}}}).host.browser.enabled,false);
 assert.equal(validateDeployment({...f.config,host:{...f.config.host,browser:{enabled:true,headless:false,executablePath:process.execPath}}}).host.browser.headless,false);
});


test('owner identity approval preserves the Browser capability selected on the joining computer',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const f=await fixture(t);f.config.host.browser={enabled:true,headless:true};fs.writeFileSync(f.configFile,JSON.stringify(f.config));await main(['create',f.configFile,f.stateDir]);
 await main(['advance',f.stateDir,'gateway.prepare','gateway.start','gateway.verify','host.prepare','host.invite','host.request','host.claim']);
 const [pending]=await listDeploymentPending(f.stateDir,{authorize:true});assert.equal(pending.browser_requested,true);assert.equal(pending.computer_requested,false);
 const approval={authorize:true,requestId:pending.request_id,fingerprint:pending.fingerprint,enableComputer:false};
 await assert.rejects(approveDeploymentPending(f.stateDir,{...approval,enableBrowser:false}),/pending_identity_or_capability_mismatch/);
 const file=path.join(f.root,'browser-approval.json');fs.writeFileSync(file,JSON.stringify(approval),{mode:0o600});
 const approved=await main(['approve',f.stateDir,file,'--authorize']);assert.equal(approved.approved_capabilities.browser,true);
 const state=await main(['advance',f.stateDir,'host.claim']);assert.equal(steps(state)['host.claim'].status,'succeeded');
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.config.host.baseDir,'device/host.json'))).browser.enabled,true);
});


const signedBrowserPreparationFixture=`import fs from 'node:fs';import path from 'node:path';
export function readManagedBrowser(profileRoot){const file=path.join(profileRoot,'test-runtime-receipt.json');return fs.existsSync(file)?JSON.parse(fs.readFileSync(file,'utf8')):{status:'not_prepared'};}
export async function prepareManagedBrowser({profileRoot,authorize,signal,recover}){if(authorize!==true)throw Error('not_authorized');if(signal?.aborted)throw Error('browser_prepare_cancelled');const result={status:'prepared',playwright:recover?'signed-test-recovered':'signed-test-version',executablePath:path.join(profileRoot,'private-runtime')};fs.writeFileSync(path.join(profileRoot,'test-runtime-receipt.json'),JSON.stringify(result),{mode:0o600});return result;}`;
async function pairedBrowserPreparation(t,{module=true}={}){
 const f=await fixture(t,{browserPreparationModule:module?signedBrowserPreparationFixture:undefined});delete f.config.pairingMode;f.config.host.browser={enabled:true};fs.writeFileSync(f.configFile,JSON.stringify(f.config));createDeployment(f.configFile,{stateDir:f.stateDir});
 await main(['advance',f.stateDir,'gateway.prepare','gateway.start','gateway.verify','host.prepare']);await main(['advance',f.stateDir,'host.pair','--approve-local-device']);return f;
}
test('Core Browser preparation imports only the signed active Host module and preserves enrolled state',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const f=await pairedBrowserPreparation(t),base=f.config.host.baseDir;
 const files=[path.join(f.stateDir,'deployment.json'),path.join(f.stateDir,'state.json'),...['identity.json','identity.pem','host.token','host.json'].map(name=>path.join(base,'device',name))],before=files.map(file=>fs.readFileSync(file));
 assert.equal((await readDeploymentBrowser(f.stateDir)).status,'not_prepared');
 await assert.rejects(prepareDeploymentBrowser(f.stateDir),/explicit_browser_preparation_authorization_required/);
 await assert.rejects(prepareDeploymentBrowser(f.stateDir,{authorize:true,module:'/foreign'}),/invalid_configuration_fields/);
 const prepared=await prepareDeploymentBrowser(f.stateDir,{authorize:true});assert.equal(prepared.status,'prepared');assert.equal(prepared.playwrightVersion,'signed-test-version');assert.equal(prepared.readiness,'not_verified');assert.equal(prepared.accountAcceptance,'NOT RUN');assert.doesNotMatch(JSON.stringify(prepared),/executablePath|profileRoot|private-runtime/);
 assert.equal((await readDeploymentBrowser(f.stateDir)).status,'prepared');
 fs.writeFileSync(path.join(base,'browser/test-runtime-receipt.json'),JSON.stringify({status:'preparation_blocked',reason:'browser_prepare_owner_alive',ownerPid:12345,profileRoot:'/private-not-for-api'}));
 const blocked=await main(['browser',f.stateDir]);assert.equal(blocked.status,'preparation_blocked');assert.equal(blocked.reason,'browser_prepare_owner_alive');assert.doesNotMatch(JSON.stringify(blocked),/ownerPid|profileRoot|12345/);
 assert.equal((await main(['browser-prepare',f.stateDir,'--recover','--authorize'])).playwrightVersion,'signed-test-recovered');for(let i=0;i<files.length;i++)assert.deepEqual(fs.readFileSync(files[i]),before[i]);
 assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),false);assert.equal(fs.existsSync(path.join(base,'browser/test-runtime-receipt.json')),true);
});
test('Core refuses missing Browser bundle, altered profiles, signed bytes or management ownership before preparation',{skip:process.platform!=='linux',timeout:20000},async t=>{
 for(const invalid of ['missing_bundle','profile','signed_bytes','management_lock']){
  const f=await pairedBrowserPreparation(t,{module:invalid!=='missing_bundle'}),base=f.config.host.baseDir;
  if(invalid==='profile'){const file=path.join(base,'device/host.json'),host=JSON.parse(fs.readFileSync(file));host.browser.profileRoot=path.join(f.root,'foreign-profile');fs.writeFileSync(file,JSON.stringify(host));}
  if(invalid==='signed_bytes')fs.appendFileSync(path.join(base,'install/releases/0.1.0-test/packages/styx-browser-provider/prepare.mjs'),'\nthrow Error("must_not_execute")');
  if(invalid==='management_lock')fs.writeFileSync(path.join(f.stateDir,'capabilities.lock'),'foreign',{mode:0o600});
  await assert.rejects(prepareDeploymentBrowser(f.stateDir,{authorize:true}));assert.equal(fs.existsSync(path.join(base,'browser/test-runtime-receipt.json')),false,invalid);
  if(invalid==='management_lock')assert.equal(fs.readFileSync(path.join(f.stateDir,'capabilities.lock'),'utf8'),'foreign');
 }
});
test('Browser preparation remains optional and never installs an unapproved Host',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});assert.equal((await readDeploymentBrowser(f.stateDir)).status,'not_configured');await assert.rejects(prepareDeploymentBrowser(f.stateDir,{authorize:true}),/browser_not_configured/);assert.equal(fs.existsSync(f.config.host.baseDir),false);
 const other=await fixture(t);other.config.host.browser={enabled:true};fs.writeFileSync(other.configFile,JSON.stringify(other.config));createDeployment(other.configFile,{stateDir:other.stateDir});assert.equal((await readDeploymentBrowser(other.stateDir)).status,'awaiting_host_approval');await assert.rejects(prepareDeploymentBrowser(other.stateDir,{authorize:true}),/approved_browser_host_required/);assert.equal(fs.existsSync(other.config.host.baseDir),false);
});


test('Linux headless Host preparation and Browser pairing do not require Cua readiness',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const saved={DISPLAY:process.env.DISPLAY,WAYLAND_DISPLAY:process.env.WAYLAND_DISPLAY};delete process.env.DISPLAY;delete process.env.WAYLAND_DISPLAY;
 t.after(()=>{for(const [name,value]of Object.entries(saved))if(value===undefined)delete process.env[name];else process.env[name]=value});
 const f=await fixture(t);delete f.config.pairingMode;f.config.host.computer=true;f.config.host.browser={enabled:true,headless:true};fs.writeFileSync(f.configFile,JSON.stringify(f.config));await main(['create',f.configFile,f.stateDir]);
 const prepared=await main(['advance',f.stateDir,'gateway.prepare','gateway.start','gateway.verify','host.prepare']);assert.equal(steps(prepared)['host.prepare'].status,'succeeded');assert.equal(prepared.roles.browser,'requested');assert.equal(prepared.roles.computer,'requested');assert.equal(prepared.roles.readiness,'not_inferred');
 const paired=await main(['advance',f.stateDir,'host.pair','--approve-local-device']);assert.equal(steps(paired)['host.pair'].status,'succeeded');assert.equal(steps(paired)['host.doctor'].status,'pending');
 const base=f.config.host.baseDir,host=JSON.parse(fs.readFileSync(path.join(base,'device/host.json'))),receipt=JSON.parse(fs.readFileSync(path.join(base,'setup-receipt.json')));assert.equal(host.browser.enabled,true);assert.equal(host.browser.headless,true);assert.equal(host.computer.enabled,true);assert.equal(receipt.native_permissions,'NOT RUN');assert.equal(paired.accountAcceptance,'NOT RUN');
});

test('Core and CLI revoke approved identity and persist denial across Gateway restart',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 const s=await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare','host.invite','host.request','host.claim']});
 const pending=steps(s)['host.request'].evidence;
 await approveDeploymentPending(f.stateDir,{authorize:true,requestId:pending.request_id,fingerprint:pending.fingerprint,enableComputer:false});
 await advanceDeployment(f.stateDir,{authorize:['host.claim']});
 const devices=await readDeploymentDevices(f.stateDir),id=devices[0].device_id;
 await assert.rejects(revokeDeploymentDevice(f.stateDir,{deviceId:id}),/explicit_device_revocation_required/);
 assert.equal((await main(['revoke-device',f.stateDir,id,'--authorize'])).status,'revoked');
 assert.equal((await readDeploymentDevices(f.stateDir)).length,0);
 await stopDeploymentGateway(f.stateDir);await startDeploymentGateway(f.stateDir);
 assert.equal((await readDeploymentDevices(f.stateDir)).length,0);
 await assert.rejects(revokeDeploymentDevice(f.stateDir,{authorize:true,deviceId:id}));
 const hostIdentity=JSON.parse(fs.readFileSync(path.join(f.config.host.baseDir,'device/identity.json')));
 assert.equal(hostIdentity.device_id,id,'revocation preserves local identity for explicit recovery review');
});


test('join keeps Exec available when the owner declines requested Browser and Computer Use',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const owner=await fixture(t);createDeployment(owner.configFile,{stateDir:owner.stateDir});
 await advanceDeployment(owner.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify']});
 const f=await fixture(t),ownerConfig=JSON.parse(fs.readFileSync(path.join(owner.stateDir,'gateway/owner.json')));
 const invitation=await ownerCommand(ownerConfig,'invite',['600']);f.config.invitationFile=path.join(f.root,'invitation');fs.writeFileSync(f.config.invitationFile,invitation.invitation+'\n',{mode:0o600});
 f.config.mode='join-existing';f.config.gateway={url:owner.config.gateway.url,caFile:path.join(owner.stateDir,'gateway/certificate.pem')};
 f.config.host.browser={enabled:true};f.config.host.computer=true;
 fs.writeFileSync(f.configFile,JSON.stringify(f.config));createDeployment(f.configFile,{stateDir:f.stateDir});
 let state=await advanceDeployment(f.stateDir,{authorize:['host.prepare','host.request','host.claim']});
 assert.equal(steps(state)['host.request'].status,'succeeded');const request=steps(state)['host.request'].evidence;
 await ownerCommand(ownerConfig,'approve',[request.request_id,request.fingerprint]);
 state=await advanceDeployment(f.stateDir,{authorize:['host.claim']});assert.equal(steps(state)['host.claim'].status,'succeeded');
 const base=f.config.host.baseDir,hostFile=path.join(base,'device/host.json'),before=fs.readFileSync(hostFile),host=JSON.parse(before);
 assert.equal(host.browser,undefined);assert.equal(host.computer,undefined);
 assert.deepEqual(await readDeploymentBrowser(f.stateDir),{schema:1,configured:true,approved:false,status:'not_approved',observation:'approved_host_configuration',readiness:'not_verified',accountAcceptance:'NOT RUN'});
 assert.equal((await main(['browser',f.stateDir])).status,'not_approved');
 await assert.rejects(prepareDeploymentBrowser(f.stateDir,{authorize:true}),/approved_browser_host_required/);
 assert.deepEqual(fs.readFileSync(hostFile),before);assert.equal(fs.existsSync(path.join(base,'browser/test-runtime-receipt.json')),false);
 assert.equal(state.roles.browser,'requested');assert.equal(state.steps.some(step=>step.id.startsWith('gateway.')),false);
 assert.equal(fs.existsSync(path.join(f.stateDir,'gateway')),false);
});
