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
import {createDeployment,readDeployment,planDeployment,advanceDeployment,stopDeploymentGateway,validateDeployment} from '../core.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
async function fixture(t){
 const root=path.join(os.tmpdir(),'styx-onboarding-'+randomUUID());ensurePrivateDirectory(root);t.after(async()=>{const d=path.join(root,'deployment');if(fs.existsSync(d))await stopDeploymentGateway(d);fs.rmSync(root,{recursive:true,force:true});});
 const server=net.createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;await new Promise(r=>server.close(r));
 const bundle=path.join(root,'bundle');fs.mkdirSync(bundle);fs.mkdirSync(path.join(bundle,'host'));fs.mkdirSync(path.join(bundle,'bin'));
 const {publicKey,privateKey}=generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
 const exe=process.platform==='win32'?'.exe':'';const contents={};
 for(const f of ['private-storage.mjs','installer.mjs','launch.mjs'])contents['host/'+f]=fs.readFileSync(new URL('../../host/'+f,import.meta.url));
 for(const f of ['enroll.mjs','doctor.mjs','setup-native.mjs','linux-service.mjs','macos-launchagent.mjs','windows-task.ps1'])contents['host/'+f]=Buffer.from('// signed test payload; never executed');
 contents['bin/node'+exe]=fs.readFileSync(process.execPath);for(const f of ['codex','cua-driver'])contents['bin/'+f+exe]=Buffer.from('test bytes never executed');
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
 assert.equal(planDeployment(f.stateDir).service.status,'not_installed');
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
 const s=await advanceDeployment(f.stateDir,{authorize:['host.prepare']});assert.equal(steps(s)['host.prepare'].status,'uncertain');
 assert.equal(fs.existsSync(f.config.host.baseDir),false);await assert.rejects(advanceDeployment(f.stateDir,{authorize:['host.prepare']}),/uncertain_step/);
});

test('CLI accepts only fixed workflow commands and returns persisted redacted status',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);const created=await main(['create',f.configFile,f.stateDir]);assert.equal(created.mode,'create-local');
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
 assert.equal(fs.existsSync(path.join(f.stateDir,'invitation')),false);
 const host=JSON.parse(fs.readFileSync(path.join(f.config.host.baseDir,'device/host.json')));
 const token=fs.readFileSync(host.token_file,'utf8').trim();
 const ws=new WebSocket(host.gateway_ws_url+'styx/hosts/'+host.host_id+'/exec',{ca:fs.readFileSync(path.join(f.stateDir,'gateway/certificate.pem')),headers:{Authorization:'Bearer '+token}});
 await once(ws,'open');const closed=once(ws,'close');const started=Date.now();
 await stopDeploymentGateway(f.stateDir);await closed;assert.ok(Date.now()-started<5000);assert.equal(ws.readyState,WebSocket.CLOSED);
 assert.equal(readDeployment(f.stateDir).gatewayRuntime.status,'not_owned_by_current_process');
});

test('CLI scoped local approval flag performs real pairing and verification evidence stays SDK scoped',{skip:process.platform!=='linux',timeout:20000},async t=>{
 const f=await fixture(t);delete f.config.pairingMode;fs.writeFileSync(f.configFile,JSON.stringify(f.config));await main(['create',f.configFile,f.stateDir]);
 const setup=await main(['advance',f.stateDir,'gateway.prepare','gateway.start','gateway.verify','host.prepare']);
 assert.equal(steps(setup)['gateway.verify'].evidence.scope,'sdk_gateway');assert.equal(steps(setup)['gateway.verify'].evidence.account_acceptance,'NOT RUN');
 await assert.rejects(main(['advance',f.stateDir,'host.doctor','--approve-local-device']),/owner_approval_requires/);
 const paired=await main(['advance',f.stateDir,'host.pair','--approve-local-device']);assert.equal(steps(paired)['host.pair'].status,'succeeded');
});
