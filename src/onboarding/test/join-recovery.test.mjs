import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import net from 'node:net';
import {execFileSync,spawnSync} from 'node:child_process';
import {acquireRecoveryGuard} from '../recovery-guard.mjs';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {recoverDeploymentJoin,rollbackDeploymentJoin,readDeploymentJoinRecovery} from '../join-recovery.mjs';
import {inspectPairingLink,acceptPairingLink,createPairingLink} from '../pairing-links.mjs';
import {EnrollmentController,handleEnrollment} from '../../gateway/enrollment.mjs';
import {TargetRegistry} from '../../gateway/registry.mjs';
import {requestEnrollment} from '../../host/enroll.mjs';
import {readDeployment,advanceDeployment} from '../core.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),write=(f,x)=>fs.writeFileSync(f,typeof x==='string'?x:JSON.stringify(x,null,2)+'\n',{mode:0o600}),read=f=>JSON.parse(fs.readFileSync(f));
const inactive={observeHostService:async()=>({status:'reported',state:'not_installed',installed:false})};
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-join-recovery-')),d=path.join(root,'deployment'),base=path.join(root,'host');t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 for(const p of [d,base,path.join(base,'device'),path.join(base,'install')])fs.mkdirSync(p,{mode:0o700});
 const key=generateKeyPairSync('rsa',{modulusLength:3072});write(path.join(base,'device/identity.pem'),key.privateKey.export({type:'pkcs8',format:'pem'}));
 write(path.join(base,'device/identity.json'),{version:1,device_id:'styx-'+randomBytes(12).toString('hex'),fingerprint:sha(key.publicKey.export({type:'spki',format:'der'})),public_key_pem:key.publicKey.export({type:'spki',format:'pem'}),platform:process.platform});
 for(const f of ['service.json','setup-receipt.json','setup-state.json','publisher.pem','install/active.json'])write(path.join(base,f),{});
 const old=path.join(root,'old-invitation');write(old,randomBytes(32).toString('base64url'));
 const config={schema:1,mode:'join-existing',gateway:{url:'https://127.0.0.1:1'},invitationFile:old,host:{baseDir:base,bundle:path.join(root,'bundle'),publisherKeyFile:path.join(base,'publisher.pem'),publisherSha256:'a'.repeat(64),label:'test',computer:false}};
 write(path.join(d,'deployment.json'),config);
 const enrollment={gateway_url:config.gateway.url,storage_dir:path.join(base,'device'),label:'test',cwd:root,shell:'/bin/sh',exec_binary:'/not-executed-codex'};write(path.join(base,'enrollment.json'),enrollment);
 const steps=['host.prepare','host.request','host.claim','host.doctor','host.service.install','host.service.start','host.service.status'].map((id,i)=>({id,status:i===0?'succeeded':i===1?'uncertain':'pending'}));steps[0].evidence={enrollmentConfiguration:{path:path.join(base,'enrollment.json'),sha256:sha(fs.readFileSync(path.join(base,'enrollment.json')))},serviceConfiguration:{path:path.join(base,'service.json'),sha256:sha(fs.readFileSync(path.join(base,'service.json')))}};
 write(path.join(d,'state.json'),{schema:1,mode:config.mode,configSha256:sha(fs.readFileSync(path.join(d,'deployment.json'))),steps});
 const link=createPairingLink({controller:{invite:()=>({invitation:randomBytes(32).toString('base64url'),expires_at:Date.now()+300000})},gatewayOrigin:'https://127.0.0.1:23456',approved:true}).link;
 const preview=inspectPairingLink(link),accepted=path.join(root,'accepted');acceptPairingLink(link,{stateDir:accepted,approvedGatewayOrigin:preview.origin});
 return {root,d,base,config,enrollment,pairingFile:path.join(accepted,'pairing.json')};
}
test('explicit replacement preserves identity/install, keeps uncertain attempt, and rollback restores exact bytes',async t=>{
 const f=fixture(t),files=['deployment.json','state.json'].map(n=>path.join(f.d,n)).concat(path.join(f.base,'enrollment.json')),before=files.map(p=>fs.readFileSync(p));
 const identity=fs.readFileSync(path.join(f.base,'device/identity.pem'));assert.equal((await readDeploymentJoinRecovery(f.d,inactive)).canRecover,true);
 const r=await recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},inactive);assert.equal(r.status,'recovered');
 const s=readDeployment(f.d);assert.equal(s.steps[1].status,'pending');assert.equal(s.steps.some(x=>x.id.startsWith('gateway.')),false);assert.equal(fs.existsSync(path.join(f.d,'gateway')),false);
 const state=read(path.join(f.d,'state.json'));assert.equal(state.joinAttempts[0].remoteOutcome,'unknown');assert.equal(state.joinAttempts[0].request.status,'uncertain');assert.deepEqual(fs.readFileSync(path.join(f.base,'device/identity.pem')),identity);
 await rollbackDeploymentJoin(f.d,{authorize:true,transactionId:r.transactionId},inactive);files.forEach((p,i)=>assert.deepEqual(fs.readFileSync(p),before[i]));
});
test('pending claim or credentials and non-quiescent services refuse replacement',async t=>{
 for(const name of ['pending.json','host.token','host.json']){const f=fixture(t);write(path.join(f.base,'device',name),{});await assert.rejects(recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},inactive),/existing_enrollment/)}
 const f=fixture(t);for(const state of ['running','unknown','loaded'])await assert.rejects(recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},{observeHostService:async()=>({status:'reported',state})}),/service_not_quiescent/);
});
test('partial writes roll back all authoritative files and preparation evidence',async t=>{
 const f=fixture(t),files=[path.join(f.d,'deployment.json'),path.join(f.d,'state.json'),path.join(f.base,'enrollment.json')],before=files.map(p=>fs.readFileSync(p));
 await assert.rejects(recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},{...inactive,beforeWrite:i=>{if(i===1)throw Error('injected_disk_failure')}}),/injected_disk_failure/);
 files.forEach((p,i)=>assert.deepEqual(fs.readFileSync(p),before[i]));assert.equal(read(path.join(f.d,'join-recovery.json')).status,'rolled_back');assert.equal(readDeployment(f.d).steps[1].status,'uncertain');
});
test('new network attempt cannot be rolled back or old invitation silently reused',async t=>{
 const f=fixture(t),r=await recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},inactive);
 const state=read(path.join(f.d,'state.json'));state.steps[1].status='uncertain';write(path.join(f.d,'state.json'),state);
 await assert.rejects(rollbackDeploymentJoin(f.d,{authorize:true,transactionId:r.transactionId},inactive),/changed_since_transaction/);
 await assert.rejects(recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},inactive),/new_invitation_required/);
});
test('interrupted journal blocks ordinary advance and explicit rollback restores it',async t=>{
 const f=fixture(t),r=await recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},inactive),j=read(path.join(f.d,'join-recovery.json'));j.status='writing';write(path.join(f.d,'join-recovery.json'),j);
 assert.throws(()=>readDeployment(f.d),/rollback_required/);await assert.rejects(advanceDeployment(f.d,{authorize:['host.request']}),/rollback_required/);
 const status=await readDeploymentJoinRecovery(f.d,inactive);assert.equal(status.rollbackRequired,true);assert.equal(status.transactionId,r.transactionId);
 await rollbackDeploymentJoin(f.d,{authorize:true,transactionId:r.transactionId},inactive);assert.equal(readDeployment(f.d).steps[1].status,'uncertain');
});
for(const lostResponse of [false,true])test(lostResponse?'accepted request with lost response retains remote conflict without identity regeneration':'real refused TLS connection then accepted new TLS invitation uses same device identity',async t=>{
 const f=fixture(t);const socket=net.createServer();await new Promise(r=>socket.listen(0,'127.0.0.1',r));const closedPort=socket.address().port;await new Promise(r=>socket.close(r));
 f.enrollment.gateway_url='https://127.0.0.1:'+closedPort;await assert.rejects(requestEnrollment(f.enrollment,randomBytes(32).toString('base64url')),/ECONNREFUSED/);assert.equal(fs.existsSync(path.join(f.base,'device/pending.json')),false);
 const id=fs.readFileSync(path.join(f.base,'device/identity.json')),priv=fs.readFileSync(path.join(f.base,'device/identity.pem'));
 const cert=execFileSync('/usr/bin/openssl',['req','-x509','-key',path.join(f.base,'device/identity.pem'),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1'],{encoding:'utf8',stdio:['ignore','pipe','pipe']});
 const adminTokenFile=path.join(f.root,'admin.token');write(adminTokenFile,randomBytes(32).toString('base64url'));
 const controller=new EnrollmentController({rootDir:path.join(f.root,'gateway-enrollment'),adminTokenFile,registry:new TargetRegistry({version:1,targets:[]})});
 let drop=lostResponse;const hosts=[],server=https.createServer({key:priv,cert},(req,res)=>{if(drop){drop=false;let body='';req.on('data',b=>body+=b);req.on('end',()=>{controller.join(JSON.parse(body));req.socket.destroy()});return;}return handleEnrollment(req,res,{controller,allowedHosts:hosts})});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());hosts.push('127.0.0.1:'+server.address().port);
 const origin='https://127.0.0.1:'+server.address().port;
 if(lostResponse){const ca=path.join(f.root,'old-ca.pem');write(ca,cert);await assert.rejects(requestEnrollment({...f.enrollment,gateway_url:origin,gateway_ca_file:ca},controller.invite({ttl_seconds:60}).invitation),/socket hang up/);assert.equal(fs.existsSync(path.join(f.base,'device/pending.json')),false);assert.equal(controller.listPending().length,1);}
 const link=createPairingLink({controller,gatewayOrigin:origin,caPem:cert,approved:true}).link,preview=inspectPairingLink(link),accepted=path.join(f.root,'new-tls');
 acceptPairingLink(link,{stateDir:accepted,approvedGatewayOrigin:origin,approvedCaSha256:preview.caSha256});await recoverDeploymentJoin(f.d,{authorize:true,pairingFile:path.join(accepted,'pairing.json')},inactive);
 const c=read(path.join(f.base,'enrollment.json')),inv=fs.readFileSync(read(path.join(f.d,'deployment.json')).invitationFile,'utf8').trim();if(lostResponse){await assert.rejects(requestEnrollment(c,inv),/device_identity_conflict/);assert.equal(fs.existsSync(path.join(f.base,'device/pending.json')),false);}else await requestEnrollment(c,inv);
 assert.deepEqual(fs.readFileSync(path.join(f.base,'device/identity.json')),id);assert.deepEqual(fs.readFileSync(path.join(f.base,'device/identity.pem')),priv);assert.equal(controller.listPending().length,1);assert.equal(fs.existsSync(path.join(f.base,'device/pending.json')),!lostResponse);
});


test('real child death after guard acquisition before journal does not strand recovery',async t=>{
 const f=fixture(t),lock=path.join(f.d,'advance.lock'),transactionId='b'.repeat(32);
 const script=`import {acquireRecoveryGuard} from ${JSON.stringify(new URL('../recovery-guard.mjs',import.meta.url).href)};acquireRecoveryGuard(process.argv[1],{kind:'uncompleted-join-recovery-v1',transactionId:process.argv[2]});process.exit(0);`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',script,lock,transactionId],{encoding:'utf8'});assert.equal(child.status,0,child.stderr);
 assert.equal(fs.existsSync(lock),true);assert.equal(fs.existsSync(path.join(f.d,'join-recovery.json')),false);
 const result=await recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},inactive);assert.equal(result.status,'recovered');assert.notEqual(result.transactionId,transactionId);assert.equal(fs.existsSync(lock),false);assert.equal(readDeployment(f.d).steps[1].status,'pending');
});
test('pre-journal reclamation refuses a live owner and preserves the guard',async t=>{
 const f=fixture(t),lock=path.join(f.d,'advance.lock'),guard=acquireRecoveryGuard(lock,{kind:'uncompleted-join-recovery-v1',transactionId:'c'.repeat(32)}),before=fs.readFileSync(lock);
 try{await assert.rejects(recoverDeploymentJoin(f.d,{authorize:true,pairingFile:f.pairingFile},inactive),/owner_alive_or_unknown/);assert.deepEqual(fs.readFileSync(lock),before)}finally{guard.close()}
});
