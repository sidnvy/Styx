import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import https from 'node:https';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {once} from 'node:events';
import WebSocket from 'ws';
import {TargetRegistry} from '../registry.mjs';
import {EnrollmentController} from '../enrollment.mjs';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';
import {
  initLocalIdentity,requestEnrollment,claimEnrollment,enrollmentRequest
} from '../../host/enroll.mjs';

async function fixture(t) {
  const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'styx-pairing-pilot-'));
  let http;
  t.after(async()=>{
    await http?.close();
    await fs.rm(tmp,{recursive:true,force:true});
  });
  const adminToken=randomBytes(48).toString('base64url');
  await fs.writeFile(path.join(tmp,'admin.token'),adminToken,{mode:0o600});
  const cert=path.join(tmp,'gateway-cert.pem'),key=path.join(tmp,'gateway-key.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
    '-sha256','-days','1','-keyout',key,'-out',cert,
    '-subj','/CN=styx-pairing-fixture','-addext','subjectAltName=IP:127.0.0.1'],
  {stdio:'ignore',timeout:12000});
  const catalog={version:1,targets:[]};
  const gateway=createStyxGateway({catalog});
  const enrollDir=path.join(tmp,'enrollment');
  const controller=new EnrollmentController({rootDir:enrollDir,
    adminTokenFile:path.join(tmp,'admin.token'),registry:gateway.registry,
    relay:gateway.relay});
  const hosts=[];
  const mcpToken=randomBytes(40).toString('base64url');
  http=await createGatewayHttp(gateway,{
    token:mcpToken,port:0,
    allowedHosts:hosts,enrollment:controller,
    tlsCertificateFile:cert,tlsPrivateKeyFile:key
  });
  hosts.push('127.0.0.1:'+http.address.port);
  function config(label,computer=true){
    return {
      gateway_url:'https://127.0.0.1:'+http.address.port,
      gateway_ca_file:cert,
      storage_dir:path.join(tmp,'device-'+label),
      label,cwd:tmp,shell:'/bin/sh',
      exec_binary:process.execPath,
      computer_requested:computer,
      ...(computer?{computer_binary:'/usr/bin/false'}:{})
    };
  }
  const admin=(route,data)=>enrollmentRequest(config('admin-client'),route,data,{
    adminToken
  });
  return {tmp,gateway,controller,admin,config,http,cert,adminToken,mcpToken,enrollDir};
}

test('one-use invitation + device-generated key + owner-approved fingerprint + encrypted host token',
  {timeout:25000},async t=>{
  const f=await fixture(t);
  const guest=f.config('first');
  const identity=initLocalIdentity(guest);
  assert.match(identity.device_id,/^styx-[0-9a-f]{24}$/);
  const keyInfo=await fs.stat(path.join(guest.storage_dir,'identity.pem'));
  assert.equal(keyInfo.mode & 0o077,0);
  const invitation=(await f.admin('invitations',{})).body;
  assert.equal(invitation.one_use,true);
  const pending=await requestEnrollment(guest,invitation.invitation);
  assert.equal(pending.fingerprint,identity.fingerprint);
  assert.equal(pending.status,'pending');
  const requests=(await f.admin('pending')).body;
  assert.equal(requests.length,1);
  assert.equal(requests[0].device_id,identity.device_id);
  assert.equal(requests[0].fingerprint,identity.fingerprint);
  const other=f.config('other');
  await assert.rejects(requestEnrollment(other,invitation.invitation),/invitation_expired_or_used/);
  assert.equal(f.gateway.registry.list().length,0);
  await assert.rejects(f.admin('approve',{request_id:pending.request_id,
    fingerprint:'0'.repeat(64),enable_computer:true}),/fingerprint_mismatch/);
  assert.equal(f.gateway.registry.list().length,0);
  const ownerApproved=await f.admin('approve',{request_id:pending.request_id,
    fingerprint:identity.fingerprint,enable_computer:true});
  assert.equal(ownerApproved.body.approved_capabilities.computer,true);
  const admitted=f.gateway.registry.resolve(identity.device_id);
  assert.equal(admitted.exec.transport,'outbound');
  assert.equal(admitted.computer.transport,'outbound');
  const status=await claimEnrollment(guest);
  assert.equal(status.status,'ready_to_connect');
  assert.equal(status.device_id,identity.device_id);
  const finalHost=JSON.parse(await fs.readFile(status.local_host_config,'utf8'));
  assert.equal(finalHost.host_id,identity.device_id);
  assert.equal(finalHost.computer.enabled,true);
  const gatewayHostToken=(await fs.readFile(admitted.exec.token_file,'utf8')).trim();
  const localToken=(await fs.readFile(finalHost.token_file,'utf8')).trim();
  assert.equal(gatewayHostToken,localToken);
  assert.ok(localToken.length>32);
  const privateState=JSON.parse(await fs.readFile(
    path.join(guest.storage_dir,'pending.json'),'utf8'));
  await assert.rejects(enrollmentRequest(guest,'claim',{
    request_id:privateState.request_id,claim_secret:privateState.claim_secret
  }),/claim_unavailable/);
  const devices=(await f.admin('devices')).body;
  assert.equal(devices.length,1);
  assert.equal(devices[0].status,'approved');
  assert.equal(devices[0].fingerprint,identity.fingerprint);
  const ws=new WebSocket('wss://127.0.0.1:'+f.http.address.port+
    '/styx/hosts/'+identity.device_id+'/exec',{
      ca:await fs.readFile(f.cert),
      headers:{Authorization:'Bearer '+localToken}
    });
  await once(ws,'open');
  assert.equal(f.gateway.relay.connected(identity.device_id),true);
  const stopped=await f.admin('revoke',{device_id:identity.device_id});
  assert.equal(stopped.body.status,'revoked');
  await once(ws,'close');
  assert.throws(()=>f.gateway.registry.resolve(identity.device_id),/environment_access_denied/);
  assert.equal(f.gateway.relay.connected(identity.device_id),false);
  assert.equal((await f.admin('devices')).body[0].status,'revoked');
  assert.equal((await fs.stat(admitted.exec.token_file).catch(()=>null)),null);
});

test('no credential before owner approval; claim secret and admin bearer are distinct',
  {timeout:22000},async t=>{
  const f=await fixture(t);
  const guest=f.config('second',false);
  const inv=(await f.admin('invitations',{})).body;
  const pending=await requestEnrollment(guest,inv.invitation);
  const poll=await claimEnrollment(guest);
  assert.equal(poll.status,'pending');
  await assert.rejects(enrollmentRequest(guest,'claim',{
    request_id:pending.request_id,claim_secret:randomBytes(32).toString('base64url')
  }),/invalid_claim/);
  await assert.rejects(enrollmentRequest(guest,'devices',undefined,{
    adminToken:'A'.repeat(52)
  }),/unauthorized/);
  const originalKey=await fs.readFile(path.join(guest.storage_dir,'identity.pem'),'utf8');
  assert.ok(originalKey.includes('BEGIN PRIVATE KEY'));
  assert.equal((await f.admin('devices')).body.length,0);
  const denied=await f.admin('approve',{request_id:pending.request_id,
    fingerprint:pending.fingerprint,enable_computer:false});
  assert.equal(denied.body.approved_capabilities.computer,false);
  const claimed=await claimEnrollment(guest);
  assert.equal(claimed.capabilities.computer,false);
  const cfg=JSON.parse(await fs.readFile(claimed.local_host_config,'utf8'));
  assert.equal(cfg.computer,undefined);
});

test('trusted Gateway CA required; tampered join proof rejected without spending invitation',
  {timeout:25000},async t=>{
  const f=await fixture(t);
  const guest=f.config('third');
  const invitation=(await f.admin('invitations',{})).body;
  const fakeCfg={...guest,gateway_ca_file:undefined};
  initLocalIdentity(guest);
  await assert.rejects(requestEnrollment(fakeCfg,invitation.invitation),
    /self.signed|certificate|unable to verify|self signed/i);
  const identity=initLocalIdentity(guest);
  const {sign,constants}=await import('node:crypto');
  const {joinPayload}=await import('../enrollment.mjs');
  const body={invitation:invitation.invitation,device_id:identity.device_id,
    label:guest.label,platform:process.platform,cwd:guest.cwd,shell:guest.shell,
    computer_requested:true,public_key_pem:identity.public_key_pem};
  const privateKey=await fs.readFile(path.join(guest.storage_dir,'identity.pem'),'utf8');
  body.signature=sign('sha256',Buffer.from(joinPayload(body)),{
    key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  }).toString('base64url');
  body.label='tampered-label';
  await assert.rejects(enrollmentRequest(guest,'join',body),/invalid_identity_proof/);
  const valid=await requestEnrollment(guest,invitation.invitation);
  assert.equal(valid.status,'pending');
});

test('expiry, confirmation replay, and durable revoked identity do not grant access',
  {timeout:22000},async t=>{
  const f=await fixture(t);
  const admin=f.admin;
  const invitation=(await admin('invitations',{ttl_seconds:60})).body;
  const guest=f.config('fourth');
  const pending=await requestEnrollment(guest,invitation.invitation);
  await admin('approve',{request_id:pending.request_id,
    fingerprint:pending.fingerprint,enable_computer:false});
  const before=JSON.parse(await fs.readFile(
    path.join(guest.storage_dir,'pending.json'),'utf8'));
  const result=await claimEnrollment(guest);
  assert.equal(result.status,'ready_to_connect');
  const {createHmac}=await import('node:crypto');
  const cap=(await fs.readFile(path.join(guest.storage_dir,'host.token'),'utf8')).trim();
  const receipt=createHmac('sha256',cap).update(
    'styx-enrollment-confirm:'+before.request_id).digest('hex');
  const second=await enrollmentRequest(guest,'confirm',{request_id:before.request_id,
    claim_secret:before.claim_secret,confirmation:receipt});
  assert.equal(second.body.status,'ready_to_connect');
  const registry=new TargetRegistry({version:1,targets:[]});
  const restored=new EnrollmentController({rootDir:f.enrollDir,
    adminTokenFile:path.join(f.tmp,'admin.token'),registry});
  assert.equal(registry.resolve(pending.device_id).id,pending.device_id);
  restored.revoke({device_id:pending.device_id});
  const rebootRegistry=new TargetRegistry({version:1,targets:[]});
  new EnrollmentController({rootDir:f.enrollDir,
    adminTokenFile:path.join(f.tmp,'admin.token'),registry:rebootRegistry});
  assert.throws(()=>rebootRegistry.resolve(pending.device_id),/environment_not_found/);
});

test('owner CLI uses a distinct private admin token and refuses invalid approval inputs',
  {timeout:22000},async t=>{
  const f=await fixture(t);
  const {ownerCommand}=await import('../enroll-admin.mjs');
  const config={gateway_url:'https://127.0.0.1:'+f.http.address.port,
    gateway_ca_file:f.cert,admin_token_file:path.join(f.tmp,'admin.token')};
  const invite=await ownerCommand(config,'invite',['75']);
  assert.equal(invite.one_use,true);
  const pending=await requestEnrollment(f.config('owner-cli'),invite.invitation);
  const records=await ownerCommand(config,'pending');
  assert.equal(records[0].fingerprint,pending.fingerprint);
  await assert.rejects(ownerCommand(config,'approve',[pending.request_id,
    pending.fingerprint,'unsupported-capability']),/invalid_approval_capability/);
  assert.equal((await ownerCommand(config,'devices')).length,0);
  await ownerCommand(config,'approve',[pending.request_id,pending.fingerprint]);
  assert.equal((await ownerCommand(config,'devices'))[0].status,'approved');
  await ownerCommand(config,'revoke',[pending.device_id]);
  assert.equal((await ownerCommand(config,'devices'))[0].status,'revoked');
  const weakToken=path.join(f.tmp,'admin-insecure.token');
  await fs.writeFile(weakToken,f.adminToken,{mode:0o644});
  await fs.chmod(weakToken,0o644);
  await assert.rejects(ownerCommand({...config,admin_token_file:weakToken},
    'devices'),/admin_token_file_permissions/);
});

test('one local enrollment command can wait for explicit owner approval without OOB execution',
  {timeout:18000},async t=>{
  const f=await fixture(t);
  const device=f.config('unattended');
  const invite=(await f.admin('invitations',{})).body;
  const submitted=await requestEnrollment(device,invite.invitation);
  const {waitForApproval}=await import('../../host/enroll.mjs');
  let approveDone;
  const approved=new Promise((resolve,reject)=>{
    setTimeout(()=>{
      f.admin('approve',{request_id:submitted.request_id,
        fingerprint:submitted.fingerprint,enable_computer:false})
        .then(resolve,reject);
    },180);
  });
  const receipt=await waitForApproval(device,{timeoutMs:5000,pollMs:120});
  await approved;
  assert.equal(receipt.status,'ready_to_connect');
  assert.equal(receipt.device_id,submitted.device_id);
  const host=JSON.parse(await fs.readFile(receipt.local_host_config,'utf8'));
  assert.equal(host.host_id,submitted.device_id);
  assert.equal(f.gateway.registry.resolve(submitted.device_id).id,submitted.device_id);
});

test('expired invitations and pending requests cannot create approved devices',
  {timeout:18000},async t=>{
  const f=await fixture(t);
  const clock={now:Date.now()};
  // A separate isolated controller with injected monotonic wall clock uses
  // exactly the same admitted Gateway registry.
  const enrollRoot=path.join(f.tmp,'expiring');
  const controller=new EnrollmentController({rootDir:enrollRoot,
    adminTokenFile:path.join(f.tmp,'admin.token'),registry:f.gateway.registry,
    now:()=>clock.now});
  const invite=controller.invite({ttl_seconds:60});
  clock.now+=61000;
  const device=f.config('expired');
  const identity=initLocalIdentity(device);
  const {sign,constants}=await import('node:crypto');
  const {joinPayload}=await import('../enrollment.mjs');
  const fields={invitation:invite.invitation,device_id:identity.device_id,
    label:device.label,platform:process.platform,cwd:device.cwd,shell:device.shell,
    computer_requested:true,public_key_pem:identity.public_key_pem};
  const privateKey=await fs.readFile(path.join(device.storage_dir,'identity.pem'),'utf8');
  fields.signature=sign('sha256',Buffer.from(joinPayload(fields)),{
    key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  }).toString('base64url');
  assert.throws(()=>controller.join(fields),/invitation_expired_or_used/);
  assert.equal(controller.listPending().length,0);
  const fresh=controller.invite({});
  fields.invitation=fresh.invitation;
  fields.signature=sign('sha256',Buffer.from(joinPayload(fields)),{
    key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  }).toString('base64url');
  const pending=controller.join(fields);
  clock.now+=15*60*1000+1000;
  assert.throws(()=>controller.approve({request_id:pending.request_id,
    fingerprint:pending.fingerprint}),/request_not_pending/);
  assert.equal(f.gateway.registry.list().length,0);
});

test('a newly approved first Host becomes visible to MCP tools without Gateway restart',
  {timeout:22000},async t=>{
  const f=await fixture(t);
  const {Client}=await import('@modelcontextprotocol/sdk/client/index.js');
  const {InMemoryTransport}=await import('@modelcontextprotocol/sdk/inMemory.js');
  const [clientTransport,serverTransport]=InMemoryTransport.createLinkedPair();
  const server=f.gateway.serverForOwner('enrollment-test-owner');
  await server.connect(serverTransport);
  const model=new Client({name:'styx-enrollment-test',version:'0.1'});
  await model.connect(clientTransport);
  t.after(async()=>{await model.close();await server.close()});
  const before=await model.listTools();
  assert.ok(!before.tools.some(t=>t.name==='get_window_state'));
  const guest=f.config('first-computer');
  const invitation=(await f.admin('invitations',{})).body;
  const pending=await requestEnrollment(guest,invitation.invitation);
  await f.admin('approve',{request_id:pending.request_id,
    fingerprint:pending.fingerprint,enable_computer:true});
  const after=await model.listTools();
  assert.ok(after.tools.some(t=>t.name==='get_window_state'));
  const environments=await model.callTool({
    name:'list_execution_environments',arguments:{}});
  assert.equal(environments.structuredContent.environments.length,1);
  assert.equal(environments.structuredContent.environments[0].environment_id,
    pending.device_id);
  assert.ok(environments.structuredContent.environments[0].capabilities.includes('computer'));
  await f.admin('revoke',{device_id:pending.device_id});
  const denied=await model.listTools();
  assert.ok(!denied.tools.some(t=>t.name==='get_window_state'));
  const removed=await model.callTool({
    name:'list_execution_environments',arguments:{}});
  assert.equal(removed.structuredContent.environments.length,0);
});

test('owner recovery retires exact identity, closes both lanes and requires fresh proof and approval',
  {timeout:30000},async t=>{
  const f=await fixture(t),guest=f.config('recover-old');
  const oldInvitation=(await f.admin('invitations',{})).body.invitation;
  const pending=await requestEnrollment(guest,oldInvitation);
  await f.admin('approve',{request_id:pending.request_id,fingerprint:pending.fingerprint,
    enable_computer:true});
  await claimEnrollment(guest);
  const token=(await fs.readFile(path.join(guest.storage_dir,'host.token'),'utf8')).trim();
  const device=(await f.admin('devices')).body[0];
  const recovery={device_id:device.device_id,fingerprint:device.fingerprint,
    generation:device.generation};
  const adminConfig={gateway_url:guest.gateway_url,gateway_ca_file:f.cert,
    admin_token_file:path.join(f.tmp,'admin.token')};
  const {ownerCommand}=await import('../enroll-admin.mjs');
  await assert.rejects(ownerCommand(adminConfig,'recover',[device.device_id]),
    /recover_requires_device_id_fingerprint_and_generation/);
  for(const adminToken of [token,f.mcpToken])
    await assert.rejects(enrollmentRequest(guest,'recover',recovery,{adminToken}),/unauthorized/);
  for(const bad of [{...recovery,device_id:'styx-'+'0'.repeat(24)},
    {...recovery,fingerprint:'0'.repeat(64)},{...recovery,generation:'old-generation'},
    {...recovery,unexpected:'credential'}])
    await assert.rejects(f.admin('recover',bad),/device_not_found|recovery_identity_mismatch|invalid_fields/);
  assert.equal(f.gateway.registry.resolve(device.device_id).allowed,true);
  const sockets=[];
  for(const lane of ['exec','computer']){
    const ws=new WebSocket(guest.gateway_url.replace('https:','wss:')+
      '/styx/hosts/'+device.device_id+'/'+lane,{ca:await fs.readFile(f.cert),
      headers:{Authorization:'Bearer '+token}});
    await once(ws,'open');sockets.push(ws);
  }
  const {sign,constants}=await import('node:crypto');
  const {joinPayload}=await import('../enrollment.mjs');
  const retiredIdentity=initLocalIdentity(guest);
  const staleApprovalBody={invitation:(await f.admin('invitations',{})).body.invitation,
    device_id:'styx-'+randomBytes(12).toString('hex'),label:guest.label,
    platform:process.platform,cwd:guest.cwd,shell:guest.shell,
    computer_requested:true,public_key_pem:retiredIdentity.public_key_pem};
  const privateKey=await fs.readFile(path.join(guest.storage_dir,'identity.pem'),'utf8');
  staleApprovalBody.signature=sign('sha256',Buffer.from(joinPayload(staleApprovalBody)),{
    key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
  const staleApproval=(await enrollmentRequest(guest,'join',staleApprovalBody)).body;
  // Claiming an executor binding races with an owner retirement. Acquisition
  // may have happened, but the peer and all subsequent bindings must fail.
  const binding=f.gateway.pool.binding(device.device_id).catch(e=>e);
  const closes=sockets.map(ws=>once(ws,'close'));
  const recovered=await ownerCommand(adminConfig,'recover',[
    device.device_id,device.fingerprint,device.generation]);
  assert.deepEqual(recovered,{device_id:device.device_id,status:'revoked',
    recovery:'fresh_enrollment_required'});
  await Promise.all(closes);
  assert.equal(f.gateway.relay.connected(device.device_id),false);
  await assert.rejects(f.gateway.pool.binding(device.device_id),/environment_access_denied/);
  await assert.rejects(f.admin('recover',recovery),/device_not_found/);
  await assert.rejects(f.admin('approve',{request_id:staleApproval.request_id,
    fingerprint:device.fingerprint}),/device_identity_retired/);
  assert.equal((await binding) instanceof Error,true);
  assert.doesNotMatch(JSON.stringify(recovered),/token|secret|private|fingerprint|generation/);
  await assert.rejects(fs.stat(path.join(f.enrollDir,'tokens',device.device_id+'.token')),/ENOENT/);
  const rebootRegistry=new TargetRegistry({version:1,targets:[]});
  const reboot=new EnrollmentController({rootDir:f.enrollDir,
    adminTokenFile:path.join(f.tmp,'admin.token'),registry:rebootRegistry});
  assert.equal(reboot.devices()[0].status,'revoked');
  assert.throws(()=>rebootRegistry.resolve(device.device_id),/environment_not_found/);
  const rejected=new WebSocket(guest.gateway_url.replace('https:','wss:')+
    '/styx/hosts/'+device.device_id+'/exec',{ca:await fs.readFile(f.cert),
    headers:{Authorization:'Bearer '+token}});
  const status=await new Promise(resolve=>{
    rejected.on('unexpected-response',(_req,res)=>{res.resume();rejected.terminate();resolve(res.statusCode)});
    rejected.on('error',()=>{});
    rejected.on('open',()=>{rejected.close();resolve(101)});
  });
  assert.equal(status,403);
  // The replacement obtains a different identity and bearer via the existing
  // signed join and encrypted claim, with independent fingerprint approval.
  const replacement=f.config('recover-new',false);
  await assert.rejects(requestEnrollment(replacement,oldInvitation),/invitation_expired_or_used/);
  const fresh=(await f.admin('invitations',{})).body.invitation;
  const replay={invitation:fresh,device_id:device.device_id,label:guest.label,
    platform:process.platform,cwd:guest.cwd,shell:guest.shell,
    computer_requested:true,public_key_pem:retiredIdentity.public_key_pem};
  replay.signature=sign('sha256',Buffer.from(joinPayload(replay)),{
    key:await fs.readFile(path.join(guest.storage_dir,'identity.pem'),'utf8'),
    padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
  await assert.rejects(enrollmentRequest(guest,'join',replay),/device_identity_retired/);
  replay.device_id='styx-'+randomBytes(12).toString('hex');
  replay.signature=sign('sha256',Buffer.from(joinPayload(replay)),{
    key:await fs.readFile(path.join(guest.storage_dir,'identity.pem'),'utf8'),
    padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
  await assert.rejects(enrollmentRequest(guest,'join',replay),/device_identity_retired/);
  const newPending=await requestEnrollment(replacement,fresh);
  assert.notEqual(newPending.device_id,device.device_id);
  assert.notEqual(newPending.fingerprint,device.fingerprint);
  assert.equal((await claimEnrollment(replacement)).status,'pending');
  await assert.rejects(f.admin('approve',{request_id:newPending.request_id,
    fingerprint:device.fingerprint}),/fingerprint_mismatch/);
  await f.admin('approve',{request_id:newPending.request_id,fingerprint:newPending.fingerprint});
  assert.equal((await claimEnrollment(replacement)).status,'ready_to_connect');
  assert.notEqual((await fs.readFile(path.join(replacement.storage_dir,'host.token'),'utf8')).trim(),token);
});

test('recovery persistence failure never acknowledges retirement or mutates live admission',async t=>{
  const f=await fixture(t),guest=f.config('recover-failure',false);
  const pending=await requestEnrollment(guest,(await f.admin('invitations',{})).body.invitation);
  await f.admin('approve',{request_id:pending.request_id,fingerprint:pending.fingerprint});
  const before=(await f.admin('devices')).body[0];
  const save=f.controller.save;
  f.controller.save=()=>{throw Error('private filesystem failure /secret/path')};
  await assert.rejects(f.admin('recover',{device_id:before.device_id,
    fingerprint:before.fingerprint,generation:before.generation}),/^Error: enrollment_internal_error$/);
  f.controller.save=save;
  assert.equal(f.gateway.registry.resolve(before.device_id).allowed,true);
  assert.equal(f.controller.devices()[0].status,'approved');
  const registry=new TargetRegistry({version:1,targets:[]});
  const restored=new EnrollmentController({rootDir:f.enrollDir,
    adminTokenFile:path.join(f.tmp,'admin.token'),registry});
  assert.equal(restored.devices()[0].status,'approved');
});

import {sign,constants} from 'node:crypto';
import {capabilityPayload} from '../../shared/enrollment-protocol.mjs';
test('capability changes need owner and exact device proof, rotate revision and preserve enrolled credentials',async t=>{
 const f=await fixture(t),cfg=f.config('capability',false),identity=initLocalIdentity(cfg);
 const invitation=(await f.admin('invitations',{})).body;
 const pending=await requestEnrollment(cfg,invitation.invitation);
 await f.admin('approve',{request_id:pending.request_id,fingerprint:identity.fingerprint,enable_computer:false});
 await claimEnrollment(cfg);
 const tokenFile=f.gateway.registry.resolve(identity.device_id).exec.token_file;
 const token=await fs.readFile(tokenFile,'utf8');
 const key=await fs.readFile(path.join(cfg.storage_dir,'identity.pem'),'utf8');
 const request=enabled=>{
  const device=f.controller.devices().find(x=>x.device_id===identity.device_id);
  const body={device_id:identity.device_id,fingerprint:identity.fingerprint,generation:device.generation,enable_computer:enabled,public_key_pem:identity.public_key_pem};
  body.signature=sign('sha256',Buffer.from(capabilityPayload(body)),{key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');return body;
 };
 const enable=request(true);
 await assert.rejects(enrollmentRequest(cfg,'capabilities',enable),/unauthorized/);
 await assert.rejects(f.admin('capabilities',{...enable,enable_computer:false}),/invalid_identity_proof/);
 const changed=(await f.admin('capabilities',enable)).body;
 assert.equal(changed.capabilities.computer,true);assert.notEqual(changed.generation,enable.generation);
 assert.equal(f.gateway.registry.resolve(identity.device_id).computer.enabled,true);
 assert.equal(await fs.readFile(tokenFile,'utf8'),token);
 await assert.rejects(f.admin('capabilities',enable),/revision_mismatch/);
 const deny=request(false);await f.admin('capabilities',deny);
 assert.equal(f.gateway.registry.resolve(identity.device_id).computer.enabled,false);
 assert.equal(await fs.readFile(tokenFile,'utf8'),token);
 const originalSave=f.controller.save;f.controller.save=()=>{throw Error('disk failure')};
 await assert.rejects(f.admin('capabilities',request(true)),/enrollment_internal_error/);
 assert.equal(f.gateway.registry.resolve(identity.device_id).computer.enabled,false);
 assert.equal(f.controller.devices().find(x=>x.device_id===identity.device_id).capabilities.computer,false);
 f.controller.save=originalSave;
 const restored=new EnrollmentController({rootDir:f.enrollDir,adminTokenFile:path.join(f.tmp,'admin.token'),registry:new TargetRegistry({version:1,targets:[]})});
 assert.equal(restored.devices().find(x=>x.device_id===identity.device_id).capabilities.computer,false);
});

test('owner-selected default persists across restart and revocation clears it without selecting another device',async t=>{
 const f=await fixture(t),cfg=f.config('default',false),identity=initLocalIdentity(cfg);
 const invitation=(await f.admin('invitations',{})).body;
 const pending=await requestEnrollment(cfg,invitation.invitation);
 await f.admin('approve',{request_id:pending.request_id,fingerprint:identity.fingerprint,enable_computer:false});
 assert.throws(()=>f.gateway.registry.resolve(),/default_environment_required/);
 await assert.rejects(enrollmentRequest(cfg,'set-default',{device_id:identity.device_id}),/unauthorized/);
 await assert.rejects(f.admin('set-default',{device_id:'styx-'+'0'.repeat(24)}),/device_not_found/);
 const selected=(await f.admin('set-default',{device_id:identity.device_id})).body;
 assert.equal(selected.default_environment_id,identity.device_id);
 assert.equal(f.gateway.registry.resolve().id,identity.device_id);
 const registry=new TargetRegistry({version:1,targets:[]});
 const restored=new EnrollmentController({rootDir:f.enrollDir,adminTokenFile:path.join(f.tmp,'admin.token'),registry});
 assert.equal(registry.resolve().id,identity.device_id);
 restored.revoke({device_id:identity.device_id});
 assert.throws(()=>registry.resolve(),/default_environment_required/);
 const after=new TargetRegistry({version:1,targets:[]});
 new EnrollmentController({rootDir:f.enrollDir,adminTokenFile:path.join(f.tmp,'admin.token'),registry:after});
 assert.throws(()=>after.resolve(),/default_environment_required/);
});


test('Browser request is signed and only its approved capability crosses the Gateway',async t=>{
 const f=await fixture(t),cfg={...f.config('browser',false),browser_requested:true,browser_config:{enabled:true,headless:true,profileRoot:path.join(f.tmp,'private-browser-profile'),executablePath:'/trusted/browser'}};
 const identity=initLocalIdentity(cfg),invitation=(await f.admin('invitations',{})).body.invitation;
 const {joinPayload}=await import('../../shared/enrollment-protocol.mjs');
 const legacy={invitation,device_id:identity.device_id,label:cfg.label,platform:process.platform,cwd:cfg.cwd,shell:cfg.shell,computer_requested:false,public_key_pem:identity.public_key_pem};
 assert.equal(joinPayload(legacy),JSON.stringify(legacy));
 const body={...legacy,browser_requested:true};
 body.signature=sign('sha256',Buffer.from(joinPayload(body)),{key:await fs.readFile(path.join(cfg.storage_dir,'identity.pem'),'utf8'),padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
 await assert.rejects(enrollmentRequest(cfg,'join',{...body,browser_requested:false}),/invalid_identity_proof/);
 const pending=await requestEnrollment(cfg,invitation);
 assert.equal(f.controller.listPending()[0].browser_requested,true);
 assert.equal((await claimEnrollment(cfg)).status,'pending');
 const owner={gateway_url:cfg.gateway_url,gateway_ca_file:cfg.gateway_ca_file,admin_token_file:path.join(f.tmp,'admin.token')};
 const {ownerCommand}=await import('../enroll-admin.mjs');
 await ownerCommand(owner,'approve',[pending.request_id,pending.fingerprint,'browser']);
 const claim=await claimEnrollment(cfg),host=JSON.parse(await fs.readFile(claim.local_host_config,'utf8'));
 assert.deepEqual(host.browser,cfg.browser_config);assert.equal(host.computer,undefined);
 assert.deepEqual(f.gateway.registry.resolve(identity.device_id).browser,{enabled:true,transport:'outbound'});
 const publicDevices=JSON.stringify(f.controller.devices()),database=await fs.readFile(path.join(f.enrollDir,'state.json'),'utf8');
 for(const text of [publicDevices,database])assert.doesNotMatch(text,/profileRoot|executablePath|private-browser-profile|trusted\/browser/);
 assert.equal(f.controller.devices()[0].capabilities.browser,true);
});
test('unrequested or denied Browser never creates a Host browser configuration',async t=>{
 const f=await fixture(t),cfg=f.config('unrequested-browser',false),pending=await requestEnrollment(cfg,(await f.admin('invitations',{})).body.invitation);
 await assert.rejects(f.admin('approve',{request_id:pending.request_id,fingerprint:pending.fingerprint,enable_browser:true}),/browser_capability_not_requested/);
 await f.admin('approve',{request_id:pending.request_id,fingerprint:pending.fingerprint,enable_browser:false});
 const claim=await claimEnrollment(cfg);assert.equal(claim.capabilities.browser,false);assert.equal(JSON.parse(await fs.readFile(claim.local_host_config,'utf8')).browser,undefined);
 const denied={...f.config('denied-browser',false),browser_requested:true,browser_config:{enabled:true,headless:true,profileRoot:path.join(f.tmp,'denied-profile')}};
 const request=await requestEnrollment(denied,(await f.admin('invitations',{})).body.invitation);
 await f.admin('approve',{request_id:request.request_id,fingerprint:request.fingerprint,enable_browser:false});
 assert.equal(JSON.parse(await fs.readFile((await claimEnrollment(denied)).local_host_config,'utf8')).browser,undefined);
});
test('Browser-only v2 grant preserves desktop grant, identity and credentials; v1 preserves Browser',async t=>{
 const f=await fixture(t),cfg=f.config('browser-capability',true),identity=initLocalIdentity(cfg);
 const pending=await requestEnrollment(cfg,(await f.admin('invitations',{})).body.invitation);
 await f.admin('approve',{request_id:pending.request_id,fingerprint:pending.fingerprint,enable_computer:true});await claimEnrollment(cfg);
 const initial=f.gateway.registry.resolve(identity.device_id),credential=await fs.readFile(initial.exec.token_file,'utf8'),key=await fs.readFile(path.join(cfg.storage_dir,'identity.pem'),'utf8');
 const request=change=>{const body={device_id:identity.device_id,fingerprint:identity.fingerprint,generation:f.gateway.registry.resolve(identity.device_id).generation,...change,public_key_pem:identity.public_key_pem};body.signature=sign('sha256',Buffer.from(capabilityPayload(body)),{key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');return body};
 const browser=request({enable_browser:true});assert.match(capabilityPayload(browser),/styx-device-capabilities-v2/);
 await assert.rejects(f.admin('capabilities',{...browser,enable_computer:false}),/invalid_identity_proof/);
 const enabled=(await f.admin('capabilities',browser)).body;assert.equal(enabled.capabilities.browser,true);assert.equal(enabled.capabilities.computer,true);
 let target=f.gateway.registry.resolve(identity.device_id);assert.deepEqual(target.computer,initial.computer);assert.deepEqual(target.exec,initial.exec);
 await assert.rejects(f.admin('capabilities',browser),/revision_mismatch/);
 const old=request({enable_computer:false});assert.match(capabilityPayload(old),/styx-device-capabilities-v1/);
 await f.admin('capabilities',old);target=f.gateway.registry.resolve(identity.device_id);assert.equal(target.browser.enabled,true);assert.equal(target.computer.enabled,false);
 const before=target,save=f.controller.save;f.controller.save=()=>{throw Error('disk failed')};
 await assert.rejects(f.admin('capabilities',request({enable_browser:false})),/enrollment_internal_error/);f.controller.save=save;
 assert.deepEqual(f.gateway.registry.resolve(identity.device_id),before);
 assert.equal(await fs.readFile(initial.exec.token_file,'utf8'),credential);assert.equal(await fs.readFile(path.join(cfg.storage_dir,'identity.pem'),'utf8'),key);
 const restored=new EnrollmentController({rootDir:f.enrollDir,adminTokenFile:path.join(f.tmp,'admin.token'),registry:new TargetRegistry({version:1,targets:[]})});
 assert.equal(restored.devices()[0].capabilities.browser,true);assert.equal(restored.devices()[0].capabilities.computer,false);
});
