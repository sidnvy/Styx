import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import syncFs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {EnrollmentController} from '../../gateway/enrollment.mjs';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {requestEnrollment,claimEnrollment,enrollmentRequest} from '../../host/enroll.mjs';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
import {createPairingLink,inspectPairingLink,acceptPairingLink} from '../pairing-links.mjs';
async function fixture(t) {
  const scratch=await fs.mkdtemp(path.join(os.tmpdir(),'styx-pairing-pilot-'));
  const tmp=path.join(scratch,'private');ensurePrivateDirectory(tmp);
  let http;
  t.after(async()=>{
    await http?.close();
    await fs.rm(scratch,{recursive:true,force:true});
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
      label,cwd:tmp,shell:process.platform==='win32'?path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe'):'/bin/sh',
      exec_binary:process.execPath,
      computer_requested:computer,
      ...(computer?{computer_binary:process.execPath}:{})
    };
  }
  const admin=(route,data)=>enrollmentRequest(config('admin-client'),route,data,{
    adminToken
  });
  return {tmp,gateway,controller,admin,config,http,cert,adminToken,mcpToken,enrollDir};
}



const mutate=(link,fn)=>{const data=JSON.parse(Buffer.from(new URL(link).hash.slice(1),'base64url').toString());fn(data);return 'styx://join#'+Buffer.from(JSON.stringify(data)).toString('base64url')};
test('actual HTTPS link import -> device request -> separate owner fingerprint approval -> encrypted claim',async t=>{
 const f=await fixture(t),cfg=f.config('link',false),ca=await fs.readFile(f.cert,'utf8');
 const created=createPairingLink({controller:f.controller,gatewayOrigin:cfg.gateway_url,approved:true,caPem:ca});
 assert.ok(created.link.startsWith('styx://join#'));assert.equal(new URL(created.link).search,'');
 const preview=inspectPairingLink(created.link);assert.ok(!JSON.stringify(preview).includes('invitation'));assert.equal(preview.caSha256,created.caSha256);
 const stateDir=path.join(f.tmp,'imported');const result=acceptPairingLink(created.link,{stateDir,approvedGatewayOrigin:cfg.gateway_url,approvedCaSha256:preview.caSha256});
 assert.equal(result.status,'pairing_material_saved');assert.ok(!JSON.stringify(result).includes(created.link));assert.ok(!JSON.stringify(result).includes(stateDir));
 const saved=JSON.parse(await fs.readFile(path.join(stateDir,'pairing.json'),'utf8'));
 const invitation=(await fs.readFile(saved.invitationFile,'utf8')).trim();assert.ok(!JSON.stringify(result).includes(invitation));
 const device={...cfg,gateway_ca_file:saved.gatewayCaFile};const pending=await requestEnrollment(device,invitation);
 assert.equal(f.gateway.registry.list().length,0);f.controller.approve({request_id:pending.request_id,fingerprint:pending.fingerprint,enable_computer:false});
 const ready=await claimEnrollment(device);assert.equal(ready.status,'ready_to_connect');
 await assert.rejects(requestEnrollment(f.config('replay',false),invitation),/invitation_expired_or_used/);
 assert.throws(()=>acceptPairingLink(created.link,{stateDir,approvedGatewayOrigin:cfg.gateway_url,approvedCaSha256:preview.caSha256}),/state_already_exists/);
 f.controller.revoke({device_id:ready.device_id});
});
test('wrong origin, unapproved/changed certificate, expiry and malformed secret fields fail before writing',async t=>{
 const f=await fixture(t),cfg=f.config('negative',false),ca=await fs.readFile(f.cert,'utf8');
 const created=createPairingLink({controller:f.controller,gatewayOrigin:cfg.gateway_url,approved:true,caPem:ca});const stateDir=path.join(f.tmp,'must-not-exist');
 for(const [link,options] of [[created.link,{approvedGatewayOrigin:'https://wrong.example',approvedCaSha256:created.caSha256}],[created.link,{approvedGatewayOrigin:cfg.gateway_url}],[created.link,{approvedGatewayOrigin:cfg.gateway_url,approvedCaSha256:'0'.repeat(64)}],[mutate(created.link,d=>d.expiresAt=Date.now()-1),{approvedGatewayOrigin:cfg.gateway_url,approvedCaSha256:created.caSha256}],[mutate(created.link,d=>d.admin_token='DO_NOT_ECHO'),{approvedGatewayOrigin:cfg.gateway_url,approvedCaSha256:created.caSha256}],[mutate(created.link,d=>d.caPem=d.caPem.replace('CERTIFICATE','PRIVATE KEY')),{approvedGatewayOrigin:cfg.gateway_url,approvedCaSha256:created.caSha256}]])assert.throws(()=>acceptPairingLink(link,{stateDir,...options}));
 assert.equal(syncFs.existsSync(stateDir),false);
});
test('strict fragment schema rejects query, oversized, credentials, duplicate JSON and secret echo',()=>{
 for(const link of ['styx://join?invitation=SECRET#abc','styx://user:SECRET@join#abc','styx://join/path#abc','styx://join#'+'a'.repeat(33000),'https://join#SECRET','styx://join#%%%'])assert.throws(()=>inspectPairingLink(link),e=>!e.message.includes('SECRET'));
 const duplicate='{"schema":1,"schema":1}';assert.throws(()=>inspectPairingLink('styx://join#'+Buffer.from(duplicate).toString('base64url')),/noncanonical/);
 let issued=0;assert.throws(()=>createPairingLink({controller:{invite(){issued++}},gatewayOrigin:'https://gateway.example',approved:false}));assert.equal(issued,0);
});
test('system-trusted TLS requires explicit origin and does not accept unsolicited CA approval',async t=>{
 const f=await fixture(t),origin=f.config('system',false).gateway_url;
 const created=createPairingLink({controller:f.controller,gatewayOrigin:origin,approved:true});assert.equal(created.requiresCertificateApproval,false);
 const stateDir=path.join(f.tmp,'system-import');assert.throws(()=>acceptPairingLink(created.link,{stateDir,approvedGatewayOrigin:origin,approvedCaSha256:'0'.repeat(64)}));
 assert.equal(acceptPairingLink(created.link,{stateDir,approvedGatewayOrigin:origin}).customCertificateApproved,false);
 const saved=JSON.parse(await fs.readFile(path.join(stateDir,'pairing.json'),'utf8'));assert.equal(saved.gatewayCaFile,undefined);
});
test('private material modes and existing broad directory refusal; expiry cannot be extended at Gateway',async t=>{
 const f=await fixture(t),cfg=f.config('expiry',false);
 const created=createPairingLink({controller:f.controller,gatewayOrigin:cfg.gateway_url,approved:true,ttlSeconds:60});
 const broad=path.join(f.tmp,'existing');await fs.mkdir(broad,{mode:0o755});
 assert.throws(()=>acceptPairingLink(created.link,{stateDir:broad,approvedGatewayOrigin:cfg.gateway_url}),/state_already_exists/);assert.deepEqual(await fs.readdir(broad),[]);
 const stateDir=path.join(f.tmp,'fresh-private');acceptPairingLink(created.link,{stateDir,approvedGatewayOrigin:cfg.gateway_url});
 const saved=JSON.parse(await fs.readFile(path.join(stateDir,'pairing.json'),'utf8'));
 if(process.platform!=='win32')for(const file of [saved.invitationFile,path.join(stateDir,'pairing.json')])assert.equal((await fs.stat(file)).mode&0o077,0);
 // Link metadata is not a signed authorization. The real controller's stored
 // expiry and single-use state remain authoritative even if metadata changes.
 const later=mutate(created.link,d=>d.expiresAt=Date.now()+590000);inspectPairingLink(later);
 f.controller.now=()=>Date.now()+61000;
 await assert.rejects(requestEnrollment(cfg,(await fs.readFile(saved.invitationFile,'utf8')).trim()),/invitation_expired_or_used/);assert.equal(f.gateway.registry.list().length,0);
});
