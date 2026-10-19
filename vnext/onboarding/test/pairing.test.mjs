import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {EnrollmentController} from '../../gateway/enrollment.mjs';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {requestEnrollment,enrollmentRequest} from '../../host/enroll.mjs';
import {pairDevice,createLocalPairingTransport} from '../pairing.mjs';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
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


const authorize=cfg=>({...cfg,platform:process.platform,approve:true,enable_computer:false});
test('actual HTTPS automatic owner pairing keeps keys and credentials only on device; revocation persists',async t=>{
 const f=await fixture(t),cfg=f.config('automatic',false),transport=createLocalPairingTransport(cfg);
 const result=await pairDevice({controller:f.controller,transport,authorization:authorize(cfg)});
 assert.equal(result.status,'ready_to_connect');assert.equal(result.capabilities.computer,false);
 const identity=JSON.parse(await fs.readFile(path.join(cfg.storage_dir,'identity.json'),'utf8'));
 assert.equal(result.fingerprint,identity.fingerprint);assert.equal(result.device_id,identity.device_id);
 const token=(await fs.readFile(path.join(cfg.storage_dir,'host.token'),'utf8')).trim();
 assert.ok(token.length>32);assert.ok(!JSON.stringify(result).includes(token));assert.ok(!JSON.stringify(result).includes('PRIVATE KEY'));
 f.controller.revoke({device_id:result.device_id});assert.equal(f.gateway.registry.list().length,0);
 const restarted=new EnrollmentController({rootDir:f.enrollDir,adminTokenFile:path.join(f.tmp,'admin.token'),registry:f.gateway.registry,relay:f.gateway.relay});
 assert.equal(restarted.devices()[0].status,'revoked');
});
test('owner absence or mismatched capability/routing scope refuses before invitation',async()=>{
 let invites=0;const controller={invite(){invites++;throw Error('unexpected')}};
 const cfg={gateway_url:'https://127.0.0.1:1',storage_dir:path.join(os.tmpdir(),'unused'),label:'scope',cwd:os.tmpdir(),shell:process.execPath,exec_binary:process.execPath};
 const transport=createLocalPairingTransport(cfg);
 for(const authorization of [{...authorize(cfg),approve:false},{...authorize(cfg),gateway_url:'https://elsewhere.invalid'},{...authorize(cfg),enable_computer:true},{...authorize(cfg),cwd:'/different'}])await assert.rejects(pairDevice({controller,transport,authorization}));
 assert.equal(invites,0);
});
test('trusted-channel fingerprint tampering is never approved',async t=>{
 const f=await fixture(t),cfg=f.config('tamper',false),real=createLocalPairingTransport(cfg);
 const transport={...real,async request(invite){return {...await real.request(invite),fingerprint:'0'.repeat(64)}}};
 await assert.rejects(pairDevice({controller:f.controller,transport,authorization:authorize(cfg)}),/trusted_identity_mismatch/);
 assert.equal(f.gateway.registry.list().length,0);
});
test('single-use invitation cannot be replayed; uncertain claim never leaks raw exception',async t=>{
 const f=await fixture(t),cfg=f.config('uncertain',false),real=createLocalPairingTransport(cfg);let invitation;
 const transport={...real,async request(value){invitation=value;return real.request(value)},async claim(){throw Error('secret_should_never_appear')}};
 const result=await pairDevice({controller:f.controller,transport,authorization:authorize(cfg)});
 assert.equal(result.status,'needs_owner_attention');assert.equal(result.phase,'claim_uncertain');assert.ok(!JSON.stringify(result).includes('secret_should_never_appear'));
 await assert.rejects(requestEnrollment(f.config('replay',false),invitation),/invitation_expired_or_used/);
 f.controller.revoke({device_id:result.device_id});
});

test('HTTPS default trust rejects an untrusted Gateway certificate without approving a device',async t=>{
 const f=await fixture(t),cfg=f.config('untrusted-tls',false);delete cfg.gateway_ca_file;
 await assert.rejects(pairDevice({controller:f.controller,transport:createLocalPairingTransport(cfg),authorization:authorize(cfg)}),/pairing_request_failed_no_approval/);
 assert.equal(f.gateway.registry.list().length,0);assert.equal(f.controller.listPending().length,0);
});
test('Gateway pending scope is checked independently of transport descriptor',async t=>{
 const f=await fixture(t),cfg=f.config('scope-tamper',false),other={...cfg,cwd:f.tmp+'/different'};
 const trusted=createLocalPairingTransport(cfg),changed=createLocalPairingTransport(other);
 await assert.rejects(pairDevice({controller:f.controller,transport:{...trusted,request:changed.request},authorization:authorize(cfg)}),/pending_scope_mismatch/);
 assert.equal(f.gateway.registry.list().length,0);
});
