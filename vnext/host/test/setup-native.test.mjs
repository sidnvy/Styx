import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,createPublicKey,generateKeyPairSync,sign,randomUUID} from 'node:crypto';
import {prepareNativeSetup} from '../setup-native.mjs';
import {ensurePrivateDirectory} from '../private-storage.mjs';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {EnrollmentController} from '../../gateway/enrollment.mjs';
import {requestEnrollment,claimEnrollment,enrollmentRequest} from '../enroll.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
function fixture(t){
 const root=path.join(os.tmpdir(),'styx-setup-'+randomUUID());ensurePrivateDirectory(root);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const bundle=path.join(root,'bundle');fs.mkdirSync(bundle);fs.mkdirSync(path.join(bundle,'host'));fs.mkdirSync(path.join(bundle,'bin'));
 const {publicKey,privateKey}=generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
 const exe=process.platform==='win32'?'.exe':'';
 const contents={};for(const f of ['private-storage.mjs','installer.mjs','launch.mjs'])contents['host/'+f]=fs.readFileSync(new URL('../'+f,import.meta.url));
 for(const f of ['enroll.mjs','doctor.mjs','setup-native.mjs','linux-service.mjs','macos-launchagent.mjs','windows-task.ps1'])contents['host/'+f]=Buffer.from('// signed fixture; never executed');
 contents['bin/node'+exe]=fs.readFileSync(process.execPath);for(const f of ['codex','cua-driver'])contents['bin/'+f+exe]=Buffer.from('fixture never executed');
 const manifest={schema:1,version:'0.1.0-test',platform:process.platform,arch:process.arch,files:Object.entries(contents).map(([name,b])=>{fs.writeFileSync(path.join(bundle,name),b);return {path:name,sha256:hash(b),size:b.length,executable:name.startsWith('bin/')};})};
 const raw=JSON.stringify(manifest);fs.writeFileSync(path.join(bundle,'manifest.json'),raw);fs.writeFileSync(path.join(bundle,'manifest.sig'),sign(null,Buffer.from(raw),privateKey).toString('base64url'));
 const publisherKeyFile=path.join(root,'publisher.pem');fs.writeFileSync(publisherKeyFile,publicKey);
 return {root,bundle,config:{bundle,publisherKeyFile,publisherSha256:hash(createPublicKey(publicKey).export({type:'spki',format:'der'})),baseDir:path.join(root,'new-device'),gatewayUrl:'https://gateway.example',label:'Fresh device',computer:false}};
}
test('fresh setup uses verified bundled paths and stops before pairing or service registration',t=>{
 const f=fixture(t),r=prepareNativeSetup(f.config);assert.equal(r.status,'prepared_not_paired');assert.equal(r.pairing,'NOT RUN');
 const cfg=JSON.parse(fs.readFileSync(r.enrollment_config));assert.ok(cfg.exec_binary.startsWith(r.release_root));assert.equal(cfg.computer_requested,false);
 assert.equal(fs.existsSync(path.join(cfg.storage_dir,'identity.pem')),false);assert.equal(fs.existsSync(path.join(cfg.storage_dir,'host.json')),false);
 assert.throws(()=>prepareNativeSetup(f.config),/setup_directory_already_exists/);
});
test('wrong independent publisher fingerprint and tampered bundle cannot create install state',t=>{
 const f=fixture(t);assert.throws(()=>prepareNativeSetup({...f.config,publisherSha256:'0'.repeat(64)}),/publisher_fingerprint_mismatch/);assert.equal(fs.existsSync(f.config.baseDir),false);
 fs.appendFileSync(path.join(f.bundle,'host/enroll.mjs'),'tamper');assert.throws(()=>prepareNativeSetup(f.config),/release_file_metadata_mismatch/);assert.equal(fs.existsSync(f.config.baseDir),false);
});
test('credential-bearing or insecure Gateway URL refuses before state writes',t=>{
 const f=fixture(t);for(const gatewayUrl of ['http://gateway.example','https://user:secret@gateway.example','https://gateway.example/?token=secret'])assert.throws(()=>prepareNativeSetup({...f.config,gatewayUrl}),/gateway_https_origin_required/);
 assert.equal(fs.existsSync(f.config.baseDir),false);
});
test('prepared configuration pairs with a fresh HTTPS Gateway and retains verified runtime paths',
 {skip:process.platform!=='linux',timeout:20000},async t=>{
 const f=fixture(t),cert=path.join(f.root,'ca.pem'),key=path.join(f.root,'tls.key'),adminFile=path.join(f.root,'admin.token');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-keyout',key,'-out',cert,'-subj','/CN=setup-test','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',timeout:10000});
 const adminToken=randomUUID()+randomUUID();fs.writeFileSync(adminFile,adminToken,{mode:0o600});
 const gateway=createStyxGateway({catalog:{version:1,targets:[]}}),allowedHosts=[];
 const enrollment=new EnrollmentController({rootDir:path.join(f.root,'registry'),adminTokenFile:adminFile,registry:gateway.registry,relay:gateway.relay});
 const http=await createGatewayHttp(gateway,{token:randomUUID()+randomUUID(),port:0,allowedHosts,enrollment,tlsCertificateFile:cert,tlsPrivateKeyFile:key});
 try{
  allowedHosts.push('127.0.0.1:'+http.address.port);
  const r=prepareNativeSetup({...f.config,gatewayUrl:'https://127.0.0.1:'+http.address.port,gatewayCaFile:cert});
  const cfg=JSON.parse(fs.readFileSync(r.enrollment_config));
  const admin=(route,data)=>enrollmentRequest(cfg,route,data,{adminToken});
  const invitation=(await admin('invitations',{})).body;
  const pending=await requestEnrollment(cfg,invitation.invitation);assert.equal((await claimEnrollment(cfg)).status,'pending');
  await admin('approve',{request_id:pending.request_id,fingerprint:pending.fingerprint,enable_computer:false});
  const result=await claimEnrollment(cfg);assert.equal(result.status,'ready_to_connect');
  const host=JSON.parse(fs.readFileSync(result.local_host_config));assert.equal(host.exec.binary,cfg.exec_binary);assert.equal(host.exec.env.CODEX_HOME,cfg.codex_home);
  assert.equal(host.gateway_ws_url,'wss://127.0.0.1:'+http.address.port+'/');assert.equal(host.computer,undefined);
  assert.equal(gateway.registry.list().length,1);
 }finally{await http.close();}
});
