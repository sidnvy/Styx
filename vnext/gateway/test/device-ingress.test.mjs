import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import {createServer} from 'node:net';
import {checkServerIdentity} from 'node:tls';
import {once} from 'node:events';
import {execFileSync} from 'node:child_process';
import {randomBytes,createHash,X509Certificate,createPublicKey,sign,constants} from 'node:crypto';
import WebSocket from 'ws';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';
import {EnrollmentController} from '../enrollment.mjs';
import {GatewayDeviceIngress} from '../device-ingress.mjs';
import {ownerCommand} from '../enroll-admin.mjs';
import {requestEnrollment,claimEnrollment} from '../../host/enroll.mjs';
import {pairingComparisonCode,capabilityPayload} from '../../shared/enrollment-protocol.mjs';

const digest=file=>createHash('sha256').update(new X509Certificate(fs.readFileSync(file)).raw).digest('hex');
const lanAddress=()=>Object.values(os.networkInterfaces()).flat().find(value=>value?.family==='IPv4'&&!value.internal)?.address;
async function availablePort(host){
 const server=createServer();server.listen(0,host);await once(server,'listening');
 const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;
}
function certificate(dir,name,ip){
 const cert=path.join(dir,name+'.pem'),key=path.join(dir,name+'-key.pem');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-keyout',key,'-out',cert,'-subj','/CN=Styx ingress test','-addext','subjectAltName=IP:'+ip],{stdio:'ignore',timeout:12000});
 fs.chmodSync(key,0o600);return {cert,key};
}
async function fixture(t,{restore}={}){
 const ip=lanAddress();
 if(!ip){t.skip('No assigned non-loopback IPv4 interface for real LAN listener coverage');return null;}
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-device-ingress-'));
 let http;const sockets=[],clients=[],cleanups=[];
 t.after(async()=>{for(const cleanup of cleanups)await cleanup();for(const ws of sockets)ws.terminate();for(const c of clients)await c.close().catch(()=>{});await http?.close();fs.rmSync(dir,{recursive:true,force:true});});
 const primary=certificate(dir,'canonical','127.0.0.1'),lan=certificate(dir,'lan',ip);
 const adminToken=randomBytes(48).toString('base64url'),localToken=randomBytes(48).toString('base64url'),mcpToken=randomBytes(48).toString('base64url');
 const adminFile=path.join(dir,'admin.token'),localFile=path.join(dir,'local.token');
 fs.writeFileSync(adminFile,adminToken,{mode:0o600});fs.writeFileSync(localFile,localToken,{mode:0o600});
 const gateway=createStyxGateway({catalog:{version:1,targets:[{id:'local-host',kind:'host',platform:'linux',generation:'local-generation',cwd:dir,shell:'/bin/sh',shells:['/bin/sh'],allowed:true,exec:{transport:'outbound',token_file:localFile}}]}});
 const enrollment=new EnrollmentController({rootDir:path.join(dir,'enrollment'),adminTokenFile:adminFile,registry:gateway.registry,relay:gateway.relay});
 const descriptor={generation:'lan-generation-1',url:'https://'+ip+':'+await availablePort(ip),listenHost:ip,tlsCertificateFile:lan.cert,tlsPrivateKeyFile:lan.key,certificateSha256:digest(lan.cert)};
 const hosts=[];
 http=await createGatewayHttp(gateway,{token:mcpToken,port:0,allowedHosts:hosts,enrollment,tlsCertificateFile:primary.cert,tlsPrivateKeyFile:primary.key,...(restore?{deviceIngress:restore(descriptor)}:{})});
 const canonical='https://127.0.0.1:'+http.address.port;hosts.push(new URL(canonical).host);
 const owner={gateway_url:canonical,gateway_ca_file:primary.cert,admin_token_file:adminFile};
 const command=(cmd,args=[])=>ownerCommand(owner,cmd,args);
 function request(origin,cert,route,{method='GET',data,headers={}}={}){
  return new Promise((resolve,reject)=>{
   const req=https.request(new URL(route,origin),{method,ca:fs.readFileSync(cert),agent:false,checkServerIdentity:(_hostname,certificate)=>checkServerIdentity(new URL(origin).hostname,certificate),headers:{...(data?{'content-type':'application/json'}:{}),...headers}},res=>{
    const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString())}));
   });req.on('error',reject);req.end(data?JSON.stringify(data):undefined);
  });
 }
 async function connect(id,token,{origin=descriptor.url,cert=lan.cert,lane='exec',expected=101}={}){
  const ws=new WebSocket(origin.replace('https:','wss:')+'/styx/hosts/'+id+'/'+lane,{ca:fs.readFileSync(cert),headers:{Authorization:'Bearer '+token},handshakeTimeout:3000});
  sockets.push(ws);
  const result=await new Promise((resolve,reject)=>{ws.once('open',()=>resolve(101));ws.once('error',reject);ws.once('unexpected-response',(_req,res)=>{res.resume();resolve(res.statusCode);});});
  assert.equal(result,expected);return ws;
 }
 function guest(name){return {gateway_url:descriptor.url,gateway_ca_file:lan.cert,storage_dir:path.join(dir,'guest-'+name),label:name,cwd:dir,shell:'/bin/sh',exec_binary:process.execPath,computer_requested:true,computer_binary:'/usr/bin/false',browser_requested:true,browser_config:{enabled:true,headless:true,profileRoot:path.join(dir,'profiles-'+name)}};}
 async function mcp(){
  const client=new Client({name:'ingress-test',version:'1'});clients.push(client);
  await client.connect(new StreamableHTTPClientTransport(new URL('/mcp',canonical),{requestInit:{headers:{Authorization:'Bearer '+mcpToken}},fetch:(url,options)=>new Promise((resolve,reject)=>{
   // The SDK accepts a standard fetch implementation. This adapter only supplies the fixture CA.
   const req=https.request(url,{method:options?.method??'GET',headers:Object.fromEntries(new Headers(options?.headers)),ca:fs.readFileSync(primary.cert),agent:false},res=>{
    const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));
   });req.on('error',reject);req.end(options?.body??undefined);
  })}));return client;
 }
 return {dir,ip,primary,lan,descriptor,gateway,enrollment,http,canonical,owner,adminToken,localToken,mcpToken,command,request,connect,guest,mcp,cleanup:fn=>cleanups.push(fn)};
}

test('one Gateway LAN listener isolates management, binds actual TLS identity and preserves local sessions',{timeout:20000},async t=>{
 const f=await fixture(t);if(!f)return;
 const local=await f.connect('local-host',f.localToken,{origin:f.canonical,cert:f.primary.cert});
 const client=await f.mcp(),sessionCount=f.http.sessions.size,heartbeat=f.gateway.relay.timer;
 assert.equal((await f.command('ingress-status')).status,'absent');
 assert.equal((await f.command('ingress-prepare',[JSON.stringify(f.descriptor)])).status,'prepared');
 assert.equal((await f.command('ingress-enable',[f.descriptor.generation])).status,'listening');
 assert.equal(f.gateway.relay.timer,heartbeat);
 assert.equal(f.gateway.relay.attachments.size,2);
 for(const route of ['/mcp','/styx/enroll/pending','/styx/enroll/invitations','/styx/enroll/approve','/styx/enroll/revoke','/styx/enroll/device-ingress/status']){
  assert.equal((await f.request(f.descriptor.url,f.lan.cert,route,{headers:{Authorization:'Bearer '+f.adminToken}})).status,404);
 }
 assert.equal((await f.request(f.descriptor.url,f.lan.cert,'/styx/enroll/join')).status,405);
 assert.equal((await f.request(f.descriptor.url,f.lan.cert,'/styx/enroll/join',{headers:{Host:'wrong.example'}})).status,403);
 assert.equal((await f.request(f.descriptor.url,f.lan.cert,'/styx/enroll/join',{headers:{Origin:'https://untrusted.example'}})).status,403);
 const invitation=await f.command('pairing-open',[f.descriptor.generation,'600']);
 assert.equal(invitation.ingress.certificate_sha256,digest(f.lan.cert));
 const guest=f.guest('new-device');
 await assert.rejects(requestEnrollment({...guest,gateway_url:f.canonical,gateway_ca_file:f.primary.cert},invitation.invitation),/invitation_ingress_mismatch/);
 const pending=await requestEnrollment(guest,invitation.invitation);
 const ownerPending=(await f.command('pending'))[0];
 assert.equal(ownerPending.comparison_code,pending.comparison_code);
 assert.deepEqual(ownerPending.ingress,invitation.ingress);
 assert.notEqual(pending.comparison_code,pairingComparisonCode({gatewayOrigin:f.canonical,certificateSha256:digest(f.primary.cert),requestId:pending.request_id,deviceFingerprint:pending.fingerprint}));
 await f.command('pairing-close',[f.descriptor.generation]);
 await f.command('approve',[pending.request_id,pending.fingerprint,'computer','browser']);
 assert.equal((await claimEnrollment(guest)).status,'ready_to_connect');
 const host=f.gateway.registry.resolve(pending.device_id),token=fs.readFileSync(host.exec.token_file,'utf8').trim();
 const remote=await Promise.all(['exec','computer','browser'].map(lane=>f.connect(pending.device_id,token,{lane})));
 await f.connect(pending.device_id,token,{origin:f.canonical,cert:f.primary.cert,expected:409});
 await f.connect('local-host',f.localToken,{expected:409});
 const unused=await f.command('pairing-open',[f.descriptor.generation]);
 await f.command('pairing-close',[f.descriptor.generation]);
 await assert.rejects(requestEnrollment(f.guest('after-close'),unused.invitation),/invitation_expired_or_used/);
 assert(remote.every(ws=>ws.readyState===WebSocket.OPEN));
 assert.equal(f.gateway.relay.connected('local-host'),true);
 const closed=remote.map(ws=>once(ws,'close'));
 assert.equal((await f.command('ingress-disable',[f.descriptor.generation])).status,'prepared');
 await Promise.all(closed);
 assert.equal(f.http.sessions.size,sessionCount);
 assert.equal(local.readyState,WebSocket.OPEN);
 assert.equal((await client.callTool({name:'list_execution_environments',arguments:{}})).isError,undefined);
 assert.equal((await f.command('ingress-enable',[f.descriptor.generation])).ingress.certificate_sha256,digest(f.lan.cert));
 const reconnected=await Promise.all(['exec','computer','browser'].map(lane=>f.connect(pending.device_id,token,{lane})));
 const revoked=reconnected.map(ws=>once(ws,'close'));
 await f.command('revoke',[pending.device_id]);await Promise.all(revoked);
 await f.connect(pending.device_id,token,{expected:403});
 assert.equal(local.readyState,WebSocket.OPEN);
 assert.equal(f.gateway.relay.connected('local-host'),true);
 assert.equal((await f.command('ingress-status')).pairing.status,'closed');
});

test('LAN bind/certificate failures leave the canonical Gateway and Host alive',{timeout:15000},async t=>{
 const f=await fixture(t,{restore:d=>({...d,listenHost:'0.0.0.0',url:'https://0.0.0.0:8999'})});if(!f)return;
 assert.equal(f.http.deviceIngress.status().status,'failed');
 const local=await f.connect('local-host',f.localToken,{origin:f.canonical,cert:f.primary.cert});
 assert.equal((await f.command('devices')).length,0);
 await assert.rejects(f.command('ingress-prepare',[JSON.stringify({...f.descriptor,certificateSha256:'0'.repeat(64)})]),/device_ingress_tls_pin_mismatch/);
 await assert.rejects(f.command('ingress-prepare',[JSON.stringify({...f.descriptor,listenHost:'192.0.2.99',url:'https://192.0.2.99:9999'})]),/owned_exact_ipv4_device_ingress_required/);
 await f.command('ingress-prepare',[JSON.stringify(f.descriptor)]);
 const originalCert=fs.readFileSync(f.lan.cert),originalKey=fs.readFileSync(f.lan.key);
 const replacement=certificate(f.dir,'replacement',f.ip);
 fs.copyFileSync(replacement.cert,f.lan.cert);fs.copyFileSync(replacement.key,f.lan.key);
 await assert.rejects(f.command('ingress-enable',[f.descriptor.generation]),/device_ingress_tls_pin_mismatch/);
 fs.writeFileSync(f.lan.cert,originalCert);fs.writeFileSync(f.lan.key,originalKey);
 const occupied=createServer();occupied.listen(new URL(f.descriptor.url).port,f.ip);await once(occupied,'listening');
 t.after(()=>new Promise(resolve=>occupied.close(resolve)));
 await f.command('ingress-prepare',[JSON.stringify(f.descriptor)]);
 await assert.rejects(f.command('ingress-enable',[f.descriptor.generation]),/enrollment_internal_error/);
 assert.match((await f.command('ingress-status')).error,/EADDRINUSE/);
 assert.equal((await f.command('ingress-status')).status,'failed');
 assert.equal(local.readyState,WebSocket.OPEN);
 assert.equal(f.gateway.relay.attachments.size,1);
 assert.equal((await f.command('pending')).length,0);
});

test('owner validates exact ingress commands and primary shutdown owns all listeners',{timeout:15000},async t=>{
 const f=await fixture(t);if(!f)return;
 await assert.rejects(f.command('ingress-status',['unexpected']),/invalid_device_ingress_arguments/);
 await assert.rejects(f.command('ingress-prepare',['{']),/device_ingress_descriptor_required/);
 await f.command('ingress-prepare',[JSON.stringify(f.descriptor)]);
 await assert.rejects(f.command('ingress-enable',['stale-generation']),/device_ingress_generation_mismatch/);
 await f.command('ingress-enable',[f.descriptor.generation]);
 const local=await f.connect('local-host',f.localToken,{origin:f.canonical,cert:f.primary.cert});
 const closed=once(local,'close');
 await f.http.close();await closed;
 assert.equal(f.gateway.relay.attachments.size,0);
 assert.equal(f.gateway.relay.stopped,true);
 assert.equal(f.http.deviceIngress.status().status,'prepared');
});


test('restored entry keeps its pinned identity and expires only new-join permission',{timeout:15000},async t=>{
 const f=await fixture(t,{restore:descriptor=>descriptor});if(!f)return;
 const status=await f.command('ingress-status');
 assert.equal(status.status,'listening');assert.equal(status.pairing.status,'closed');
 assert.equal(status.ingress.certificate_sha256,f.descriptor.certificateSha256);
 assert.equal(status.certificate.renewal_required,true);
 const local=await f.connect('local-host',f.localToken,{origin:f.canonical,cert:f.primary.cert});
 let clock=Date.now();f.enrollment.now=()=>clock;
 const invitation=await f.command('pairing-open',[f.descriptor.generation,'60']);
 clock+=60001;
 assert.equal((await f.command('ingress-status')).pairing.status,'closed');
 await assert.rejects(requestEnrollment(f.guest('expired-window'),invitation.invitation),/invitation_expired_or_used/);
 assert.equal((await f.command('ingress-status')).status,'listening');
 assert.equal(local.readyState,WebSocket.OPEN);
});


const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(predicate){const deadline=Date.now()+3000;while(!predicate()){if(Date.now()>deadline)throw Error('startup ingress recovery timed out');await sleep(5);}}
function startupManager(f){const manager=new GatewayDeviceIngress({gateway:f.gateway,enrollment:f.enrollment,restoreRetryIntervalsMs:[15,25,40]});f.cleanup(()=>manager.close());return manager;}
async function occupy(f){const server=createServer();server.listen(new URL(f.descriptor.url).port,f.ip);await once(server,'listening');f.cleanup(()=>server.listening?new Promise(resolve=>server.close(resolve)):undefined);return server;}

test('startup port conflict automatically recovers the same LAN TLS entry without invitations or local connection loss',{timeout:15000},async t=>{
 const f=await fixture(t);if(!f)return;
 const local=await f.connect('local-host',f.localToken,{origin:f.canonical,cert:f.primary.cert});
 const client=await f.mcp(),sessions=f.http.sessions.size,heartbeat=f.gateway.relay.timer;
 const manager=startupManager(f),occupied=await occupy(f),certificateBefore=fs.readFileSync(f.lan.cert),keyBefore=fs.readFileSync(f.lan.key);
 const initial=await manager.restore(f.descriptor);
 assert.equal(initial.status,'failed');assert.match(initial.error,/EADDRINUSE/);assert.equal(initial.recovery.status,'waiting');assert.equal(initial.recovery.generation,f.descriptor.generation);
 assert.equal(manager.restoreTimer.hasRef(),false);
 await until(()=>manager.status().recovery?.attempt>=2);
 await new Promise(resolve=>occupied.close(resolve));
 await until(()=>manager.status().status==='listening');
 const status=manager.status();assert.equal(status.generation,f.descriptor.generation);assert.equal(status.url,f.descriptor.url);assert.equal(status.ingress.certificate_sha256,f.descriptor.certificateSha256);
 assert.equal(status.pairing.status,'closed');assert.equal(status.recovery,undefined);assert.equal(f.enrollment.db.invitations.length,0);
 assert.equal((await f.request(f.descriptor.url,f.lan.cert,'/styx/enroll/join')).status,405);
 assert.equal((await f.request(f.descriptor.url,f.lan.cert,'/mcp')).status,404);
 assert.equal(local.readyState,WebSocket.OPEN);assert.equal(f.http.sessions.size,sessions);assert.equal(f.gateway.relay.timer,heartbeat);
 assert.equal((await client.callTool({name:'list_execution_environments',arguments:{}})).isError,undefined);
 assert.deepEqual(fs.readFileSync(f.lan.cert),certificateBefore);assert.deepEqual(fs.readFileSync(f.lan.key),keyBefore);
});

for(const operation of ['prepare','enable','disable','close'])test('explicit '+operation+' cancels startup recovery instead of reopening the listener',{timeout:15000},async t=>{
 const f=await fixture(t);if(!f)return;
 const manager=startupManager(f),occupied=await occupy(f);
 assert.equal((await manager.restore(f.descriptor)).recovery.status,'waiting');
 if(operation==='prepare')manager.prepare(f.descriptor);
 else if(operation==='enable')await assert.rejects(manager.enable({generation:f.descriptor.generation}),/EADDRINUSE/);
 else if(operation==='disable')await manager.disable({generation:f.descriptor.generation});
 else await manager.close();
 const epoch=manager.restoreEpoch;
 await new Promise(resolve=>occupied.close(resolve));await sleep(120);
 assert.notEqual(manager.status().status,'listening');assert.equal(manager.status().recovery,undefined);assert.equal(manager.restoreEpoch,epoch);assert.equal(manager.restoreTimer,null);
 assert.equal(f.gateway.relay.attachments.size,1);
 await assert.rejects(f.request(f.descriptor.url,f.lan.cert,'/styx/enroll/join'),/ECONNREFUSED/);
 assert.equal((await f.request(f.canonical,f.primary.cert,'/styx/enroll/pending')).status,401);
});

test('disable retires an in-flight startup epoch before its actual listen can be adopted',{timeout:15000},async t=>{
 const f=await fixture(t);if(!f)return;
 const manager=startupManager(f),restoring=manager.restore(f.descriptor),disabling=manager.disable({generation:f.descriptor.generation});
 await Promise.all([restoring,disabling]);await sleep(80);
 assert.equal(manager.status().status,'prepared');assert.equal(manager.status().recovery,undefined);assert.equal(f.gateway.relay.attachments.size,1);
 await assert.rejects(f.request(f.descriptor.url,f.lan.cert,'/styx/enroll/join'),/ECONNREFUSED/);
});

test('a certificate replaced during startup backoff never changes the authorized TLS trust',{timeout:15000},async t=>{
 const f=await fixture(t);if(!f)return;
 const manager=startupManager(f),occupied=await occupy(f);
 assert.equal((await manager.restore(f.descriptor)).recovery.status,'waiting');
 const replacement=certificate(f.dir,'backoff-replacement',f.ip);fs.copyFileSync(replacement.cert,f.lan.cert);fs.copyFileSync(replacement.key,f.lan.key);
 await new Promise(resolve=>occupied.close(resolve));await until(()=>manager.status().error==='device_ingress_tls_pin_mismatch');await sleep(80);
 const status=manager.status();assert.equal(status.status,'failed');assert.equal(status.recovery,undefined);assert.equal(status.ingress.certificate_sha256,f.descriptor.certificateSha256);assert.notEqual(digest(f.lan.cert),f.descriptor.certificateSha256);
 assert.equal(f.gateway.relay.attachments.size,1);assert.equal(f.enrollment.db.invitations.length,0);
 await assert.rejects(f.request(f.descriptor.url,replacement.cert,'/styx/enroll/join'),/ECONNREFUSED/);
 assert.equal((await f.request(f.canonical,f.primary.cert,'/styx/enroll/pending')).status,401);
});


test('closed pairing LAN ingress permits only authenticated self-device capability GET and signed CAS POST',{timeout:20000},async t=>{
 const f=await fixture(t);if(!f)return;
 await f.command('ingress-prepare',[JSON.stringify(f.descriptor)]);await f.command('ingress-enable',[f.descriptor.generation]);
 async function join(label){
  const invite=await f.command('pairing-open',[f.descriptor.generation,'600']),guest=f.guest(label),pending=await requestEnrollment(guest,invite.invitation);
  await f.command('approve',[pending.request_id,pending.fingerprint]);const claimed=await claimEnrollment(guest),host=JSON.parse(fs.readFileSync(claimed.local_host_config));
  return {id:claimed.device_id,token:fs.readFileSync(host.token_file,'utf8').trim(),key:fs.readFileSync(path.join(guest.storage_dir,'identity.pem')),tokenFile:host.token_file};
 }
 const a=await join('self-a'),b=await join('self-b');await f.command('pairing-close',[f.descriptor.generation]);
 assert.equal((await f.command('ingress-status')).pairing.status,'closed');
 const route=id=>'/styx/enroll/self/'+id+'/capabilities',request=(id,token,body,options={})=>f.request(f.descriptor.url,f.lan.cert,route(id),{method:body===undefined?'GET':'POST',data:body,...options,headers:{Authorization:'Bearer '+token,...options.headers}});
 const current=await request(a.id,a.token);assert.equal(current.status,200);assert.equal(current.body.device_id,a.id);assert.deepEqual(current.body.capabilities,{exec:true,computer:false,browser:false});
 for(const token of [b.token,f.adminToken,f.mcpToken,'x'.repeat(48)])assert.equal((await request(a.id,token)).status,403);
 assert.equal((await request(b.id,a.token)).status,403);
 assert.equal((await request(a.id,a.token,undefined,{method:'DELETE'})).status,405);
 for(const headers of [{Host:'wrong.example'},{Origin:f.descriptor.url},{Authorization:['Bearer '+a.token,'Bearer '+a.token]}])assert.equal((await request(a.id,a.token,undefined,{headers})).status,403);
 for(const url of [route(a.id)+'/',route(a.id)+'?x=1','/styx/enroll/self/'+a.id+'/capabilities/extra','/styx/enroll/self/'+a.id+'/revoke','/styx/enroll/self/styx-INVALID/capabilities','/mcp','/styx/enroll/capabilities','/styx/enroll/devices','/styx/enroll/pending','/styx/enroll/invitations','/styx/enroll/approve','/styx/enroll/revoke']){
  assert.equal((await f.request(f.descriptor.url,f.lan.cert,url,{method:'POST',data:{},headers:{Authorization:'Bearer '+f.adminToken}})).status,404,url);
 }
 const update={device_id:a.id,fingerprint:current.body.fingerprint,generation:current.body.generation,enable_computer:true,enable_browser:true,public_key_pem:createPublicKey(a.key).export({type:'spki',format:'pem'})};
 update.signature=sign('sha256',Buffer.from(capabilityPayload(update)),{key:a.key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64url');
 assert.equal((await request(a.id,b.token,update)).status,403);assert.equal((await request(b.id,b.token,update)).status,403);assert.equal((await request(a.id,a.token,{...update,signature:'invalid'})).status,403);
 const changed=await request(a.id,a.token,update);assert.equal(changed.status,200);assert.equal(changed.body.status,'updated');assert.deepEqual(changed.body.capabilities,{exec:true,computer:true,browser:true});assert.notEqual(changed.body.generation,current.body.generation);
 assert.equal((await request(a.id,a.token,update)).status,409,'stale generation cannot replay');
 const observed=await request(a.id,a.token);assert.equal(observed.body.generation,changed.body.generation);assert.deepEqual(observed.body.capabilities,changed.body.capabilities);assert.equal(fs.readFileSync(a.tokenFile,'utf8').trim(),a.token);
 assert.deepEqual((await request(b.id,b.token)).body.capabilities,{exec:true,computer:false,browser:false},'other enrolled device unchanged');
 await f.command('revoke',[a.id]);assert.equal((await request(a.id,a.token)).status,403);assert.equal((await request(b.id,b.token)).status,200);
});
