import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {createHash,X509Certificate} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import WebSocket from 'ws';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';

async function createCert(dir,prefix,extra=[]){
  const key=path.join(dir,prefix+'-key.pem'),cert=path.join(dir,prefix+'-cert.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
    '-sha256','-days','1','-keyout',key,'-out',cert,'-subj',
    '/CN=styx-'+prefix,...extra],{stdio:'ignore',timeout:10000});
  return {key,cert};
}
async function upgrade(url,opts={}){
  const ws=new WebSocket(url,{...opts,handshakeTimeout:3000,perMessageDeflate:false});
  return await new Promise(resolve=>{
    let done=false;
    const finish=(result)=>{if(done)return;done=true;resolve({result,ws})};
    ws.once('open',()=>finish(101));
    ws.once('unexpected-response',(_,res)=>{res.resume();finish(res.statusCode)});
    ws.once('error',()=>finish(0));
  });
}
test('mTLS pins the native Host certificate without sharing bearer secrets',{timeout:25000},async t=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),'styx-mtls-'));
  t.after(()=>rm(tmp,{recursive:true,force:true}));
  const serverCert=await createCert(tmp,'gateway',['-addext','subjectAltName=IP:127.0.0.1']);
  const allowedClient=await createCert(tmp,'allowed-client',['-addext','extendedKeyUsage=clientAuth']);
  const otherClient=await createCert(tmp,'other-client',['-addext','extendedKeyUsage=clientAuth']);
  const x509=new X509Certificate(await readFile(allowedClient.cert));
  const fingerprint=createHash('sha256').update(x509.raw).digest('hex');
  const catalog={version:1,default_environment_id:'one',targets:[{
    id:'one',kind:'host',platform:'linux',generation:'mtls-one',
    cwd:tmp,shell:'/bin/sh',shells:['/bin/sh'],allowed:true,
    exec:{transport:'outbound',client_certificate_sha256:fingerprint}
  }]};
  const gateway=createStyxGateway({catalog});
  const hosts=[];
  const server=await createGatewayHttp(gateway,{
    token:'styx_local_inbound_mock_'+ 'p'.repeat(48),port:0,allowedHosts:hosts,
    tlsCertificateFile:serverCert.cert,tlsPrivateKeyFile:serverCert.key
  });
  t.after(()=>server.close());
  const port=server.address.port;hosts.push('127.0.0.1:'+port);
  const url='wss://127.0.0.1:'+port+'/styx/hosts/one/exec';
  const ca=await readFile(serverCert.cert);
  const mtlsOpts=async keys=>({ca,cert:await readFile(keys.cert),key:await readFile(keys.key)});
  const bad=await upgrade(url,await mtlsOpts(otherClient));
  assert.equal(bad.result,401);
  const anonymous=await upgrade(url,{ca});
  assert.equal(anonymous.result,401);
  const ok=await upgrade(url,await mtlsOpts(allowedClient));
  assert.equal(ok.result,101);
  assert.equal(gateway.relay.connected('one'),true);
  const duplicate=await upgrade(url,await mtlsOpts(allowedClient));
  assert.equal(duplicate.result,409);
  ok.ws.terminate();
  await new Promise(resolve=>ok.ws.once('close',resolve));
  const wait=Date.now()+3000;
  while(gateway.relay.connected('one')&&Date.now()<wait)
    await new Promise(r=>setTimeout(r,30));
  assert.equal(gateway.relay.connected('one'),false);
});
