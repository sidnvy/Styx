import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import https from 'node:https';
import {CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {verifyGatewayConnection,gatewayFetch} from '../connection.mjs';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';

async function fixture(t,{callResult}={}){
 const dir=path.join(os.tmpdir(),'styx-connection-'+randomUUID());ensurePrivateDirectory(dir);
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const key=path.join(dir,'tls.key'),cert=path.join(dir,'tls.pem');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',key,'-out',cert,'-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',timeout:10000});
 const token=randomUUID()+randomUUID(),tokenFile=path.join(dir,'model.token');fs.writeFileSync(tokenFile,token,{mode:0o600});
 const allowedHosts=[];const g=createStyxGateway({catalog:{version:1,targets:[]}});
 if(callResult){const original=g.serverForOwner.bind(g);g.serverForOwner=owner=>{const server=original(owner);server.setRequestHandler(CallToolRequestSchema,async()=>callResult);return server;};}
 const server=await createGatewayHttp(g,{token,allowedHosts,port:0,tlsCertificateFile:cert,tlsPrivateKeyFile:key});
 allowedHosts.push('127.0.0.1:'+server.address.port);t.after(()=>server.close());
 return {key,cert,config:{url:'https://127.0.0.1:'+server.address.port+'/mcp',tokenFile,caFile:cert,independentStyx:true,freshConnection:true}};
}
test('real HTTPS discovery and read-only call yield tool evidence, never claims account acceptance',{skip:process.platform==='win32',timeout:30000},async t=>{
 const f=await fixture(t);const r=await verifyGatewayConnection(f.config);
 assert.deepEqual(r.receipt.toolCall,{name:'list_execution_environments',status:'PASS',environmentCount:0});
 assert.equal(r.receipt.method,'authenticated-mcp-discovery-and-readonly-call');
 assert.equal(r.status,'gateway_verified');assert.equal(r.account_acceptance,'NOT RUN');
 assert.ok(r.receipt.tools.includes('exec_command'));assert.ok(!JSON.stringify(r).includes(fs.readFileSync(f.config.tokenFile,'utf8')));
 await assert.rejects(verifyGatewayConnection({...f.config,caFile:undefined}),/^Error: gateway_verification_failed$/);
 fs.writeFileSync(f.config.tokenFile,'wrong-credential-'.repeat(4),{mode:0o600});
 await assert.rejects(verifyGatewayConnection(f.config),/^Error: gateway_verification_failed$/);
});
test('owner attestation and HTTPS required before network access',async()=>{
 await assert.rejects(verifyGatewayConnection({url:'http://127.0.0.1/mcp'}),/invalid_gateway_endpoint/);
 await assert.rejects(verifyGatewayConnection({url:'https://localhost/mcp'}),/attestation_required/);
 const fetch=gatewayFetch('https://localhost/mcp');
 await assert.rejects(fetch('https://foreign.example/mcp'),/endpoint_changed/);
});
test('redirect refuses credential forwarding',{skip:process.platform==='win32',timeout:30000},async t=>{
 const f=await fixture(t);let calls=0;
 const server=https.createServer({key:fs.readFileSync(f.key),cert:fs.readFileSync(f.cert)},(_req,res)=>{calls++;res.writeHead(302,{Location:'https://foreign.example/mcp'});res.end();});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const url='https://127.0.0.1:'+server.address().port+'/mcp';
 await assert.rejects(gatewayFetch(url,{ca:fs.readFileSync(f.cert)})(url),/redirect_refused/);assert.equal(calls,1);
});

test('discovery alone cannot pass verification when tools/call fails or is malformed',{skip:process.platform==='win32',timeout:30000},async t=>{
 for(const callResult of [
  {isError:true,content:[{type:'text',text:'private upstream failure'}]},
  {content:[{type:'text',text:'ok'}],structuredContent:{unexpected:[]}}
 ]){
  const f=await fixture(t,{callResult});
  await assert.rejects(verifyGatewayConnection(f.config),/^Error: gateway_verification_failed$/);
 }
});
