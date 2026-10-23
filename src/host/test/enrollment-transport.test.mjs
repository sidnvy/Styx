import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import {fork,execFileSync} from 'node:child_process';
import {enrollmentHttpRequest} from '../enroll.mjs';
import {gatewayFetch} from '../../onboarding/connection.mjs';

// The peer must run in another process: native bundle preparation blocks the
// client's event loop, while a real remote Gateway can still close its socket.
const PEER = String.raw`
import fs from 'node:fs';
import https from 'node:https';
const [certificate,key,closedMarker]=process.argv.slice(2);
let nextConnection=0,warmSocket;
const connections=new Map(),counts={warm:0,operation:0};
const server=https.createServer({cert:fs.readFileSync(certificate),key:fs.readFileSync(key)},(req,res)=>{
 req.resume();
 if(req.url==='/warm'){counts.warm++;warmSocket=req.socket;}
 else counts.operation++;
 res.writeHead(req.url==='/styx/enroll/join'?202:200,{'content-type':'application/json'});
 res.end(JSON.stringify({connection:connections.get(req.socket),counts:{...counts}}));
});
server.on('secureConnection',socket=>connections.set(socket,++nextConnection));
process.on('message',message=>{
 if(message==='close-warm'){
  warmSocket.once('close',()=>fs.writeFileSync(closedMarker,'closed'));
  warmSocket.destroy();
 }else if(message==='stats')process.send({type:'stats',counts:{...counts},connections:nextConnection});
 else if(message==='stop'){server.closeAllConnections();server.close(()=>process.exit(0));}
});
server.listen(0,'127.0.0.1',()=>process.send({type:'ready',port:server.address().port}));
`;

function peerMessage(peer,type){
 return new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>finish(Error('fixture_peer_message_timeout')),5000);
  const message=value=>{if(value?.type===type)finish(null,value)};
  const error=()=>finish(Error('fixture_peer_exited'));
  function finish(err,value){clearTimeout(timer);peer.off('message',message);peer.off('error',error);peer.off('exit',error);err?reject(err):resolve(value)}
  peer.on('message',message);peer.once('error',error);peer.once('exit',error);
 });
}

async function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-enrollment-transport-'));
 const certificate=path.join(root,'certificate.pem'),key=path.join(root,'key.pem'),closed=path.join(root,'peer-closed');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-keyout',key,'-out',certificate,'-subj','/CN=styx-transport-fixture','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',timeout:12000});
 const script=path.join(root,'peer.mjs');fs.writeFileSync(script,PEER);
 const peer=fork(script,[certificate,key,closed],{stdio:['ignore','ignore','ignore','ipc']});
 t.after(async()=>{
  if(peer.exitCode===null){
   const stopped=new Promise(resolve=>peer.once('exit',resolve));
   if(peer.connected)peer.send('stop');
   const timer=setTimeout(()=>peer.kill(),1000);
   await stopped;clearTimeout(timer);
  }
  fs.rmSync(root,{recursive:true,force:true});
 });
 const ready=await peerMessage(peer,'ready');
 return {peer,certificate,ca:fs.readFileSync(certificate),closed,port:ready.port,origin:'https://127.0.0.1:'+ready.port};
}

async function leaveClosedSocketUnobserved(f){
 let socket;
 await new Promise((resolve,reject)=>{
  const req=https.request(f.origin+'/warm',{ca:f.ca,rejectUnauthorized:true},res=>{
   res.resume();res.once('end',resolve);res.once('error',reject);
  });
  req.once('socket',value=>{socket=value});req.once('error',reject);req.end();
 });
 // Allow the Agent's response completion hook to put the socket in its pool.
 await new Promise(resolve=>setImmediate(resolve));
 assert.ok(Object.values(https.globalAgent.freeSockets).some(pool=>pool.includes(socket)),'fixture must warm the real shared keep-alive pool');
 f.peer.send('close-warm');
 const deadline=Date.now()+5000,blocker=new Int32Array(new SharedArrayBuffer(4));
 // Observe peer closure through a file without yielding to the client event
 // loop. This recreates the signed release's synchronous preparation boundary.
 while(!fs.existsSync(f.closed)&&Date.now()<deadline)Atomics.wait(blocker,0,0,5);
 assert.ok(fs.existsSync(f.closed),'fixture peer must close before the request');
 assert.equal(socket.destroyed,false,'client must not have processed peer closure yet');
}

for(const adapter of ['enrollment','gateway verification']){
 test(adapter+' uses a fresh TLS connection after synchronous setup leaves a stale shared socket',{timeout:20000},async t=>{
  const f=await fixture(t);
  await leaveClosedSocketUnobserved(f);
  let body,error;
  try{
   if(adapter==='enrollment'){
    const result=await enrollmentHttpRequest({gateway_url:f.origin,gateway_ca_file:f.certificate},'join',{probe:'one request'});
    assert.equal(result.status,202);body=result.body;
   }else{
    const endpoint=f.origin+'/mcp';
    const response=await gatewayFetch(endpoint,{ca:f.ca})(endpoint,{method:'POST',body:'{}'});
    assert.equal(response.status,200);body=await response.json();
   }
  }catch(value){error=value}
  const observed=peerMessage(f.peer,'stats');f.peer.send('stats');const stats=await observed;
  t.diagnostic(JSON.stringify({adapter,connections:stats.connections,warmRequests:stats.counts.warm,operationRequests:stats.counts.operation,errorCode:error?.code??null}));
  assert.ifError(error);
  assert.equal(body.connection,2,'operation must establish its own TLS connection');
  assert.deepEqual(stats.counts,{warm:1,operation:1},'mutating enrollment must never be retried');
 });
}
