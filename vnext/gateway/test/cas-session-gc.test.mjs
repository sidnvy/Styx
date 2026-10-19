import test from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';

async function setup(t,options={},configure){
 const gateway=createStyxGateway({catalog:{version:1,targets:[]},computer:null});configure?.(gateway);
 const hosts=[],token='styx_http_lifecycle_test_'+'u'.repeat(40);
 const server=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts,...options});
 hosts.push('127.0.0.1:'+server.address.port);const clients=[];
 t.after(async()=>{
  await Promise.allSettled(clients.map(async({client,transport})=>{await transport.terminateSession().catch(()=>{});await client.close().catch(()=>{});}));
  await server.close();
 });
 return {gateway,server,async client(){
  const transport=new StreamableHTTPClientTransport(new URL('http://'+hosts[0]+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+token}}});
  const client=new Client({name:'session-lifecycle-test',version:'1'});clients.push({client,transport});await client.connect(transport);return {client,transport};
 }};
}

test('MCP clients exceed the former 32-session cap with no admission rejection',async t=>{
 const x=await setup(t,{idleSessionTimeoutMs:0});
 const clients=await Promise.all(Array.from({length:96},()=>x.client()));
 assert.equal(x.server.sessions.size,96);
 assert.equal((await clients[0].client.listTools()).tools.length,4);
 assert.equal((await clients[95].client.listTools()).tools.length,4);
 await clients[0].transport.terminateSession();assert.equal(x.server.sessions.size,95);
 assert.equal((await clients[95].client.listTools()).tools.length,4);
});

test('idle cleanup runs independently of session count and keeps recent clients',async t=>{
 const x=await setup(t,{idleSessionTimeoutMs:60000});
 const a=await x.client();await a.client.listTools();const previous=[...x.server.sessions.values()][0];
 const b=await x.client();assert.equal(x.server.sessions.size,2);previous.lastActivityAt=Date.now()-60001;
 const c=await x.client();assert.equal(x.server.sessions.size,2);
 assert.equal((await b.client.listTools()).tools.length,4);assert.equal((await c.client.listTools()).tools.length,4);
 await assert.rejects(a.client.listTools(),/404|Session not found/);
});

test('idle cleanup protects active requests without blocking newcomers',async t=>{
 const x=await setup(t,{idleSessionTimeoutMs:60000});const a=await x.client();const active=[...x.server.sessions.values()][0];
 active.lastActivityAt=Date.now()-60001;active.inFlight++;
 const b=await x.client();assert.equal(x.server.sessions.size,2);assert.equal((await b.client.listTools()).tools.length,4);
 assert.ok([...x.server.sessions.values()].includes(active));active.inFlight--;active.lastActivityAt=Date.now()-60001;
 const c=await x.client();assert.equal(x.server.sessions.size,2);assert.equal((await c.client.listTools()).tools.length,4);
 await assert.rejects(a.client.listTools(),/404|Session not found/);
});

test('production cleanup preserves owned Exec work and retires lost runtimes',async t=>{
 const x=await setup(t);const a=await x.client();await a.client.listTools();const previous=[...x.server.sessions.values()][0];
 previous.lastActivityAt=Date.now()-16*60*1000;x.gateway.exec.sessions.set(17,{owner:previous.owner,state:'running'});
 const b=await x.client();assert.equal(x.server.sessions.size,2);assert.ok([...x.server.sessions.values()].includes(previous));
 x.gateway.exec.sessions.get(17).runtime={lost:true};previous.lastActivityAt=Date.now()-16*60*1000;const c=await x.client();x.gateway.exec.sessions.delete(17);
 assert.equal(x.server.sessions.size,2);assert.equal((await b.client.listTools()).tools.length,4);assert.equal((await c.client.listTools()).tools.length,4);
 await assert.rejects(a.client.listTools(),/404|Session not found/);
});

test('async tools/call stays protected until its HTTP response ends',async t=>{
 const {CallToolRequestSchema}=await import('@modelcontextprotocol/sdk/types.js');
 let release,started;const began=new Promise(r=>{started=r}),blocked=new Promise(r=>{release=r});
 const x=await setup(t,{idleSessionTimeoutMs:60000},gateway=>{
  const original=gateway.serverForOwner.bind(gateway);
  gateway.serverForOwner=owner=>{const s=original(owner);s.setRequestHandler(CallToolRequestSchema,async()=>{started();await blocked;return{content:[{type:'text',text:'done'}]}});return s;};
 });
 const a=await x.client(),pending=a.client.callTool({name:'list_execution_environments',arguments:{}});await began;
 const active=[...x.server.sessions.values()][0];active.lastActivityAt=Date.now()-60001;
 try{assert.equal(active.inFlight,1);const b=await x.client();assert.equal(x.server.sessions.size,2);assert.equal((await b.client.listTools()).tools.length,4);assert.ok([...x.server.sessions.values()].includes(active));}
 finally{release();await pending;}
 assert.equal(active.inFlight,0);active.lastActivityAt=Date.now()-60001;await x.client();assert.equal(x.server.sessions.size,2);
});
