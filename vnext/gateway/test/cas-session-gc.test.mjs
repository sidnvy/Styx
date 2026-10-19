import test from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';

async function setup(t, {idleSessionTimeoutMs = 0} = {}) {
  const gateway = createStyxGateway({catalog: {version: 1, targets: []}, computer: null});
  const hosts = [];
  const token = 'styx_vnext_ephemeral_session_gc_test_token_' + 'u'.repeat(36);
  const server = await createGatewayHttp(gateway, {
    token, port: 0, allowedHosts: hosts, maxSessions: 1, idleSessionTimeoutMs
  });
  hosts.push('127.0.0.1:' + server.address.port);
  t.after(() => server.close());
  return {
    server,
    async client() {
      const transport = new StreamableHTTPClientTransport(
        new URL('http://127.0.0.1:' + server.address.port + '/mcp'),
        {requestInit: {headers: {Authorization: 'Bearer ' + token}}}
      );
      const client = new Client({name: 'session-gc-test', version: '0.1'});
      await client.connect(transport);
      t.after(async () => { await client.close().catch(() => {}); });
      return client;
    }
  };
}

test('explicit zero idle timeout still enforces max MCP sessions', async t => {
  const x = await setup(t);
  const a = await x.client();
  assert.equal((await a.listTools()).tools.length, 4);
  assert.equal(x.server.sessions.size, 1);
  await assert.rejects(x.client(), /503|Session capacity/i);
  assert.equal(x.server.sessions.size, 1);
});

test('CAS lab reaps inactive orphan sessions on saturation and permits fresh initialize', async t => {
  const x = await setup(t, {idleSessionTimeoutMs: 20});
  const a = await x.client();
  assert.equal((await a.listTools()).tools.length, 4);
  assert.equal(x.server.sessions.size, 1);
  const active = [...x.server.sessions.values()][0];
  assert.equal(active.inFlight, 0);
  // Preserve a recent session even if another initialization arrives.
  await assert.rejects(x.client(), /503|Session capacity/i);
  await new Promise(resolve => setTimeout(resolve, 35));
  const b = await x.client();
  assert.equal(x.server.sessions.size, 1);
  assert.deepEqual((await b.listTools()).tools.map(v => v.name),
    ['exec_command', 'write_stdin', 'list_execution_environments', 'get_execution_environment_status']);
  assert.equal(x.server.sessions.size, 1);
});

test('CAS lab does not evict a session holding an active request', async t => {
  const x = await setup(t, {idleSessionTimeoutMs: 15});
  await x.client();
  const active = [...x.server.sessions.values()][0];
  // Simulate a long-running in-flight MCP request without requiring a side effect.
  active.inFlight++;
  await new Promise(resolve => setTimeout(resolve, 28));
  await assert.rejects(x.client(), /503|Session capacity/i);
  assert.equal(x.server.sessions.size, 1);
  active.inFlight--;
});

test('production defaults reclaim abandoned discovery but preserve owned Exec work', async t => {
  const gateway = createStyxGateway({catalog:{version:1,targets:[]},computer:null});
  const hosts=[];const token='production_gc_test_'+'z'.repeat(40);
  const server=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts,maxSessions:1});
  hosts.push('127.0.0.1:'+server.address.port);t.after(()=>server.close());
  async function connect(){
    const transport=new StreamableHTTPClientTransport(new URL('http://'+hosts[0]+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+token}}});
    const client=new Client({name:'production-gc',version:'1'});
    t.after(()=>client.close().catch(()=>{}));await client.connect(transport);return client;
  }
  const a=await connect();await a.listTools();
  const previous=[...server.sessions.values()][0];
  previous.lastActivityAt=Date.now()-16*60*1000;
  // Retained Exec records include yielded interactive and uncertain processes.
  gateway.exec.sessions.set(17,{owner:previous.owner,state:'running'});
  await assert.rejects(connect(),/503|Session capacity/);
  assert.equal(server.sessions.size,1);
  // A lost native runtime cannot be resumed and must not pin its HTTP owner.
  gateway.exec.sessions.get(17).runtime={lost:true};
  const b=await connect();
  gateway.exec.sessions.delete(17);assert.equal((await b.listTools()).tools.length,4);
  assert.notEqual([...server.sessions.values()][0].owner,previous.owner);
  await assert.rejects(a.listTools(),/404|Session not found/);
});

test('an actual asynchronous tools/call remains active until its HTTP response ends',async t=>{
  const {CallToolRequestSchema}=await import('@modelcontextprotocol/sdk/types.js');
  const gateway=createStyxGateway({catalog:{version:1,targets:[]},computer:null});
  let release,started;const began=new Promise(resolve=>{started=resolve});
  const blocked=new Promise(resolve=>{release=resolve});
  const original=gateway.serverForOwner.bind(gateway);
  gateway.serverForOwner=owner=>{const s=original(owner);s.setRequestHandler(CallToolRequestSchema,async()=>{started();await blocked;return{content:[{type:'text',text:'done'}]}});return s;};
  const hosts=[];const token='inflight_gc_test_'+'z'.repeat(40);
  const server=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts,maxSessions:1,idleSessionTimeoutMs:10});
  hosts.push('127.0.0.1:'+server.address.port);t.after(()=>server.close());
  async function connect(){const tr=new StreamableHTTPClientTransport(new URL('http://'+hosts[0]+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+token}}});const c=new Client({name:'inflight-gc',version:'1'});t.after(()=>c.close().catch(()=>{}));await c.connect(tr);return c;}
  const a=await connect();const pending=a.callTool({name:'list_execution_environments',arguments:{}});
  await began;await new Promise(r=>setTimeout(r,30));
  const session=[...server.sessions.values()][0];
  try{assert.equal(session.inFlight,1);await assert.rejects(connect(),/503|Session capacity/);}
  finally{release();await pending;}
  await new Promise(r=>setTimeout(r,15));
  const b=await connect();assert.equal((await b.listTools()).tools.length,4);
});
