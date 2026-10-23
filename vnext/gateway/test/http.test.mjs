import test from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {request as httpRequest} from 'node:http';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';

function catalog() {
  return {version: 1, default_environment_id: 'dev', targets: [{
    id: 'dev', kind: 'host', platform: 'linux', generation: 'gen-1',
    cwd: '/tmp', shell: '/bin/sh', shells: ['/bin/sh'], allowed: true,
    exec: {transport: 'websocket', url: 'ws://127.0.0.1:9'}
  }]};
}
function fakeRuntime() {
  const processes = new Map();
  return {sessionId: 'executor-session', lost: false,
    async close() {}, async request(method, args) {
      if (method === 'process/start') {
        processes.set(args.processId, {command: args.argv.at(-1), cursor: 0});
        return {processId: args.processId};
      }
      const p = processes.get(args.processId);
      if (!p) throw Error('Unexpected process');
      if (method === 'process/read') {
        if (p.command === 'sleep') return {chunks: [], nextSeq: 1, exited: false,
          closed: false, failure: null};
        const chunks = (args.afterSeq ?? 0) === 0 ? [{seq: 1, stream: 'stdout',
          chunk: Buffer.from('fixture-ok').toString('base64')}] : [];
        return {chunks, nextSeq: 2, exited: true, closed: true, exitCode: 0, failure: null};
      }
      if (method === 'process/terminate') {
        p.command = 'terminated';
        return {status: 'accepted'};
      }
      if (method === 'process/write') return {status: 'accepted'};
      throw Error('Unexpected request');
    }
  };
}
test('authenticated HTTP MCP transport, Codex tools and session isolation', async t => {
  const hosts = [];
  const controller = createStyxGateway({catalog: catalog(), connect: async () => fakeRuntime()});
  const token = 'styx_vnext_ephemeral_test_token_' + 'z'.repeat(36);
  const server = await createGatewayHttp(controller, {token, port: 0, allowedHosts: hosts});
  const address = 'http://127.0.0.1:' + server.address.port + '/mcp';
  hosts.push('127.0.0.1:' + server.address.port);
  t.after(async () => server.close());
  const unauthorized = await fetch(address, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method: 'initialize', params: {}})});
  assert.equal(unauthorized.status, 401);
  const wrongHost = await new Promise((resolve, reject) => {
    const req = httpRequest(address, {method: 'POST',
      headers: {Authorization: 'Bearer ' + token, Host: 'evil.local'}},
      res => {res.resume(); resolve(res.statusCode);});
    req.on('error', reject); req.end();
  });
  assert.equal(wrongHost, 403);
  const originRejected = await fetch(address, {headers: {Authorization: 'Bearer ' + token,
    Origin: 'https://untrusted.example'}, method: 'POST'});
  assert.equal(originRejected.status, 403);

  async function client() {
    const transport = new StreamableHTTPClientTransport(new URL(address), {
      requestInit: {headers: {Authorization: 'Bearer ' + token}}
    });
    const conn = new Client({name: 'styx-vnext-test', version: '0.1'});
    await conn.connect(transport);
    t.after(async () => conn.close());
    return conn;
  }
  const a = await client(), b = await client();
  const list = await a.listTools();
  assert.deepEqual(list.tools.map(t => t.name),
    ['exec_command', 'write_stdin', 'list_execution_environments', 'get_execution_environment_status']);
  const environments = await a.callTool({name: 'list_execution_environments', arguments: {}});
  assert.equal(environments.structuredContent.environments[0].environment_id, 'dev');
  const status = await a.callTool({name: 'get_execution_environment_status',
    arguments: {environment_id: 'dev'}});
  assert.equal(status.structuredContent.exec.connection, 'unknown');
  assert.equal(status.structuredContent.exec.readiness, 'unknown');
  assert.equal(status.structuredContent.computer.configured, false);
  assert.equal((await a.callTool({name: 'get_execution_environment_status',
    arguments: {}})).isError, true);
  const finished = await a.callTool({name: 'exec_command', arguments: {
    cmd: 'test', yield_time_ms: 0
  }});
  const completed = finished.structuredContent.session_id
    ? await a.callTool({name: 'write_stdin', arguments: {
      session_id: finished.structuredContent.session_id, chars: '', yield_time_ms: 200
    }}) : finished;
  assert.equal(finished.structuredContent.output + (completed === finished ? '' : completed.structuredContent.output), 'fixture-ok');
  assert.equal(completed.structuredContent.exit_code, 0);
  const running = await a.callTool({name: 'exec_command', arguments: {
    cmd: 'sleep', yield_time_ms: 0
  }});
  assert.ok(running.structuredContent.session_id > 0);
  const stolen = await b.callTool({name: 'write_stdin', arguments: {
    session_id: running.structuredContent.session_id, chars: 'x', yield_time_ms: 0
  }});
  assert.equal(stolen.isError, true);
  assert.equal(JSON.parse(stolen.content[0].text).error, 'unknown_session');
});

test('Exec target-selection errors remain actionable before connecting a native runtime',async()=>{
 const config=catalog();delete config.default_environment_id;let connected=false;
 const gateway=createStyxGateway({catalog:config,connect:async()=>{connected=true;return fakeRuntime()}});
 try{
  const missing=await gateway.exec.callTool('exec_command',{cmd:'pwd'},'test-owner');
  assert.equal(missing.structuredContent.error,'default_environment_required');
  const unknown=await gateway.exec.callTool('exec_command',{cmd:'pwd',environment_id:'unknown'},'test-owner');
  assert.equal(unknown.structuredContent.error,'environment_not_found');
  assert.equal(connected,false);
 }finally{await gateway.close()}
});

test('trusted Tunnel conversation survives HTTP reconnects without merging users or chats', async t => {
 const hosts=[],token='test-model-'+ 'a'.repeat(40),context='b'.repeat(64),browserOwners=[],computerOwners=[];
 const cfg=catalog();cfg.targets[0].exec={transport:'outbound',token_file:'/tmp/fixture-token'};cfg.targets[0].computer={enabled:true,transport:'outbound'};cfg.targets[0].browser={enabled:true,transport:'outbound'};
 const browser={bindPrincipal(owner,principal){browserOwners.push({owner,principal})},async listTools(){return [{name:'browser_probe',inputSchema:{type:'object'}}]},async callTool(_n,_a,owner){return {content:[{type:'text',text:owner}]}},async close(){}};
 const computer={async listTools(){return [{name:'computer_probe',inputSchema:{type:'object'}}]},async callTool(_n,_a,owner){computerOwners.push(owner);return {content:[{type:'text',text:owner}]}},async close(){}};
 const gateway=createStyxGateway({catalog:cfg,connect:async()=>fakeRuntime(),browser,computer});
 const server=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts,tunnelContextToken:context});
 const address='http://127.0.0.1:'+server.address.port+'/mcp';hosts.push('127.0.0.1:'+server.address.port);t.after(()=>server.close());
 async function client(capability=context){
  const transport=new StreamableHTTPClientTransport(new URL(address),{requestInit:{headers:{Authorization:'Bearer '+token,...(capability?{'X-Styx-Tunnel-Context':capability}:{})}}});
  const c=new Client({name:'conversation-test',version:'1'});await c.connect(transport);t.after(()=>c.close());return c;
 }
 const meta={'openai/subject':'user-a','openai/session':'chat-a','openai/organization':'org-a'};
 const call=(c,name,args={},m=meta)=>c.callTool({name,arguments:args,_meta:m});
 const a=await client();
 const running=await call(a,'exec_command',{cmd:'sleep',yield_time_ms:0});
 const id=running.structuredContent.session_id;assert.ok(id);
 const browserA=await call(a,'browser_probe');await a.close();
 const b=await client();
 const resumed=await call(b,'write_stdin',{session_id:id,chars:'',yield_time_ms:0});
 assert.equal(resumed.isError,undefined);assert.equal(resumed.structuredContent.session_id,id);
 assert.equal((await call(b,'browser_probe')).content[0].text,browserA.content[0].text);
 assert.equal((await call(b,'computer_probe')).content[0].text,browserA.content[0].text);
 for(const change of [{'openai/session':'chat-b'},{'openai/subject':'user-b'},{'openai/organization':'org-b'}]) {
  assert.equal(JSON.parse((await call(b,'write_stdin',{session_id:id,chars:'x',yield_time_ms:0},{...meta,...change})).content[0].text).error,'unknown_session');
 }
 const plain=await client(null);
 assert.equal(JSON.parse((await call(plain,'write_stdin',{session_id:id,chars:'',yield_time_ms:0})).content[0].text).error,'unknown_session');
 assert.equal(JSON.parse((await call(b,'exec_command',{cmd:'test'},{})).content[0].text).error,'trusted_conversation_metadata_required');
 assert.equal(JSON.parse((await call(b,'exec_command',{cmd:'test'},{...meta,'openai/session':{bad:true}})).content[0].text).error,'trusted_conversation_metadata_required');
 await assert.rejects(client('c'.repeat(64)));
 await call(b,'browser_probe',{}, {...meta,'openai/subject':'user-b'});
 const profiles=browserOwners.filter(x=>x.owner.startsWith('tunnel-conversation:'));
 assert.notEqual(profiles[0].principal,profiles.at(-1).principal);
 assert.equal(computerOwners[0],browserA.content[0].text);
});


test('SDK validates success schemas while empty Gateway, unknown target and maintenance errors stay actionable', async t => {
 for (const empty of [true, false]) {
  const hosts=[], token='isolated-error-contract-'+ 'x'.repeat(32);
  let connections=0;
  const gateway=createStyxGateway({catalog:empty?{version:1,targets:[]}:catalog(),connect:async()=>{connections++;return fakeRuntime()}});
  const server=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts});
  const address='http://127.0.0.1:'+server.address.port+'/mcp';hosts.push('127.0.0.1:'+server.address.port);
  const client=new Client({name:'error-contract',version:'1'});
  try {
   await client.connect(new StreamableHTTPClientTransport(new URL(address),{requestInit:{headers:{Authorization:'Bearer '+token}}}));
   const tools=await client.listTools();assert.ok(tools.tools.find(t=>t.name==='exec_command').outputSchema);
   const check=async(args,code)=>{const result=await client.callTool({name:'exec_command',arguments:args});assert.equal(result.isError,true);assert.equal(result.structuredContent,undefined);assert.equal(JSON.parse(result.content[0].text).error,code);};
   if(empty) await check({cmd:'never-run'},'default_environment_required');
   await check({cmd:'never-run',environment_id:'absent'},'environment_not_found');
   if(!empty){gateway.workAdmission.begin({ticketId:'f'.repeat(32),scope:'all'});await check({cmd:'never-run'},'device_in_maintenance');gateway.workAdmission.cancel('f'.repeat(32));}
   assert.equal(connections,0);
   if(!empty){
    const diagnostic={error:'transport_lost',session_id:123,uncertain:true};
    gateway.exec.callTool=async()=>({isError:true,structuredContent:diagnostic,content:[{type:'text',text:JSON.stringify(diagnostic)}]});
    const result=await client.callTool({name:'exec_command',arguments:{cmd:'injected-terminal-transport-error'}});
    assert.equal(result.isError,true);assert.equal(result.structuredContent,undefined);
    assert.deepEqual(JSON.parse(result.content[0].text),diagnostic);
    assert.equal(gateway.uncertainWorkHistory().length,1,'internal uncertain observation precedes wire projection');
   }
  } finally {await client.close();await server.close();}
 }
});
