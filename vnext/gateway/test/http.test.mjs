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
  assert.equal(stolen.structuredContent.error, 'unknown_session');
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
