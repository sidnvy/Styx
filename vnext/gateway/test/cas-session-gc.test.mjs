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

test('default transport still enforces max MCP sessions', async t => {
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
