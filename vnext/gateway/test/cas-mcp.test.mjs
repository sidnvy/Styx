import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';
import {CasExperimentLedger} from '../cas/ledger.mjs';
import {CAS_APP_URI} from '../cas/mcp.mjs';

function catalog() {
  return {version: 1, default_environment_id: 'dev', targets: [{
    id: 'dev', kind: 'host', platform: 'linux', generation: 'gen-1',
    cwd: '/tmp', shell: '/bin/sh', shells: ['/bin/sh'], allowed: true,
    exec: {transport: 'websocket', url: 'ws://127.0.0.1:9'}
  }]};
}
async function start(t, cas = null, casOnly = false) {
  const controller = createStyxGateway({catalog: catalog(), computer: null, cas, casOnly});
  const token = 'styx_vnext_ephemeral_cas_test_' + 'p'.repeat(36);
  const hosts = [];
  const gateway = await createGatewayHttp(controller, {token, port: 0, allowedHosts: hosts});
  const address = 'http://127.0.0.1:' + gateway.address.port + '/mcp';
  hosts.push('127.0.0.1:' + gateway.address.port);
  t.after(() => gateway.close());
  async function client() {
    const transport = new StreamableHTTPClientTransport(new URL(address), {
      requestInit: {headers: {Authorization: 'Bearer ' + token}}
    });
    const c = new Client({name: 'styx-cas-contract-test', version: '0.1'});
    await c.connect(transport);
    t.after(() => c.close());
    return c;
  }
  return {client, gateway};
}
const tool = async (client, name, args) => {
  const result = await client.callTool({name, arguments: args});
  if (result.isError) throw Error(result.structuredContent?.error || 'tool_error');
  return result.structuredContent;
};

test('disabled by default: original tool discovery and capabilities remain unchanged', async t => {
  const http = await start(t);
  const client = await http.client();
  assert.deepEqual((await client.listTools()).tools.map(t => t.name),
    ['exec_command', 'write_stdin', 'list_execution_environments']);
  const response = await client.callTool({name: 'cas_experiment_create', arguments: {objective: 'no'}});
  assert.equal(response.isError, true);
});

test('CAS tools, exact resource, two-turn simulated Host handoff across MCP sessions', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'styx-cas-mcp-'));
  t.after(() => fs.rm(root, {recursive: true, force: true}));
  let now = Date.parse('2026-10-18T12:00:00Z');
  const ledger = await new CasExperimentLedger({directory: root, now: () => now}).init();
  const http = await start(t, ledger);
  const model = await http.client();
  const view = await http.client();

  const inventory = await model.listTools();
  const present = inventory.tools.find(t => t.name === 'cas_experiment_present');
  assert.equal(present._meta.ui.resourceUri, CAS_APP_URI);
  assert.deepEqual(present._meta.ui.visibility, ['model']);
  const appPrivate = inventory.tools.find(t => t.name === 'cas_experiment_claim');
  assert.deepEqual(appPrivate._meta.ui.visibility, ['app']);
  assert.equal(appPrivate._meta.ui.resourceUri, undefined);
  const resource = (await model.listResources()).resources[0];
  assert.equal(resource.uri, CAS_APP_URI);
  const read = (await view.readResource({uri: CAS_APP_URI})).contents[0];
  assert.equal(read.mimeType, 'text/html;profile=mcp-app');
  assert.match(read.text, /ui\/message/);
  assert.match(read.text, /ui\/initialize/);
  const script = /<script>([\s\S]*?)<\/script>/.exec(read.text)?.[1];
  assert.ok(script);
  new vm.Script(script);

  const begin = await tool(model, 'cas_experiment_create', {
    objective: 'A harmless Host continuation test', rounds: 2, delay_ms: 15000
  });
  assert.equal(begin.status, 'running');
  const initial = await tool(model, 'cas_experiment_present', {run_id: begin.run_id});
  assert.equal(initial.wake.round, 1);
  assert.equal(initial.wake.phase, 'pending');
  now += 15000;

  const controllerId = randomUUID();
  const claim = await tool(view, 'cas_experiment_claim', {
    run_id: begin.run_id, controller_id: controllerId
  });
  assert.equal(claim.claimed, true);
  const prepared = await tool(view, 'cas_experiment_prepare', {
    run_id: begin.run_id, controller_id: controllerId, claim_id: claim.claim_id
  });
  const round1Args = JSON.parse(prepared.message.match(/with exactly (\{.*?\})\./)[1]);
  assert.equal(round1Args.round, 1);
  assert.equal(round1Args.run_id, begin.run_id);
  assert.equal((await tool(view, 'cas_experiment_finish', {
    run_id: begin.run_id, controller_id: controllerId,
    attempt_id: prepared.attempt_id, accepted: true
  })).wake.phase, 'dispatch_accepted');
  assert.equal((await tool(model, 'cas_experiment_status', {run_id: begin.run_id}))
    .completed_rounds, 0); // Host acceptance is NOT a resumed-turn receipt.

  // Represents an independently started, exact new model turn.
  const newTurnClient = await http.client();
  const consumed = await tool(newTurnClient, 'cas_experiment_consume', round1Args);
  assert.equal(consumed.completed_rounds, 1);
  assert.equal(consumed.wake.round, 2);
  now += 15000;
  const claim2 = await tool(view, 'cas_experiment_claim', {
    run_id: begin.run_id, controller_id: controllerId
  });
  const prepared2 = await tool(view, 'cas_experiment_prepare', {
    run_id: begin.run_id, controller_id: controllerId, claim_id: claim2.claim_id
  });
  const round2Args = JSON.parse(prepared2.message.match(/with exactly (\{.*?\})\./)[1]);
  const finished = await tool(newTurnClient, 'cas_experiment_consume', round2Args);
  assert.equal(finished.status, 'completed');
  assert.equal(finished.completed_rounds, 2);
  assert.equal((await tool(model, 'cas_experiment_status', {run_id: begin.run_id})).wake, null);
  assert.equal((await tool(view, 'cas_experiment_claim', {
    run_id: begin.run_id, controller_id: controllerId
  })).claimed, false);
});

test('CAS-only lab profile advertises zero execution tools and denies hidden execution calls', async t => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'styx-cas-isolated-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const ledger = await new CasExperimentLedger({directory}).init();
  const {client} = await start(t, ledger, true);
  const conn = await client();
  const names = (await conn.listTools()).tools.map(t => t.name);
  assert.ok(names.length > 0);
  assert.ok(names.every(name => name.startsWith('cas_experiment_')));
  assert.ok(!names.includes('exec_command'));
  assert.ok(!names.includes('write_stdin'));
  assert.ok(!names.includes('list_execution_environments'));
  const rejected = await conn.callTool({name: 'exec_command', arguments: {cmd: 'echo dangerous'}});
  assert.equal(rejected.isError, true);
  assert.match(rejected.content[0].text, /unknown_tool/);
});
