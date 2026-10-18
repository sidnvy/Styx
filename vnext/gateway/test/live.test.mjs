import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {randomBytes, createHash} from 'node:crypto';
import {mkdtemp, mkdir, rm} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import WebSocket from 'ws';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';

const live = process.env.STYX_LIVE_EXEC_TEST === '1' && process.platform === 'linux' &&
  process.arch === 'x64';
const binary = fileURLToPath(new URL('../../packages/styx-exec-adapter/.runtime/codex', import.meta.url));

async function port() {
  const socket = createServer(); socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const n = socket.address().port; await new Promise(resolve => socket.close(resolve)); return n;
}
async function ready(url, token) {
  for (let i = 0; i < 50; i++) {
    try {
      const ws = new WebSocket(url, {handshakeTimeout: 300,
        headers: {Authorization: 'Bearer ' + token}});
      await once(ws, 'open'); ws.close(); return;
    } catch { await new Promise(resolve => setTimeout(resolve, 60)); }
  }
  throw new Error('Executor WebSocket did not become ready');
}
test('real Codex Exec Server -> authenticated Styx HTTP -> shell and PTY', {skip: !live}, async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'styx-http-real-'));
  const codexHome = path.join(root, 'codex-home'); await mkdir(codexHome);
  const execPort = await port(), token = randomBytes(24).toString('hex');
  const wsUrl = 'ws://127.0.0.1:' + execPort;
  const child = spawn(binary, ['exec-server', '--listen', wsUrl,
    '--ws-auth', 'capability-token', '--ws-token-sha256',
    createHash('sha256').update(token).digest('hex')], {
    cwd: root, env: {...process.env, HOME: root, CODEX_HOME: codexHome},
    detached: true, stdio: 'ignore'
  });
  t.after(async () => {
    if (child.exitCode === null) {
      try {process.kill(-child.pid, 'SIGTERM');} catch {}
      await Promise.race([once(child, 'exit').catch(() => {}), new Promise(r=>setTimeout(r, 2000))]);
    }
    await rm(root, {recursive: true, force: true});
  });
  await ready(wsUrl, token);
  const catalog = {version: 1, default_environment_id: 'dev', targets: [{
    id: 'dev', kind: 'environment', platform: 'linux', generation: 'test-generation-1',
    cwd: root, shell: '/bin/sh', shells: ['/bin/sh'], allowed: true,
    exec: {transport: 'websocket', url: wsUrl, allow_unauthenticated_loopback: false}
  }]};
  // The real executor expects the signed bearer on its own connection.
  // Use a fixed explicit trusted connection factory while keeping the public
  // target schema and gateway entrypoint exactly as in production.
  const {ExecConnection, websocketClient} = await import('../../packages/styx-exec-adapter/rpc.mjs');
  const styx = createStyxGateway({catalog, connect: async () =>
    new ExecConnection(() => websocketClient({url: wsUrl, token}))
  });
  const hosts = [], inbound = randomBytes(36).toString('hex');
  const server = await createGatewayHttp(styx, {token: inbound, port: 0, allowedHosts: hosts});
  const addr = 'http://127.0.0.1:' + server.address.port + '/mcp';
  hosts.push('127.0.0.1:' + server.address.port);
  t.after(async () => server.close());
  const client = new Client({name: 'styx-live-test', version: '0.1.0'});
  await client.connect(new StreamableHTTPClientTransport(new URL(addr), {
    requestInit: {headers: {Authorization: 'Bearer ' + inbound}}
  }));
  t.after(async () => client.close());
  async function complete(initial) {
    let result = initial, output = initial.structuredContent.output;
    for (let i = 0; result.structuredContent.session_id && i < 20; i++) {
      result = await client.callTool({name: 'write_stdin', arguments: {
        session_id: result.structuredContent.session_id, chars: '', yield_time_ms: 250
      }});
      output += result.structuredContent.output;
    }
    assert.equal(result.isError, undefined);
    assert.equal(result.structuredContent.exit_code, 0);
    return output;
  }
  const out = await complete(await client.callTool({name: 'exec_command', arguments: {
    cmd: "printf 'STYX_HTTP_EXEC_OK'", yield_time_ms: 250, login: false
  }}));
  assert.equal(out, 'STYX_HTTP_EXEC_OK');
  const initial = await client.callTool({name: 'exec_command', arguments: {
    cmd: 'read line; printf "ACK:%s" "$line"', yield_time_ms: 0, login: false
  }});
  assert.ok(initial.structuredContent.session_id);
  const fed = await client.callTool({name: 'write_stdin', arguments: {
    session_id: initial.structuredContent.session_id, chars: 'PING\n', yield_time_ms: 250
  }});
  const roundtrip = await complete(fed);
  assert.equal(roundtrip, 'ACK:PING');
});
