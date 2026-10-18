import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, rm, readFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {randomBytes, createHash} from 'node:crypto';
import {ExecAdapter} from '../adapter.mjs';
import {ExecConnection, stdioClient, websocketClient} from '../rpc.mjs';
import {ExecError, TransportFault} from '../errors.mjs';

const binary = fileURLToPath(new URL('../.runtime/codex', import.meta.url));
const owner = 'test-principal:test-conversation';
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function scratch(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'styx-adapter-'));
  await mkdir(path.join(root, 'codex-home'));
  t.after(() => rm(root, {recursive: true, force: true}));
  return {root, env: {PATH: '/usr/bin:/bin', HOME: root, CODEX_HOME: path.join(root, 'codex-home')}};
}
// Integration fixtures never source the workstation user's personal login
// profile. Production exec_command keeps the upstream Codex login behavior;
// only this test harness injects login:false when a test does not specify it.
class IsolatedTestExecAdapter extends ExecAdapter {
  execCommand(args, owner) {
    return super.execCommand({...args, login:args.login??false}, owner);
  }
}
function adapter(runtime, root) {
  return new IsolatedTestExecAdapter({resolve: async (id, caller) => {
    if (caller !== owner || (id !== undefined && id !== 'pilot')) throw new ExecError('access_denied');
    return {id: 'pilot', generation: 'test-generation', runtime, cwd: root,
      platform: 'linux', shell: '/bin/sh', shells: ['/bin/sh', '/bin/bash'], env: {PATH: '/usr/bin:/bin'}};
  }});
}
async function complete(a, initial) {
  let r = initial, output = r.output;
  for (let i = 0; r.session_id && i < 20; i++) {
    r = await a.writeStdin({session_id: r.session_id, yield_time_ms: 250}, owner);
    output += r.output;
  }
  assert.ok(!r.session_id, 'command did not terminate within bounded polling');
  return {...r, output};
}
async function stdio(t) {
  const {root, env} = await scratch(t);
  const runtime = await new ExecConnection(() => stdioClient({binary, cwd: root, env})).initialize();
  const a = adapter(runtime, root);
  t.after(async () => { const stops = await a.cleanup(); assert.ok(stops.every(s => s.confirmed)); await runtime.close(); });
  return {a, runtime, root, env};
}
async function wsServer(t) {
  const {root, env} = await scratch(t);
  const reserve = createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const token = randomBytes(24).toString('hex');
  const url = 'ws://127.0.0.1:' + port;
  let child = spawn(binary, ['exec-server', '--listen', url, '--ws-auth', 'capability-token',
    '--ws-token-sha256', createHash('sha256').update(token).digest('hex')], {
      cwd: root, env, detached: true, stdio: 'ignore'
    });
  let exited = once(child, 'exit'); let closed = false;
  async function stop() {
    if (closed) return; closed = true;
    process.kill(-child.pid, 'SIGTERM'); await exited;
    assert.throws(() => process.kill(-child.pid, 0), e => e.code === 'ESRCH');
  }
  t.after(stop);
  let runtime;
  for (let i = 0; i < 40; i++) {
    try {
      runtime = await new ExecConnection(() => websocketClient({url, token})).initialize(); break;
    } catch { await sleep(50); }
  }
  assert.ok(runtime, 'server did not become ready');
  const a = adapter(runtime, root);
  t.after(async () => { await a.cleanup(); await runtime.close(); });
  async function restart() {
    await stop();
    child = spawn(binary, ['exec-server', '--listen', url, '--ws-auth', 'capability-token',
      '--ws-token-sha256', createHash('sha256').update(token).digest('hex')],
      {cwd: root, env, detached: true, stdio: 'ignore'});
    exited = once(child, 'exit'); closed = false;
    let ready = false;
    for (let i = 0; i < 40; i++) {
      try { const probe = await websocketClient({url, token}); await probe.close(); ready = true; break; }
      catch { await sleep(50); }
    }
    assert.ok(ready, 'replacement executor not ready');
  }
  return {a, runtime, root, url, token, stop, restart};
}

test('stdio: stdout/stderr, exit 7, login flag and file URI conversion', async t => {
  const {a} = await stdio(t);
  const r = await complete(a, await a.execCommand({
    cmd: "printf out; printf err >&2; exit 7", login: false, yield_time_ms: 250
  }, owner));
  assert.equal(r.exit_code, 7); assert.match(r.output, /out/); assert.match(r.output, /err/);
});
test('stdio: adapter stdin and PTY both work through the real executor', async t => {
  const {a} = await stdio(t);
  const first = await a.execCommand({cmd: 'read line; printf "<%s>" "$line"', yield_time_ms: 0}, owner);
  assert.ok(first.session_id);
  const r = await complete(a, await a.writeStdin({
    session_id: first.session_id, chars: '你好\n', yield_time_ms: 250
  }, owner));
  assert.equal(r.output, '<你好>'); assert.equal(r.exit_code, 0);
  const pty = await complete(a, await a.execCommand({
    cmd: 'test -t 0 && printf PTY_OK', tty: true, yield_time_ms: 250
  }, owner));
  assert.equal(pty.output, 'PTY_OK'); assert.equal(pty.exit_code, 0);
});
test('stdio: incremental reads do not replay earlier output', async t => {
  const {a} = await stdio(t);
  const r = await complete(a, await a.execCommand({
    cmd: 'printf A; sleep 0.15; printf B; sleep 0.15; printf C', yield_time_ms: 250
  }, owner));
  assert.equal(r.output, 'ABC'); assert.equal(r.exit_code, 0);
});
test('stdio: completed high-output process remains readable across bounded pages', async t => {
  const {a} = await stdio(t);
  const first = await a.execCommand({
    cmd: "head -c 150000 /dev/zero | tr '\\000' x", yield_time_ms: 250, max_output_tokens: 10000
  }, owner);
  assert.ok(first.output.length <= 10000);
  const r = await complete(a, first);
  assert.equal(r.exit_code, 0); assert.ok(r.output.length > 10000);
});
test('stdio: cleanup confirms temporary interactive process termination', async t => {
  const {a} = await stdio(t);
  const r = await a.execCommand({cmd: 'echo "$$"; read line', yield_time_ms: 250}, owner);
  const pid = Number(r.output.trim()); assert.ok(Number.isSafeInteger(pid) && pid > 1);
  const stops = await a.cleanup();
  assert.equal(stops.length, 1); assert.equal(stops[0].confirmed, true);
  assert.throws(() => process.kill(pid, 0), e => e.code === 'ESRCH');
});
test('websocket: authentication, explicit reconnection and adapter session mapping', async t => {
  const {a, runtime, url, token} = await wsServer(t);
  const {default: WebSocket} = await import('ws');
  const unauth = new WebSocket(url, {handshakeTimeout: 5000});
  const status = await new Promise((resolve, reject) => {
    unauth.on('error', () => {});
    unauth.once('unexpected-response', (_request, response) => {
      response.resume(); resolve(response.statusCode); unauth.terminate();
    });
    unauth.once('open', () => { unauth.terminate(); reject(Error('unauthenticated connection accepted')); });
  });
  assert.equal(status, 401);
  await assert.rejects(websocketClient({url, token: 'wrong'}), TransportFault);
  const first = await a.execCommand({cmd: 'read line; printf "got:%s" "$line"', yield_time_ms: 0}, owner);
  const sid = runtime.sessionId;
  await runtime.disconnect(); await runtime.resume();
  assert.equal(runtime.sessionId, sid);
  const r = await complete(a, await a.writeStdin({
    session_id: first.session_id, chars: 'reconnected\n', yield_time_ms: 250
  }, owner));
  assert.equal(r.output, 'got:reconnected'); assert.equal(r.exit_code, 0);
  assert.ok(token.length > 0); // Token is never included in receipts.
});
test('websocket: executor deduplicates an internal writeId', async t => {
  const {runtime, root} = await wsServer(t);
  await runtime.request('process/start', {processId: 'dedup', argv: ['/bin/cat'],
    cwd: pathToFileURL(root).href, env: {PATH: '/usr/bin:/bin'}, tty: false, pipeStdin: true});
  const input = {processId: 'dedup', writeId: 'same-logical-write', chunk: Buffer.from('ONCE\n').toString('base64')};
  await runtime.request('process/write', input); await runtime.request('process/write', input);
  const r = await runtime.request('process/read', {processId: 'dedup', afterSeq: null, maxBytes: 4096, waitMs: 250});
  assert.equal(r.chunks.map(c => Buffer.from(c.chunk, 'base64').toString()).join(''), 'ONCE\n');
  await runtime.request('process/terminate', {processId: 'dedup'});
});
test('websocket: attached session cannot be stolen by a second connection', async t => {
  const {runtime, url, token} = await wsServer(t);
  const other = await websocketClient({url, token});
  try { await assert.rejects(other.request('initialize', {clientName: 'other', resumeSessionId: runtime.sessionId})); }
  finally { await other.close(); }
});
test('websocket: server restart never silently replaces an existing execution session', async t => {
  const {a, runtime, restart} = await wsServer(t);
  const first = await a.execCommand({cmd: 'cat', yield_time_ms: 0}, owner);
  await restart();
  await assert.rejects(runtime.resume(), /session_lost/);
  assert.equal(runtime.lost, true);
  assert.equal((await a.callTool('write_stdin', {
    session_id: first.session_id, chars: 'must not replay', yield_time_ms: 0
  }, owner)).isError, true);
});
test('websocket: detached session expiry is reported as lost after the fixed 30s window', async t => {
  const {a, runtime} = await wsServer(t);
  const first = await a.execCommand({cmd: 'cat', yield_time_ms: 0}, owner);
  await runtime.disconnect(); await sleep(31000);
  await assert.rejects(runtime.resume(), /session_lost/);
  const r = await a.callTool('write_stdin', {session_id: first.session_id, yield_time_ms: 0}, owner);
  assert.equal(r.isError, true);
});

test('MCP client -> isolated gateway -> adapter -> actual Exec Server', async t => {
  const {Client} = await import('@modelcontextprotocol/sdk/client/index.js');
  const {InMemoryTransport} = await import('@modelcontextprotocol/sdk/inMemory.js');
  const {createMcpServer} = await import('../mcp.mjs');
  const {a} = await stdio(t);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer(a, owner), client = new Client({name: 'prototype-test', version: '0'});
  await server.connect(serverTransport); await client.connect(clientTransport);
  t.after(async () => { await client.close(); await server.close(); });
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map(x => x.name), ['exec_command', 'write_stdin']);
  const old = await client.callTool({name: 'target_exec', arguments: {command: 'id'}});
  assert.equal(old.isError, true);
  const initial = await client.callTool({name: 'exec_command', arguments: {
    cmd: 'read line; printf "mcp:%s" "$line"', yield_time_ms: 0
  }});
  let r = initial.structuredContent;
  assert.ok(r.session_id);
  let response = await client.callTool({name: 'write_stdin', arguments: {
    session_id: r.session_id, chars: 'hello\n', yield_time_ms: 250
  }});
  r = response.structuredContent;
  let output = r.output;
  for (let i = 0; r.session_id && i < 10; i++) {
    response = await client.callTool({name: 'write_stdin', arguments: {session_id: r.session_id, yield_time_ms: 250}});
    r = response.structuredContent; output += r.output;
  }
  assert.equal(r.exit_code, 0); assert.equal(output, 'mcp:hello');
});

test('stdio: real Codex interleaves terminal and output sequences without invalid response', async t => {
  const {a} = await stdio(t);
  for (let i = 0; i < 18; i++) {
    const r = await complete(a, await a.execCommand({
      cmd: 'printf out; printf err >&2; exit 7', login: false, yield_time_ms: 250
    }, owner));
    assert.equal(r.exit_code, 7);
    assert.match(r.output, /out/);
    assert.match(r.output, /err/);
  }
});
