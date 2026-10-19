import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {ExecAdapter} from '../adapter.mjs';
import {RpcClient, ExecConnection, websocketClient} from '../rpc.mjs';
import {ExecError, RpcFault, TransportFault} from '../errors.mjs';

function fixture(options = {}) {
  const calls = [], processes = new Map();
  const runtime = {sessionId: 'server-session', lost: false, async request(method, p) {
    calls.push({method, ...p});
    if (method === 'process/start') {
      processes.set(p.processId, {chunks: [], next: 1, exited: false, exitCode: null});
      if (options.startError) throw options.startError;
      return {processId: p.processId};
    }
    const process = processes.get(p.processId);
    if (!process) throw new RpcFault(-32600);
    if (method === 'process/write') {
      if (options.writeError) throw options.writeError;
      push(process, Buffer.from(p.chunk, 'base64'));
      return {status: options.writeStatus ?? 'accepted'};
    }
    if (method === 'process/terminate') { process.exited = true; process.exitCode = 143; return {running: true}; }
    if (method === 'process/read') {
      if (options.readError) throw options.readError;
      return options.reply ?? {chunks: process.chunks.filter(c => c.seq > (p.afterSeq ?? 0)),
        nextSeq: process.next, exited: process.exited, closed: process.exited,
        exitCode: process.exitCode, failure: null};
    }
    throw Error('unexpected method');
  }};
  const binding = {id: 'dev', generation: 'generation-1', runtime, cwd: '/tmp/pilot',
    shell: '/bin/sh', shells: ['/bin/sh', '/bin/bash'], platform: 'linux', env: {PATH: '/usr/bin:/bin'}};
  const allowed = new Set(['alice:chat-1', 'alice:chat-2', 'bob:chat-1']);
  const adapter = new ExecAdapter({resolve: async (id, owner) => {
    if (!allowed.has(owner) || (id !== undefined && id !== 'dev')) throw new ExecError('access_denied');
    return binding;
  }, ...options.adapter});
  const push = (process, data, stream = 'stdout') => {
    process.chunks.push({seq: process.next++, stream, chunk: Buffer.from(data).toString('base64')});
  };
  const start = () => adapter.execCommand({cmd: 'cat', yield_time_ms: 0}, 'alice:chat-1');
  return {adapter, runtime, binding, calls, processes, push, start, allowed, options};
}
const owner = 'alice:chat-1';
test('only Codex tool names and declared arguments are accepted before execution', async () => {
  const f = fixture();
  for (const [name, args] of [
    ['target_exec', {command: 'id'}], ['exec_command', {cmd: 'id', target: {kind: 'host', id: 'x'}}],
    ['exec_command', {cmd: 'id', sandbox_permissions: 'require_escalated'}],
    ['exec_command', {cmd: 'id', yield_time_ms: NaN}], ['exec_command', {cmd: 'id', tty: 1}],
    ['exec_command', {cmd: 'id', max_output_tokens: 1.5}], ['write_stdin', {session_id: 1, environment_id: 'x'}],
    ['exec_command', {cmd: 'x\0y'}]
  ]) assert.equal((await f.adapter.callTool(name, args, owner)).isError, true);
  assert.equal(f.calls.length, 0);
});
test('trusted binding resolves file URI, shell, login and pipe stdin', async () => {
  const f = fixture();
  const r = await f.adapter.execCommand({cmd: 'printf hi', workdir: 'a b', login: false,
    environment_id: 'dev', yield_time_ms: 0}, owner);
  const launch = f.calls[0];
  assert.equal(launch.cwd, 'file:///tmp/pilot/a%20b');
  assert.deepEqual(launch.argv, ['/bin/sh', '-c', 'printf hi']);
  assert.equal(launch.pipeStdin, true); assert.ok(Number.isSafeInteger(r.session_id));
  assert.equal((await f.adapter.callTool('exec_command', {cmd: 'id', shell: '/bin/evil'}, owner)).isError, true);
});
test('session is bound to principal AND conversation, and does not leak through mismatched callers', async () => {
  const f = fixture(), r = await f.start();
  for (const other of ['bob:chat-1', 'alice:chat-2', 'unknown']) {
    const result = await f.adapter.callTool('write_stdin', {session_id: r.session_id, chars: 'SECRET'}, other);
    assert.equal(result.structuredContent.error, 'unknown_session');
  }
  assert.equal(f.calls.filter(c => c.method === 'process/write').length, 0);
});
test('revocation and generation changes prevent further IO', async () => {
  const f = fixture(), r = await f.start(), before = f.calls.length;
  f.allowed.delete(owner);
  await assert.rejects(f.adapter.writeStdin({session_id: r.session_id, chars: 'x'}, owner), /session_unavailable/);
  f.allowed.add(owner); f.binding.generation = 'new-generation';
  await assert.rejects(f.adapter.writeStdin({session_id: r.session_id, chars: 'x'}, owner), /session_lost/);
  assert.equal(f.calls.length, before);
});
test('cursor prevents duplicate output and UTF-8 is preserved across chunks', async () => {
  const f = fixture(), r = await f.start(), p = [...f.processes.values()][0];
  const data = Buffer.from('你好');
  f.push(p, data.subarray(0, 2));
  let poll = await f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner);
  assert.equal(poll.output, '');
  f.push(p, data.subarray(2));
  poll = await f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner);
  assert.equal(poll.output, '你好');
  poll = await f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner);
  assert.equal(poll.output, '');
  assert.deepEqual(f.calls.filter(c => c.method === 'process/read').map(c => c.afterSeq), [null, 0, 1, 2]);
});
test('writes are serialized and every logical write receives an internal unique writeId', async () => {
  const f = fixture(), r = await f.start();
  const results = await Promise.all(['one', 'two', 'three'].map(chars => f.adapter.writeStdin({
    session_id: r.session_id, chars, yield_time_ms: 0}, owner)));
  assert.deepEqual(results.map(x => x.output), ['one', 'two', 'three']);
  const writes = f.calls.filter(x => x.method === 'process/write');
  assert.equal(new Set(writes.map(w => w.writeId)).size, 3);
  assert.deepEqual(writes.map(w => Buffer.from(w.chunk, 'base64').toString()), ['one', 'two', 'three']);
});
test('uncertain start retains recovery handle without replaying the command', async () => {
  const f = fixture({startError: new TransportFault()});
  const r = await f.adapter.callTool('exec_command', {cmd: 'side effect', yield_time_ms: 0}, owner);
  assert.equal(r.structuredContent.error, 'outcome_unknown');
  const sid = r.structuredContent.session_id; assert.ok(sid);
  await f.adapter.writeStdin({session_id: sid, yield_time_ms: 0}, owner);
  assert.equal(f.calls.filter(x => x.method === 'process/start').length, 1);
});
test('uncertain input is never resent; reads remain available but new writes are blocked', async () => {
  const f = fixture({writeError: new TransportFault()}), r = await f.start();
  await assert.rejects(f.adapter.writeStdin({session_id: r.session_id, chars: 'one'}, owner), /outcome_unknown/);
  await f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner);
  await assert.rejects(f.adapter.writeStdin({session_id: r.session_id, chars: 'two'}, owner), /outcome_unknown/);
  assert.equal(f.calls.filter(c => c.method === 'process/write').length, 1);
});
test('definite rejection differs from uncertain transport outcome', async () => {
  const f = fixture({startError: new RpcFault(-32602)});
  const r = await f.adapter.callTool('exec_command', {cmd: 'id'}, owner);
  assert.equal(r.structuredContent.error, 'executor_rejected'); assert.equal(r.structuredContent.uncertain, false);
  assert.equal(f.adapter.sessions.size, 0);
});
test('exit code 7 is a completed command, not an MCP transport error', async () => {
  const f = fixture(), r = await f.start(), p = [...f.processes.values()][0];
  f.push(p, 'out'); f.push(p, 'err', 'stderr'); p.exited = true; p.exitCode = 7;
  const output = await f.adapter.callTool('write_stdin', {session_id: r.session_id, yield_time_ms: 100}, owner);
  assert.equal(output.isError, undefined); assert.equal(output.structuredContent.exit_code, 7);
  assert.equal(output.structuredContent.output, 'outerr'); assert.equal(f.adapter.sessions.size, 0);
});
test('terminal result drains paginated output before removing session', async () => {
  const f = fixture(), r = await f.start(), p = [...f.processes.values()][0];
  f.push(p, 'one'); p.exited = true; p.exitCode = 0;
  const first = await f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner);
  assert.equal(first.session_id, r.session_id); assert.equal(first.exit_code, undefined);
  const last = await f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner);
  assert.equal(last.exit_code, 0); assert.equal(f.adapter.sessions.size, 0);
});
test('output budget stays bounded without evicting earlier command handles', async () => {
  const f=fixture(),r=await f.start();
  f.push([...f.processes.values()][0],'abcdefghij');
  const poll=await f.adapter.writeStdin({session_id:r.session_id,yield_time_ms:0,max_output_tokens:4},owner);
  assert.equal(poll.output,'abcd');assert.equal(poll.original_token_count,10);
  const later=await f.start();assert.notEqual(later.session_id,r.session_id);
  assert.ok(f.adapter.sessions.has(r.session_id));
});
test('more than 64 unpolled command handles do not block another conversation', async () => {
  const f=fixture(),handles=[];
  for(let i=0;i<96;i++){
    const r=await f.start();handles.push(r.session_id);
    const p=[...f.processes.values()].at(-1);f.push(p,'completed-'+i);p.exited=true;p.exitCode=0;
  }
  assert.equal(new Set(handles).size,96);assert.equal(f.adapter.sessions.size,96);
  const other=await f.adapter.execCommand({cmd:'cat',yield_time_ms:0},'bob:chat-1');
  assert.ok(other.session_id);assert.equal(f.adapter.sessions.size,97);
  const wrong=await f.adapter.callTool('write_stdin',{session_id:handles[0],chars:'',yield_time_ms:0},'bob:chat-1');
  assert.equal(wrong.structuredContent.error,'unknown_session');
  const first=await f.adapter.writeStdin({session_id:handles[0],chars:'',yield_time_ms:100},owner);
  assert.equal(first.output,'completed-0');assert.equal(first.exit_code,0);
  assert.ok(f.adapter.sessions.has(handles[95]));
  for(const id of handles.slice(1))await f.adapter.writeStdin({session_id:id,chars:'',yield_time_ms:100},owner);
  assert.equal(f.adapter.sessions.size,1);
});
test('retired command IDs do not impose a lifetime command-count ceiling', async () => {
  const f=fixture();
  // IDs remain non-reusable, but their accumulated count cannot reject work.
  for(let id=1;id<=100000;id++)f.adapter.usedIds.add(id);
  const r=await f.start();assert.ok(r.session_id);assert.ok(r.session_id>100000);
});
test('malformed executor output and execution failure are not success', async () => {
  const f = fixture(), r = await f.start();
  for (const reply of [
    {chunks: [], nextSeq: 1, exited: true, closed: true, exitCode: null},
    {chunks: [{seq: 1, stream: 'stdout', chunk: '!'}], nextSeq: 2, exited: false, closed: false},
    {chunks: [], nextSeq: 1, exited: false, closed: false, failure: 'private secret'}
  ]) {
    f.options.reply = reply;
    const out = await f.adapter.callTool('write_stdin', {session_id: r.session_id, yield_time_ms: 0}, owner);
    assert.equal(out.isError, true); assert.ok(!JSON.stringify(out).includes('private secret'));
  }
});
test('cleanup checks exit evidence instead of equating terminate acknowledgement with stop', async () => {
  const f = fixture(); await f.start();
  assert.deepEqual((await f.adapter.cleanup()).map(x => x.confirmed), [true]);
  assert.equal(f.adapter.sessions.size, 0);
});
test('RPC timeout rejects pending work and never retries a mutation', async () => {
  const channel = new EventEmitter(); let sends = 0;
  channel.send = () => sends++; channel.close = () => channel.emit('closed');
  const client = new RpcClient(channel, {timeoutMs: 10});
  await assert.rejects(client.request('process/start', {}), TransportFault);
  assert.equal(sends, 1); assert.equal(client.pending.size, 0); assert.equal(client.closed, true);
});
test('resume must preserve server session and provider identity', async () => {
  let n = 0;
  const conn = new ExecConnection(async () => ({
    request: async () => ({sessionId: ++n === 1 ? 'original' : 'replacement', environmentInfo: {providerId: 'p'}}),
    notify() {}, async close() {}
  }));
  await conn.initialize();
  await assert.rejects(conn.resume(), /session_lost/); assert.equal(conn.lost, true);
});
test('RPC errors never expose raw executor text', async () => {
  const channel = new EventEmitter(); channel.close = () => {};
  channel.send = wire => {
    const m = JSON.parse(wire);
    queueMicrotask(() => channel.emit('message', JSON.stringify({id: m.id, error: {code: -32602, message: 'PRIVATE'}})));
  };
  const client = new RpcClient(channel);
  await assert.rejects(client.request('x', {}), e => e instanceof RpcFault && !e.message.includes('PRIVATE'));
  await client.close();
});
test('websocket auth rejects plaintext remote URLs and credentials in URLs before connecting', async () => {
  for (const url of ['ws://example.com:1234', 'wss://token@example.com', 'wss://example.com/?token=x']) {
    await assert.rejects(websocketClient({url, token: 'secret'}), /invalid_transport_config/);
  }
});

test('authorization is checked again immediately before dispatch and before returning output', async () => {
  const f = fixture();
  let resolves = 0;
  const trusted = f.adapter.resolve;
  f.adapter.resolve = async (...args) => {
    if (++resolves === 2) throw new ExecError('access_denied');
    return trusted(...args);
  };
  await assert.rejects(f.start(), /session_unavailable/);
  assert.equal(f.calls.length, 0);
  f.adapter.resolve = trusted;
  const r = await f.start();
  const request = f.runtime.request.bind(f.runtime);
  f.runtime.request = async (method, params) => {
    const result = await request(method, params);
    if (method === 'process/read') f.allowed.delete(owner);
    return result;
  };
  await assert.rejects(f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner), /session_unavailable/);
});
test('output gaps, replayed chunks and regressing cursors fail explicitly', async () => {
  const f = fixture(), r = await f.start();
  for (const seq of [0, 2]) {
    f.options.reply = {chunks: [{seq, stream: 'stdout', chunk: 'eA=='}],
      nextSeq: 3, exited: false, closed: false};
    await assert.rejects(f.adapter.writeStdin({session_id: r.session_id, yield_time_ms: 0}, owner), /invalid_executor_response/);
  }
});
test('malformed start acknowledgement retains an uncertain handle instead of claiming success', async () => {
  const f = fixture(), request = f.runtime.request.bind(f.runtime);
  f.runtime.request = async (method, params) => {
    const r = await request(method, params);
    return method === 'process/start' ? {processId: 'wrong-process'} : r;
  };
  const r = await f.adapter.callTool('exec_command', {cmd: 'side effect'}, owner);
  assert.equal(r.structuredContent.error, 'outcome_unknown');
  assert.ok(r.structuredContent.session_id); assert.equal(r.structuredContent.uncertain, true);
});

test('gateway restart loses mapping rather than assigning the old ID to a new process', async () => {
  const f = fixture(), r = await f.start();
  const replacement = new ExecAdapter({resolve: f.adapter.resolve});
  await assert.rejects(replacement.writeStdin({session_id: r.session_id, chars: 'no replay'}, owner), /unknown_session/);
  assert.equal(f.calls.filter(c => c.method === 'process/start').length, 1);
  await f.adapter.cleanup();
});
test('missing executor rejects without hanging a stdio client', {timeout: 3000}, async () => {
  const {stdioClient} = await import('../rpc.mjs');
  const c = new ExecConnection(() => stdioClient({
    binary: '/nonexistent-styx-pilot-executor', cwd: '/tmp', env: {PATH: '/usr/bin:/bin'}, timeoutMs: 200
  }));
  await assert.rejects(c.initialize(), TransportFault);
});
test('a connection cannot initialize twice or replace its server session silently', async () => {
  const c = new ExecConnection(async () => ({
    request: async () => ({sessionId: 'one', environmentInfo: {providerId: 'fixed'}}),
    notify() {}, async close() {}
  }));
  await c.initialize();
  await assert.rejects(c.initialize(), /connection_busy/);
});

test('Codex terminal event sequence slots may separate valid stdout and stderr chunks', async () => {
  const f = fixture();
  const initial = await f.start();
  const original = f.runtime.request.bind(f.runtime);
  let reads = 0;
  f.runtime.request = async (method, params) => {
    if (method !== 'process/read') return original(method, params);
    reads++;
    if (reads === 1) return {
      chunks: [
        {seq: 1, stream: 'stdout', chunk: Buffer.from('out').toString('base64')},
        {seq: 3, stream: 'stderr', chunk: Buffer.from('err').toString('base64')}
      ],
      nextSeq: 5, exited: true, closed: true, exitCode: 7, failure: null
    };
    return {chunks: [], nextSeq: 5, exited: true, closed: true,
      exitCode: 7, failure: null};
  };
  const result = await f.adapter.writeStdin({
    session_id: initial.session_id, yield_time_ms: 200
  }, owner);
  assert.equal(result.output, 'outerr');
  assert.equal(result.exit_code, 7);
});

test('genuine output gaps exceeding proven terminal event slots remain rejected', async () => {
  const f = fixture();
  const initial = await f.start();
  const original = f.runtime.request.bind(f.runtime);
  f.runtime.request = async (method, params) => {
    if (method !== 'process/read') return original(method, params);
    return {
      chunks: [{seq: 5, stream: 'stdout', chunk: 'eA=='}],
      nextSeq: 6, exited: true, closed: true, exitCode: 7, failure: null
    };
  };
  await assert.rejects(
    f.adapter.writeStdin({session_id: initial.session_id, yield_time_ms: 0}, owner),
    /invalid_executor_response/
  );
});

test('exit before output EOF retains session and UTF-8 decoder until closed drain', async () => {
  const f=fixture(), initial=await f.start();
  const empty={chunks:[],nextSeq:2,exited:true,closed:false,exitCode:0,failure:null};
  f.options.reply=empty;
  const early=await f.adapter.writeStdin({session_id:initial.session_id,yield_time_ms:0},owner);
  assert.equal(early.session_id,initial.session_id);
  assert.equal(early.exit_code,undefined);
  const bytes=Buffer.from('你好');
  f.options.reply={...empty,chunks:[{seq:2,stream:'stdout',chunk:bytes.subarray(0,2).toString('base64')}],nextSeq:3};
  const partial=await f.adapter.writeStdin({session_id:initial.session_id,yield_time_ms:0},owner);
  assert.equal(partial.output,'');assert.equal(partial.session_id,initial.session_id);
  f.options.reply={...empty,chunks:[{seq:3,stream:'stdout',chunk:bytes.subarray(2).toString('base64')}],nextSeq:5,closed:true};
  const tail=await f.adapter.writeStdin({session_id:initial.session_id,yield_time_ms:0},owner);
  assert.equal(tail.output,'你好');assert.equal(tail.session_id,initial.session_id);
  f.options.reply={...empty,nextSeq:5,closed:true};
  const drained=await f.adapter.writeStdin({session_id:initial.session_id,yield_time_ms:0},owner);
  assert.equal(drained.exit_code,0);assert.equal(drained.output,'');
  assert.equal(f.adapter.sessions.size,0);
  assert.equal(f.calls.filter(c=>c.method==='process/start').length,1);
  assert.equal(f.calls.filter(c=>c.method==='process/write').length,0);
});
test('exited but open streams yield a retained session without a busy read loop', async () => {
  const f=fixture(),initial=await f.start(),before=f.calls.length;
  f.options.reply={chunks:[],nextSeq:2,exited:true,closed:false,exitCode:0,failure:null};
  const result=await f.adapter.writeStdin({session_id:initial.session_id,yield_time_ms:30},owner);
  assert.equal(result.session_id,initial.session_id);assert.equal(result.exit_code,undefined);
  const reads=f.calls.slice(before).filter(c=>c.method==='process/read');
  assert.ok(reads.length>=1&&reads.length<=8,'open streams must use bounded observation, not hot spin');
});
