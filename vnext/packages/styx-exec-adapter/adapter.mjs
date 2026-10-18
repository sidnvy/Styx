import {randomInt, randomUUID} from 'node:crypto';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {StringDecoder} from 'node:string_decoder';
import {ExecError, RpcFault} from './errors.mjs';
import {tools} from './schema.mjs';

function fail(code, session_id, uncertain = false) { throw new ExecError(code, {session_id, uncertain}); }
function validate(name, args) {
  const tool = tools.find(t => t.name === name);
  if (!tool) fail('unknown_tool');
  if (!args || Object.getPrototypeOf(args) !== Object.prototype) fail('invalid_arguments');
  for (const key of Object.keys(args)) {
    const type = tool.inputSchema.properties[key]?.type;
    if (!type || typeof args[key] !== type ||
        (type === 'number' && !Number.isSafeInteger(args[key])) ||
        (type === 'string' && args[key].includes('\0'))) fail('invalid_arguments');
  }
  for (const key of tool.inputSchema.required) if (!(key in args)) fail('invalid_arguments');
  if ('session_id' in args && args.session_id < 1) fail('invalid_arguments');
  if (args.cmd !== undefined && (!args.cmd.length || Buffer.byteLength(args.cmd) > 65536)) fail('invalid_arguments');
  if (args.chars !== undefined && Buffer.byteLength(args.chars) > 65536) fail('invalid_arguments');
  if (args.max_output_tokens !== undefined && (args.max_output_tokens < 1 || args.max_output_tokens > 10000)) fail('invalid_arguments');
  if (args.yield_time_ms !== undefined && (args.yield_time_ms < 0 || args.yield_time_ms > 30000)) fail('invalid_arguments');
  return args;
}
const identity = binding => JSON.stringify([binding.id, binding.generation, binding.runtime.sessionId]);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const nativePath = platform => platform === 'win32' ? path.win32 : path.posix;
function cwdUri(location, platform) {
  if (platform === 'win32') {
    if (!/^[a-zA-Z]:\\/.test(location)) fail('invalid_workdir');
    // RFC8089 Windows drive URI, without interpreting a Windows path using
    // the Gateway's local POSIX host semantics.
    return new URL('file:///' + location.replace(/\\/g, '/')).href;
  }
  return pathToFileURL(location).href;
}
// Codex Exec Server 0.163.0 process/start.env is an exact environment, NOT
// inherited by default. Use its upstream envPolicy contract to preserve only
// benign platform/session variables on the native Host. Never forward Host
// bearer credentials, SSH sockets, arbitrary user environment or Gateway env.
const TRUSTED_UNIX_ENV = Object.freeze([
  'PATH','HOME','SHELL','USER','LOGNAME','TMPDIR','TMP','TEMP',
  'LANG','LC_ALL','LC_CTYPE','TZ',
  'WAYLAND_DISPLAY','DISPLAY','XDG_RUNTIME_DIR','XDG_SESSION_TYPE',
  'XDG_CURRENT_DESKTOP','DBUS_SESSION_BUS_ADDRESS','XAUTHORITY'
]);
const TRUSTED_WINDOWS_ENV = Object.freeze([
  'Path','PATHEXT','SystemRoot','WinDir','ComSpec','USERNAME','USERPROFILE',
  'HOMEDRIVE','HOMEPATH','APPDATA','LOCALAPPDATA','TEMP','TMP',
  'PSModulePath','LANG'
]);
export function codexEnvPolicy(platform) {
  if (!['linux','darwin','win32'].includes(platform)) fail('unsupported_platform');
  return {
    inherit: 'all',
    ignoreDefaultExcludes: false,
    exclude: [],
    set: {},
    includeOnly: platform==='win32' ? [...TRUSTED_WINDOWS_ENV] : [...TRUSTED_UNIX_ENV]
  };
}

function commandArgs(platform, shell, command, login) {
  const name = nativePath(platform).basename(shell).toLowerCase();
  if (platform === 'win32') {
    if (!['powershell.exe','pwsh.exe','pwsh'].includes(name)) fail('unsupported_shell');
    return [shell, '-NoLogo', ...(login === true ? [] : ['-NoProfile']),
      '-NonInteractive', '-Command', command];
  }
  if (!['sh', 'bash', 'zsh'].includes(name)) fail('unsupported_shell');
  return [shell, login === false ? '-c' : '-lc', command];
}


export class ExecAdapter {
  constructor({resolve, maxSessions = 64, maxRetainedIds = 100000}) {
    if (typeof resolve !== 'function') throw new TypeError('Trusted resolver required');
    this.resolve = resolve; this.maxSessions = maxSessions; this.maxRetainedIds = maxRetainedIds;
    this.sessions = new Map(); this.usedIds = new Set();
  }
  async binding(environment_id, owner) {
    if (typeof owner !== 'string' || !owner) fail('invalid_owner');
    const b = await this.resolve(environment_id, owner);
    if (!b || !b.id || !b.generation || !b.runtime?.sessionId || b.runtime.lost ||
        !['linux','darwin','win32'].includes(b.platform) ||
        !nativePath(b.platform).isAbsolute(b.cwd) ||
        !nativePath(b.platform).isAbsolute(b.shell) || !Array.isArray(b.shells))
      fail('execution_context_unavailable');
    return b;
  }
  allocate() {
    if (this.sessions.size >= this.maxSessions || this.usedIds.size >= this.maxRetainedIds) fail('session_capacity');
    let id; do { id = randomInt(1, 2 ** 48); } while (this.usedIds.has(id));
    this.usedIds.add(id); return id;
  }
  async execCommand(raw, owner) {
    const a = validate('exec_command', raw);
    const b = await this.binding(a.environment_id, owner);
    const shell = a.shell ?? b.shell;
    if (!b.shells.includes(shell)) fail('unsupported_shell');
    const cwd = a.workdir ? nativePath(b.platform).resolve(b.cwd, a.workdir) : b.cwd;
    // Perform all deterministic validation before a remote mutation is possible.
    const argv = commandArgs(b.platform,shell,a.cmd,a.login);
    const cwdFileUri = cwdUri(cwd,b.platform);
    const id = this.allocate();
    const record = {id, owner, environment: b.id, binding: identity(b), runtime: b.runtime,
      process: randomUUID(), cursor: null, state: 'starting', queue: Promise.resolve(),
      decoders: new Map(), terminalSeqSlots: 0,
      uncertainInput: false, tty: a.tty ?? false};
    this.sessions.set(id, record);
    return this.serial(record, async () => {
      const began = performance.now();
      try { await this.owned(id, owner); }
      catch (e) { this.sessions.delete(id); throw e; }
      try {
        const started = await b.runtime.request('process/start', {
          processId: record.process, argv,
          cwd: cwdFileUri, env: {...b.env}, envPolicy: codexEnvPolicy(b.platform),
          tty: record.tty, pipeStdin: !record.tty,
          arg0: null, ...(b.sandbox ? {sandbox: b.sandbox} : {})
        });
        if (started?.processId !== record.process) { record.state = 'start_unknown'; fail('outcome_unknown', id, true); }
        record.state = 'running';
      } catch (e) {
        if (e instanceof RpcFault) { this.sessions.delete(id); fail('executor_rejected'); }
        record.state = 'start_unknown'; fail('outcome_unknown', id, true);
      }
      return this.read(record, a, began, a.yield_time_ms ?? 10000);
    });
  }
  serial(record, task) {
    const next = record.queue.then(task);
    record.queue = next.catch(() => {});
    return next;
  }
  async owned(id, owner) {
    const r = this.sessions.get(id);
    if (!r || r.owner !== owner) fail('unknown_session');
    let b;
    try { b = await this.binding(r.environment, owner); }
    catch { if (r.runtime.lost) { r.state = 'lost'; fail('session_lost', id); } fail('session_unavailable', id); }
    if (r.runtime !== b.runtime || r.binding !== identity(b)) { r.state = 'lost'; fail('session_lost', id); }
    if (r.runtime.lost || r.state === 'lost') fail('session_lost', id);
    return r;
  }
  async writeStdin(raw, owner) {
    const a = validate('write_stdin', raw);
    const r = await this.owned(a.session_id, owner);
    return this.serial(r, async () => {
      await this.owned(a.session_id, owner); // Recheck after queued operations.
      const began = performance.now(), chars = a.chars ?? '';
      if (chars) {
        if (r.uncertainInput || r.state === 'start_unknown') fail('outcome_unknown', r.id, true);
        try {
          const reply = await r.runtime.request('process/write', {
            processId: r.process, writeId: randomUUID(), chunk: Buffer.from(chars).toString('base64')
          });
          if (reply?.status !== 'accepted') fail('stdin_not_accepted', r.id);
        } catch (e) {
          if (e instanceof RpcFault || e.code === 'stdin_not_accepted') throw e;
          r.uncertainInput = true; fail('outcome_unknown', r.id, true);
        }
      }
      const wait = a.yield_time_ms ?? (chars ? 250 : 5000);
      return this.read(r, a, began, wait);
    });
  }
  async read(r, args, began, waitMs) {
    const deadline = performance.now() + waitMs, chunks = [];
    let size = 0, final, drained = false;
    const tokens = args.max_output_tokens ?? 10000;
    do {
      await this.owned(r.id, r.owner);
      let reply;
      try {
        reply = await r.runtime.request('process/read', {
          processId: r.process, afterSeq: r.cursor, maxBytes: 65536,
          waitMs: Math.max(0, Math.min(1000, Math.ceil(deadline - performance.now())))
        });
      } catch (e) {
        if (e.code === 'session_lost') { r.state = 'lost'; fail('session_lost', r.id); }
        if (e instanceof RpcFault && r.state === 'start_unknown') fail('outcome_unknown', r.id, true);
        fail('read_unavailable', r.id);
      }
      await this.owned(r.id, r.owner);
      const decoded = this.decode(reply, r);
      if (reply.failure !== null && reply.failure !== undefined) fail('execution_failed', r.id);
      for (const bytes of decoded) { chunks.push(bytes); size += bytes.length; }
      final = reply;
      if (reply.exited && reply.chunks.length === 0) { drained = true; break; }
      if (size >= tokens || (!reply.exited && decoded.length > 0)) break;
      if (reply.exited) continue;
      const remaining = deadline - performance.now();
      if (remaining > 0) await delay(Math.min(10, remaining));
    } while (performance.now() < deadline);
    if (final.closed && !final.exited) fail('outcome_unknown', r.id, true);
    if (drained) {
      for (const decoder of r.decoders.values()) {
        const tail = decoder.end(); if (tail) chunks.push(tail);
      }
      this.sessions.delete(r.id); r.state = 'exited';
    } else if (r.state === 'start_unknown') {
      // process/read proves the named process exists. It never replays start.
      r.state = 'running';
    }
    const full = chunks.join('');
    // One UTF-8 byte per requested token is conservative even for byte-fallback tokenizers.
    const bytes = Buffer.from(full), truncated = bytes.length > tokens;
    const output = truncated ? new StringDecoder('utf8').write(bytes.subarray(0, tokens)) : full;
    return {chunk_id: randomUUID(), wall_time_seconds: (performance.now() - began) / 1000,
      output, ...(truncated ? {original_token_count: bytes.length} : {}),
      ...(drained ? {exit_code: final.exitCode} : {session_id: r.id})};
  }
  decode(reply, r) {
    const invalid = () => fail('invalid_executor_response', r.id);
    if (!reply || !Array.isArray(reply.chunks) || typeof reply.exited !== 'boolean' ||
        typeof reply.closed !== 'boolean' || !Number.isSafeInteger(reply.nextSeq) ||
        reply.nextSeq < 1 || (r.cursor !== null && reply.nextSeq < r.cursor + 1) ||
        (reply.exited && !Number.isSafeInteger(reply.exitCode))) invalid();
    let previous = r.cursor === null ? 0 : r.cursor;
    let terminalSeqSlots = r.terminalSeqSlots ?? 0;
    const decoded = [];
    // Codex numbers process/exited and process/closed in the SAME sequence
    // stream as stdout/stderr/PTY output. Those terminal events are not
    // included in process/read.chunks, so valid output seq values need not be
    // contiguous. Never treat more gaps as legitimate than the terminal
    // events that the response independently confirms.
    for (const c of reply.chunks) {
      if (!Number.isSafeInteger(c.seq) || c.seq <= previous || c.seq >= reply.nextSeq ||
          !['stdout', 'stderr', 'pty'].includes(c.stream) || typeof c.chunk !== 'string') invalid();
      const b = Buffer.from(c.chunk, 'base64');
      if (b.toString('base64') !== c.chunk) invalid();
      terminalSeqSlots += c.seq - previous - 1;
      previous = c.seq;
    }
    terminalSeqSlots += reply.nextSeq - 1 - previous;
    if (terminalSeqSlots > Number(reply.exited) + Number(reply.closed)) invalid();
    // Validate the full response before advancing cursors or decoder state.
    for (const c of reply.chunks) {
      let decoder = r.decoders.get(c.stream);
      if (!decoder) { decoder = new StringDecoder('utf8'); r.decoders.set(c.stream, decoder); }
      decoded.push(decoder.write(Buffer.from(c.chunk, 'base64')));
    }
    r.cursor = reply.nextSeq - 1;
    r.terminalSeqSlots = terminalSeqSlots;
    return decoded;
  }
  async cleanup() {
    const results = [];
    for (const r of this.sessions.values()) {
      await r.queue;
      let confirmed = false;
      try {
        // terminate only requests cancellation; a successful RPC ack is NOT
        // independent evidence that the OS process has exited.
        await r.runtime.request('process/terminate', {processId: r.process});
        const deadline = performance.now() + 2000;
        do {
          const final = await r.runtime.request('process/read', {
            processId: r.process, afterSeq: null, maxBytes: 1,
            waitMs: Math.max(0, Math.min(300, Math.ceil(deadline - performance.now())))
          });
          if (final.exited === true || final.closed === true) {
            confirmed = true;
            break;
          }
          if (performance.now() < deadline) await delay(20);
        } while (performance.now() < deadline);
      } catch {
        // Unknown termination is never silently converted to a success.
      }
      results.push({session_id: r.id, confirmed});
    }
    this.sessions.clear();
    return results;
  }
  async callTool(name, args, owner) {
    try {
      const result = name === 'exec_command' ? await this.execCommand(args, owner) :
        name === 'write_stdin' ? await this.writeStdin(args, owner) : fail('unknown_tool');
      return {content: [{type: 'text', text: JSON.stringify(result)}], structuredContent: result};
    } catch (error) {
      const e = error instanceof ExecError ? error : new ExecError('internal_error');
      const result = {error: e.code, ...(e.session_id ? {session_id: e.session_id} : {}), uncertain: e.uncertain};
      return {isError: true, content: [{type: 'text', text: JSON.stringify(result)}], structuredContent: result};
    }
  }
}
