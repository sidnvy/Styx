import {spawn} from 'node:child_process';
import {EventEmitter} from 'node:events';
import {once} from 'node:events';
import WebSocket from 'ws';
import {ExecError, RpcFault, TransportFault} from './errors.mjs';

const MAX_FRAME = 2 * 1024 * 1024;
export class RpcClient {
  constructor(channel, {timeoutMs = 35000} = {}) {
    this.channel = channel; this.timeoutMs = timeoutMs; this.pending = new Map(); this.seq = 0;
    this.closed = false;
    channel.on('message', bytes => {
      try {
        if (Buffer.byteLength(bytes) > MAX_FRAME) throw Error();
        const m = JSON.parse(String(bytes));
        if (!m || typeof m !== 'object' || Array.isArray(m)) throw Error();
        if (m.method && m.id === undefined) return; // Output is consumed via cursor RPC.
        const pending = this.pending.get(m.id);
        if (!pending) return;
        if (Object.hasOwn(m, 'result') === Object.hasOwn(m, 'error')) throw Error();
        this.pending.delete(m.id); clearTimeout(pending.timer);
        if (m.error) pending.reject(new RpcFault(m.error.code));
        else pending.resolve(m.result);
      } catch { this.fail(); channel.close(); }
    });
    channel.on('closed', () => this.fail());
  }
  fail() {
    this.closed = true;
    for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new TransportFault()); }
    this.pending.clear();
  }
  notify(method, params) {
    if (this.closed) throw new TransportFault();
    try { this.channel.send(JSON.stringify({method, params})); }
    catch { this.fail(); throw new TransportFault(); }
  }
  request(method, params) {
    if (this.closed) return Promise.reject(new TransportFault());
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.fail(); this.channel.close(); }, this.timeoutMs);
      this.pending.set(id, {resolve, reject, timer});
      try { this.channel.send(JSON.stringify({id, method, params})); }
      catch { this.fail(); this.channel.close(); }
    });
  }
  async close() { this.fail(); await this.channel.close(); }
}

export async function stdioClient({binary, cwd, env, timeoutMs}) {
  const c = new EventEmitter();
  const child = spawn(binary, ['exec-server', '--listen', 'stdio://'], {
    cwd, env, stdio: ['pipe', 'pipe', 'pipe']
  });
  let buffer = Buffer.alloc(0);
  c.send = text => child.stdin.write(text + '\n');
  child.stderr.resume(); // Never log arbitrary executor diagnostics or credentials.
  const exited = new Promise(resolve => child.once('close', resolve));
  child.on('error', () => c.emit('closed'));
  child.stdin.on('error', () => c.emit('closed'));
  child.stdout.on('data', bytes => {
    buffer = Buffer.concat([buffer, bytes]);
    let i;
    while ((i = buffer.indexOf(10)) >= 0) {
      const line = buffer.subarray(0, i); buffer = buffer.subarray(i + 1);
      c.emit('message', line);
    }
    if (buffer.length > MAX_FRAME) { c.emit('closed'); child.kill(); }
  });
  child.on('exit', () => c.emit('closed'));
  c.close = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.stdin.end();
    let timer;
    await Promise.race([exited, new Promise(resolve => {
      timer = setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 2000);
    })]);
    clearTimeout(timer);
    await exited;
  };
  return new RpcClient(c, {timeoutMs});
}

export async function websocketClient({url, token, timeoutMs, allowUnauthenticatedLoopback = false}) {
  const parsed = new URL(url);
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(parsed.hostname);
  if (!['ws:', 'wss:'].includes(parsed.protocol) || parsed.username || parsed.password ||
      parsed.search || parsed.hash || (!loopback && parsed.protocol !== 'wss:') ||
      (!token && !(loopback && allowUnauthenticatedLoopback)))
    throw new ExecError('invalid_transport_config');
  const c = new EventEmitter();
  const ws = new WebSocket(url, {
    headers: token ? {Authorization: 'Bearer ' + token} : {},
    maxPayload: MAX_FRAME, handshakeTimeout: 5000, followRedirects: false
  });
  ws.on('error', () => c.emit('closed'));
  try { await once(ws, 'open'); }
  catch { ws.terminate(); throw new TransportFault(); }
  ws.on('message', bytes => c.emit('message', bytes));
  ws.on('close', () => c.emit('closed'));
  c.send = text => { if (ws.readyState !== WebSocket.OPEN) throw Error(); ws.send(text); };
  c.close = async () => {
    if (ws.readyState === WebSocket.CLOSED) return;
    const closed = once(ws, 'close').catch(() => {});
    ws.terminate(); await closed;
  };
  return new RpcClient(c, {timeoutMs});
}

export class ExecConnection {
  constructor(factory) { this.factory = factory; this.client = null; this.sessionId = null; this.lost = false; }
  async initialize(resume = false) {
    if (this.lost) throw new ExecError('session_lost');
    if (this.connecting || (!resume && this.sessionId)) throw new ExecError('connection_busy');
    this.connecting = true;
    let client;
    try {
      client = await this.factory();
      const r = await client.request('initialize', {
        clientName: 'styx-isolated-prototype', ...(resume ? {resumeSessionId: this.sessionId} : {})
      });
      if (typeof r?.sessionId !== 'string' || !r.sessionId ||
          (resume && (r.sessionId !== this.sessionId ||
            r.environmentInfo?.providerId !== this.info?.providerId))) {
        this.lost = true; throw new ExecError('session_lost');
      }
      client.notify('initialized', {});
      this.client = client; this.sessionId = r.sessionId; this.info = r.environmentInfo;
      return this;
    } catch (e) {
      await client?.close();
      if (resume && e instanceof RpcFault) { this.lost = true; throw new ExecError('session_lost'); }
      throw e;
    } finally { this.connecting = false; }
  }
  async resume() {
    if (!this.sessionId) throw new ExecError('session_lost');
    await this.client?.close();
    return this.initialize(true); // Explicit read-side reconciliation; no RPC replay.
  }
  request(method, params) {
    if (this.lost) return Promise.reject(new ExecError('session_lost'));
    if (!this.client) return Promise.reject(new TransportFault());
    return this.client.request(method, params);
  }
  async disconnect() { await this.client?.close(); }
  async close() { await this.disconnect(); }
}
