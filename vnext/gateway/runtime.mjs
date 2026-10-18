import fs from 'node:fs';
import {requirePrivateFile} from '../shared/private-file.mjs';
import {ExecConnection, stdioClient, websocketClient} from '../packages/styx-exec-adapter/rpc.mjs';

// Runtime sessions are independent of MCP HTTP requests. No implicit restart or
// replay when a connection is lost: the original process may have mutated state.
export class RuntimePool {
  constructor(registry, {connect,relay} = {}) {
    this.registry = registry;
    this.connect = connect ?? (target=>createConnection(target,{relay}));
    this.pending = new Map();
  }
  async get(target) {
    const key = target.id + ':' + target.generation;
    let promise = this.pending.get(key);
    if(promise) {
      const existing=await promise;
      if(!existing.lost && !existing.client?.closed) return existing;
      // A lost executor session is never resumed implicitly. A new command
      // may use a freshly authenticated outbound Host connection; old process
      // handles remain invalid.
      existing.lost=true;
      if(this.pending.get(key)===promise) this.pending.delete(key);
      return this.get(target);
    }
    if (!promise) {
      promise = this.connect(target).then(async runtime => {
        if (!runtime.sessionId) await runtime.initialize();
        return runtime;
      });
      this.pending.set(key, promise);
      promise.catch(() => { if (this.pending.get(key) === promise) this.pending.delete(key); });
    }
    return promise;
  }
  async binding(environmentId) {
    const target = this.registry.resolve(environmentId);
    const runtime = await this.get(target);
    return {
      id: target.id, generation: target.generation,
      platform: target.platform, cwd: target.cwd, shell: target.shell,
      shells: target.shells, env: target.env ?? {}, runtime
    };
  }
  async close() {
    const all = [...this.pending.values()];
    this.pending.clear();
    await Promise.allSettled(all.map(async p => (await p).close()));
  }
}
async function createConnection(target,{relay}={}) {
  const t = target.exec;
  if(t.transport === 'outbound') {
    if(!relay) throw Error('outbound_relay_not_attached');
    return new ExecConnection(()=>relay.acquire(target));
  }
  if (t.transport === 'stdio') {
    const home = t.home ?? process.env.HOME;
    return new ExecConnection(() => stdioClient({
      binary: t.binary, cwd: target.cwd,
      env: {...process.env, ...(home ? {HOME: home} : {}), ...t.env},
      timeoutMs: t.timeout_ms ?? 35000
    }));
  }
  let token;
  if (t.token_file) {
    requirePrivateFile(t.token_file);
    token = fs.readFileSync(t.token_file, 'utf8').trim();
  }
  return new ExecConnection(() => websocketClient({
    url: t.url, token, timeoutMs: t.timeout_ms ?? 35000,
    allowUnauthenticatedLoopback: t.allow_unauthenticated_loopback === true
  }));
}
