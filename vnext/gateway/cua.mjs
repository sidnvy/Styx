import fs from 'node:fs';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const CONTRACT=JSON.parse(fs.readFileSync(new URL('./cua-portable-0.36.0.json',import.meta.url),'utf8'));
const COMMON_CUA_TOOLS = Object.freeze([
  'list_apps', 'list_windows', 'get_window_state', 'get_desktop_state',
  'click', 'set_value', 'type_text', 'press_key', 'scroll', 'verify_state'
]);
const READ_TOOLS = new Set([
  'list_apps', 'list_windows', 'get_window_state', 'get_desktop_state', 'verify_state'
]);
const plain = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const failure = (code,uncertain=false) => {
  const data={error:code,...(uncertain?{uncertain:true}:{})};
  return {isError:true,structuredContent:data,
    content:[{type:'text',text:JSON.stringify(data)}]};
};
const sessionKey = (owner, id) => JSON.stringify([owner, id]);

function requireToken(path) {
  const info = fs.statSync(path);
  if (!info.isFile() || (info.mode & 0o077)) throw Error('computer_token_permissions');
  const token = fs.readFileSync(path, 'utf8').trim();
  if (token.length < 32 || /\s/.test(token)) throw Error('computer_token_invalid');
  return token;
}

export async function connectCuaMcp(target,{relay}={}) {
  const cfg = target.computer;
  if (!cfg || cfg.enabled !== true) throw Error('computer_disabled');
  const client = new Client({name:'styx-cua-provider', version:'0.1.0'}, {capabilities:{}});
  let transport;
  if (cfg.transport === 'stdio') {
    transport = new StdioClientTransport({
      command: cfg.binary,
      args: ['mcp', ...(cfg.socket ? ['--socket',cfg.socket] : [])],
      env: {...process.env, ...(cfg.env ?? {})},
      cwd: target.cwd
    });
  } else if (cfg.transport === 'mcp-http') {
    const url = new URL(cfg.url);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' &&
      ['localhost','127.0.0.1','::1'].includes(url.hostname))) {
      throw Error('computer_http_requires_tls');
    }
    transport = new StreamableHTTPClientTransport(url, {
      requestInit: {headers:{Authorization:'Bearer ' + requireToken(cfg.token_file)}, redirect:'error'}
    });
  } else if(cfg.transport === 'outbound') {
    if (!relay) throw Error('computer_outbound_relay_missing');
    transport=await relay.acquireComputer(target);
    client.styxTransport=transport;
  } else {
    throw Error('unsupported_computer_transport');
  }
  try {
    await client.connect(transport);
    return client;
  } catch (e) {
    await transport?.close().catch(() => {});
    throw e;
  }
}

function wrapTool(tool) {
  const schema = structuredClone(tool.inputSchema);
  if (!plain(schema) || schema.type !== 'object' || !plain(schema.properties) ||
      Object.hasOwn(schema.properties, 'environment_id')) throw Error('invalid_cua_schema');
  // Every model-facing MCP connection receives a separate Cua transport
  // lease; the user cannot override its implicit native session name.
  delete schema.properties.session;
  schema.properties.environment_id = {type:'string', description:
    'Styx execution environment; defaults to the configured default when omitted.'};
  return {
    name:tool.name, title:tool.title || tool.name,
    description:tool.description,
    inputSchema:schema,
    ...(tool.annotations ? {annotations:tool.annotations} : {})
  };
}

// The native Cua MCP server is the schema authority. Each MCP session has its
// own Cua MCP Client, so Cua's implicit session and element token cache cannot
// be shared across unrelated ChatGPT sessions.
export class CuaProvider {
  constructor({registry, relay, connect, toolNames=COMMON_CUA_TOOLS,
    manifest=CONTRACT, idleMs=5*60*1000, reapIntervalMs=30*1000,
    clock=()=>Date.now()} = {}) {
    if (!registry || typeof registry.resolve !== 'function' ||
        (connect!==undefined && typeof connect !== 'function'))
      throw TypeError('Cua registry and connector required');
    this.registry = registry;
    this.connect = connect ?? (target=>connectCuaMcp(target,{relay}));
    this.toolNames = new Set(toolNames);
    this.manifest=manifest;
    this.schema=(manifest.tools??[]).filter(t=>this.toolNames.has(t.name))
      .map(t=>wrapTool(t));
    if (!Number.isSafeInteger(idleMs) || idleMs<1000 ||
      !Number.isSafeInteger(reapIntervalMs) || reapIntervalMs<100 ||
      typeof clock !== 'function') throw TypeError('Invalid native Cua lease policy');
    // Cua v0.36.0 defaults to five idle minutes per implicit session.
    // Styx releases unclaimed WebSocket *resources* after that same window;
    // it never sends a new GUI action on behalf of the model.
    this.idleMs=idleMs;this.clock=clock;
    this.sessions = new Map(); this.pending = new Map();
    this.stopped = false;
    this.reaper=setInterval(()=>{void this.reapIdle()},reapIntervalMs);
    this.reaper.unref?.();
  }

  #target(environmentId) {
    const target = this.registry.resolve(environmentId);
    if (target.computer?.enabled !== true) throw Error('computer_not_available');
    return target;
  }

  async #get(owner, target) {
    if (this.stopped) throw Error('computer_provider_closed');
    if (typeof owner !== 'string' || !owner) throw Error('invalid_owner');
    const key=sessionKey(owner, target.id);
    const current = this.sessions.get(key);
    if (current) {
      if(current.client.styxTransport?.closed){
        this.sessions.delete(key);
        await current.client.close().catch(()=>{});
        throw Error('computer_session_lost');
      }
      if (current.generation !== target.generation) {
        this.sessions.delete(key);
        await current.client.close().catch(() => {});
        throw Error('computer_generation_changed');
      }
      current.lastUsed=this.clock();
      return current.client;
    }
    const opening = this.pending.get(key);
    if (opening) return opening;
    const promise = (async () => {
      const client = await this.connect(target,owner);
      if (this.stopped) {await client.close(); throw Error('computer_provider_closed');}
      const identity=client.getServerVersion?.();
      if (!identity || identity.name!==this.manifest.driver ||
        identity.version!==this.manifest.version) {
        await client.close();
        throw Error('computer_version_mismatch');
      }
      // Re-read admission after an asynchronous connection handshake.
      const now = this.#target(target.id);
      if (now.generation !== target.generation) {
        await client.close();throw Error('computer_generation_changed');
      }
      const snapshot = {generation:target.generation,client,active:0,
        lastUsed:this.clock()};
      this.sessions.set(key,snapshot);
      return client;
    })();
    this.pending.set(key,promise);
    try {return await promise;} finally {
      if (this.pending.get(key) === promise) this.pending.delete(key);
    }
  }

  async listTools() {
    return this.schema;
  }

  async callTool(name,args={},owner) {
    if (!this.toolNames.has(name)) return failure('unknown_tool');
    if (!plain(args)) return failure('invalid_arguments');
    const {environment_id,...nativeArgs}=args;
    if (environment_id!==undefined && (typeof environment_id!=='string' ||
      !environment_id)) return failure('invalid_environment');
    const tool=this.schema.find(x=>x.name===name);
    if (!tool) return failure('unknown_tool');
    const permitted=tool.inputSchema.properties;
    if (Object.keys(nativeArgs).some(k=>!Object.hasOwn(permitted,k)) ||
      (tool.inputSchema.required||[]).some(k=>!Object.hasOwn(nativeArgs,k)))
      return failure('invalid_arguments');
    let dispatched=false;
    try {
      const target=this.#target(environment_id);
      const client=await this.#get(owner,target);
      const current=this.sessions.get(sessionKey(owner,target.id));
      if(!current || current.client!==client) throw Error('computer_session_lost');
      current.active++;
      current.lastUsed=this.clock();
      try {
        // The Cua server validates the official native input schema.
        // Model arguments cannot override the transport lease or Host identity.
        dispatched=true;
        return await client.callTool({name,arguments:nativeArgs});
      } finally {
        current.active--;
        current.lastUsed=this.clock();
      }
    } catch (e) {
      const code=e?.message;
      if (['environment_not_found','environment_access_denied','computer_not_available',
        'computer_generation_changed','computer_version_mismatch',
        'computer_session_lost','invalid_owner','computer_provider_closed',
        'computer_slots_busy','computer_host_offline'].includes(code))
        return failure(code);
      // Before dispatch, nothing could have mutated. After dispatch an
      // action transport failure is ambiguous; never replay automatically.
      return failure('computer_transport_unavailable',dispatched&&!READ_TOOLS.has(name));
    }
  }

  async reapIdle() {
    if (this.stopped)return;
    const stale=[];
    for (const [key,item] of this.sessions) {
      if(item.active===0 && this.clock()-item.lastUsed>=this.idleMs) {
        this.sessions.delete(key);
        stale.push(item.client);
      }
    }
    await Promise.allSettled(stale.map(client=>client.close()));
  }

  async closeOwner(owner) {
    const prefix=JSON.stringify([owner]).slice(0,-1)+',';
    await Promise.allSettled([...this.sessions.entries()].filter(([k])=>k.startsWith(prefix))
      .map(async ([key,item])=>{this.sessions.delete(key);await item.client.close();}));
  }
  async close() {
    this.stopped=true;
    clearInterval(this.reaper);
    await Promise.allSettled([...this.pending.values()]);
    await Promise.allSettled([...this.sessions.values()].map(x=>x.client.close()));
    this.sessions.clear();this.pending.clear();
  }
}
