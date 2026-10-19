import fs from 'node:fs';
import {randomUUID} from 'node:crypto';
import {requirePrivateFile} from '../shared/private-file.mjs';
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
const RECOVERY = Object.freeze({
  default_environment_required: 'Call list_execution_environments and pass the selected environment_id, or choose a default device in Styx Settings.',
  computer_slots_busy: 'The desktop connection is temporarily unavailable. Retry after the current operation finishes.',
  computer_snapshot_required: 'Take a fresh get_window_state or get_desktop_state snapshot in this conversation before acting. Desktop observations from another connection cannot be reused.',
  computer_queue_full: 'The desktop has too many pending operations. Wait for the current operations to finish, then retry.',
  computer_host_offline: 'Open Styx on the selected device and check its connection in Settings.'
});
const failure = (code,uncertain=false) => {
  const data={error:code,...(RECOVERY[code]?{recovery:RECOVERY[code]}:{}),...(uncertain?{uncertain:true}:{})};
  return {isError:true,structuredContent:data,
    content:[{type:'text',text:JSON.stringify(data)}]};
};

function requireToken(path) {
  requirePrivateFile(path);
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
  // Each authenticated owner receives a private native session name on the
  // shared device transport. The model cannot choose or override that name.
  delete schema.properties.session;
  if (schema.required) schema.required=schema.required.filter(name=>name!=='session');
  schema.properties.environment_id = {type:'string', description:
    'Device from list_execution_environments. Pass its environment_id unless a default device has been configured.'};
  return {
    name:tool.name, title:tool.title || tool.name,
    description:tool.description,
    inputSchema:schema,
    ...(tool.annotations ? {annotations:tool.annotations} : {})
  };
}

// A device has one transport, but each authenticated MCP owner has a separate
// native Cua session label plus gateway-enforced snapshot ownership. Operations
// queue briefly; connections do
// not reserve the desktop for the lifetime of a conversation.
export class CuaProvider {
  constructor({registry, relay, connect, toolNames=COMMON_CUA_TOOLS,
    manifest=CONTRACT, idleMs=5*60*1000, reapIntervalMs=30*1000,
    clock=()=>Date.now(), maxQueue=64} = {}) {
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
      typeof clock !== 'function' || !Number.isSafeInteger(maxQueue) || maxQueue<1) throw TypeError('Invalid native Cua lease policy');
    // Retire idle shared transport resources without reserving the desktop
    // for any owner. Active and queued operations prevent idle retirement.
    this.idleMs=idleMs;this.clock=clock;this.maxQueue=maxQueue;
    this.sessions = new Map(); this.pending = new Map();
    this.ownerStates = new Map();
    this.stopped = false;
    this.reaper=setInterval(()=>{void this.reapIdle()},reapIntervalMs);
    this.reaper.unref?.();
  }

  #target(environmentId) {
    const target = this.registry.resolve(environmentId);
    if (target.computer?.enabled !== true) throw Error('computer_not_available');
    return target;
  }

  async #get(target) {
    if (this.stopped) throw Error('computer_provider_closed');
    const key=target.id;
    const current=this.sessions.get(key);
    if (current) {
      if (current.client.styxTransport?.closed || current.generation!==target.generation) {
        this.sessions.delete(key);
        await current.client.close().catch(()=>{});
        throw Error(current.generation!==target.generation ?
          'computer_generation_changed':'computer_session_lost');
      }
      return current;
    }
    const opening=this.pending.get(key);
    if(opening) return opening;
    const promise=(async()=>{
      const client=await this.connect(target);
      try {
        if(this.stopped) throw Error('computer_provider_closed');
        if(![...this.ownerStates.values()].some(state=>!state.closed && state.targets.has(target.id)))
          throw Error('computer_owner_closed');
        const identity=client.getServerVersion?.();
        if(!identity || identity.name!==this.manifest.driver ||
          identity.version!==this.manifest.version) throw Error('computer_version_mismatch');
        if(this.#target(target.id).generation!==target.generation)
          throw Error('computer_generation_changed');
        const item={generation:target.generation,client,active:0,queued:0,
          tail:Promise.resolve(),snapshots:new Map(),capture:null,lastUsed:this.clock()};
        this.sessions.set(key,item);
        return item;
      } catch(error) {
        await client.close().catch(()=>{});throw error;
      }
    })();
    this.pending.set(key,promise);
    try{return await promise;}finally{
      if(this.pending.get(key)===promise)this.pending.delete(key);
    }
  }

  async #enqueue(item, operation) {
    if(item.active+item.queued>=this.maxQueue)throw Error('computer_queue_full');
    item.queued++;
    const previous=item.tail;
    let release;
    item.tail=new Promise(resolve=>{release=resolve;});
    await previous;
    item.queued--;item.active++;
    try{return await operation();}finally{
      item.active--;item.lastUsed=this.clock();release();
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
      if(typeof owner!=='string' || !owner)throw Error('invalid_owner');
      const target=this.#target(environment_id);
      let ownerState=this.ownerStates.get(owner);
      if(!ownerState){
        ownerState={closed:false,contexts:new Map(),targets:new Set()};this.ownerStates.set(owner,ownerState);
      }
      ownerState.targets.add(target.id);
      const current=await this.#get(target);
      return await this.#enqueue(current,async()=>{
        if(this.stopped)throw Error('computer_provider_closed');
        if(ownerState.closed)throw Error('computer_owner_closed');
        if(this.#target(target.id).generation!==target.generation ||
          current.generation!==target.generation)throw Error('computer_generation_changed');
        if(this.sessions.get(target.id)!==current || current.client.styxTransport?.closed)
          throw Error('computer_session_lost');
        let context=ownerState.contexts.get(target.id);
        if(!context || context.transport!==current){
          context={transport:current,session:'styx-'+randomUUID()};
          ownerState.contexts.set(target.id,context);
        }
        // Cua 0.36 native session labels do NOT isolate element tokens. Bind
        // snapshots to authenticated owners here, before any action dispatch.
        const token=nativeArgs.element_token;
        if(token!==undefined) {
          const match=typeof token==='string' && /^(s[0-9a-f]{8}):[0-9]+$/.exec(token);
          if(!match || current.snapshots.get(match[1])!==context)
            throw Error('computer_snapshot_required');
        }
        const coordinates=nativeArgs.x!==undefined || nativeArgs.y!==undefined;
        const captureTarget=nativeArgs.target?.kind==='desktop' || nativeArgs.scope==='desktop'
          ? 'desktop' : JSON.stringify([nativeArgs.target?.pid??nativeArgs.pid,
            nativeArgs.target?.window_id??nativeArgs.window_id]);
        if(coordinates && (current.capture?.context!==context || current.capture.target!==captureTarget || nativeArgs.from_zoom))
          throw Error('computer_snapshot_required');
        const observes=name==='get_window_state' || name==='get_desktop_state';
        if(observes || name==='verify_state')current.capture=null;
        // A different owner's mutation may change any previously observed UI.
        if(!READ_TOOLS.has(name)) {
          for(const [id,holder] of current.snapshots)if(holder!==context)current.snapshots.delete(id);
          if(current.capture?.context!==context)current.capture=null;
        }
        // Never replay an action after an ambiguous transport failure.
        dispatched=true;
        const result=await current.client.callTool({name,arguments:{...nativeArgs,session:context.session}});
        if(observes && !result.isError) {
          const data=result.structuredContent;
          if(plain(data)) {
            for(const id of Array.isArray(data.invalidated_snapshot_ids)?data.invalidated_snapshot_ids:[])
              current.snapshots.delete(id);
            if(typeof data.snapshot_id==='string' && /^s[0-9a-f]{8}$/.test(data.snapshot_id)) {
              current.snapshots.set(data.snapshot_id,context);
              while(current.snapshots.size>64)current.snapshots.delete(current.snapshots.keys().next().value);
            }
          }
          // Implicit screenshot selection is global in some native backends.
          // Permit pixels only from this owner's latest matching observation.
          current.capture=null;
          if(nativeArgs.display_only!==true && plain(data) && typeof data.capture_id==='string' && data.screenshot_frame_valid!==false && (name==='get_desktop_state' || nativeArgs.include_screenshot!==false))
            current.capture={context,target:name==='get_desktop_state'?'desktop':JSON.stringify([nativeArgs.pid,nativeArgs.window_id])};
        }
        return result;
      });
    } catch (e) {
      const code=e?.message;
      if (['default_environment_required','environment_not_found','environment_access_denied','computer_not_available',
        'computer_generation_changed','computer_version_mismatch',
        'computer_session_lost','invalid_owner','computer_provider_closed','computer_owner_closed',
        'computer_slots_busy','computer_queue_full','computer_snapshot_required','computer_host_offline'].includes(code))
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
      if(item.active===0 && item.queued===0 && this.clock()-item.lastUsed>=this.idleMs) {
        this.sessions.delete(key);
        for(const owner of this.ownerStates.values()) {
          if(owner.contexts.get(key)?.transport===item) owner.contexts.delete(key);
        }
        stale.push(item.client);
      }
    }
    await Promise.allSettled(stale.map(client=>client.close()));
  }

  async closeOwner(owner) {
    const state=this.ownerStates.get(owner);
    if(state)state.closed=true;
    this.ownerStates.delete(owner);
    // Retire this owner's native namespace. Native Cua expires its cache;
    // closing the shared transport here would interrupt unrelated owners.
    state?.contexts.clear();
  }
  async close() {
    this.stopped=true;
    for(const state of this.ownerStates.values())state.closed=true;
    this.ownerStates.clear();
    clearInterval(this.reaper);
    await Promise.allSettled([...this.pending.values()]);
    await Promise.allSettled([...this.sessions.values()].map(x=>x.client.close()));
    this.sessions.clear();this.pending.clear();
  }
}
