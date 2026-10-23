import {randomBytes} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {AjvJsonSchemaValidator} from '@modelcontextprotocol/sdk/validation/ajv';
import {BROWSER_VERSION,BROWSER_META_OWNER,BROWSER_OWNER_CLOSED,BROWSER_STATE_CHANGED,browserTools,browserFailure} from '../packages/styx-browser-provider/contract.mjs';
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const nativeRef=/^(?:f\d+)?e\d+$/;
const tokenRef=/^styx-[a-f0-9]{32}$/;
const targetKeys=new Set(['target','startTarget','endTarget']);
const PROFILE_OWNER='app.styx/browser-profile-owner';
const wrapTool=tool=>({...structuredClone(tool),inputSchema:{...structuredClone(tool.inputSchema),properties:{...structuredClone(tool.inputSchema.properties),environment_id:{type:'string',minLength:1,description:'Device from list_execution_environments. Omit only when a default device is configured.'}}}});

// Schemas stay native. Only opaque reference VALUES are bound to owner and the
// current observation; no model-visible page/session protocol is introduced.
export class BrowserProvider{
  constructor({registry,relay,connect}={}){
    this.registry=registry;this.relay=relay;this.stopped=false;this.connections=new Map();this.pending=new Map();this.pendingAbort=new Map();this.owners=new Map();this.tokens=new Map();this.principals=new Map();
    this.schema=browserTools.map(wrapTool);const validator=new AjvJsonSchemaValidator();
    this.validators=new Map(this.schema.map(tool=>[tool.name,validator.getValidator(tool.inputSchema)]));
    this.connect=connect??(async (target,{signal}={})=>{
      const transport=await relay.acquireBrowser(target);
      if(signal?.aborted){await transport.close();throw Error('browser_provider_closed');}
      const abort=()=>{void transport.close().catch(()=>{})};signal?.addEventListener('abort',abort,{once:true});
      const client=new Client({name:'styx-browser-provider',version:'0.1.0'});client.styxTransport=transport;client.styxRemovePendingAbort=()=>signal?.removeEventListener('abort',abort);
      client.fallbackNotificationHandler=async({method,params})=>{
        if(method!==BROWSER_STATE_CHANGED)return;const context=this.tokens.get(params?.owner);
        if(context&&context.environment===target.id&&plain(params.state)){
          context.readiness=['ready_observed','not_started','unknown'].includes(params.state.readiness)?params.state.readiness:'unknown';
          context.headless=typeof params.state.headless==='boolean'?params.state.headless:'unknown';
          context.version=typeof params.state.version==='string'?params.state.version.slice(0,100):'unknown';
          if(context.readiness!=='ready_observed'||params.state.observationChanged===true)context.refs.clear();
        }
      };
      try{await client.connect(transport);return client;}catch(error){client.styxRemovePendingAbort();await transport.close().catch(()=>{});throw error;}
    });
  }
  async listTools(){return this.schema;}
  // Only the authenticated transport binds this identity. It is not an account
  // assertion or a model-supplied workspace selector; tabs/refs retain the
  // short-lived invocation owner even when dedicated login storage is reused.
  bindPrincipal(owner,principal){
    if(typeof owner!=='string'||!owner||!/^[a-f0-9]{64}$/.test(principal??''))throw Error('invalid_browser_principal');
    const current=this.principals.get(owner);if(current&&current!==principal)throw Error('browser_principal_changed');
    this.principals.set(owner,principal);
  }
  target(id){const target=this.registry.resolve(id);if(target.browser?.enabled!==true)throw Error('browser_not_available');return target;}
  context(owner,target){
    if(typeof owner!=='string'||!owner)throw Error('invalid_owner');
    let state=this.owners.get(owner);if(!state){state={closed:false,contexts:new Map()};this.owners.set(owner,state);}
    if(state.closed)throw Error('browser_owner_closed');
    let context=state.contexts.get(target.id);
    if(context&&context.generation!==target.generation){this.tokens.delete(context.token);context.closed=true;context.refs.clear();state.contexts.delete(target.id);context=null;}
    if(!context){context={environment:target.id,generation:target.generation,token:randomBytes(32).toString('hex'),refs:new Map(),closed:false,readiness:'unknown',version:'unknown',headless:'unknown',active:0,queued:0,tail:Promise.resolve()};state.contexts.set(target.id,context);this.tokens.set(context.token,context);}
    return context;
  }
  async connection(target){
    if(this.stopped)throw Error('browser_provider_closed');
    const current=this.connections.get(target.id);
    if(current&&!current.closed&&!current.client.styxTransport?.closed&&current.generation===target.generation)return current;
    if(current){this.connections.delete(target.id);await current.client.close().catch(()=>{});}
    if(this.pending.has(target.id))return this.pending.get(target.id);
    const controller=new AbortController();this.pendingAbort.set(target.id,controller);
    const pending=(async()=>{
      const client=await this.connect(target,{signal:controller.signal});
      try{
        const identity=client.getServerVersion();if(identity?.name!=='styx-browser-host'||identity.version!==BROWSER_VERSION)throw Error('browser_version_mismatch');
        if(JSON.stringify((await client.listTools()).tools)!==JSON.stringify(browserTools))throw Error('browser_contract_mismatch');
        if(this.stopped||this.target(target.id).generation!==target.generation)throw Error('browser_generation_changed');
        const item={client,generation:target.generation,closed:false};
        client.onclose=()=>{item.closed=true;for(const state of this.owners.values()){const context=state.contexts.get(target.id);if(context){context.refs.clear();context.readiness='unknown';context.version='unknown';}}};
        this.connections.set(target.id,item);return item;
      }catch(error){await client.close().catch(()=>{});throw error;}finally{client.styxRemovePendingAbort?.();}
    })();this.pending.set(target.id,pending);
    try{return await pending;}finally{if(this.pending.get(target.id)===pending){this.pending.delete(target.id);this.pendingAbort.delete(target.id);}}
  }
  unwrap(value,context,key=''){
    if(Array.isArray(value))return value.map(v=>this.unwrap(v,context));
    if(plain(value))return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,this.unwrap(v,context,k)]));
    if(targetKeys.has(key)&&typeof value==='string'){
      if(tokenRef.test(value)){const ref=context.refs.get(value);if(!ref)throw Error('browser_snapshot_required');return ref;}
      if(nativeRef.test(value)||value.startsWith('styx-'))throw Error('browser_snapshot_required');
    }
    return value;
  }
  wrapResult(result,context){
    const serialized=JSON.stringify(result);if(!/\[ref=(?:f\d+)?e\d+\]/.test(serialized))return result;
    context.refs.clear();const nativeToToken=new Map();
    const transform=value=>{
      if(Array.isArray(value))return value.map(transform);
      if(plain(value))return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,transform(v)]));
      if(typeof value!=='string')return value;
      return value.replace(/\[ref=((?:f\d+)?e\d+)\]/g,(_,ref)=>{if(!nativeToToken.has(ref)){const token='styx-'+randomBytes(16).toString('hex');nativeToToken.set(ref,token);context.refs.set(token,ref);}return '[ref='+nativeToToken.get(ref)+']';});
    };return transform(result);
  }
  async callTool(name,args={},owner){
    const validator=this.validators.get(name);if(!validator)return browserFailure('unknown_tool');
    if(!plain(args)||!validator(args).valid)return browserFailure('invalid_arguments');
    let dispatched=false,context;
    const nativeTool=browserTools.find(t=>t.name===name);
    const readOnly=nativeTool.annotations?.readOnlyHint===true||(name==='browser_tabs'&&args.action==='list');
    try{
      const target=this.target(args.environment_id);context=this.context(owner,target);
      const previous=context.tail;let release;context.tail=new Promise(r=>{release=r});context.queued++;await previous;context.queued--;context.active++;
      try{
        if(this.stopped||context.closed)throw Error('browser_owner_closed');
        if(this.target(target.id).generation!==context.generation)throw Error('browser_generation_changed');
        const {environment_id,...nativeArgs}=args;
        const item=await this.connection(target);
        // The connection await may cross revocation, shutdown or generation change.
        if(context.closed||this.target(target.id).generation!==context.generation)throw Error('browser_generation_changed');
        const unwrapped=this.unwrap(nativeArgs,context);
        if(!readOnly||name==='browser_snapshot')context.refs.clear();
        const meta={[BROWSER_META_OWNER]:context.token};
        if(this.principals.has(owner))meta[PROFILE_OWNER]=this.principals.get(owner);
        if(Buffer.byteLength(JSON.stringify({name,arguments:unwrapped,_meta:meta}))+256>8*1024*1024)throw Error('browser_frame_limit');
        dispatched=true;
        const result=await item.client.callTool({name,arguments:unwrapped,_meta:meta});
        if(name==='browser_close'){context.refs.clear();context.readiness='not_started';}
        return name==='browser_snapshot'&&!nativeArgs.filename?this.wrapResult(result,context):result;
      }finally{context.active--;release();}
    }catch(error){
      const known=new Set(['default_environment_required','environment_not_found','environment_access_denied','browser_not_available','invalid_owner','browser_owner_closed','browser_generation_changed','browser_version_mismatch','browser_contract_mismatch','browser_snapshot_required','browser_host_offline','browser_provider_closed','browser_frame_limit']);
      const code=known.has(error.message)?error.message:'browser_transport_unavailable';
      if(context&&dispatched){context.refs.clear();context.readiness='unknown';}
      const result=browserFailure(code,dispatched&&!readOnly);
      if(code==='browser_snapshot_required')result.structuredContent.recovery='Call browser_snapshot with no filename in this conversation, then use its current target references. References from another chat, tab or pre-reconnect observation are invalid.';
      result.content[0].text=JSON.stringify(result.structuredContent);return result;
    }
  }
  status(target,owner){const context=this.owners.get(owner)?.contexts.get(target.id);const active=context&&!context.closed&&context.generation===target.generation&&this.connections.get(target.id)?.closed===false;return {configured:target.browser?.enabled===true,readiness:active?context.readiness:'unknown',version:active?context.version:'unknown',headless:active?context.headless:'unknown'};}
  hasOwnerWork(owner){return [...(this.owners.get(owner)?.contexts.values()??[])].some(c=>c.active>0||c.queued>0);}
  async closeOwner(owner){
    this.principals.delete(owner);
    const state=this.owners.get(owner);if(!state)return;state.closed=true;
    for(const [id,context]of state.contexts){context.closed=true;context.refs.clear();this.tokens.delete(context.token);const item=this.connections.get(id);if(item&&!item.closed)await item.client.notification({method:BROWSER_OWNER_CLOSED,params:{owner:context.token}}).catch(()=>{});}
    this.owners.delete(owner);
  }
  async close(){this.stopped=true;for(const controller of this.pendingAbort.values())controller.abort();await Promise.allSettled([...this.owners.keys()].map(owner=>this.closeOwner(owner)));await Promise.allSettled([...this.pending.values()]);await Promise.allSettled([...this.connections.values()].map(item=>item.client.close()));this.connections.clear();}
}
