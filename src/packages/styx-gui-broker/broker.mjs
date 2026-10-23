import {randomUUID} from 'node:crypto';
export class GuiError extends Error {
  constructor(code, uncertain = false) { super(code); this.code = code; this.uncertain = uncertain; }
}
const fail = code => { throw new GuiError(code); };
const object = x => x && Object.getPrototypeOf(x) === Object.prototype;
function argumentsFor(name, a) {
  const types = name === 'get_window_state' ? {environment_id:'string',pid:'number',window_id:'number',include_screenshot:'boolean',tree_format:'string'} :
    name === 'click' ? {element_token:'string'} :
    name === 'set_value' ? {element_token:'string',value:'string'} : fail('unknown_tool');
  if (!object(a)) fail('invalid_arguments');
  for (const [k,v] of Object.entries(a)) {
    if (typeof v !== types[k] || (typeof v === 'number' && (!Number.isSafeInteger(v) || v<1)) ||
      (typeof v === 'string' && (v.includes('\0') || v.length>4096))) fail('invalid_arguments');
  }
  if(a.environment_id !== undefined && !a.environment_id.length)fail('invalid_arguments');
  if (name === 'get_window_state') {
    if (!a.pid || !a.window_id || (a.tree_format !== undefined && a.tree_format !== 'elements')) fail('invalid_arguments');
  } else if (!a.element_token || (name === 'set_value' && (typeof a.value !== 'string' || a.value.length>500))) fail('invalid_arguments');
  return a;
}
const key = (owner,id) => JSON.stringify([owner,id]);
const stamp = b => JSON.stringify([b.id,b.host,b.osUser,b.sessionGeneration,b.appGeneration,b.runtimeGeneration]);
const pick = (a, fields) => Object.fromEntries(fields.filter(k=>a[k]!==undefined).map(k=>[k,a[k]]));
export class GuiBroker {
  constructor({resolve, connect, verifyTarget, ttlMs=30000, clock=()=>Date.now(), maxScopes=16,maxTokens=1024}) {
    if (![resolve,connect,verifyTarget].every(x=>typeof x==='function')) throw TypeError('Trusted bindings required');
    Object.assign(this,{resolve,connect,verifyTarget,ttlMs,clock,maxScopes,maxTokens});
    this.scopes=new Map();this.tokens=new Map();this.locks=new Map();this.opening=0;
  }
  async binding(id,owner) {
    if(typeof owner!=='string'||!owner)fail('invalid_owner');
    const b=await this.resolve(id,owner);
    if(!b||![b.id,b.host,b.osUser,b.sessionGeneration,b.appGeneration,b.runtimeGeneration].every(x=>typeof x==='string'&&x) ||
       b.ready!==true)fail('gui_unavailable');
    return b;
  }
  async serial(k,task) {
    const prior=this.locks.get(k)??Promise.resolve();
    const next=prior.catch(()=>{}).then(task);this.locks.set(k,next);
    try{return await next;}finally{if(this.locks.get(k)===next)this.locks.delete(k);}
  }
  invalidate(scope,state='invalidated') {
    scope.state=state;if(state==='disconnected')scope.connected=false;
    for(const [id,t] of this.tokens)if(t.scope===scope)this.tokens.delete(id);
    scope.snapshots.clear();
  }
  async scope(id,owner) {
    const b=await this.binding(id,owner),k=key(owner,b.id);
    return this.serial('scope:'+k,async()=>{
      let s=this.scopes.get(k);
      if(s && (s.stamp!==stamp(b)||!s.connected||s.client.closed)) {
        this.invalidate(s);await s.client.close();this.scopes.delete(k);s=null;
      }
      if(!s){
        if(this.scopes.size+this.opening>=this.maxScopes)fail('scope_capacity');
        this.opening++;let client;
        try{client=await this.connect(b,owner);}finally{this.opening--;}
        if(client.closed)fail('connection_closed');
        s={owner,id:b.id,stamp:stamp(b),binding:b,client,state:'ready_unobserved',connected:true,snapshots:new Map()};
        client.onClose?.(()=>this.invalidate(s,'disconnected'));
        this.scopes.set(k,s);
      }
      return s;
    });
  }
  async assertLive(s) {
    let b;try{b=await this.binding(s.id,s.owner);}catch{this.invalidate(s);fail('gui_unavailable');}
    if(this.scopes.get(key(s.owner,s.id))!==s||s.stamp!==stamp(b)||s.state==='disconnected') {
      this.invalidate(s);fail('stale_generation');
    }
    return b;
  }
  invalidateWindow(host,window) {
    for(const s of this.scopes.values()) if(s.binding.host===host) {
      for(const [snapshot,rec]of s.snapshots)if(rec.window===window){
        s.snapshots.delete(snapshot);
        for(const [id,t]of this.tokens)if(t.snapshot===snapshot)this.tokens.delete(id);
      }
    }
  }
  async observe(raw,owner) {
    const a=argumentsFor('get_window_state',raw),s=await this.scope(a.environment_id,owner);
    return this.serial('window:'+JSON.stringify([s.binding.host,a.window_id]),async()=>{
      const b=await this.assertLive(s),target=await this.verifyTarget(b,a.pid,a.window_id);
      if(!target||typeof target.generation!=='string'||!target.generation)fail('target_unverified');
      const old=[...s.snapshots].filter(([,rec])=>rec.window===a.window_id).map(([id])=>id);
      const oldMap=new Map(s.snapshots);
      this.invalidateWindow(b.host,a.window_id);
      const observedAt=this.clock();let result;
      try{result=await s.client.call('get_window_state',{pid:a.pid,window_id:a.window_id,tree_format:'elements',include_screenshot:a.include_screenshot??false});}
      catch(e){this.invalidate(s,'disconnected');throw e instanceof GuiError?e:new GuiError('observation_unavailable');}
      await this.assertLive(s);
      const after=await this.verifyTarget(b,a.pid,a.window_id);
      if(after?.generation!==target.generation)fail('stale_target');
      const d=result?.structuredContent;
      if(result.isError||!object(d)||d.pid!==a.pid||d.window_id!==a.window_id||
         typeof d.snapshot_id!=='string'||!Array.isArray(d.elements)||d.elements.length>256||
         typeof d.elements_complete!=='boolean')fail('invalid_observation');
      const seen=new Set();
      for(const e of d.elements) {
        if(!object(e)||typeof e.element_token!=='string'||!e.element_token||seen.has(e.element_token))fail('invalid_observation');
        seen.add(e.element_token);
      }
      for(const [id,t]of this.tokens)if(t.expires<=this.clock())this.tokens.delete(id);
      if(this.tokens.size+d.elements.length>this.maxTokens)fail('token_capacity');
      // No upstream IDs/tokens are exposed as gateway authority.
      const snapshot=randomUUID(),expires=observedAt+this.ttlMs;
      if(expires<=this.clock())fail('observation_expired');
      if(s.snapshots.size>=128)fail('snapshot_capacity');
      s.snapshots.set(snapshot,{native:d.snapshot_id,window:a.window_id});
      const elements=d.elements.map(e=>{
        const token=randomUUID();
        this.tokens.set(token,{owner,scope:s,snapshot,native:e.element_token,pid:a.pid,window:a.window_id,
          targetGeneration:target.generation,expires});
        return {...pick(e,['actions','depth','element_index','enabled','frame','label','parent_index','role','screenshot_frame','value']),element_token:token};
      });
      for(const [id,rec]of oldMap)if(d.invalidated_snapshot_ids?.includes(rec.native)&&!old.includes(id)){
        old.push(id);s.snapshots.delete(id);for(const [ref,t]of this.tokens)if(t.snapshot===id)this.tokens.delete(ref);
      }
      s.state='observed';
      const data={...pick(d,['app_name','element_count','elements_complete','returned_element_count','total_element_count',
        'truncated','pid','window_id','window_title','window_bounds','screenshot_frame_valid','screenshot_height',
        'screenshot_width','screenshot_scale','screenshot_mime_type']),snapshot_id:snapshot,elements,
        invalidated_snapshot_ids:old,expires_at:new Date(expires).toISOString()};
      const images=(result.content??[]).filter(c=>c.type==='image').map(c=>{
        if(c.mimeType!=='image/png'||typeof c.data!=='string'||c.data.length>2800000){this.invalidate(s);fail('invalid_capture');}
        const bytes=Buffer.from(c.data,'base64');
        if(bytes.toString('base64')!==c.data||!bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))){this.invalidate(s);fail('invalid_capture');}
        return {type:'image',mimeType:c.mimeType,data:c.data};
      });
      return {structuredContent:data,content:[{type:'text',text:JSON.stringify(data)},...images]};
    });
  }
  async act(name,raw,owner) {
    const a=argumentsFor(name,raw),t=this.tokens.get(a.element_token);
    if(!t||t.owner!==owner)fail('unknown_element_token');
    const s=t.scope,k='window:'+JSON.stringify([s.binding.host,t.window]);
    return this.serial(k,async()=>{
      if(this.tokens.get(a.element_token)!==t||t.expires<=this.clock())fail('stale_element_token');
      const b=await this.assertLive(s),target=await this.verifyTarget(b,t.pid,t.window);
      if(target?.generation!==t.targetGeneration){this.invalidateWindow(b.host,t.window);fail('stale_target');}
      await this.assertLive(s);
      if(t.expires<=this.clock())fail('stale_element_token');
      if(!s.snapshots.has(t.snapshot))fail('stale_element_token');
      this.invalidateWindow(b.host,t.window); // Consume before dispatch, across chatting scopes.
      s.state='dispatching';const action_id=randomUUID();let result;
      try {
        result=await s.client.call(name,{element_token:t.native,...(name==='set_value'?{value:a.value}:{})});
      } catch {
        s.state='outcome_unknown';
        const data={action_id,outcome:'outcome_unknown',verified:false};
        return {structuredContent:data,content:[{type:'text',text:JSON.stringify(data)}]};
      }
      try{await this.assertLive(s);}catch{
        s.state='outcome_unknown';
        const data={action_id,outcome:'outcome_unknown',verified:false};
        return {structuredContent:data,content:[{type:'text',text:JSON.stringify(data)}]};
      }
      const d=result?.structuredContent;
      if(result?.isError||d?.status==='refused'){
        if(d?.status==='refused'&&['stale_element_token','window_owner_pid_mismatch','window_id_not_found'].includes(d.refusal?.code)){
          s.state='ready_unobserved';fail('native_action_refused');
        }
        s.state='outcome_unknown';
        const data={action_id,outcome:'outcome_unknown',verified:false};
        return {structuredContent:data,content:[{type:'text',text:JSON.stringify(data)}]};
      }
      s.state='needs_verification';
      if(!object(d)||!['confirmed','unverifiable'].includes(d.effect)){
        const data={action_id,outcome:'outcome_unknown',verified:false};
        return {structuredContent:data,content:[{type:'text',text:JSON.stringify(data)}]};
      }
      const data={action_id,...pick(d,['effect','route','delivery','evidence']),verification:{status:'not_independently_verified'}};
      return {structuredContent:data,content:[{type:'text',text:JSON.stringify(data)}]};
    });
  }
  async reconnect(id,owner) {
    const b=await this.binding(id,owner),k=key(owner,b.id);
    return this.serial('scope:'+k,async()=>{
      const s=this.scopes.get(k);
      if(s){this.invalidate(s);await s.client.close();this.scopes.delete(k);}
      // Establishing a replacement is deliberately separate from any mutation.
    }).then(()=>this.scope(id,owner));
  }
  async close(){
    for(const s of this.scopes.values()){this.invalidate(s);await s.client.close();}
    this.scopes.clear();
  }
  async callTool(name,args,owner) {
    try{return name==='get_window_state'?await this.observe(args,owner):await this.act(name,args,owner);}
    catch(e){const code=e instanceof GuiError?e.code:'gui_unavailable';
      const data={error:code,uncertain:e instanceof GuiError&&e.uncertain};
      return {isError:true,structuredContent:data,content:[{type:'text',text:JSON.stringify(data)}]};}
  }
}
