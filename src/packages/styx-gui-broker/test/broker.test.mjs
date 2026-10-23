import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {GuiBroker,GuiError} from '../broker.mjs';
function fixture({ttlMs=30000,maxTokens=1024}={}) {
 let now=100000,allowed=true,target='p1';const clients=[],calls=[];
 const binding={id:'mac',host:'test-host',osUser:'u',sessionGeneration:'login-1',appGeneration:'app-1',runtimeGeneration:'driver-1',ready:true};
 const broker=new GuiBroker({ttlMs,maxTokens,clock:()=>now,resolve:async(id,owner)=>{
  if(!allowed||!['alice/chat1','alice/chat2','bob/chat1'].includes(owner)||id&&id!=='mac')throw new GuiError('denied');
  return {...binding};
 },verifyTarget:async(b,pid,window)=>({generation:target}),connect:async()=>{
  let seq=0;const client=new EventEmitter();client.closed=false;client.onClose=fn=>client.on('close',fn);
  client.close=async()=>{if(!client.closed){client.closed=true;client.emit('close');}};
  client.call=async(name,args)=>{
   calls.push({client:clients.indexOf(client),name,args});
   if(client.closed)throw Error('closed');
   if(client.hook)return client.hook(name,args);
   if(name==='get_window_state')return {structuredContent:{pid:args.pid,window_id:args.window_id,
    snapshot_id:'s'+(++seq),elements_complete:false,truncated:false,
    elements:[{element_token:'s'+seq+':0',role:'AXButton',label:'fixture'}]},content:[]};
   return {structuredContent:{effect:name==='set_value'?'confirmed':'unverifiable',
    route:'accessibility',delivery:{mode:'background'},...(name==='set_value'?{evidence:[{kind:'value_readback'}]}:{})}};
  };clients.push(client);return client;
 }});
 return {broker,binding,clients,calls,advance:n=>now+=n,revoke:()=>allowed=false,target:n=>target=n};
}
const owner='alice/chat1',observe=(f,other=owner)=>f.broker.observe({pid:123,window_id:44},other);
const token=r=>r.structuredContent.elements[0].element_token;
test('one persistent client per owner/chat/context; only scoped opaque tokens leave the broker',async()=>{
 const f=fixture(),a=await observe(f),b=await observe(f);
 assert.equal(f.clients.length,1);assert.notEqual(token(a),token(b));
 assert.ok(!JSON.stringify(b).includes('s2:0'));
 assert.equal(b.structuredContent.elements_complete,false);assert.equal(b.structuredContent.truncated,false);
 assert.deepEqual(b.structuredContent.invalidated_snapshot_ids,[a.structuredContent.snapshot_id]);
});
test('new observation invalidates earlier tokens and never forwards a stale click',async()=>{
 const f=fixture(),a=await observe(f);await observe(f);
 await assert.rejects(f.broker.act('click',{element_token:token(a)},owner),/unknown_element_token/);
 assert.equal(f.calls.filter(c=>c.name==='click').length,0);
});
test('tokens cannot cross user or conversation even if native token strings collide',async()=>{
 const f=fixture(),a=await observe(f);
 for(const other of ['alice/chat2','bob/chat1'])
  await assert.rejects(f.broker.act('click',{element_token:token(a)},other),/unknown_element_token/);
 await observe(f,'alice/chat2');assert.equal(f.clients.length,2);
 await assert.rejects(f.broker.act('click',{element_token:token(a)},owner));
});
test('observed snapshot is consumed before await; concurrent duplicate mutation dispatches once',async()=>{
 const f=fixture(),a=await observe(f);
 const results=await Promise.allSettled([1,2].map(()=>f.broker.act('click',{element_token:token(a)},owner)));
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(f.calls.filter(c=>c.name==='click').length,1);
});
test('effect unverifiable is retained and not relabeled successful verification',async()=>{
 const f=fixture(),a=await observe(f),r=await f.broker.act('click',{element_token:token(a)},owner);
 assert.equal(r.structuredContent.effect,'unverifiable');
 assert.equal(r.structuredContent.verification.status,'not_independently_verified');
});
test('confirmed value_readback stays distinct from an application goal verification',async()=>{
 const f=fixture(),a=await observe(f),r=await f.broker.act('set_value',{element_token:token(a),value:'中文'},owner);
 assert.equal(r.structuredContent.effect,'confirmed');
 assert.deepEqual(r.structuredContent.evidence,[{kind:'value_readback'}]);
 assert.equal(r.structuredContent.verification.status,'not_independently_verified');
});
test('disconnect immediately invalidates tokens; fresh observation establishes a new client',async()=>{
 const f=fixture(),a=await observe(f);await f.clients[0].close();
 await assert.rejects(f.broker.act('click',{element_token:token(a)},owner));
 const b=await observe(f);assert.equal(f.clients.length,2);
 assert.notEqual(token(a),token(b));
});
test('explicit reconnect never rebinds old tokens or replays any mutation',async()=>{
 const f=fixture(),a=await observe(f);await f.broker.reconnect('mac',owner);
 await assert.rejects(f.broker.act('click',{element_token:token(a)},owner));
 assert.equal(f.calls.filter(c=>c.name==='click').length,0);
 assert.equal(f.clients.length,2);
});
test('all runtime, app, login and Host bindings are checked before mutation',async()=>{
 for(const field of ['runtimeGeneration','appGeneration','sessionGeneration','host','osUser']){
  const f=fixture(),a=await observe(f);f.binding[field]+='-new';
  await assert.rejects(f.broker.act('click',{element_token:token(a)},owner),/stale_generation/);
  assert.equal(f.calls.filter(c=>c.name==='click').length,0);
 }
});
test('authorization revocation and target process generation changes block action',async()=>{
 const f=fixture(),a=await observe(f);f.revoke();
 await assert.rejects(f.broker.act('click',{element_token:token(a)},owner),/gui_unavailable/);
 const g=fixture(),b=await observe(g);g.target('new-pid-generation');
 await assert.rejects(g.broker.act('click',{element_token:token(b)},owner),/stale_target/);
 assert.equal(f.calls.concat(g.calls).filter(c=>c.name==='click').length,0);
});
test('expiry is rechecked after asynchronous native target validation',async()=>{
 const f=fixture({ttlMs:20}),a=await observe(f);
 f.broker.verifyTarget=async()=>{f.advance(21);return {generation:'p1'};};
 await assert.rejects(f.broker.act('click',{element_token:token(a)},owner),/stale_element_token/);
 assert.equal(f.calls.filter(c=>c.name==='click').length,0);
});
test('unknown mutation result is not retried and its observation is consumed',async()=>{
 const f=fixture(),a=await observe(f);f.clients[0].hook=async()=>{throw Error('private failure');};
 const r=await f.broker.act('click',{element_token:token(a)},owner);
 assert.equal(r.structuredContent.outcome,'outcome_unknown');
 assert.ok(!JSON.stringify(r).includes('private failure'));
 await assert.rejects(f.broker.act('click',{element_token:token(a)},owner));
 assert.equal(f.calls.filter(c=>c.name==='click').length,1);
});
test('native refusal and malformed observation fail rather than minting authority',async()=>{
 const f=fixture();await observe(f);
 f.clients[0].hook=async()=>({structuredContent:{snapshot_id:'bad',pid:999,window_id:44,elements_complete:true,elements:[]}});
 await assert.rejects(observe(f),/invalid_observation/);
 assert.equal(f.broker.tokens.size,0);
});
test('host unavailable never implicitly starts a driver or switches execution context',async()=>{
 const f=fixture();f.binding.ready=false;
 await assert.rejects(observe(f),/gui_unavailable/);assert.equal(f.clients.length,0);
});
test('raw tokens, socket paths and legacy interface arguments are rejected',async()=>{
 const f=fixture();
 for(const [name,args]of [['get_window_state',{pid:123,window_id:44,socket:'/tmp/x'}],
 ['get_window_state',{pid:123,window_id:44,host_bundle_id:'pretend'}],
 ['desktop_act',{snapshot_id:'x'}],['click',{element_token:'raw',environment_id:'other'}]]){
  assert.equal((await f.broker.callTool(name,args,owner)).isError,true);
 }
 assert.equal(f.clients.length,0);
});
test('host dies during dispatch: retain uncertainty, discard capability',async()=>{
 const f=fixture(),a=await observe(f);
 f.clients[0].hook=async()=>{f.binding.ready=false;return {structuredContent:{effect:'confirmed'}};};
 const r=await f.broker.act('click',{element_token:token(a)},owner);
 assert.equal(r.structuredContent.outcome,'outcome_unknown');assert.equal(f.broker.tokens.size,0);
});
test('broker restart loses its token mapping and does not replay native actions',async()=>{
 const f=fixture(),a=await observe(f),g=fixture();
 await assert.rejects(g.broker.act('click',{element_token:token(a)},owner));
 assert.equal(g.calls.length,0);
});

test('a different window observation does not falsely invalidate a still-current snapshot',async()=>{
 const f=fixture(),first=await observe(f);
 const other=await f.broker.observe({pid:123,window_id:55},owner);
 assert.deepEqual(other.structuredContent.invalidated_snapshot_ids,[]);
 await f.broker.act('click',{element_token:token(first)},owner);
 assert.equal(f.calls.filter(c=>c.name==='click').length,1);
});
test('malformed screenshot does not leave live tokens behind',async()=>{
 const f=fixture();await observe(f);
 f.clients[0].hook=async()=>({structuredContent:{pid:123,window_id:44,snapshot_id:'raw',elements_complete:false,elements:[{element_token:'raw:0'}]},
 content:[{type:'image',mimeType:'image/png',data:'not-png'}]});
 await assert.rejects(observe(f),/invalid_capture/);assert.equal(f.broker.tokens.size,0);
});

test('ambiguous native errors stay unknown, rather than implying no mutation occurred',async()=>{
 const f=fixture(),a=await observe(f);
 f.clients[0].hook=async()=>({isError:true,structuredContent:{error:'failure_after_possible_dispatch'}});
 const r=await f.broker.act('click',{element_token:token(a)},owner);
 assert.equal(r.structuredContent.outcome,'outcome_unknown');
 assert.equal(f.broker.tokens.size,0);
});
test('empty context and invalid optional tree format are rejected',async()=>{
 const f=fixture();
 for(const args of [{pid:123,window_id:44,environment_id:''},{pid:123,window_id:44,tree_format:''}])
  await assert.rejects(f.broker.observe(args,owner),/invalid_arguments/);
 assert.equal(f.clients.length,0);
});
