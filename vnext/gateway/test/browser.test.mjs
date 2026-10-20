import test from 'node:test';
import assert from 'node:assert/strict';
import {TargetRegistry} from '../registry.mjs';
import {BrowserProvider} from '../browser.mjs';
import {browserTools,BROWSER_META_OWNER} from '../../packages/styx-browser-provider/contract.mjs';
const target=(id,browser=true)=>({id,kind:'host',platform:'linux',generation:'g1',allowed:true,cwd:'/tmp',shell:'/bin/sh',shells:['/bin/sh'],exec:{transport:'outbound',token_file:'/tmp/token'},browser:{enabled:browser,...browser?{transport:'outbound'}:{}}});
const registry=()=>new TargetRegistry({version:1,default_environment_id:'a',targets:[target('a'),target('b'),target('no',false)]});
const snapshot={content:[{type:'text',text:'### Snapshot\n- button "Store" [ref=e2]\n- button "Inside" [ref=f1e3]'}]};
const token=r=>/ref=(styx-[a-f0-9]+)/.exec(r.content[0].text)[1];
function fixture(t,{call,connect}={}){const calls=[];const client={getServerVersion:()=>({name:'styx-browser-host',version:'0.0.83'}),listTools:async()=>({tools:browserTools}),callTool:async params=>{calls.push(params);return call?call(params):snapshot;},notification:async()=>{},close:async()=>{client.onclose?.();}};const provider=new BrowserProvider({registry:registry(),connect:connect??(async()=>client)});t.after(()=>provider.close());return {provider,client,calls};}

test('Browser schemas preserve locked native definitions and add only environment_id',async t=>{
  const {provider}=fixture(t);const actual=await provider.listTools();assert.equal(actual.length,24);
  for(let i=0;i<actual.length;i++){const native=structuredClone(actual[i]);delete native.inputSchema.properties.environment_id;assert.deepEqual(native,browserTools[i]);}
  assert.deepEqual(actual.find(t=>t.name==='browser_take_screenshot').inputSchema.required,['scale']);
  assert.equal((await provider.callTool('browser_take_screenshot',{},'a')).structuredContent.error,'invalid_arguments');
  assert.equal((await provider.callTool('browser_snapshot',{_meta:{[BROWSER_META_OWNER]:'forged'}},'a')).structuredContent.error,'invalid_arguments');
});
test('Browser scopes all target fields to owner, device and latest observation',async t=>{
  const {provider,calls}=fixture(t);const first=token(await provider.callTool('browser_snapshot',{},'alice'));
  for(const [name,args]of [['browser_click',{target:first}],['browser_drag',{startTarget:first,endTarget:first}],['browser_fill_form',{fields:[{name:'field',type:'textbox',target:first,value:'x'}]}]])assert.equal((await provider.callTool(name,args,'bob')).structuredContent.error,'browser_snapshot_required');
  assert.equal((await provider.callTool('browser_click',{environment_id:'b',target:first},'alice')).structuredContent.error,'browser_snapshot_required');
  for(const ref of ['e2','f1e3','styx-deadbeef'])assert.equal((await provider.callTool('browser_click',{target:ref},'alice')).structuredContent.error,'browser_snapshot_required');
  const second=token(await provider.callTool('browser_snapshot',{},'alice'));assert.notEqual(first,second);
  assert.equal((await provider.callTool('browser_click',{target:first},'alice')).structuredContent.error,'browser_snapshot_required');
  await provider.callTool('browser_click',{target:second},'alice');assert.equal(calls.at(-1).arguments.target,'e2');assert.match(calls.at(-1)._meta[BROWSER_META_OWNER],/^[a-f0-9]{64}$/);
});
test('Browser transport ambiguity is explicit and never replays a dispatched action',async t=>{
  let count=0;const {provider}=fixture(t,{call:async()=>{count++;throw Error('wire_lost');}});
  const result=await provider.callTool('browser_navigate',{url:'https://example.invalid'},'owner');assert.equal(count,1);assert.equal(result.structuredContent.error,'browser_transport_unavailable');assert.equal(result.structuredContent.uncertain,true);
});
test('Browser revocation and owner close during connection prevent dispatch',async t=>{
  let release;const gate=new Promise(r=>{release=r});const {provider,client,calls}=fixture(t,{connect:async()=>{await gate;return client;}});
  const result=provider.callTool('browser_navigate',{url:'https://example.invalid'},'owner');await Promise.resolve();await provider.closeOwner('owner');release();assert.equal((await result).isError,true);assert.equal(calls.length,0);
  provider.registry.revokeHost('a');assert.equal((await provider.callTool('browser_snapshot',{},'new')).structuredContent.error,'environment_access_denied');
});
test('Browser passive status has no profile paths, transport acquisition or readiness inference',async t=>{
  const {provider}=fixture(t,{connect:async()=>{throw Error('must_not_connect');}});const state=provider.status(provider.registry.resolve('a'),'owner');assert.deepEqual(state,{configured:true,readiness:'unknown',version:'unknown',headless:'unknown'});assert.equal(provider.owners.size,0);
  assert.equal((await provider.callTool('browser_snapshot',{environment_id:'no'},'owner')).structuredContent.error,'browser_not_available');
});

test('Browser shutdown waits for pending connection settlement without dispatch',async t=>{
  let release;const gate=new Promise(r=>{release=r});const {provider,client,calls}=fixture(t,{connect:async()=>{await gate;return client;}});
  const request=provider.callTool('browser_snapshot',{},'owner');await new Promise(r=>setImmediate(r));
  let stopped=false;const close=provider.close().then(()=>{stopped=true});await new Promise(r=>setImmediate(r));assert.equal(stopped,false);
  release();await close;assert.equal((await request).isError,true);assert.equal(calls.length,0);assert.equal(provider.pending.size,0);
});

test('default Browser connector cancels a pending MCP initialize at shutdown',async t=>{
  let sent;const initializing=new Promise(r=>{sent=r});let closed=false;
  const transport={async start(){},async send(message){if(message.method==='initialize')sent()},async close(){closed=true;transport.onclose?.()}};
  const provider=new BrowserProvider({registry:registry(),relay:{acquireBrowser:async()=>transport}});t.after(()=>provider.close());
  const result=provider.callTool('browser_snapshot',{},'owner');await initializing;await provider.close();assert.equal(closed,true);assert.equal((await result).isError,true);assert.equal(provider.pending.size,0);
});
test('oversize Browser requests are rejected before dispatch with no uncertain result',async t=>{
  const {provider,calls}=fixture(t);const result=await provider.callTool('browser_type',{target:'#field',text:'a'.repeat(9*1024*1024)},'owner');
  assert.equal(result.structuredContent.error,'browser_frame_limit');assert.equal(result.structuredContent.uncertain,undefined);assert.equal(calls.length,0);
});

test('only a current inline native snapshot can mint actionable reference values',async t=>{
  let response=snapshot;const {provider}=fixture(t,{call:async()=>response});const old=token(await provider.callTool('browser_snapshot',{},'owner'));
  response={content:[{type:'text',text:'### Snapshot\nNo elements'}]};await provider.callTool('browser_snapshot',{},'owner');
  assert.equal((await provider.callTool('browser_click',{target:old},'owner')).structuredContent.error,'browser_snapshot_required');
  response=snapshot;const evaluated=await provider.callTool('browser_evaluate',{function:'() => "[ref=e2]"'},'owner');assert.match(evaluated.content[0].text,/ref=e2/);assert.equal(provider.owners.get('owner').contexts.get('a').refs.size,0);
  await provider.callTool('browser_snapshot',{filename:'observation.md'},'owner');assert.equal(provider.owners.get('owner').contexts.get('a').refs.size,0);
});
