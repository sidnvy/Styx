import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {EventEmitter} from 'node:events';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {CallToolRequestSchema,ListToolsRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {browserTools} from '../contract.mjs';
const installed=fs.existsSync(new URL('../node_modules/@playwright/mcp/package.json',import.meta.url));
const owner='a'.repeat(64);
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r});return {promise,resolve}};
async function fixture(t,{call=async()=>({content:[]}),launch,persistLogin=false}={}){
  const {HostBrowserSupervisor}=await import('../host.mjs');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-browser-life-'));fs.chmodSync(root,0o700);
  const cwd=path.join(root,'work');fs.mkdirSync(cwd,{mode:0o700});
  let getter;const context=new EventEmitter();context.browser=()=>({version:()=> 'fixture'});context.close=async()=>{context.emit('close')};
  const operations={launchContext:launch??(async()=>context),createConnection:async(config,getContext)=>{
    getter=getContext;const server=new Server({name:'fixture',version:'1'},{capabilities:{tools:{}}});
    server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:browserTools}));
    server.setRequestHandler(CallToolRequestSchema,async({params})=>call(params,getContext));return server;
  }};
  const browser={enabled:true,headless:true,persistLogin,profileRoot:path.join(root,'profiles'),executablePath:process.execPath};
  const supervisor=new HostBrowserSupervisor({browser,cwd,operations});
  t.after(async()=>{context.close=async()=>{context.emit('close')};await supervisor.close();fs.rmSync(root,{recursive:true,force:true});});
  return {supervisor,root,cwd,browser,context,getContext:()=>getter()};
}
test('workspace real paths cannot contain or alias any owner profile',{skip:!installed},async t=>{
  const {HostBrowserSupervisor}=await import('../host.mjs'),f=await fixture(t);
  assert.throws(()=>new HostBrowserSupervisor({browser:f.browser,cwd:f.root}),/browser_workspace_profile_overlap/);
  const link=path.join(f.root,'profile-link');fs.symlinkSync(f.browser.profileRoot,link,'dir');
  assert.throws(()=>new HostBrowserSupervisor({browser:f.browser,cwd:link}),/browser_workspace_profile_overlap/);
});
test('shutdown awaits launch and real closure before releasing profile ownership',{skip:!installed},async t=>{
  const started=deferred(),opening=deferred();let closes=0;
  const context=new EventEmitter();context.browser=()=>({version:()=> 'fixture'});context.close=async()=>{closes++;context.emit('close')};
  const f=await fixture(t,{launch:async()=>{started.resolve();return opening.promise},call:async(params,get)=>{await get();return {content:[]}}});
  const call=f.supervisor.callTool('browser_snapshot',{},owner);call.catch(()=>{});await started.promise;
  let stopped=false;const stop=f.supervisor.close().then(()=>{stopped=true});await new Promise(r=>setImmediate(r));assert.equal(stopped,false);
  opening.resolve(context);await stop;await call.catch(()=>{});assert.equal(closes,1);assert.equal(f.supervisor.leases.size,0);
});
test('a failed context close retains unknown state and a retryable resource handle',{skip:!installed},async t=>{
  const f=await fixture(t);await f.supervisor.lease(owner);await f.getContext();
  f.context.close=async()=>{throw Error('close_failed')};
  await assert.rejects(f.supervisor.closeOwner(owner),/browser_shutdown_unconfirmed/);
  assert.equal(f.supervisor.leases.get(owner).context,f.context);assert.equal(f.supervisor.status(owner).state,'unknown');
  f.context.close=async()=>{f.context.emit('close')};await f.supervisor.closeOwner(owner);assert.equal(f.supervisor.leases.size,0);
});
test('an SDK timeout cannot admit the next operation until explicit context closure',{skip:!installed},async t=>{
  const running=deferred();const calls=[];
  const f=await fixture(t,{call:async(params,get)=>{await get();calls.push(params.name);if(params.name==='browser_evaluate')await running.promise;return {content:[]}}});
  const item=await f.supervisor.lease(owner),nativeCall=item.client.callTool.bind(item.client);
  item.client.callTool=params=>nativeCall(params,undefined,{timeout:15});
  await assert.rejects(f.supervisor.callTool('browser_evaluate',{function:'async()=>{}'},owner));
  assert.equal(f.supervisor.status(owner).state,'unknown');
  const blocked=await f.supervisor.callTool('browser_snapshot',{},owner);assert.equal(blocked.structuredContent.error,'browser_result_unconfirmed_close_required');assert.deepEqual(calls,['browser_evaluate']);
  f.context.close=async()=>{running.resolve();f.context.emit('close')};
  const closed=await f.supervisor.callTool('browser_close',{},owner);assert.match(closed.content[0].text,/outcome remains unconfirmed/);assert.equal(f.supervisor.leases.size,0);
});

test('file navigation checks canonical URLs before any native dispatch',{skip:!installed},async t=>{
  let calls=0;const f=await fixture(t,{call:async()=>{calls++;return {content:[]}}});
  for(const url of ['file:///private/data','  FILE:///private/data','\nfile:///private/data'])assert.equal((await f.supervisor.callTool('browser_navigate',{url},owner)).structuredContent.error,'browser_file_navigation_denied');
  assert.equal(calls,0);
});


test('login snapshots use trusted principal identity across isolated session profiles',{skip:!installed},async t=>{
  const principal='c'.repeat(64),other='d'.repeat(64),profiles=[],restored=[];
  let current={cookies:[],origins:[{origin:'https://example.test',localStorage:[{name:'login',value:'dedicated-login'}]}]};
  const f=await fixture(t,{persistLogin:true,launch:async(profile)=>{
    profiles.push(profile);const ctx=new EventEmitter();ctx.browser=()=>({version:()=> 'fixture'});ctx.close=async()=>ctx.emit('close');
    ctx.storageState=async()=>current;ctx.setStorageState=async state=>restored.push(state);return ctx;
  },call:async(params,get)=>{await get();return {content:[]}}});
  await assert.rejects(f.supervisor.callTool('browser_snapshot',{},owner),/browser_profile_owner_required/);
  await f.supervisor.callTool('browser_snapshot',{},owner,principal);
  await assert.rejects(f.supervisor.lease(owner,other),/browser_profile_owner_changed/);
  await f.supervisor.closeOwner(owner);
  await f.supervisor.callTool('browser_snapshot',{},'b'.repeat(64),principal);
  assert.deepEqual(restored,[current]);assert.notEqual(profiles[0],profiles[1]);
  await f.supervisor.callTool('browser_snapshot',{},'e'.repeat(64),other);
  assert.equal(restored.length,1,'unrelated principal does not import another login');
  assert.equal(fs.statSync(path.join(f.browser.profileRoot,'login-state',principal+'.json')).mode&0o777,0o600);
});

test('a failed login restore cannot admit later calls or overwrite the prior snapshot',{skip:!installed},async t=>{
  const principal='c'.repeat(64);let dispatched=0;
  const f=await fixture(t,{persistLogin:true,call:async(params,get)=>{await get();dispatched++;return {content:[]}}});
  const folder=path.join(f.browser.profileRoot,'login-state');fs.mkdirSync(folder,{mode:0o700});const file=path.join(folder,principal+'.json');fs.writeFileSync(file,'invalid',{mode:0o600});
  await assert.rejects(f.supervisor.callTool('browser_snapshot',{},owner,principal));
  assert.equal((await f.supervisor.callTool('browser_snapshot',{},owner,principal)).isError,true);
  assert.equal(dispatched,0);await f.supervisor.closeOwner(owner);assert.equal(fs.readFileSync(file,'utf8'),'invalid');
});
