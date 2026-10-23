import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {RpcClient,ExecConnection,stdioClient} from '../rpc.mjs';
import {ExecAdapter} from '../adapter.mjs';
function clientFixture(){
 const channel=new EventEmitter();channel.send=()=>{};channel.close=()=>{};
 const client=new RpcClient(channel),send=(method,params)=>channel.emit('message',JSON.stringify({method,params}));
 return {client,channel,send};
}
test('native terminal observations require the registered process, both events, exit code and ordered sequence',()=>{
 const {client,send}=clientFixture(),seen=[];const stop=client.observeProcess('owned',x=>seen.push(x));
 send('process/exited',{processId:'foreign',seq:1,exitCode:0});send('process/closed',{processId:'foreign',seq:2});assert.deepEqual(seen,[]);
 send('process/exited',{processId:'owned',seq:2,exitCode:0});assert.deepEqual(seen,[]);
 send('process/closed',{processId:'owned',seq:3});assert.deepEqual(seen,[{settled:true,unknown:false}]);stop();assert.equal(client.processObservers.size,0);
 for(const params of [{seq:0,exitCode:0},{seq:1,exitCode:'0'},{seq:1.5,exitCode:0}]){
  const observations=[];client.observeProcess('bad',x=>observations.push(x));send('process/exited',{processId:'bad',...params});assert.deepEqual(observations,[{settled:false,unknown:true}]);assert.equal(client.processObservers.size,0);
 }
 const reversed=[];client.observeProcess('order',x=>reversed.push(x));send('process/exited',{processId:'order',seq:3,exitCode:0});send('process/closed',{processId:'order',seq:2});assert.deepEqual(reversed,[{settled:false,unknown:true}]);client.fail();
});
test('per-process subscriptions share one channel listener and transport loss invalidates observations',()=>{
 const {client,channel,send}=clientFixture(),seen=[],stops=[];
 for(let i=0;i<100;i++)stops.push(client.observeProcess(String(i),x=>seen.push(x)));
 assert.equal(channel.listenerCount('message'),1);for(const stop of stops.slice(0,99))stop();
 send('process/exited',{processId:'99',seq:1,exitCode:0});send('process/closed',{processId:'99',seq:2});assert.equal(seen.at(-1).settled,true);
 client.fail();assert.deepEqual(seen.at(-1),{settled:false,unknown:true,transportLost:true});assert.equal(client.processObservers.size,0);stops[99]();
});
const binary=process.env.STYX_COMPLETION_CODEX_BINARY;
test('real completed command retains owner and unread output without blocking on another poll',{skip:!binary||process.platform==='win32',timeout:10000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-completion-'));fs.mkdirSync(path.join(root,'codex-home'));
 const runtime=await new ExecConnection(()=>stdioClient({binary,cwd:root,env:{HOME:root,CODEX_HOME:path.join(root,'codex-home'),PATH:'/usr/bin:/bin'}})).initialize();
 const adapter=new ExecAdapter({resolve:async()=>({id:'owned',generation:'one',runtime,cwd:root,platform:'linux',shell:'/bin/sh',shells:['/bin/sh'],env:{PATH:'/usr/bin:/bin'}})});
 t.after(async()=>{await adapter.cleanup();await runtime.close();fs.rmSync(root,{recursive:true,force:true})});
 const first=await adapter.execCommand({cmd:'printf start; sleep 0.2; printf tail',login:false,yield_time_ms:1000,max_output_tokens:100},'owner');
 assert(first.session_id);assert.equal(first.output,'start');const record=adapter.sessions.get(first.session_id),cursor=record.cursor;assert.equal(record.executionSettled,false);
 for(let i=0;i<200&&!record.executionSettled;i++)await new Promise(r=>setTimeout(r,10));
 assert.equal(record.executionSettled,true);assert.equal(record.executionUnknown,false);assert.equal(record.cursor,cursor);assert.equal(adapter.sessions.get(first.session_id),record);
 await assert.rejects(adapter.writeStdin({session_id:first.session_id,chars:''},'other'),/unknown_session/);
 const final=await adapter.writeStdin({session_id:first.session_id,chars:'',yield_time_ms:1000},'owner');assert.equal(final.output,'tail');assert.equal(final.exit_code,0);assert.equal(adapter.sessions.size,0);assert.equal(runtime.client.processObservers.size,0);
 const another=await adapter.execCommand({cmd:'printf done',login:false,yield_time_ms:1000,max_output_tokens:1},'owner');assert(another.session_id);
 const completed=adapter.sessions.get(another.session_id);for(let i=0;i<200&&!completed.executionSettled;i++)await new Promise(r=>setTimeout(r,10));assert.equal(completed.executionSettled,true);
 await runtime.close();assert.equal(completed.executionSettled,true);assert.equal(completed.executionUnknown,false);
});
