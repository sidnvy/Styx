import test from 'node:test';
import assert from 'node:assert/strict';
import {CuaProvider} from '../cua.mjs';
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const tick=()=>new Promise(r=>setImmediate(r));
function fixture(options={}) {
  const target={id:'mac',generation:1,computer:{enabled:true}};
  const calls=[];let connects=0,closes=0;
  const provider=new CuaProvider({registry:{resolve:()=>target},connect:async()=>{
    connects++;
    return {getServerVersion:()=>({name:'cua-driver',version:'0.36.0'}),
      callTool:async input=>{calls.push(input);return options.call?options.call(input):{content:[]};},
      close:async()=>{closes++;}};
  },...options});
  return {provider,calls,target,get connects(){return connects;},get closes(){return closes;}};
}
test('shared transport queues owners FIFO and retires only closed owner context',async t=>{
  const gate=deferred();let first=true;
  const f=fixture({call:async()=>{if(first){first=false;await gate.promise;}return {content:[]};}});
  t.after(()=>f.provider.close());
  const a=f.provider.callTool('list_apps',{},'alice');
  await tick();
  const b=f.provider.callTool('list_apps',{},'bob');
  await tick();
  assert.equal(f.connects,1);assert.equal(f.calls.length,1);
  await f.provider.closeOwner('alice');assert.equal(f.closes,0);
  gate.resolve();await Promise.all([a,b]);
  assert.equal(f.calls.length,2);
  assert.notEqual(f.calls[0].arguments.session,f.calls[1].arguments.session);
  const bob=f.calls[1].arguments.session;
  await f.provider.callTool('list_apps',{},'bob');
  assert.equal(f.calls[2].arguments.session,bob);
  await f.provider.callTool('list_apps',{},'alice');
  assert.notEqual(f.calls[3].arguments.session,f.calls[0].arguments.session);
});
test('queue is bounded, idle reaper respects queued work and closed owners never dispatch',async t=>{
  let now=0;const gate=deferred();
  const f=fixture({maxQueue:2,idleMs:1000,clock:()=>now,call:()=>gate.promise});
  t.after(()=>f.provider.close());
  const a=f.provider.callTool('list_apps',{},'alice');await tick();
  const b=f.provider.callTool('list_apps',{},'bob');await tick();
  const c=await f.provider.callTool('list_apps',{},'carol');
  assert.equal(c.structuredContent.error,'computer_queue_full');
  now=5000;await f.provider.reapIdle();assert.equal(f.closes,0);
  await f.provider.closeOwner('bob');gate.resolve({content:[]});await a;
  assert.equal((await b).structuredContent.error,'computer_owner_closed');
  assert.equal(f.calls.length,1);
  now=7000;await f.provider.reapIdle();assert.equal(f.closes,1);
});
test('model cannot choose native session and ambiguous actions are not replayed',async t=>{
  const f=fixture({call:async()=>{throw Error('transport dropped');}});
  t.after(()=>f.provider.close());
  const forged=await f.provider.callTool('list_apps',{session:'other'},'alice');
  assert.equal(forged.structuredContent.error,'invalid_arguments');
  const result=await f.provider.callTool('click',{target:{kind:'window'}},'alice');
  assert.equal(result.structuredContent.uncertain,true);assert.equal(f.calls.length,1);
});
test('native globally shared tokens cannot cross owners, and invalidated observations require reread',async t=>{
  let serial=0,last;
  const f=fixture({call:async input=>{
    if(input.name==='get_window_state') {
      const snapshot_id='s'+(++serial).toString(16).padStart(8,'0');
      const data={snapshot_id,capture_id:'capture_'+serial,screenshot_frame_valid:true,
        invalidated_snapshot_ids:last?[last]:[]};last=snapshot_id;
      return {structuredContent:data,content:[]};
    }
    return {content:[]};
  }});
  t.after(()=>f.provider.close());
  await f.provider.callTool('get_window_state',{pid:1,window_id:2},'alice');
  const stolen=await f.provider.callTool('click',{element_token:'s00000001:3'},'bob');
  assert.equal(stolen.structuredContent.error,'computer_snapshot_required');assert.equal(f.calls.length,1);
  await f.provider.callTool('get_window_state',{pid:1,window_id:2},'bob');
  const stale=await f.provider.callTool('click',{element_token:'s00000001:3'},'alice');
  assert.equal(stale.structuredContent.error,'computer_snapshot_required');
  const pixels=await f.provider.callTool('click',{pid:1,window_id:2,x:10,y:20},'alice');
  assert.equal(pixels.structuredContent.error,'computer_snapshot_required');
  await f.provider.callTool('click',{element_token:'s00000002:3'},'bob');
  assert.equal(f.calls.length,3);
  await f.provider.callTool('get_window_state',{pid:1,window_id:2},'alice');
  await f.provider.callTool('click',{pid:1,window_id:2,x:10,y:20},'alice');
  assert.equal(f.calls.length,5);
});
