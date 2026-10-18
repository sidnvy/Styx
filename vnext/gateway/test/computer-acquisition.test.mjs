import test from 'node:test';
import assert from 'node:assert/strict';
import {WebSocket} from 'ws';
import {OutboundHostRelay} from '../outbound.mjs';
function fixture(t,wait=50){
  const target={id:'owned',generation:'first',computer:{transport:'outbound'}};
  let current=target;
  const relay=new OutboundHostRelay({computerAcquireWaitMs:wait,registry:{resolve(){
    if(!current)throw Error('environment_access_denied');return current;
  }}});
  t.after(()=>relay.close());
  const peer={id:target.id,lane:'computer',generation:target.generation,closed:false,
    claimed:false,ws:{readyState:WebSocket.OPEN,close(){},terminate(){}}};
  return {target,relay,peer,setCurrent:value=>{current=value}};
}
test('fresh pre-dispatch Computer lease waits for authenticated reconnect without sending a tool',async t=>{
  const f=fixture(t);let sent=0;f.peer.ws.send=()=>sent++;
  const opening=f.relay.acquireComputer(f.target);
  setTimeout(()=>f.relay.computerPeers.set(f.target.id,new Set([f.peer])),5);
  const transport=await opening;
  assert.equal(f.peer.claimed,true);assert.equal(sent,0);await transport.close();
});
test('Computer reconnect waiting refuses revoked and replaced admission',async t=>{
  for(const kind of ['revoke','replace']){
    const f=fixture(t);const opening=f.relay.acquireComputer(f.target);
    setTimeout(()=>f.setCurrent(kind==='revoke'?null:{...f.target,generation:'second'}),5);
    await assert.rejects(opening,kind==='revoke'?/environment_access_denied/:/computer_generation_changed/);
    assert.equal(f.peer.claimed,false);
  }
});
test('offline wait is bounded, while busy native slots fail without waiting or dispatch',async t=>{
  const f=fixture(t,5);await assert.rejects(f.relay.acquireComputer(f.target),/computer_host_offline/);
  f.peer.claimed=true;f.relay.computerPeers.set(f.target.id,new Set([f.peer]));
  await assert.rejects(f.relay.acquireComputer(f.target),/computer_slots_busy/);
});
