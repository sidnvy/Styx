import test from 'node:test';
import assert from 'node:assert/strict';
import {ConversationOwners} from '../conversation-owners.mjs';

test('conversation ownership is request-local under concurrency and idle cleanup respects active work',async()=>{
 let now=0,finish;const closed=[],busy=new Set();
 const owners=new ConversationOwners({key:'a'.repeat(64),principal:'credential-authority-a',clock:()=>now,gateway:{hasOwnerWork:o=>busy.has(o),closeOwner:async o=>closed.push(o)}});
 const meta={'openai/subject':'user','openai/session':'chat'};
 let activeOwner;
 const active=owners.run(meta,async owner=>{activeOwner=owner;await new Promise(r=>finish=r);return owner;});
 const other=await owners.run({...meta,'openai/session':'other'},async owner=>owner);
 assert.notEqual(activeOwner,other);
 now=1000;await owners.reap(100);assert.deepEqual(closed,[other]);
 finish();assert.equal(await active,activeOwner);
 busy.add(activeOwner);now=2000;await owners.reap(100);assert.equal(closed.length,1);
 busy.clear();await owners.reap(100);assert.deepEqual(closed,[other,activeOwner]);
 const rotated=new ConversationOwners({key:'a'.repeat(64),principal:'credential-authority-b',gateway:{}});
 assert.notEqual(await rotated.run(meta,async o=>o),activeOwner);
});

// An idle cleanup can yield while the same conversation reconnects. New work
// must start after that cleanup, or the old close can destroy its resources.
test('a returning conversation waits for its in-progress cleanup before dispatch',async()=>{
 let now=0,releaseClose,startedClose;const resources=new Map();
 const closing=new Promise(resolve=>startedClose=resolve);
 const owners=new ConversationOwners({key:'a'.repeat(64),principal:'authority',clock:()=>now,gateway:{
  closeOwner:async owner=>{startedClose();await new Promise(resolve=>releaseClose=resolve);resources.delete(owner);}
 }});
 const meta={'openai/subject':'user','openai/session':'chat'};
 const original=await owners.run(meta,async owner=>{resources.set(owner,'old');return owner;});
 now=1000;const cleanup=owners.reap(100);await closing;
 let dispatched=false;const reconnect=owners.run(meta,async owner=>{dispatched=true;resources.set(owner,'new');return owner;});
 await Promise.resolve();const raced=dispatched;
 releaseClose();await cleanup;const returned=await reconnect;
 assert.equal(raced,false,'reconnect dispatched while old owner resources were still closing');
 assert.equal(returned,original);assert.equal(resources.get(original),'new');
});
