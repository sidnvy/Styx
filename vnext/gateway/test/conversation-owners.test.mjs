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
