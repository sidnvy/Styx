import test from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {createStyxGateway} from '../index.mjs';
const tick=()=>new Promise(r=>setImmediate(r));
test('real MCP request holds admission before async provider lookup; Gateway-wide fence includes remote device',async t=>{
 let releaseLookup,lookupEntered=false,mutations=0;const lookup=new Promise(r=>releaseLookup=r),tool={name:'browser_test',description:'fixture',inputSchema:{type:'object',properties:{environment_id:{type:'string'}}}};
 const browser={bindPrincipal(){},async listTools(){lookupEntered=true;await lookup;return[tool]},async callTool(){mutations++;return{content:[{type:'text',text:'done'}]}},async close(){}};
 const gateway=createStyxGateway({catalog:{version:1,default_environment_id:'remote',targets:[{id:'remote',kind:'host',platform:'linux',generation:'one',cwd:'/tmp',shell:'/bin/sh',shells:['/bin/sh'],allowed:true,exec:{transport:'outbound',token_file:'/tmp/unused-admission-token'},browser:{enabled:true,transport:'outbound'}}]},browser,computer:null});
 const client=new Client({name:'admission-test',version:'1'}),server=gateway.serverForOwner('owner'),[a,b]=InMemoryTransport.createLinkedPair();await server.connect(a);await client.connect(b);t.after(async()=>{await client.close();await gateway.close()});
 const first=client.callTool({name:'browser_test',arguments:{environment_id:'remote'}});while(!lookupEntered)await tick();const id='a'.repeat(32);assert.equal(gateway.workAdmission.begin({ticketId:id,scope:'all'}).status,'waiting');
 const rejected=await client.callTool({name:'browser_test',arguments:{environment_id:'remote'}});assert.equal(rejected.structuredContent.error,'device_in_maintenance');assert.equal(mutations,0);releaseLookup();assert.equal((await first).isError,undefined);assert.equal(mutations,1);assert.equal(gateway.workAdmission.commit(id).status,'ready');gateway.workAdmission.cancel(id);await client.callTool({name:'browser_test',arguments:{environment_id:'remote'}});assert.equal(mutations,2);
});

test('experimental CAS without job-drain contract never claims Gateway-wide maintenance ready',async()=>{
 const gateway=createStyxGateway({catalog:{version:1,targets:[]},cas:{}});assert.equal(gateway.workAdmission.begin({ticketId:'b'.repeat(32),scope:'all'}).status,'unknown');gateway.workAdmission.cancel('b'.repeat(32));await gateway.close();
});

import {createHostWorkAdmission,observeOwnedHostSettlement} from '../../shared/work-admission.mjs';
const ticket='c'.repeat(32);
function fixture(){
 const target=id=>({id,kind:'host',platform:'linux',generation:'one',cwd:'/tmp',shell:'/bin/sh',shells:['/bin/sh'],allowed:true,exec:{transport:'outbound',token_file:'/tmp/unused-admission-token'}});
 return createStyxGateway({catalog:{version:1,default_environment_id:'local',targets:[target('local'),target('remote')]},computer:null,browser:null});
}
function hostProof(gateway,lanes=['exec','computer','browser']){
 const host=createHostWorkAdmission('local',{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'d'.repeat(32),lanes});
 host.begin({ticketId:ticket,scope:'all'});return {host,proof:observeOwnedHostSettlement(host,ticket,{gatewayAdmission:gateway.workAdmission})};
}
function uncertain(gateway,operationId,lane='computer',deviceId='local',deviceGeneration='one'){
 gateway.workAdmission.markUnknown({deviceId,deviceGeneration,lane,operationId});
}
test('same fenced owned Host settles GUI liveness without changing uncertain outcomes or replaying tools',async()=>{
 const gateway=fixture();try{
 uncertain(gateway,'gui');uncertain(gateway,'browser','browser');assert.equal(gateway.workAdmission.begin({ticketId:ticket}).status,'unknown');
 const {proof}=hostProof(gateway);const r=gateway.reconcileOwnedHostWork(proof);assert.equal(r.settled,2);assert.equal(r.status.status,'ready');
 assert.ok(gateway.uncertainWorkHistory().every(r=>r.outcome==='uncertain'&&r.livenessSettled));
 assert.equal(gateway.reconcileOwnedHostWork(proof).settled,0);
 assert.throws(()=>gateway.workAdmission.enter('local','computer'),/device_in_maintenance/);
 }finally{await gateway.close()}
});
test('Exec, unclassified, remote and old-generation history never clear with owned GUI proof',async()=>{
 const gateway=fixture();try{
 uncertain(gateway,'gui');uncertain(gateway,'exec','exec');uncertain(gateway,'other','unknown');uncertain(gateway,'remote','computer','remote');uncertain(gateway,'old','computer','local','zero');
 gateway.workAdmission.begin({ticketId:ticket});const {proof}=hostProof(gateway);assert.equal(gateway.reconcileOwnedHostWork(proof).settled,1);assert.equal(gateway.workAdmission.status(ticket).status,'unknown');
 assert.equal(gateway.uncertainWorkHistory().filter(r=>!r.livenessSettled).length,4);
 }finally{await gateway.close()}
});
test('forged, cancelled, missing-lane and non-all-scope proofs cannot settle GUI work',async()=>{
 for(const mode of ['fake','cancelled','missing','scope']){
 const gateway=fixture();try{
 uncertain(gateway,'gui');gateway.workAdmission.begin({ticketId:ticket});
 const {host,proof}=hostProof(gateway,mode==='missing'?['exec']:undefined);if(mode==='cancelled')host.cancel(ticket);if(mode==='scope'){gateway.workAdmission.cancel(ticket);gateway.workAdmission.begin({ticketId:ticket,scope:'local'});}
 assert.throws(()=>gateway.reconcileOwnedHostWork(mode==='fake'?{...proof}:proof),/owned_host_settlement_unavailable/);assert.equal(gateway.uncertainWorkHistory()[0].livenessSettled,false);
 }finally{await gateway.close()}}
});
test('active work and changed authenticated relay peer prevent settling history',async()=>{
 for(const mode of ['active','peer']){
 const gateway=fixture();let release;try{
 uncertain(gateway,'gui');if(mode==='active')release=gateway.workAdmission.enter('local','computer');gateway.workAdmission.begin({ticketId:ticket});
 if(mode==='peer')gateway.relay.sessions.set('local',{id:'local',lane:'exec',generation:'one'});
 const {proof}=hostProof(gateway);assert.throws(()=>gateway.reconcileOwnedHostWork(proof),/owned_host_settlement_unavailable/);assert.equal(gateway.uncertainWorkHistory()[0].livenessSettled,false);
 }finally{release?.();gateway.relay.sessions.clear();await gateway.close()}}
});
test('real MCP dispatch records the actual provider lane and uncertain operation identity',async t=>{
 const observations=[];const tool={name:'browser_fixture',description:'fixture',inputSchema:{type:'object',properties:{environment_id:{type:'string'}}}};
 const gateway=createStyxGateway({catalog:{version:1,targets:[{id:'local',kind:'host',platform:'linux',generation:'one',cwd:'/tmp',shell:'/bin/sh',shells:['/bin/sh'],allowed:true,exec:{transport:'outbound',token_file:'/tmp/unused-admission-token'},browser:{enabled:true,transport:'outbound'}}]},computer:null,browser:{async listTools(){return[tool]},async callTool(){return{structuredContent:{uncertain:true},content:[]}},async close(){}},onToolResult:result=>observations.push(result)});
 const client=new Client({name:'lane-test',version:'1'}),server=gateway.serverForOwner('owner'),[a,b]=InMemoryTransport.createLinkedPair();await server.connect(a);await client.connect(b);t.after(async()=>{await client.close();await gateway.close()});
 await client.callTool({name:'browser_fixture',arguments:{environment_id:'local'}});assert.equal(observations[0].lane,'browser');const [record]=gateway.uncertainWorkHistory();assert.equal(record.lane,'browser');assert.equal(record.operationId,observations[0].operationId);assert.equal(record.deviceGeneration,'one');
});

test('cancelling and recreating Gateway fence invalidates a previously valid Host proof',async()=>{
 const gateway=fixture();try{uncertain(gateway,'gui');gateway.workAdmission.begin({ticketId:ticket});const {proof}=hostProof(gateway);gateway.workAdmission.cancel(ticket);gateway.workAdmission.begin({ticketId:ticket});assert.throws(()=>gateway.reconcileOwnedHostWork(proof),/owned_host_settlement_unavailable/);assert.equal(gateway.uncertainWorkHistory()[0].livenessSettled,false);}finally{await gateway.close()}
});
test('Host-only unbound proof and later Host active work cannot authorize Gateway reconciliation',async()=>{
 for(const mode of ['unbound','host-active']){
 const gateway=fixture();let release;try{
 uncertain(gateway,'gui');gateway.workAdmission.begin({ticketId:ticket});const {host,proof:bound}=hostProof(gateway);
 const proof=mode==='unbound'?observeOwnedHostSettlement(host,ticket):bound;
 if(mode==='host-active')release=host.enter('local','exec',{continuation:true});
 assert.throws(()=>gateway.reconcileOwnedHostWork(proof),/owned_host_settlement_unavailable/);assert.equal(gateway.uncertainWorkHistory()[0].livenessSettled,false);
 }finally{release?.();await gateway.close()}}
});
