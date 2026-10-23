import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createHostWorkAdmission} from '../../shared/work-admission.mjs';
import {prepareHostUpdateAdmission,readHostUpdateAdmission,commitHostUpdateAdmission,cancelHostUpdateAdmission} from '../host-update-admission.mjs';

async function fixture(t,{complete=true}={}){
 const gateway=createStyxGateway({catalog:{version:1,targets:[{id:'local',kind:'host',platform:'linux',generation:'one',cwd:'/tmp',shell:'/bin/sh',shells:['/bin/sh'],allowed:true,exec:{transport:'outbound',token_file:'/tmp/unused-settlement-token'},browser:{enabled:true,transport:'outbound'}}]},computer:null,browser:{
  async listTools(){return[{name:'browser_fixture',description:'fixture',inputSchema:{type:'object',properties:{environment_id:{type:'string'}}}}]},
  async callTool(){return{content:[],structuredContent:{uncertain:true}}},async close(){}
 }});
 const host=createHostWorkAdmission('local',complete?{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'a'.repeat(32),lanes:['exec','browser']}:undefined);
 const peer=host.openPeer('browser');
 const client=new Client({name:'core-settlement-test',version:'1'}),server=gateway.serverForOwner('owner'),[a,b]=InMemoryTransport.createLinkedPair();
 await server.connect(a);await client.connect(b);
 const stateDir='/tmp/styx-core-settlement-'+randomUUID(),options={gateway,localHost:host,ownsGateway:true,requiresLocalHost:true};
 let admission;
 t.after(async()=>{if(admission)cancelHostUpdateAdmission({stateDir,ticketId:admission.ticketId});peer.close();await client.close();await gateway.close()});
 return {gateway,host,peer,client,stateDir,
  prepare(overrides={}){return admission=prepareHostUpdateAdmission({stateDir,purpose:'quit'},{...options,...overrides})},
  read(){return readHostUpdateAdmission({stateDir,ticketId:admission.ticketId})},
  commit(){return commitHostUpdateAdmission({stateDir,ticketId:admission.ticketId})}
 };
}

test('Core waits for the local terminal reply then reconciles GUI history under the same fences',async t=>{
 const f=await fixture(t);
 f.peer.request({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'fixture'}});
 const result=await f.client.callTool({name:'browser_fixture',arguments:{environment_id:'local'}});
 assert.equal(result.structuredContent.uncertain,true);
 const first=f.prepare();assert.equal(first.status,'unknown');assert.equal(first.active,1);
 assert.throws(()=>f.host.enter('local','browser'),/device_in_maintenance/);
 f.peer.response({jsonrpc:'2.0',id:1,result:{content:[]}});
 assert.equal(f.read().status,'unknown','a status read does not mutate reconciliation');
 const settled=f.prepare();assert.equal(settled.ticketId,first.ticketId);assert.equal(settled.status,'ready');
 const [history]=f.gateway.uncertainWorkHistory();assert.equal(history.outcome,'uncertain');assert.equal(history.livenessSettled,true);
 assert.equal(f.commit().exitAuthorized,true);
});

test('Core keeps a disconnect before terminal response blocked even after the Gateway call returns',async t=>{
 const f=await fixture(t);
 f.peer.request({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'fixture'}});f.peer.close();
 await f.client.callTool({name:'browser_fixture',arguments:{environment_id:'local'}});
 assert.equal(f.prepare().status,'unknown');assert.throws(()=>f.commit(),/maintenance_work_not_settled/);
 assert.equal(f.gateway.uncertainWorkHistory()[0].livenessSettled,false);
});

test('Core never treats unverified Host coverage as evidence for a quiet Gateway',async t=>{
 const f=await fixture(t,{complete:false});
 await f.client.callTool({name:'browser_fixture',arguments:{environment_id:'local'}});
 assert.equal(f.prepare().status,'unknown');assert.throws(()=>f.commit(),/maintenance_work_not_settled/);
 assert.equal(f.gateway.uncertainWorkHistory()[0].livenessSettled,false);
});

test('Core reconciliation leaves uncertain Exec work blocking maintenance',async t=>{
 const f=await fixture(t);
 await f.client.callTool({name:'browser_fixture',arguments:{environment_id:'local'}});
 f.gateway.workAdmission.markUnknown({deviceId:'local',deviceGeneration:'one',lane:'exec',operationId:'exec-unknown'});
 assert.equal(f.prepare().status,'unknown');assert.throws(()=>f.commit(),/maintenance_work_not_settled/);
 const history=f.gateway.uncertainWorkHistory();assert.equal(history.find(x=>x.lane==='browser').livenessSettled,true);assert.equal(history.find(x=>x.lane==='exec').livenessSettled,false);
});

test('repeated preparation rejects a replacement Host with active work and changed owner scope',async t=>{
 const f=await fixture(t);assert.equal(f.prepare().status,'ready');
 const replacement=createHostWorkAdmission('local',{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'b'.repeat(32),lanes:['exec','browser']});
 const peer=replacement.openPeer('browser');t.after(()=>peer.close());
 peer.request({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'fixture'}});
 assert.equal(replacement.active.size,1);
 assert.throws(()=>f.prepare({localHost:replacement}),/maintenance_owner_changed/);
 assert.throws(()=>f.prepare({ownsGateway:false}),/maintenance_owner_changed/);
 assert.throws(()=>f.prepare({requiresLocalHost:false}),/maintenance_owner_changed/);
 assert.equal(f.prepare().status,'ready','the original fence remains available to its actual owners');
});
