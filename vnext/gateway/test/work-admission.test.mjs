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
