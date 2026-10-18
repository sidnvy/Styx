import test from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {createStyxGateway} from '../index.mjs';

const target = (id, allowed=true) => ({id, allowed, kind:'host', platform:'linux',
  generation:'g1', cwd:'/private/work', shell:'/bin/sh', shells:['/bin/sh'],
  exec:{transport:'outbound',token_file:'/private/token'},
  computer:{enabled:true,transport:'outbound'}});

test('passive explicit status keeps admission, connection and readiness separate', async t => {
  let connections=0;
  const gateway=createStyxGateway({catalog:{version:1,default_environment_id:'a',
    targets:[target('a'),target('secret',false)]},computer:null,
    connect:async()=>{connections++;throw Error('must not connect')}});
  const server=gateway.serverForOwner('authenticated-owner');
  const [a,b]=InMemoryTransport.createLinkedPair();
  const client=new Client({name:'test',version:'1'});
  await server.connect(a);await client.connect(b);
  t.after(async()=>{await client.close();await server.close();await gateway.close()});
  const call=args=>client.callTool({name:'get_execution_environment_status',arguments:args});
  for(const args of [{},{environment_id:''},{environment_id:'a',probe:true}])
    assert.equal((await call(args)).isError,true);
  assert.deepEqual(await call({environment_id:'secret'}),await call({environment_id:'missing'}));
  let result=(await call({environment_id:'a'})).structuredContent;
  assert.equal(result.exec.connection,'offline');
  assert.equal(result.computer.connection,'offline');
  const entry={generation:'g1',closed:false,claimed:false,ws:{readyState:1,terminate(){}}};
  gateway.relay.sessions.set('a',entry);
  gateway.relay.computerPeers.set('a',new Set([entry]));
  result=(await call({environment_id:'a'})).structuredContent;
  assert.equal(result.exec.connection,'connected');
  assert.equal(result.computer.connection,'connected');
  assert.equal(result.computer.permission,'unknown');
  assert.equal(result.computer.readiness,'unknown');
  assert.equal(result.exec.version,'unknown');
  assert.equal(entry.claimed,false);
  assert.equal(connections,0);
  assert.doesNotMatch(JSON.stringify(result),/private|token|generation|g1/);
  gateway.registry.targets.set('a',{...gateway.registry.resolve('a'),generation:'g2'});
  result=(await call({environment_id:'a'})).structuredContent;
  assert.equal(result.exec.connection,'offline');
  assert.equal(result.computer.connection,'offline');
  gateway.registry.revokeHost('a');
  assert.equal((await call({environment_id:'a'})).isError,true);
});
