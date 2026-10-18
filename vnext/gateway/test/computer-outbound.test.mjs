import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';

const canRun=process.platform==='linux';
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(f,timeout=11000){
  const end=Date.now()+timeout;
  while(Date.now()<end){
    if(f())return;
    await wait(50);
  }
  throw Error('computer_relay_not_connected');
}

async function setup(t,{slots=2,native=false}={}){
  const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'styx-native-mcp-reverse-'));
  let child,server;
  const clients=[];
  t.after(async()=>{
    await Promise.allSettled(clients.map(c=>c.close()));
    if(child && child.exitCode===null && child.signalCode===null){
      child.kill('SIGTERM');
      await Promise.race([new Promise(r=>child.once('close',r)),wait(1400)]);
      if(child.exitCode===null && child.signalCode===null)child.kill('SIGKILL');
    }
    await server?.close();
    await fs.rm(tmp,{recursive:true,force:true});
  });
  const hostBearer=randomBytes(34).toString('hex');
  const inbound=randomBytes(34).toString('hex');
  const tokenFile=path.join(tmp,'host.token');
  await fs.writeFile(tokenFile,hostBearer,{mode:0o600});
  const fixture=path.resolve('gateway/test/fixtures/cua-driver-mcp.mjs');
  await fs.chmod(fixture,0o755);
  const computerBinary=native
    ? '/tmp/styx-cua-linux-Hp38ba/cua-driver' : fixture;
  const target={id:'cua-pilot',kind:'host',platform:'linux',generation:'g1',
    allowed:true,cwd:tmp,shell:'/bin/sh',shells:['/bin/sh'],
    exec:{transport:'outbound',token_file:tokenFile},
    computer:{enabled:true,transport:'outbound',max_connections:slots}};
  const gateway=createStyxGateway({catalog:{version:1,
    default_environment_id:target.id,targets:[target]}});
  const allowedHosts=[];
  server=await createGatewayHttp(gateway,{token:inbound,port:0,allowedHosts});
  const port=server.address.port;allowedHosts.push('127.0.0.1:'+port);
  const cfg={host_id:target.id,gateway_ws_url:'ws://127.0.0.1:'+port,
    token_file:tokenFile,
    exec:{binary:path.resolve('packages/styx-exec-adapter/.runtime/codex'),cwd:tmp,
      env:{CODEX_HOME:path.join(tmp,'codex-home')}},
    computer:{enabled:true,binary:computerBinary,connections:slots}};
  await fs.mkdir(cfg.exec.env.CODEX_HOME);
  const cfgPath=path.join(tmp,'host.json');
  await fs.writeFile(cfgPath,JSON.stringify(cfg),{mode:0o600});
  child=spawn(process.execPath,['host/connect.mjs',cfgPath],{
    cwd:path.resolve('.'),stdio:['ignore','pipe','pipe'],
    env:{...process.env,DO_NOT_TRACK:'1'}
  });
  child.stdout.resume();child.stderr.resume();
  await until(()=>gateway.relay.connected(target.id)&&
    gateway.relay.computerConnected(target.id)===slots);
  async function newClient(){
    const transport=new StreamableHTTPClientTransport(
      new URL('http://127.0.0.1:'+port+'/mcp'),{
        requestInit:{headers:{Authorization:'Bearer '+inbound}}
      });
    const client=new Client({name:'styx-cua-session-test',version:'0.1.0'});
    await client.connect(transport);
    clients.push(client);
    return client;
  }
  return {gateway,child,newClient};
}

test('native computer lane requires an admitted, enabled target',{skip:!canRun},async t=>{
  const {gateway,newClient}=await setup(t);
  const c=await newClient();
  const tools=await c.listTools();
  assert.ok(tools.tools.some(x=>x.name==='get_window_state'));
  const appSchema=tools.tools.find(x=>x.name==='list_apps').inputSchema;
  assert.equal(appSchema.properties.session,undefined);
  const list=await c.callTool({name:'list_execution_environments',arguments:{}});
  assert.ok(list.structuredContent.environments[0].capabilities.includes('computer'));
});
test('dedicated Cua MCP connection per owner; cannot reuse another lease',
  {skip:!canRun},async t=>{
  const {gateway,newClient}=await setup(t);
  const a=await newClient(), b=await newClient(), c=await newClient();
  const call=client=>client.callTool({name:'list_apps',arguments:{}});
  const one=await call(a),two=await call(b);
  assert.equal(one.isError,false);
  assert.equal(two.isError,false);
  const leaseA=one.structuredContent.lease, leaseB=two.structuredContent.lease;
  assert.notEqual(leaseA,leaseB,'separate model sessions must own distinct MCP workers');
  assert.deepEqual(one.structuredContent.args,{});
  const denied=await call(c);
  assert.equal(denied.isError,true);
  assert.equal(denied.structuredContent.error,'computer_transport_unavailable');
  assert.equal(gateway.relay.computerConnected('cua-pilot'),2);
  const still=await call(b);
  assert.equal(still.structuredContent.lease,leaseB);
});
test('unseen native session labels refused; loss of GUI action transport is uncertain',
  {skip:!canRun},async t=>{
  const {gateway,newClient}=await setup(t,{slots:1});
  const a=await newClient();
  const unseen=await a.callTool({name:'list_apps',arguments:{session:'other-owner'}});
  assert.equal(unseen.isError,true);
  assert.equal(unseen.structuredContent.error,'invalid_arguments');
  const known=await a.callTool({name:'list_apps',arguments:{}});
  assert.equal(known.isError,false);
  const dispatch=a.callTool({name:'click',arguments:{element_token:'simulate-unknown'}});
  await wait(130);
  const entry=[...gateway.relay.computerPeers.get('cua-pilot')][0];
  entry.ws.terminate();
  const reply=await dispatch;
  assert.equal(reply.isError,true);
  assert.equal(reply.structuredContent.uncertain,true);
  await until(()=>gateway.relay.computerConnected('cua-pilot')===1);
  // An old MCP session is intentionally NOT resumed or replayed.
  const lost=await a.callTool({name:'list_apps',arguments:{}});
  assert.equal(lost.isError,true);
  assert.equal(lost.structuredContent.error,'computer_session_lost');
});
test('real native Cua Driver over loopback reverse MCP, read-only',
  {skip:!canRun||process.env.STYX_LIVE_CUA_TEST!=='1'},async t=>{
  const {newClient}=await setup(t,{slots:1,native:true});
  const c=await newClient();
  const res=await c.callTool({name:'list_apps',arguments:{}});
  assert.notEqual(res.isError,true);
  assert.ok(Array.isArray(res.structuredContent?.apps));
});
