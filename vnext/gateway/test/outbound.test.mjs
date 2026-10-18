import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import WebSocket from 'ws';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../index.mjs';
import {createGatewayHttp} from '../http.mjs';
import {normalizeConnector} from '../../host/connect.mjs';

const live=process.env.STYX_LIVE_EXEC_TEST==='1' &&
  process.platform==='linux' && process.arch==='x64';
const binary=path.resolve('packages/styx-exec-adapter/.runtime/codex');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(fn, timeout=8000) {
  const deadline=Date.now()+timeout;
  while(Date.now()<deadline) {
    if(await fn())return;
    await sleep(50);
  }
  throw Error('outbound_pilot_timeout');
}
async function tool(client,name,args) {
  return client.callTool({name,arguments:args});
}
async function complete(client,initial) {
  let r=initial, output=r.structuredContent?.output??'';
  for(let i=0;i<15 && r.structuredContent?.session_id;i++) {
    r=await tool(client,'write_stdin',{session_id:r.structuredContent.session_id,
      chars:'',yield_time_ms:250});
    if(r.isError)throw Error('execution_failed_'+r.structuredContent?.error);
    output+=r.structuredContent.output;
  }
  assert.equal(r.structuredContent?.exit_code,0);
  return output;
}
async function environment(t) {
  const tmp=await fs.mkdtemp(path.join(os.tmpdir(),'styx-outbound-test-'));
  let child,server,client;
  t.after(async()=>{
    await client?.close().catch(()=>{});
    if(child && child.exitCode===null && child.signalCode===null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(r=>child.once('close',r)),sleep(2000)]);
      if(child.exitCode===null && child.signalCode===null) child.kill('SIGKILL');
    }
    await server?.close().catch(()=>{});
    await fs.rm(tmp,{recursive:true,force:true});
  });
  const hostToken=randomBytes(32).toString('hex'),inbound=randomBytes(32).toString('hex');
  const tokenFile=path.join(tmp,'host-token'),codexHome=path.join(tmp,'codex-home');
  await fs.writeFile(tokenFile,hostToken,{mode:0o600});await fs.mkdir(codexHome);
  const catalog={version:1,default_environment_id:'fixture',targets:[{
    id:'fixture',kind:'host',platform:'linux',generation:'generation-1',
    cwd:tmp,shell:'/bin/sh',shells:['/bin/sh'],allowed:true,
    exec:{transport:'outbound',token_file:tokenFile}
  }]};
  const gateway=createStyxGateway({catalog});
  const hosts=[];
  server=await createGatewayHttp(gateway,{token:inbound,port:0,allowedHosts:hosts});
  const port=server.address.port;
  hosts.push('127.0.0.1:'+port);

  const config={host_id:'fixture',gateway_ws_url:'ws://127.0.0.1:'+port,
    token_file:tokenFile,exec:{binary,cwd:tmp,env:{CODEX_HOME:codexHome}}};
  const configFile=path.join(tmp,'host.json');
  await fs.writeFile(configFile,JSON.stringify(config),{mode:0o600});
  child=spawn(process.execPath,['host/connect.mjs',configFile],
    {cwd:path.resolve('.'),stdio:['ignore','pipe','pipe']});
  let stdout='',stderr='';
  child.stdout.on('data',v=>{stdout+=v.toString()});
  child.stderr.on('data',v=>{stderr+=v.toString().slice(0,200)});

  await until(()=>gateway.relay.connected('fixture'));
  client=new Client({name:'styx-outbound-live',version:'0.1.0'});
  await client.connect(new StreamableHTTPClientTransport(
    new URL('http://127.0.0.1:'+port+'/mcp'),
    {requestInit:{headers:{Authorization:'Bearer '+inbound}}}));

  return {gateway,client,port,hostToken,inbound,stdout,stderr};
}
test('connector never accepts remote plaintext WebSocket or inline credentials',()=>{
  const c={host_id:'n',gateway_ws_url:'ws://test.example:80',
    token_file:'/tmp/private',exec:{binary:'/bin/false',cwd:'/tmp'}};
  assert.throws(()=>normalizeConnector(c),/gateway_requires_tls/);
  assert.throws(()=>normalizeConnector({...c,gateway_ws_url:'wss://secret@test.example/'}),
    /gateway_requires_tls/);
  assert.throws(()=>normalizeConnector({...c,gateway_ws_url:'wss://test.example/?secret=abc'}),
    /gateway_requires_tls/);
});
test('loopback native Host connects without Coder, executes shell and PTY via MCP', {skip:!live,timeout:25000}, async t=>{
  const {gateway,client}=await environment(t);
  assert.equal(gateway.relay.connected('fixture'),true);
  const stdout=await complete(client,await tool(client,'exec_command',{
    cmd:'printf STYX_OUTBOUND_PASS',yield_time_ms:250,login:false}));
  assert.equal(stdout,'STYX_OUTBOUND_PASS');
  const first=await tool(client,'exec_command',{cmd:'read line; printf "ACK:%s" "$line"',
    yield_time_ms:0,login:false});
  assert.ok(first.structuredContent.session_id);
  const input=await tool(client,'write_stdin',{session_id:first.structuredContent.session_id,
    chars:'PING\n',yield_time_ms:250});
  assert.equal(await complete(client,input),'ACK:PING');
  assert.equal(await complete(client,await tool(client,'exec_command',{
    cmd:'test -t 0 && printf PTY_OK',yield_time_ms:250,tty:true,login:false})),
  'PTY_OK');
});
test('outbound Host requires its own bearer and rejects unknown and duplicate peers', {skip:!live,timeout:25000}, async t=>{
  const {gateway,port,hostToken}=await environment(t);
  async function connect(host,token,origin) {
    const url='ws://127.0.0.1:'+port+'/styx/hosts/'+host+'/exec';
    const w=new WebSocket(url,{headers:{
      Authorization:'Bearer '+token,...(origin?{Origin:origin}:{})
    },handshakeTimeout:2000});
    return new Promise(resolve=>{
      w.on('unexpected-response',(_,res)=>{const code=res.statusCode;res.resume();resolve(code)});
      w.on('error',()=>resolve(0));
      w.on('open',()=>{w.terminate();resolve(101)});
    });
  }
  assert.equal(await connect('fixture',randomBytes(32).toString('hex')),401);
  assert.equal(await connect('missing',hostToken),403);
  assert.equal(await connect('fixture',hostToken,'https://invalid.example'),401);
  assert.equal(await connect('fixture',hostToken),409);
  assert.equal(gateway.relay.connected('fixture'),true);
});
test('disconnect never replays old process and new Host requires new executor session', {skip:!live,timeout:25000}, async t=>{
  const {gateway,client}=await environment(t);
  const old=await tool(client,'exec_command',{cmd:'sleep 15',yield_time_ms:0,login:false});
  assert.ok(old.structuredContent.session_id);
  const oldSession=old.structuredContent.session_id;
  gateway.relay.sessions.get('fixture').ws.terminate();
  await until(()=>!gateway.relay.connected('fixture'));
  const lost=await tool(client,'write_stdin',{session_id:oldSession,chars:'',yield_time_ms:0});
  assert.equal(lost.isError,true);
  assert.ok(['session_unavailable','session_lost'].includes(lost.structuredContent.error),
    JSON.stringify(lost.structuredContent));
  await until(()=>gateway.relay.connected('fixture'),12000);
  const fresh=await complete(client,await tool(client,'exec_command',{
    cmd:'printf NEW_EXEC_SESSION',yield_time_ms:250,login:false}));
  assert.equal(fresh,'NEW_EXEC_SESSION');
  const oldAgain=await tool(client,'write_stdin',{session_id:oldSession,chars:'',yield_time_ms:0});
  assert.equal(oldAgain.isError,true);
});
