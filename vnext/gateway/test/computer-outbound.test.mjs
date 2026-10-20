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
    ? process.env.STYX_CUA_NATIVE_BINARY : fixture;
  if(native && (!computerBinary || !path.isAbsolute(computerBinary)))
    throw Error('STYX_CUA_NATIVE_BINARY_required');
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
    computer:{enabled:true,binary:computerBinary,connections:slots,
      ...(native?{env:{CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}}:{env:{DISPLAY:':styx-protocol-fixture'}})}};
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
    // Client.close() does not send HTTP Session DELETE. Expose this only to
    // the test so the immediate-release path exercises terminateSession().
    client.testTransport=transport;
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
test('one Cua transport serves multiple MCP owners without a slot reservation',
  {skip:!canRun},async t=>{
  const {gateway,newClient}=await setup(t,{slots:1});
  const a=await newClient(), b=await newClient(), c=await newClient();
  const call=client=>client.callTool({name:'list_apps',arguments:{}});
  const one=await call(a),two=await call(b);
  assert.equal(one.isError,false);
  assert.equal(two.isError,false);
  const leaseA=one.structuredContent.lease, leaseB=two.structuredContent.lease;
  assert.equal(leaseA,leaseB,'model sessions share one MCP worker');
  assert.notEqual(one.structuredContent.args.session,two.structuredContent.args.session);
  const third=await call(c);
  assert.equal(third.isError,false);
  assert.equal(third.structuredContent.lease,leaseA);
  assert.equal(gateway.relay.computerConnected('cua-pilot'),1);
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
  const dispatch=a.callTool({name:'press_key',arguments:{key:'STYX_TEST_DISCONNECT'}});
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

test('real Cua on owned Wayland scratch: list window, screenshot, AX and action readback',
  {skip:!canRun || process.env.STYX_LIVE_CUA_GUI_TEST!=='1',timeout:45000},async t=>{
  const {newClient}=await setup(t,{slots:1,native:true});
  const {spawn}=await import('node:child_process');
  const title='STYX_CUA_OWNED_SESSION_PROOF_'+process.pid+'_'+Date.now();
  const fixture=spawn('/usr/bin/zenity',['--question',
    '--title='+title,
    '--text=Owned test dialog, not a personal application',
    '--ok-label=Styx Verify Click','--cancel-label=Cancel'],{
    env:{...process.env,GDK_BACKEND:'wayland'},stdio:'ignore'
  });
  t.after(async()=>{
    if(fixture.exitCode===null && fixture.signalCode===null)fixture.kill('SIGTERM');
  });
  const mcp=await newClient();
  async function call(name,args){
    const result=await mcp.callTool({name,arguments:args});
    if(result.isError){
      throw Error(name+'_error_'+result.structuredContent?.error);
    }
    return result;
  }
  const app=await call('list_apps',{});
  assert.ok(Array.isArray(app.structuredContent?.apps));
  let window;
  for(let i=0;i<20;i++){
    const r=await call('list_windows',{pid:fixture.pid,on_screen_only:false});
    const windows=r.structuredContent?.windows??r.structuredContent?.data?.windows??[];
    window=windows.find(x=>String(x.title||'')===title);
    if(window)break;
    await wait(120);
  }
  assert.ok(window,'owned window discovery failed');
  const pid=Number(window.pid),id=Number(window.window_id);
  assert.equal(pid,fixture.pid);
  const state=await call('get_window_state',{pid,window_id:id,tree_format:'elements',
    include_screenshot:true,max_elements:80});
  const elements=state.structuredContent?.elements??[];
  const screenshot=state.content?.some(x=>x.type==='image'&&x.mimeType==='image/png');
  assert.equal(screenshot,true,'native Cua screenshot required');
  const button=elements.find(x=>String(x.label??'').includes('Styx Verify Click'));
  assert.ok(button?.element_token,'native Cua accessibility button not found');
  const reply=await call('click',{pid,window_id:id,element_token:button.element_token});
  assert.notEqual(reply.isError,true);
  for(let i=0;i<18&&fixture.exitCode===null;i++)await wait(150);
  assert.equal(fixture.exitCode,0,'independent owned-window exit must confirm action');
  console.log(JSON.stringify({nativeCuaVersion:'0.36.0',ownedPid:pid,verified:true,
    screenshot:true,elementCount:elements.length,action:'owned_button'}));
});


test('closing one model session preserves the shared native Cua worker',
  {skip:!canRun,timeout:16000},async t=>{
  const {newClient,gateway}=await setup(t,{slots:1});
  const first=await newClient();
  const a=await first.callTool({name:'list_apps',arguments:{}});
  assert.equal(a.isError,false);
  const leaseA=a.structuredContent.lease;
  assert.equal(gateway.computer.sessions.size,1);
  assert.equal(gateway.relay.computerConnected('cua-pilot'),1);
  // The MCP SDK exposes session DELETE separately from Client.close().
  // Terminating the owner must not close the shared Cua worker.
  await first.testTransport.terminateSession();
  await first.close();
  assert.equal(gateway.computer.sessions.size,1);
  const second=await newClient();
  const b=await second.callTool({name:'list_apps',arguments:{}});
  assert.equal(b.isError,false);
  assert.equal(b.structuredContent.lease,leaseA);
  assert.notEqual(a.structuredContent.args.session,b.structuredContent.args.session);
});

test('Gateway five-minute abandoned lease cleanup frees the Cua Host worker',
  {skip:!canRun,timeout:16000},async t=>{
  const {newClient,gateway}=await setup(t,{slots:1});
  const first=await newClient();
  const a=await first.callTool({name:'list_apps',arguments:{}});
  const leaseA=a.structuredContent.lease;
  assert.ok(leaseA);
  // Simulate five-minute idle in the test-only broker; no real waiting.
  const session=[...gateway.computer.sessions.values()][0];
  await first.close(); // No HTTP DELETE, so Gateway still owns the Cua lease.
  assert.equal(gateway.computer.sessions.size,1);
  session.lastUsed=Date.now()-5*60*1000-2000;
  await gateway.computer.reapIdle();
  assert.equal(gateway.computer.sessions.size,0);
  await until(()=>gateway.relay.computerConnected('cua-pilot')===1 &&
    [...gateway.relay.computerPeers.get('cua-pilot')].every(e=>!e.claimed));
  const second=await newClient();
  const b=await second.callTool({name:'list_apps',arguments:{}});
  assert.equal(b.isError,false);
  assert.notEqual(b.structuredContent.lease,leaseA);
});
