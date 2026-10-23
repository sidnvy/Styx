import test from 'node:test';
import assert from 'node:assert/strict';
import {TargetRegistry} from '../registry.mjs';
import {CuaProvider,connectCuaMcp} from '../cua.mjs';
import {createStyxGateway} from '../index.mjs';

const target = (id,platform,enabled=true) => ({
  id,kind:'host', platform,generation:'runtime-v1',allowed:true,
  cwd: platform==='win32' ? 'C:\\Users\\Demo' : '/tmp/styx',
  shell: platform==='win32' ? 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe':'/bin/sh',
  shells: platform==='win32' ? ['C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']:['/bin/sh'],
  exec: platform==='win32' ? {transport:'websocket',url:'wss://test.example/exec'} :
    {transport:'stdio',binary:'/usr/local/bin/codex'},
  computer: {enabled,transport:'mcp-http',url:'https://driver.example/mcp',token_file:'/tmp/cua-test'}
});

function fixture() {
  const calls=[], instances=[], closed=[];
  const registry=new TargetRegistry({version:1,default_environment_id:'mac',
    targets:[target('mac','darwin'),target('linux','linux'),target('windows','win32')]});
  const connect=async (target,owner)=> {
    instances.push({target:target.id,owner});
    return {
      getServerVersion() {return {name:'cua-driver',version:'0.36.0'};},
      async listTools() {
        return {tools:[
          {name:'list_apps',description:'Cua list_apps',
            inputSchema:{type:'object',properties:{},additionalProperties:false}},
          {name:'click',description:'Cua native click',
            inputSchema:{type:'object',properties:{target:{type:'object'},
              element_token:{type:'string'}},required:['target'],additionalProperties:false}},
          {name:'install_extension',inputSchema:{type:'object',properties:{}}}
        ]};
      },
      async callTool(input) {
        calls.push({owner,target:target.id,input});
        return {content:[{type:'text',text:'accepted'}],
          structuredContent:{owner,target:target.id,name:input.name}};
      },
      async close(){closed.push({owner,target:target.id});}
    };
  };
  const provider=new CuaProvider({registry,connect,toolNames:['list_apps','click']});
  return {provider,registry,calls,instances,closed};
}
test('Cua MCP is schema authority; Styx adds only optional environment_id',async()=>{
  const f=fixture();
  const definitions=await f.provider.listTools();
  assert.deepEqual(definitions.map(t=>t.name),['list_apps','click']);
  assert.equal(definitions[0].inputSchema.properties.environment_id.type,'string');
  const fields=Object.keys(definitions[1].inputSchema.properties);
  assert.ok(fields.includes('target'));
  assert.ok(fields.includes('element_token'));
  assert.ok(fields.includes('environment_id'));
  assert.equal(fields.includes('coordinate_frame'),false);
  await f.provider.close();
});
test('macOS Linux and Windows use the same Cua tool surface',async()=>{
  const f=fixture();
  for(const id of ['mac','linux','windows']){
    const r=await f.provider.callTool('click',{environment_id:id,
      target:{kind:'window',pid:123,window_id:456}},'alice');
    assert.equal(r.structuredContent.target,id);
  }
  assert.deepEqual(f.calls.map(c=>c.target),['mac','linux','windows']);
  for(const c of f.calls) {
    const {session,...args}=c.input.arguments;
    assert.match(session,/^styx-/);
    assert.deepEqual(args,{target:{kind:'window',pid:123,window_id:456}});
  }
  assert.equal(f.instances.length,3);
  await f.provider.close();
});
test('Cua owners share transport with private native session names',async()=>{
  const f=fixture();
  await f.provider.callTool('list_apps',{},'alice');
  await f.provider.callTool('list_apps',{},'bob');
  assert.equal(f.instances.length,1);
  const [alice,bob]=f.calls.map(c=>c.input.arguments.session);
  assert.notEqual(alice,bob);
  await f.provider.closeOwner('alice');
  assert.equal(f.closed.length,0);
  await f.provider.callTool('list_apps',{},'bob');
  assert.equal(f.calls.at(-1).input.arguments.session,bob);
  assert.equal(f.instances.length,1);
  await f.provider.close();
  assert.equal(f.closed.length,1);
});
test('unknown tools and unauthorized targets are rejected before native calls',async()=>{
  const f=fixture();
  assert.equal((await f.provider.callTool('install_extension',{},'alice')).structuredContent.error,'unknown_tool');
  assert.equal((await f.provider.callTool('click',{environment_id:'other'},'alice')).structuredContent.error,'environment_not_found');
  assert.equal((await f.provider.callTool('click',{environment_id:23},'alice')).structuredContent.error,'invalid_environment');
  assert.deepEqual(f.calls,[]);
  await f.provider.close();
});
test('Gateway advertises Codex and dynamically discovered official Cua tool names',async()=>{
  const f=fixture();
  const runtime={sessionId:'fixture-runtime', lost:false, async request(){throw Error('no exec');},async close(){}};
  const gateway=createStyxGateway({catalog:f.registry,connect:async()=>runtime,computer:f.provider});
  const {InMemoryTransport}=await import('@modelcontextprotocol/sdk/inMemory.js');
  const {Client}=await import('@modelcontextprotocol/sdk/client/index.js');
  const [ct,st]=InMemoryTransport.createLinkedPair();
  const server=gateway.serverForOwner('alice');
  await server.connect(st);
  const client=new Client({name:'styx-cua-test',version:'0.1'});
  await client.connect(ct);
  assert.match(client.getInstructions(),/Do not replace desktop tools with osascript/);
  const list=await client.listTools();
  assert.match(list.tools.find(t=>t.name==='exec_command').description,/not osascript/);
  assert.match(list.tools.find(t=>t.name==='write_stdin').description,/not osascript/);
  assert.deepEqual(list.tools.map(x=>x.name),
    ['exec_command','write_stdin','list_apps','click','list_execution_environments', 'get_execution_environment_status']);
  const r=await client.callTool({name:'click',arguments:{
    environment_id:'linux',target:{kind:'window'}}});
  assert.equal(r.structuredContent.target,'linux');
  await client.close();await server.close();await gateway.close();
});
test('Windows absolute paths use Windows rules regardless of gateway OS',()=>{
  const r=new TargetRegistry({version:1,default_environment_id:'windows',
    targets:[target('windows','win32')]});
  assert.equal(r.resolve().platform,'win32');
  assert.ok(r.list()[0].capabilities.includes('computer'));
});

test('an idle Styx transport lease expires at the documented five-minute boundary',async()=>{
  let clock=0,open=0,closed=0;
  const f=fixture();
  const broker=new CuaProvider({registry:f.registry,
    connect:async()=> {
      open++;
      return {
        getServerVersion(){return {name:'cua-driver',version:'0.36.0'}},
        async callTool(){return {structuredContent:{open},content:[]}},
        async close(){closed++}
      };
    },
    idleMs:300000,reapIntervalMs:30000,clock:()=>clock
  });
  try{
    let result=await broker.callTool('list_apps',{},'owner');
    assert.equal(result.structuredContent.open,1);
    clock=299999;
    await broker.reapIdle();
    assert.equal(closed,0);
    clock=300000;
    await broker.reapIdle();
    assert.equal(closed,1);
    result=await broker.callTool('list_apps',{},'owner');
    assert.equal(result.structuredContent.open,2);
  }finally{
    await broker.close();
  }
});

test('an active native Cua action is never released by idle transport reaper',async()=>{
  let clock=0,closed=0,resolveAction;
  const gate=new Promise(resolve=>{resolveAction=resolve});
  const f=fixture();
  const broker=new CuaProvider({registry:f.registry,
    connect:async()=> ({
      getServerVersion(){return {name:'cua-driver',version:'0.36.0'}},
      async callTool(){await gate;return {structuredContent:{effect:'confirmed'},content:[]}},
      async close(){closed++}
    }),idleMs:300000,reapIntervalMs:30000,clock:()=>clock
  });
  try{
    const call=broker.callTool('click',{target:{kind:'window'}},'owner');
    for(let i=0;broker.sessions.size===0&&i<20;i++)
      await new Promise(resolve=>setImmediate(resolve));
    assert.equal(broker.sessions.size,1);
    clock=400000;
    await broker.reapIdle();
    assert.equal(closed,0);
    resolveAction();
    await call;
    await broker.reapIdle();
    assert.equal(closed,0);
    clock=700001;
    await broker.reapIdle();
    assert.equal(closed,1);
  }finally{
    resolveAction();
    await broker.close();
  }
});
for(const revoke of ['device','owner'])test(revoke+' closure during native Cua handshake closes the orphan without dispatch',async t=>{
  const registry=new TargetRegistry({version:1,default_environment_id:'linux',
    targets:[target('linux','linux')]});
  let release,entered;
  const gate=new Promise(resolve=>{release=resolve});
  const started=new Promise(resolve=>{entered=resolve});
  let closed=0,calls=0;
  const provider=new CuaProvider({registry,toolNames:['list_apps'],connect:async()=>{
    entered();await gate;
    return {getServerVersion:()=>({name:'cua-driver',version:'0.36.0'}),
      async close(){closed++},async callTool(){calls++;return {content:[]}}};
  }});
  t.after(()=>provider.close());
  const pending=provider.callTool('list_apps',{},'closing-owner');await started;
  if(revoke==='device')registry.revokeHost('linux');
  else await provider.closeOwner('closing-owner');
  release();const result=await pending;
  assert.equal(result.isError,true);
  assert.match(result.content[0].text,revoke==='device'?/environment_access_denied/:/computer_owner_closed/);
  assert.equal(closed,1);assert.equal(calls,0);
  assert.equal(provider.sessions.size,0);assert.equal(provider.pending.size,0);
});

test('missing default and busy desktop return actionable categories without raw driver errors',async()=>{
 const f=fixture();f.registry.defaultId=undefined;
 const missing=await f.provider.callTool('list_apps',{},'alice');
 assert.equal(missing.structuredContent.error,'default_environment_required');
 assert.match(missing.structuredContent.recovery,/list_execution_environments.*environment_id/);
 assert.equal(f.instances.length,0);
 f.provider.connect=async()=>{throw Error('computer_slots_busy')};
 const busy=await f.provider.callTool('list_apps',{environment_id:'mac'},'alice');
 assert.equal(busy.structuredContent.error,'computer_slots_busy');
 assert.match(busy.structuredContent.recovery,/current operation/);
 f.provider.connect=async()=>{throw Error('PRIVATE_RAW_DRIVER_MESSAGE')};
 const unknown=await f.provider.callTool('list_apps',{environment_id:'mac'},'alice');
 assert.equal(unknown.structuredContent.error,'computer_transport_unavailable');
 assert.doesNotMatch(JSON.stringify(unknown),/PRIVATE_RAW_DRIVER_MESSAGE/);
 await f.provider.close();
});

const endedSession=input=>({isError:true,
  // Captured from the signed macOS 0.36.0 MCP driver. Its error_code is absent.
  structuredContent:{code:'tool_invocation_failed',exit_code:1},
  content:[{type:'text',text:`session has ended; tool call '${input.name}' was rejected. Call start_session with session '${input.arguments.session}' to start it again, or use a new session label.`}]});

function lifecycleFixture(t) {
  const registry=new TargetRegistry({version:1,default_environment_id:'mac',targets:[target('mac','darwin')]});
  const calls=[],expired=new Set();let connections=0,closed=0,snapshot=0,respond;
  const provider=new CuaProvider({registry,connect:async()=>{
    connections++;
    return {getServerVersion:()=>({name:'cua-driver',version:'0.36.0'}),
      async close(){closed++},async callTool(input){
        calls.push(input);
        if(respond)return respond(input);
        if(expired.has(input.arguments.session))return endedSession(input);
        return {content:[],structuredContent:{snapshot_id:'s'+(++snapshot).toString(16).padStart(8,'0'),capture_id:'capture-'+snapshot,screenshot_frame_valid:true}};
      }};
  }});
  t.after(()=>provider.close());
  return {provider,registry,calls,expired,setResponder(value){respond=value},
    get connections(){return connections},get closed(){return closed}};
}
const windowArgs={pid:123,window_id:456};

test('an ended owner observation recovers once on the shared transport without merging snapshots',async t=>{
  const f=lifecycleFixture(t);
  const a=await f.provider.callTool('get_window_state',windowArgs,'alice');
  const alice=f.calls.at(-1).arguments.session;
  const b=await f.provider.callTool('get_window_state',windowArgs,'bob');
  const bob=f.calls.at(-1).arguments.session;
  f.expired.add(alice);
  await f.provider.callTool('list_windows',{},'bob');
  const before=f.calls.length;
  const result=await f.provider.callTool('get_window_state',{...windowArgs,since:a.structuredContent.snapshot_id},'alice');
  assert.equal(result.isError,undefined);assert.equal(f.connections,1);assert.equal(f.closed,0);
  assert.equal(f.calls.length,before+2);
  assert.equal(f.calls.at(-2).arguments.session,alice);
  assert.notEqual(f.calls.at(-1).arguments.session,alice);
  assert.notEqual(f.calls.at(-1).arguments.session,bob);
  assert.equal(f.calls.at(-1).arguments.since,undefined,'old snapshot diffs must not cross recovery');
  const snapshots=f.provider.sessions.get('mac').snapshots;
  assert.equal(snapshots.has(a.structuredContent.snapshot_id),false);
  assert.equal(snapshots.get(b.structuredContent.snapshot_id).session,bob);
  assert.equal(snapshots.get(result.structuredContent.snapshot_id).session,f.calls.at(-1).arguments.session);
  for(const id of [a.structuredContent.snapshot_id,b.structuredContent.snapshot_id]) {
    const denied=await f.provider.callTool('click',{element_token:id+':1'},'alice');
    assert.equal(denied.structuredContent.error,'computer_snapshot_required');
  }
  const valid=await f.provider.callTool('click',{element_token:b.structuredContent.snapshot_id+':1'},'bob');
  assert.equal(valid.isError,undefined);assert.equal(f.calls.at(-1).arguments.session,bob);
});

test('ended native input is never replayed and only its owner loses references',async t=>{
  const f=lifecycleFixture(t);
  const a=await f.provider.callTool('get_window_state',windowArgs,'alice');
  const alice=f.calls.at(-1).arguments.session;
  const b=await f.provider.callTool('get_window_state',windowArgs,'bob');
  const bob=f.calls.at(-1).arguments.session;
  f.expired.add(alice);
  const before=f.calls.length;
  const result=await f.provider.callTool('type_text',{element_token:a.structuredContent.snapshot_id+':1',text:'test-only'},'alice');
  assert.equal(f.calls.length,before+1);assert.equal(result.structuredContent.error,'computer_session_expired');
  assert.equal(result.structuredContent.uncertain,undefined);
  const shared=f.provider.sessions.get('mac');
  assert.equal(shared.snapshots.has(a.structuredContent.snapshot_id),false);
  assert.equal(shared.snapshots.get(b.structuredContent.snapshot_id).session,bob);
  assert.equal(shared.capture.context.session,bob);
  for(const args of [{element_token:a.structuredContent.snapshot_id+':1'},{...windowArgs,x:10,y:10},{target:{kind:'window',...windowArgs}}]) {
    assert.equal((await f.provider.callTool('click',args,'alice')).structuredContent.error,'computer_session_expired');
  }
  assert.equal(f.calls.length,before+1,'explicit target must not bypass fresh-observation gate');
  await f.provider.callTool('list_windows',{},'alice');
  assert.equal((await f.provider.callTool('click',{target:{kind:'window',...windowArgs}},'alice')).structuredContent.error,'computer_session_expired');
  const fresh=await f.provider.callTool('get_window_state',windowArgs,'alice');
  assert.equal((await f.provider.callTool('click',{element_token:fresh.structuredContent.snapshot_id+':1'},'alice')).isError,undefined);
});

test('native session recovery is bounded to one read retry',async t=>{
  const f=lifecycleFixture(t);f.setResponder(endedSession);
  const result=await f.provider.callTool('get_window_state',windowArgs,'alice');
  assert.equal(result.structuredContent.error,'computer_session_expired');
  assert.equal(f.calls.length,2);assert.notEqual(f.calls[0].arguments.session,f.calls[1].arguments.session);
  assert.equal(f.provider.ownerStates.get('alice').contexts.size,0);
  assert.equal(f.provider.sessions.get('mac').snapshots.size,0);
  assert.equal(f.connections,1);
});

test('lookalike native errors do not retire or retry a session',async t=>{
  const variants=[r=>({...r,isError:false}),r=>({...r,structuredContent:{...r.structuredContent,error_code:'OTHER'}}),
    r=>({...r,structuredContent:{...r.structuredContent,exit_code:2}}),
    r=>({...r,content:[{type:'text',text:r.content[0].text.replace("'list_windows'","'click'")}]}),
    r=>({...r,content:[{type:'text',text:r.content[0].text.replace(/styx-[a-f0-9-]+/,'styx-different-owner')}]}),
    r=>({...r,content:[{type:'text',text:'session has ended'}]})];
  const f=lifecycleFixture(t);
  for(const change of variants) {
    let expected;f.setResponder(input=>(expected=change(endedSession(input))));
    const before=f.calls.length;
    assert.deepEqual(await f.provider.callTool('list_windows',{},'alice'),expected);
    assert.equal(f.calls.length,before+1);
  }
  assert.equal(new Set(f.calls.map(x=>x.arguments.session)).size,1);
});

test('explicit INVALID_ARGUMENT metadata also admits an exact ended-session rejection',async t=>{
  const f=lifecycleFixture(t);
  f.setResponder(input=>{
    const result=endedSession(input);result.structuredContent.error_code='INVALID_ARGUMENT';return result;
  });
  const result=await f.provider.callTool('list_windows',{},'alice');
  assert.equal(result.structuredContent.error,'computer_session_expired');
  assert.equal(f.calls.length,2);
});

test('signed native MCP ended-session response recovers on the same transport',{
  skip:!process.env.STYX_NATIVE_CUA_SOCKET || !process.env.STYX_NATIVE_CUA_BINARY,
  timeout:20000
},async t=>{
  const nativeTarget={id:'native-contract',generation:'contract-test',cwd:process.cwd(),computer:{enabled:true,
    transport:'stdio',binary:process.env.STYX_NATIVE_CUA_BINARY,socket:process.env.STYX_NATIVE_CUA_SOCKET,
    env:{CUA_DRIVER_EMBEDDED:'1',DO_NOT_TRACK:'1',CUA_DRIVER_RS_TELEMETRY_ENABLED:'false'}}};
  const calls=[];let client,connections=0;
  const provider=new CuaProvider({registry:{resolve:()=>nativeTarget},connect:async target=>{
    connections++;client=await connectCuaMcp(target);
    const call=client.callTool.bind(client);
    client.callTool=async input=>{calls.push(input);return call(input)};
    return client;
  }});
  t.after(async()=>{
    if(client)for(const session of new Set(calls.map(call=>call.arguments.session)))
      await client.callTool({name:'end_session',arguments:{session}}).catch(()=>{});
    await provider.close();
  });
  assert.notEqual((await provider.callTool('list_windows',{app:'Styx'},'alice')).isError,true);
  const alice=calls.at(-1).arguments.session;
  assert.notEqual((await provider.callTool('list_windows',{app:'Styx'},'bob')).isError,true);
  const bob=calls.at(-1).arguments.session;
  assert.notEqual((await client.callTool({name:'end_session',arguments:{session:alice}})).isError,true);
  const rejected=await client.callTool({name:'list_windows',arguments:{session:alice,app:'Styx'}});
  assert.equal(rejected.isError,true);assert.equal(rejected.structuredContent.code,'tool_invocation_failed');
  assert.equal(rejected.structuredContent.exit_code,1);
  const before=calls.length;
  const recovered=await provider.callTool('list_windows',{app:'Styx'},'alice');
  assert.notEqual(recovered.isError,true);assert.equal(calls.length,before+2);
  assert.equal(calls.at(-2).arguments.session,alice);
  assert.notEqual(calls.at(-1).arguments.session,alice);
  assert.notEqual(calls.at(-1).arguments.session,bob);
  assert.notEqual((await provider.callTool('list_windows',{app:'Styx'},'bob')).isError,true);
  assert.equal(calls.at(-1).arguments.session,bob);assert.equal(connections,1);
});

test('ambiguous input transport failure is not retried and invalidates foreign references',async t=>{
  const f=lifecycleFixture(t);
  const a=await f.provider.callTool('get_window_state',windowArgs,'alice');
  const b=await f.provider.callTool('get_window_state',windowArgs,'bob');
  const before=f.calls.length;f.setResponder(()=>{throw Error('session has ended')});
  const result=await f.provider.callTool('click',{element_token:a.structuredContent.snapshot_id+':1'},'alice');
  assert.equal(f.calls.length,before+1);assert.equal(result.structuredContent.error,'computer_transport_unavailable');
  assert.equal(result.structuredContent.uncertain,true);
  assert.equal(f.provider.sessions.get('mac').snapshots.has(b.structuredContent.snapshot_id),false);
});

for(const interruption of ['owner','device','provider'])test(interruption+' closure during expired read prevents recovery dispatch',async t=>{
  const f=lifecycleFixture(t);let entered,release;
  const started=new Promise(resolve=>{entered=resolve}),gate=new Promise(resolve=>{release=resolve});
  f.setResponder(async input=>{entered();await gate;return endedSession(input)});
  const pending=f.provider.callTool('get_window_state',windowArgs,'alice');await started;
  if(interruption==='owner')await f.provider.closeOwner('alice');
  else if(interruption==='device')f.registry.revokeHost('mac');
  else await f.provider.close();
  release();const result=await pending;
  assert.equal(f.calls.length,1);
  assert.equal(result.structuredContent.error,{owner:'computer_owner_closed',device:'environment_access_denied',provider:'computer_provider_closed'}[interruption]);
});
