import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {doctor} from '../../host/doctor.mjs';
import {normalizeConnector} from '../../host/connect.mjs';
import {TargetRegistry} from '../registry.mjs';
import {createGatewayMcp} from '../mcp.mjs';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {tools as execTools} from '../../packages/styx-exec-adapter/schema.mjs';
import {guiTools} from '../../packages/styx-gui-broker/mcp.mjs';

test('catalog admits only an explicit trusted outbound Host',()=>{
  const base={id:'mac',kind:'host',platform:'darwin',generation:'a1',
    cwd:'/Users/test',shell:'/bin/sh',shells:['/bin/sh'],allowed:true,
    exec:{transport:'outbound',token_file:'/tmp/styx-host-token'}};
  const r=new TargetRegistry({version:1,default_environment_id:'mac',targets:[base]});
  assert.equal(r.resolve().exec.transport,'outbound');
  assert.throws(()=>new TargetRegistry({version:1,targets:[{...base,kind:'environment'}]}),
    /outbound Host authentication/);
  assert.throws(()=>new TargetRegistry({version:1,targets:[{
    ...base,exec:{transport:'outbound',token_file:'relative'}
  }]}),/outbound Host authentication/);
});
test('Host bootstrap doctor validates token and Codex binary without deployment',async t=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'styx-host-doctor-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const token=path.join(root,'host-token');
  await fs.writeFile(token,randomBytes(30).toString('hex'),{mode:0o600});
  const config={host_id:'fixture',gateway_ws_url:'wss://private.example',
    token_file:token,exec:{binary:process.execPath,cwd:root}};
  const out=await doctor(config);
  assert.equal(out.checks.configuration,'ok');
  assert.equal(out.checks.host_credential,'ok');
  assert.equal(out.status,'blocked');
  assert.ok(out.blockers.includes('codex_executor_unavailable'));
  assert.equal(out.checks.gateway_transport,'wss');
  assert.equal(normalizeConnector(config).endpoint,'wss://private.example/styx/hosts/fixture/exec');
  await fs.chmod(token,0o644);
  const broken=await doctor(config);
  assert.ok(broken.blockers.includes('host_credential_unavailable'));
});

test('mTLS certificate pin is an alternate Host identity, never bearer fallback',()=>{
  const pin='ab'.repeat(32);
  const base={id:'pinned',kind:'host',platform:'darwin',generation:'mtls-1',
    cwd:'/tmp',shell:'/bin/sh',shells:['/bin/sh'],allowed:true,
    exec:{transport:'outbound',client_certificate_sha256:pin}};
  const c={version:1,default_environment_id:'pinned',targets:[base]};
  assert.equal(new TargetRegistry(c).resolve().exec.client_certificate_sha256,pin);
  assert.throws(()=>new TargetRegistry({...c,targets:[{
    ...base,exec:{...base.exec,token_file:'/tmp/old-token'}
  }]}),/outbound Host authentication/);
  assert.throws(()=>new TargetRegistry({...c,targets:[{
    ...base,exec:{transport:'outbound',client_certificate_sha256:'not-sha256'}
  }]}),/outbound Host authentication/);
  const {client_certificate_sha256,...authRemoved}=base.exec;
  assert.throws(()=>new TargetRegistry({...c,targets:[{
    ...base,exec:authRemoved
  }]}),/outbound Host authentication/);
});

test('Cua 0.36.0 native process launch modes follow upstream documentation',async()=>{
  const {computerMcpArgs}=await import('../../host/computer.mjs');
  assert.deepEqual(computerMcpArgs({}, {platform:'linux'}),['mcp']);
  assert.deepEqual(computerMcpArgs({}, {platform:'win32'}),['mcp']);
  assert.deepEqual(computerMcpArgs({socket:'/tmp/cua.sock'},{platform:'linux'}),
    ['mcp','--socket','/tmp/cua.sock']);
  assert.deepEqual(computerMcpArgs({socket:'/private/tmp/app-owned.sock'},{platform:'darwin'}),
    ['mcp','--embedded','--socket','/private/tmp/app-owned.sock']);
  assert.throws(()=>computerMcpArgs({},{platform:'darwin'}),
    /macos_requires_embedded_cua_socket/);
});

test('Host doctor reports native Wayland opt-in separately from Exec readiness',async()=>{
  const old=process.env.WAYLAND_DISPLAY, oldFlag=process.env.CUA_DRIVER_RS_ENABLE_WAYLAND;
  const root=await (await import('node:fs/promises')).mkdtemp(
    (await import('node:path')).join((await import('node:os')).tmpdir(),'styx-cua-doctor-'));
  try{
    process.env.WAYLAND_DISPLAY='styx-virtual-session';
    delete process.env.CUA_DRIVER_RS_ENABLE_WAYLAND;
    const {writeFile,rm}=await import('node:fs/promises');
    const {join}=await import('node:path');
    const privateToken=join(root,'secret.token');
    await writeFile(privateToken,'b'.repeat(50),{mode:0o600});
    const options={
      host_id:'native-demo',gateway_ws_url:'wss://example.invalid',
      token_file:privateToken,
      exec:{binary:process.execPath,cwd:root},
      computer:{enabled:true,binary:'/usr/bin/cua-driver'}
    };
    let report=await doctor(options,{platform:'linux'});
    assert.equal(report.checks.cua_wayland,'xwayland_fallback');
    assert.ok(report.warnings.includes('native_wayland_requires_explicit_opt_in'));
    report=await doctor({...options,computer:{...options.computer,
      env:{CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}}},{platform:'linux'});
    assert.equal(report.checks.cua_wayland,'native_opted_in');
    assert.ok(!report.warnings.includes('native_wayland_requires_explicit_opt_in'));
  }finally{
    if(old===undefined)delete process.env.WAYLAND_DISPLAY;
    else process.env.WAYLAND_DISPLAY=old;
    if(oldFlag===undefined)delete process.env.CUA_DRIVER_RS_ENABLE_WAYLAND;
    else process.env.CUA_DRIVER_RS_ENABLE_WAYLAND=oldFlag;
    await (await import('node:fs/promises')).rm(root,{recursive:true,force:true});
  }
});

test('MCP initialize and tools/list deliver Exec-first guidance with both computer providers',async t=>{
  const sharedDefinitions=JSON.stringify({execTools,guiTools});
  for(const mode of ['native-cua','legacy-gui'])await t.test(mode,async t=>{
    const nativeTools=Object.freeze([
      Object.freeze({name:'list_apps',description:'Observe running native applications.',
        inputSchema:{type:'object',properties:{}}}),
      Object.freeze({name:'click',description:'Click a freshly observed native element.',
        inputSchema:{type:'object',properties:{}}})
    ]);
    const calls=[];
    const error={isError:true,content:[{type:'text',text:'exec_disconnected'}]};
    const exec={async callTool(name,args,owner){calls.push({lane:'exec',name,args,owner});return error;}};
    const computer={async listTools(){return nativeTools;},
      async callTool(name,args,owner){calls.push({lane:'computer',name,args,owner});return {content:[]};}};
    const registry={list(){return [{capabilities:['exec','computer']}];},resolve(){return null;}};
    const server=createGatewayMcp({exec,registry,owner:'routing-test-owner',
      ...(mode==='native-cua'?{computer}:{gui:computer})});
    const client=new Client({name:'routing-protocol-test',version:'1'});
    const [ct,st]=InMemoryTransport.createLinkedPair();
    t.after(async()=>{await client.close();await server.close();});
    await server.connect(st);
    await client.connect(ct); // Actual MCP initialize, not an instructions constant assertion.
    const instructions=client.getInstructions();
    assert.match(instructions,/Use browser_\* for webpage and tab automation/);
    assert.match(instructions,/Default to exec_command for Git\/GitHub clone/);
    assert.match(instructions,/downloads \(curl\/wget\), file operations, builds, tests/);
    assert.match(instructions,/TTY sessions managed by exec_command\/write_stdin are Exec sessions/);
    assert.match(instructions,/Do not open Terminal.*Spotlight/);
    assert.match(instructions,/authentication, permission or sandbox errors.*get_execution_environment_status/);
    assert.match(instructions,/For native desktop tasks, use Styx computer tools/);
    assert.match(instructions,/explicitly requested GUI workflow may use computer tools/);
    assert.match(instructions,/Do not replace desktop tools with osascript/);
    assert.match(instructions,/separate Automation permission/);
    const {tools}=await client.listTools();
    for(const name of ['exec_command','write_stdin']){
      const delivered=tools.find(tool=>tool.name===name);
      assert.match(delivered.description,/Default to exec_command for Git\/GitHub clone/);
      assert.match(delivered.description,/never use a desktop terminal to bypass it/);
      assert.match(delivered.description,/not osascript\/System Events/);
      assert.deepEqual(delivered.inputSchema,execTools.find(tool=>tool.name===name).inputSchema);
    }
    for(const original of mode==='native-cua'?nativeTools:guiTools){
      const delivered=tools.find(tool=>tool.name===original.name);
      assert.ok(delivered.description.startsWith(original.description+' '));
      assert.match(delivered.description,/GUI observation\/interaction is necessary or the user explicitly requests a GUI workflow/);
      assert.match(delivered.description,/CLI work default to exec_command, including foreground\/TTY sessions/);
      assert.match(delivered.description,/Do not open Terminal through Spotlight/);
      assert.match(delivered.description,/authentication, sandbox restrictions or disconnection/);
      assert.match(delivered.description,/not osascript\/System Events/);
      assert.deepEqual(delivered.inputSchema,original.inputSchema);
    }
    assert.deepEqual(calls,[]); // Discovery does not run either capability.
    const args={cmd:'git clone local-source checkout',environment_id:'selected'};
    assert.equal((await client.callTool({name:'exec_command',arguments:args})).isError,true);
    assert.deepEqual(calls,[{lane:'exec',name:'exec_command',args,owner:'routing-test-owner'}]);
    // Guidance preserves explicit GUI calls; an Exec failure does not dispatch a GUI fallback.
    await client.callTool({name:'click',arguments:{}});
    assert.equal(calls.at(-1).lane,'computer');
    assert.equal(calls.length,2);
    await client.listTools();
    assert.equal(JSON.stringify({execTools,guiTools}),sharedDefinitions);
    assert.equal(nativeTools[0].description,'Observe running native applications.');
  });
});
