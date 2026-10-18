import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {doctor} from '../../host/doctor.mjs';
import {normalizeConnector} from '../../host/connect.mjs';
import {TargetRegistry} from '../registry.mjs';

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
