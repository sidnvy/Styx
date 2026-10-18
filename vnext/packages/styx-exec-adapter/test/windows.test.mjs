import test from 'node:test';
import assert from 'node:assert/strict';
import {ExecAdapter} from '../adapter.mjs';

test('Codex-shaped exec routes Windows native paths and PowerShell flags correctly',async()=>{
  const calls=[];
  const runtime={sessionId:'windows-codex-runtime',lost:false,
    async request(method,args){
      calls.push({method,args});
      if(method==='process/start') return {processId:args.processId};
      if(method==='process/read')return {chunks:[],nextSeq:1,
        exited:false,closed:false,failure:null};
      if(method==='process/terminate')return {status:'accepted'};
      throw Error('unexpected');
    }
  };
  const shell='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
  const context={id:'nab',generation:'test1',platform:'win32',
    cwd:'C:\\Users\\Sid\\Projects',shell,shells:[shell],env:{},runtime};
  const adapter=new ExecAdapter({resolve:async()=>context});
  const out=await adapter.execCommand({cmd:'Write-Output styx',
    workdir:'sample folder',yield_time_ms:0,login:false},'owner-1');
  assert.ok(out.session_id);
  const launch=calls.find(c=>c.method==='process/start').args;
  assert.equal(launch.cwd,'file:///C:/Users/Sid/Projects/sample%20folder');
  assert.deepEqual(launch.argv,[shell,'-NoLogo','-NoProfile',
    '-NonInteractive','-Command','Write-Output styx']);
  assert.equal(launch.pipeStdin,true);
});
test('Win32 rejects POSIX shell and Windows paths do not fall back to Gateway OS',async()=>{
  const runtime={sessionId:'windows-session',lost:false,async request(){throw Error('unreachable');}};
  const context={id:'nab',generation:'test1',platform:'win32',
    cwd:'C:\\Scratch',shell:'C:\\Windows\\System32\\cmd.exe',
    shells:['C:\\Windows\\System32\\cmd.exe'],env:{},runtime};
  const adapter=new ExecAdapter({resolve:async()=>context});
  await assert.rejects(adapter.execCommand({cmd:'dir',yield_time_ms:0},'owner-1'),/unsupported_shell/);
});

test('Codex native envPolicy preserves only platform variables, not host secrets',async()=>{
  const {codexEnvPolicy}=await import('../adapter.mjs');
  const linux=codexEnvPolicy('linux');
  assert.equal(linux.inherit,'all');
  assert.equal(linux.ignoreDefaultExcludes,false);
  for(const key of ['WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS',
    'DISPLAY','XAUTHORITY','PATH','HOME'])
    assert.ok(linux.includeOnly.includes(key),key);
  for(const key of ['CODER_AGENT_AUTH','SSH_AUTH_SOCK','GITHUB_TOKEN',
    'AWS_SECRET_ACCESS_KEY','OPENAI_API_KEY','NODE_REPL_AUTH_TOKEN'])
    assert.ok(!linux.includeOnly.includes(key),key);
  const win=codexEnvPolicy('win32');
  for(const key of ['SystemRoot','Path','PATHEXT','USERPROFILE','APPDATA'])
    assert.ok(win.includeOnly.includes(key));
  assert.ok(!win.includeOnly.includes('WAYLAND_DISPLAY'));
  assert.deepEqual(codexEnvPolicy('darwin').includeOnly,linux.includeOnly);
});
