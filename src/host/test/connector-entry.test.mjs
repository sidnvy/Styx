import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {WebSocketServer} from 'ws';
import {ensurePrivateDirectory,writePrivateFile} from '../private-storage.mjs';

// Spawn the actual CLI entrypoint: importing runHostConnector in this test
// would miss a top-level-await cycle between connect.mjs and browser.mjs.
test('Host CLI entrypoint establishes its authenticated Browser lane while Exec is also active', {timeout:20000},async t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-connector-entry-'));
  ensurePrivateDirectory(root);
  const token='owned-connector-entry-token-'.repeat(3),tokenFile=path.join(root,'token');
  writePrivateFile(tokenFile,token);fs.mkdirSync(path.join(root,'work'),{mode:0o700});
  const server=new WebSocketServer({host:'127.0.0.1',port:0});
  await new Promise(resolve=>server.once('listening',resolve));
  let child,logs='',browserConnected=false,execConnected=false;
  server.on('connection',(socket,request)=>{
    assert.equal(request.headers.authorization,'Bearer '+token);
    if(request.url.endsWith('/browser'))browserConnected=true;
    if(request.url.endsWith('/exec'))execConnected=true;
  });
  t.after(async()=>{
    if(child&&child.exitCode===null&&child.signalCode===null){
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve=>child.once('exit',resolve)),new Promise(resolve=>setTimeout(resolve,2000))]);
      if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
    }
    for(const socket of server.clients)socket.terminate();
    await new Promise(resolve=>server.close(resolve));
    fs.rmSync(root,{recursive:true,force:true});
  });
  const config=path.join(root,'host.json');
  writePrivateFile(config,JSON.stringify({host_id:'styx-entry-fixture',gateway_ws_url:'ws://127.0.0.1:'+server.address().port,
    token_file:tokenFile,exec:{binary:process.execPath,cwd:path.join(root,'work')},
    // No browser operation is requested. This executable is never launched;
    // the test exercises real provider initialization and the transport lane.
    browser:{enabled:true,headless:true,profileRoot:path.join(root,'profiles'),executablePath:process.execPath}}));
  child=spawn(process.execPath,[fileURLToPath(new URL('../connect.mjs',import.meta.url)),config],{stdio:['ignore','pipe','pipe'],windowsHide:true});
  child.stdout.on('data',data=>{logs+=data});child.stderr.on('data',data=>{logs+=data});
  const deadline=Date.now()+10000;
  while(Date.now()<deadline&&(!browserConnected||!execConnected||!logs.includes('"lane":"browser","status":"connected"'))){
    if(child.exitCode!==null||child.signalCode!==null)break;
    await new Promise(resolve=>setTimeout(resolve,25));
  }
  assert.equal(browserConnected,true,'actual CLI Browser lane must connect (not merely an imported connector): '+logs);
  assert.equal(execConnected,true,'Exec and Browser lanes are both started');
  assert.match(logs,/"lane":"browser","status":"connected"/);
});
