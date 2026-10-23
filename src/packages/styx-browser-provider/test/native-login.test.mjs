import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
// Explicit opt-in: this launches only a dedicated, task-local browser profile.
test('installed native Chrome restores dedicated login state in a new isolated session',{
  skip:!process.env.STYX_TEST_BROWSER_BINARY,timeout:45000
},async t=>{
  const {HostBrowserSupervisor}=await import('../host.mjs');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-login-'));fs.chmodSync(root,0o700);
  const work=path.join(root,'work');fs.mkdirSync(work,{mode:0o700});
  const server=http.createServer((req,res)=>res.end('<!doctype html><title>Dedicated login fixture</title>'));
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const supervisor=new HostBrowserSupervisor({browser:{enabled:true,headless:true,persistLogin:true,profileRoot:path.join(root,'profiles'),executablePath:process.env.STYX_TEST_BROWSER_BINARY},cwd:work});
  t.after(async()=>{await supervisor.close();await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true});});
  const url='http://127.0.0.1:'+server.address().port,principal='c'.repeat(64),first='a'.repeat(64),second='b'.repeat(64);
  const call=async(name,args,owner)=>{const result=await supervisor.callTool(name,args,owner,principal);assert.ok(!result.isError,JSON.stringify(result));return result;};
  await call('browser_navigate',{url},first);
  await call('browser_evaluate',{function:"async()=>{document.cookie='login=dedicated-fixture; path=/';localStorage.setItem('login','dedicated-fixture');await new Promise((resolve,reject)=>{const r=indexedDB.open('login',1);r.onupgradeneeded=()=>r.result.createObjectStore('auth');r.onerror=()=>reject(r.error);r.onsuccess=()=>{const db=r.result,tx=db.transaction('auth','readwrite');tx.objectStore('auth').put('dedicated-fixture','login');tx.oncomplete=()=>{db.close();resolve()}}});return true;}"},first);
  const firstProfile=supervisor.leases.get(first).profile;
  await supervisor.closeOwner(first);
  await call('browser_navigate',{url},second);
  assert.notEqual(supervisor.leases.get(second).profile,firstProfile);
  const result=await call('browser_evaluate',{function:"async()=>({cookie:document.cookie,local:localStorage.getItem('login'),idb:await new Promise((resolve,reject)=>{const r=indexedDB.open('login',1);r.onerror=()=>reject(r.error);r.onsuccess=()=>{const db=r.result,tx=db.transaction('auth'),q=tx.objectStore('auth').get('login');q.onsuccess=()=>{db.close();resolve(q.result)}}})})"},second);
  const output=JSON.stringify(result);assert.match(output,/dedicated-fixture/);assert.match(output,/cookie/);assert.match(output,/local/);assert.match(output,/idb/);
  const state=await supervisor.leases.get(second).context.storageState({indexedDB:true});
  assert.equal(state.cookies.find(x=>x.name==='login').value,'dedicated-fixture');
  assert.equal(state.origins[0].localStorage.find(x=>x.name==='login').value,'dedicated-fixture');
  assert.equal(state.origins[0].indexedDB[0].stores[0].records[0].value,'dedicated-fixture');
});
