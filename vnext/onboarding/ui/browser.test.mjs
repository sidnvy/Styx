// Opt-in real-browser integration: private UI + real core + owned TLS Gateway.
// No Host install, account connection, desktop permissions or personal profile.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {createOnboardingServer} from '../server.mjs';
const enabled=process.env.STYX_ONBOARDING_BROWSER_TEST==='1';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,code,ms=12000){const end=Date.now()+ms;while(Date.now()<end){if(await fn())return;await sleep(100)}throw Error(code)}
test('real browser saves config, explicitly prepares/starts/pauses owned Gateway and resumes status',{skip:!enabled,timeout:60000},async()=>{
 const binary=process.env.STYX_ONBOARDING_BROWSER_BINARY;assert.ok(binary&&path.isAbsolute(binary));
 const core=await import(process.env.STYX_ONBOARDING_CORE_MODULE?pathToFileURL(process.env.STYX_ONBOARDING_CORE_MODULE):new URL('../core.mjs',import.meta.url));
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ui-browser-'));fs.chmodSync(root,0o700);
 let instance,browser,ws;let next=0;const pending=new Map();
 const command=(method,params={})=>new Promise((resolve,reject)=>{const id=++next;const timer=setTimeout(()=>{pending.delete(id);reject(Error('browser_command_timeout'))},15000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}))});
 async function evaluate(expression){const r=await command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});assert.equal(r.exceptionDetails,undefined);return r.result.value}
 try{
  const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const gatewayPort=listener.address().port;await new Promise(r=>listener.close(r));
  instance=await createOnboardingServer({stateDir:path.join(root,'state'),core});
  const profile=path.join(root,'browser');fs.mkdirSync(profile,{mode:0o700});
  browser=spawn(binary,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','--user-data-dir='+profile,instance.url],{stdio:'ignore'});
  const active=path.join(profile,'DevToolsActivePort');await until(()=>fs.existsSync(active),'browser_not_started');const debugPort=fs.readFileSync(active,'utf8').split('\n')[0];
  const targets=await(await fetch('http://127.0.0.1:'+debugPort+'/json/list')).json();const page=targets.find(p=>p.type==='page');assert.ok(page);
  ws=new WebSocket(page.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true})});
  ws.addEventListener('message',event=>{const message=JSON.parse(event.data),entry=pending.get(message.id);if(!entry)return;pending.delete(message.id);clearTimeout(entry.timer);message.error?entry.reject(Error('browser_protocol_error')):entry.resolve(message.result)});
  await until(()=>evaluate("document.querySelector('#setup')?.hidden===false"),'setup_not_ready');
  assert.equal(await evaluate("location.hash"),''); // bootstrap is removed from history
  const fields={gatewayUrl:'https://127.0.0.1:'+gatewayPort,label:'Owned UI Gateway test',bundle:path.join(root,'bundle-not-executed'),publisherKeyFile:path.join(root,'publisher-not-read.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'host-not-created')};
  await evaluate(`(()=>{const f=document.querySelector('#setup');for(const[k,v]of Object.entries(${JSON.stringify(fields)}))f.elements[k].value=v;f.elements.reviewed.checked=true;f.requestSubmit();return true})()`);
  await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'config_not_saved');
  assert.equal(fs.existsSync(path.join(root,'host-not-created')),false);
  async function clickStep(label,status){await evaluate(`(()=>{const s=[...document.querySelectorAll('.step')].find(s=>s.querySelector('strong').textContent===${JSON.stringify(label)});if(!s||s.querySelector('button').disabled)throw Error('step_not_ready');s.querySelector('button').click();return true})()`);await until(()=>evaluate(`(()=>{const s=[...document.querySelectorAll('.step')].find(s=>s.querySelector('strong').textContent===${JSON.stringify(label)});return s?.querySelector('.status').textContent===${JSON.stringify(status)}})()`),'step_not_completed')}
  await clickStep('准备本机 Gateway','已记录成功');await clickStep('启动前台 Gateway','已记录成功');
  await until(()=>evaluate("document.querySelector('#runtime').textContent.includes('正在运行')"),'actual_gateway_not_running');
  await evaluate("document.querySelector('#pause').click();true");
  await until(()=>evaluate("document.querySelector('#runtime').textContent.includes('未持有运行实例')"),'actual_gateway_not_stopped');
  await command('Page.reload');await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'resume_not_loaded');
  assert.equal(await evaluate("document.querySelectorAll('.step .status.succeeded').length"),2);
  assert.equal(fs.existsSync(path.join(root,'host-not-created')),false);
 }finally{
  for(const entry of pending.values()){clearTimeout(entry.timer);entry.reject(Error('browser_cleanup'))}pending.clear();ws?.close();
  if(browser&&browser.exitCode===null){browser.kill('SIGTERM');await Promise.race([new Promise(r=>browser.once('close',r)),sleep(5000)]);if(browser.exitCode===null&&browser.signalCode===null){browser.kill('SIGKILL');await new Promise(r=>browser.once('close',r))}}
  await instance?.close();fs.rmSync(root,{recursive:true,force:true});
 }
});
