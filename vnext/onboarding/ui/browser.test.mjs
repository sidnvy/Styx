// Opt-in real-browser integration: private UI + real core + owned TLS Gateway.
// No Host install, account connection, desktop permissions or personal profile.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {generateKeyPairSync,createHash,createPublicKey} from 'node:crypto';
import {buildHostRelease} from '../../host/build-host-release.mjs';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {createOnboardingServer} from '../server.mjs';
const native=process.env.STYX_ONBOARDING_NATIVE_BUNDLE==='1';
const enabled=process.env.STYX_ONBOARDING_BROWSER_TEST==='1';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,code,ms=12000){const end=Date.now()+ms;while(Date.now()<end){if(await fn())return;await sleep(100)}throw Error(code)}
test(native?'real browser prepares native Hosts, verifies Gateway, pairs locally and joins by private link with separate approval':'real browser saves config, explicitly prepares/starts/pauses owned Gateway and resumes status',{skip:!enabled,timeout:120000},async()=>{
 const binary=process.env.STYX_ONBOARDING_BROWSER_BINARY;assert.ok(binary&&path.isAbsolute(binary));
 const coreUrl=process.env.STYX_ONBOARDING_CORE_MODULE?pathToFileURL(process.env.STYX_ONBOARDING_CORE_MODULE):new URL('../core.mjs',import.meta.url);
 const core=await import(coreUrl);const pairingLinks=native?await import(new URL('./pairing-links.mjs',coreUrl)):undefined;
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ui-browser-'));fs.chmodSync(root,0o700);
 let instance,joinInstance,browser,browserClosed,ws,primaryFailure;let next=0;const pending=new Map();
 const command=(method,params={})=>new Promise((resolve,reject)=>{const id=++next;const timer=setTimeout(()=>{pending.delete(id);reject(Error('browser_command_timeout'))},15000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}))});
 async function evaluate(expression){const r=await command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});assert.equal(r.exceptionDetails,undefined);return r.result.value}
 try{
  const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const gatewayPort=listener.address().port;await new Promise(r=>listener.close(r));
  let artifacts,artifactDefaultsFile;
  if(native){
   const key=generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
   const privateKeyFile=path.join(root,'publisher-private.pem');fs.writeFileSync(privateKeyFile,key.privateKey,{mode:0o600});
   const publisherKeyFile=path.join(root,'publisher.pem');fs.writeFileSync(publisherKeyFile,key.publicKey,{mode:0o600});
   const bundle=path.join(root,'bundle');buildHostRelease({destination:bundle,version:'0.1.0-ui-native-pilot',privateKeyFile,nodeBinary:process.env.STYX_ONBOARDING_NODE_BINARY,codexBinary:process.env.STYX_ONBOARDING_CODEX_BINARY,cuaBinary:process.env.STYX_ONBOARDING_CUA_BINARY});
   artifacts={bundle,publisherKeyFile,publisherSha256:createHash('sha256').update(createPublicKey(key.publicKey).export({type:'spki',format:'der'})).digest('hex')};
   artifactDefaultsFile=path.join(root,'artifacts.json');fs.writeFileSync(artifactDefaultsFile,JSON.stringify(artifacts),{mode:0o600});
  }
  instance=await createOnboardingServer({stateDir:path.join(root,'state'),core,artifactDefaultsFile,pairingLinks});
  const profile=path.join(root,'browser');fs.mkdirSync(profile,{mode:0o700});
  browser=spawn(binary,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','--user-data-dir='+profile,instance.url],{stdio:'ignore'});
  browserClosed=new Promise(resolve=>browser.once('close',resolve));
  const active=path.join(profile,'DevToolsActivePort');await until(()=>fs.existsSync(active),'browser_not_started');const debugPort=fs.readFileSync(active,'utf8').split('\n')[0];
  const targets=await(await fetch('http://127.0.0.1:'+debugPort+'/json/list')).json();const page=targets.find(p=>p.type==='page');assert.ok(page);
  ws=new WebSocket(page.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true})});
  ws.addEventListener('message',event=>{const message=JSON.parse(event.data);if(message.method==='Page.javascriptDialogOpening'){void command('Page.handleJavaScriptDialog',{accept:true});return}const entry=pending.get(message.id);if(!entry)return;pending.delete(message.id);clearTimeout(entry.timer);message.error?entry.reject(Error('browser_protocol_error')):entry.resolve(message.result)});
  await until(()=>evaluate("document.querySelector('#setup')?.hidden===false"),'setup_not_ready');
  assert.equal(await evaluate("location.hash"),''); // bootstrap is removed from history
  if(native)assert.equal(await evaluate("document.querySelector('#setup').elements.bundle.value"),artifacts.bundle);
  const fields={gatewayUrl:'https://127.0.0.1:'+gatewayPort,label:'Owned UI Gateway test',bundle:path.join(root,'bundle-not-executed'),publisherKeyFile:path.join(root,'publisher-not-read.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'host-not-created'),...(artifacts??{})};
  await evaluate(`(()=>{const f=document.querySelector('#setup');for(const[k,v]of Object.entries(${JSON.stringify(fields)}))f.elements[k].value=v;f.elements.reviewed.checked=true;f.requestSubmit();return true})()`);
  await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'config_not_saved');
  assert.equal(fs.existsSync(path.join(root,'host-not-created')),false);
  async function clickStep(label,status){await evaluate(`(()=>{const s=[...document.querySelectorAll('.step')].find(s=>s.querySelector('strong').textContent===${JSON.stringify(label)});if(!s||s.querySelector('button').disabled)throw Error('step_not_ready');s.querySelector('button').click();return true})()`);await until(()=>evaluate(`(()=>{const s=[...document.querySelectorAll('.step')].find(s=>s.querySelector('strong').textContent===${JSON.stringify(label)});return s?.querySelector('.status').textContent===${JSON.stringify(status)}})()`),'step_not_completed')}
  await clickStep('准备本机 Gateway','已记录成功');await clickStep('启动前台 Gateway','已记录成功');
  await until(()=>evaluate("document.querySelector('#runtime').textContent.includes('正在运行')"),'actual_gateway_not_running');
  if(native){
   await clickStep('验证 Gateway 认证与工具发现','已记录成功');
   const discovery={url:'https://127.0.0.1:'+gatewayPort+'/mcp',tokenFile:path.join(root,'state/gateway/model.token'),caFile:path.join(root,'state/gateway/certificate.pem')};
   await evaluate(`(()=>{const f=document.querySelector('#discovery-form');for(const[k,v]of Object.entries(${JSON.stringify(discovery)}))f.elements[k].value=v;f.elements.independentStyx.checked=true;f.elements.freshConnection.checked=true;f.requestSubmit();return true})()`);
   await until(()=>evaluate("document.querySelector('#discovery-result').textContent.includes('SDK 工具发现已验证')"),'discovery_not_verified');
   assert.equal(await evaluate("document.querySelector('#discovery-form').elements.tokenFile.value"),'');
   const modelToken=fs.readFileSync(discovery.tokenFile,'utf8').trim();assert.equal((await evaluate('document.body.textContent')).includes(modelToken),false);

   await clickStep('验证并准备 Host','已记录成功');
   await command('Page.enable');await clickStep('批准并配对这台 Host','已记录成功');
   await clickStep('检查 Host','已记录成功');
   const status=core.readDeployment(path.join(root,'state'));assert.equal(status.steps.find(s=>s.id==='host.pair').status,'succeeded');assert.equal(status.steps.find(s=>s.id==='host.doctor').evidence.status,'ready_for_exec');
   assert.equal(status.accountAcceptance,'NOT RUN');
   await evaluate("document.querySelector('#create-link').click();true");
   await until(()=>evaluate("document.querySelector('#created-link')?.hidden===false"),'owner_link_not_created');
   const link=await evaluate("document.querySelector('#created-link-value').value");assert.match(link,/^styx:\/\/join#/);
   assert.equal((await evaluate('document.body.textContent')).includes(link),false);
   joinInstance=await createOnboardingServer({stateDir:path.join(root,'join-state'),core,artifactDefaultsFile,pairingLinks});
   await command('Page.navigate',{url:joinInstance.url});await until(()=>evaluate("document.querySelector('#setup')?.hidden===false"),'join_setup_not_ready');
   await evaluate(`(()=>{const f=document.querySelector('#setup'),radio=f.querySelector('[value="join-existing"]');radio.checked=true;radio.dispatchEvent(new Event('change',{bubbles:true}));document.querySelector('#pairing-link-input').value=${JSON.stringify(link)};document.querySelector('#inspect-link').click();return true})()`);
   await until(()=>evaluate("document.querySelector('#link-preview')?.hidden===false"),'join_link_not_inspected');
   assert.equal(await evaluate("document.querySelector('#pairing-link-input').value"),'');
   await evaluate("document.querySelector('#accept-link').click();true");await until(()=>evaluate("document.querySelector('#link-import-result').textContent.includes('私有配对材料已保存')"),'join_link_not_accepted');
   const joinFields={label:'Owned linked Host',baseDir:path.join(root,'linked-host')};
   await evaluate(`(()=>{const f=document.querySelector('#setup');for(const[k,v]of Object.entries(${JSON.stringify(joinFields)}))f.elements[k].value=v;f.elements.reviewed.checked=true;f.requestSubmit();return true})()`);
   await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'linked_config_not_saved');
   await clickStep('验证并准备 Host','已记录成功');await clickStep('提交设备加入请求','已记录成功');
   const independentFingerprint=core.readDeployment(path.join(root,'join-state')).steps.find(s=>s.id==='host.request').evidence.fingerprint;
   await command('Page.navigate',{url:instance.origin});await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'owner_resume_not_ready');
   await evaluate("document.querySelector('#list-pending').click();true");await until(()=>evaluate("document.querySelector('#pending-devices').textContent.includes('Owned linked Host')"),'pending_device_not_listed');
   await evaluate(`(()=>{const card=[...document.querySelectorAll('#pending-devices>.prerequisite')].find(c=>c.querySelector('strong').textContent.includes('Owned linked Host'));card.querySelector('input:not([type=checkbox])').value=${JSON.stringify(independentFingerprint.slice(0,16))};card.querySelector('button').click();return true})()`);
   await until(()=>evaluate("document.querySelector('#pending-devices').textContent.includes('设备已批准')"),'explicit_linked_approval_not_completed');
   await command('Page.navigate',{url:joinInstance.origin});await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'linked_resume_not_ready');
   await clickStep('领取管理员审批结果','已记录成功');await clickStep('检查 Host','已记录成功');
   assert.equal(core.readDeployment(path.join(root,'join-state')).steps.find(s=>s.id==='host.doctor').evidence.status,'ready_for_exec');
   assert.equal(await evaluate('location.hash'),'');
   await command('Page.navigate',{url:instance.origin});await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'owner_final_resume_not_ready');

  }
  await evaluate("document.querySelector('#pause').click();true");
  await until(()=>evaluate("document.querySelector('#runtime').textContent.includes('未持有运行实例')"),'actual_gateway_not_stopped');
  await command('Page.reload');await until(()=>evaluate("document.querySelector('#progress')?.hidden===false"),'resume_not_loaded');
  assert.equal(await evaluate("document.querySelectorAll('.step .status.succeeded').length"),native?6:2);
  assert.equal(fs.existsSync(path.join(root,'host-not-created')),native);
  if(process.env.STYX_ONBOARDING_SCREENSHOT_DIR){
   const directory=process.env.STYX_ONBOARDING_SCREENSHOT_DIR;assert.ok(path.isAbsolute(directory));fs.mkdirSync(directory,{recursive:true});
   await evaluate("(()=>{for(const id of ['created-link-value','pairing-link-input']){const input=document.getElementById(id);if(input)input.value=''}document.querySelector('#created-link').hidden=true;window.scrollTo(0,0);return true})()");
   await command('Emulation.setDeviceMetricsOverride',{width:1440,height:1200,deviceScaleFactor:1,mobile:false});
   let image=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(directory,'onboarding-desktop.png'),Buffer.from(image.data,'base64'));
   await command('Emulation.setDeviceMetricsOverride',{width:390,height:1500,deviceScaleFactor:1,mobile:true});
   image=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(directory,'onboarding-mobile.png'),Buffer.from(image.data,'base64'));
  }

 }catch(error){primaryFailure=error;throw error}
 finally{
  try{
   // Ask this isolated browser to close its own children/profile first. Retain
   // the close promise from spawn, so a prior exit cannot race the observer.
   if(ws?.readyState===1){try{ws.send(JSON.stringify({id:++next,method:'Browser.close'}))}catch{}}
   if(browserClosed){
    const waitClosed=()=>new Promise(resolve=>{const timer=setTimeout(()=>resolve(false),5000);browserClosed.then(()=>{clearTimeout(timer);resolve(true)})});
    if(!await waitClosed()){browser.kill('SIGTERM');if(!await waitClosed()){browser.kill('SIGKILL');if(!await waitClosed())throw Error('owned_browser_close_timeout')}}
   }
   for(const entry of pending.values()){clearTimeout(entry.timer);entry.reject(Error('browser_cleanup'))}pending.clear();ws?.close();
   await joinInstance?.close();await instance?.close();
   // Chromium profile children may finish SQLite cleanup after browser close.
   fs.rmSync(root,{recursive:true,force:true,maxRetries:10,retryDelay:150});
  }catch(cleanupError){
   if(primaryFailure)primaryFailure.cleanupFailure=cleanupError.code??'owned_browser_cleanup_failed';
   else throw cleanupError;
  }
 }
});
