// Real Chrome with an isolated profile and explicit UI API fixtures. These
// tests verify UI contracts/privacy, not native permissions or actual chat proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {spawn} from 'node:child_process';
const enabled=process.env.STYX_ONBOARDING_BROWSER_TEST==='1';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(fn,code,timeout=10000){const end=Date.now()+timeout;while(Date.now()<end){if(await fn())return;await sleep(50)}throw Error(code)}
const ids=['local_setup','system_permissions','background','external_entry','chat_connection','chat_request_proof','target_chat_confirmation'];
function fixture(){
 const state={deployment:null,background:'foreground',tunnel:'not_configured',acceptance:{schema:1,status:'not_started',challenge:null,requestProof:{status:'pending'},targetChatConfirmation:{status:'pending',providerIdentity:'not_verified'},desktop:{status:'pending'},complete:false},plugin:{schema:1,required:true,presentation:{displayName:'Styx',shortDescription:'让聊天连接这台电脑',longDescription:'通过 Styx 安全连接本机终端与可选桌面能力。',icon:null},selection:{mode:'create',accountLabel:'',pluginUrl:''},profileSaved:false,export:{status:'not_exported'},accountActions:{upload:'not_observed',installation:'not_observed',connection:'not_verified'},requiresAccountAction:true},calls:[],handoffExpires:5000,tunnelShouldFail:false};
 const secret='UI_TEST_MODEL_ONLY_CREDENTIAL_0123456789abcdef';
 const capability={csrf:'fixture-csrf',platform:'darwin',packagedPreviewTrusted:true,journeySupported:true,diagnosticsSupported:true,acceptanceSupported:true,connectionHandoffSupported:true,foregroundSupported:true,backgroundSupported:true,tunnelSupported:true,localGatewayAvailable:true,localGatewayAddresses:['192.0.2.8'],pauseSupported:true,startSupported:true,pairingLinkImportSupported:true,gatewayService:{},defaults:{label:'我的 MacBook',gatewayUrl:'https://127.0.0.1:48795',bundle:'/private/tmp/fixture/bundle',publisherKeyFile:'/private/tmp/fixture/publisher.pem',publisherSha256:'a'.repeat(64),baseDir:'/private/tmp/fixture/host'}};
 const deployment=config=>({schema:1,mode:config.mode,roles:{gateway:config.mode==='join-existing'?'external':'local',host:'local',exec:'enabled',computer:config.host.computer?'requested':'disabled'},gatewayRuntime:'running',steps:(config.mode==='join-existing'?['host.prepare','host.request','host.claim','host.doctor']:['gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.doctor']).map(id=>({id,status:config.mode==='join-existing'?'pending':'succeeded'})),hostServiceMaintenance:{hasUncertainMutation:false},gatewayServiceMaintenance:{}});
 async function api(route,data){
  state.calls.push({route,data});
  if(route==='session')return capability;
  if(route==='status')return {deployment:state.deployment,dependencies:[],ownerPairingScope:state.deployment?.mode==='create-local'?{gatewayUrl:capability.defaults.gatewayUrl,label:'我的 MacBook',enableComputer:true}:null,background:{status:'needs_attention',observation:'current'},tunnel:{status:state.tunnel},busy:false};
  if(route==='journey'){
   const joined=state.deployment?.mode==='join-existing';
   return {journey:{schema:1,currentStep:!state.deployment?'local_setup':state.acceptance.complete?null:state.tunnel==='running'?'chat_request_proof':'system_permissions',steps:ids.map((id,i)=>({id,status:joined&&i>=3?'not_required':i===0&&state.deployment?'completed':'pending',reason:'user_action_or_observation_required'})),readiness:{exec:{status:state.deployment?'connected':'unknown'},desktop:{status:state.acceptance.desktop.status==='verified'?'verified':'not_verified'}},permissions:[{id:'accessibility',label:'辅助功能',status:'not_observed'},{id:'screen_recording',label:'屏幕录制',status:'not_observed'},{id:'automation',label:'应用自动化',status:'not_required'}],background:{preference:state.background},connectionHandoff:{status:state.tunnel==='running'?'available':'unavailable'},diagnostics:{canRetry:true}}};
  }
  if(route==='plugin')return {plugin:state.plugin};
  if(route==='plugin/profile'){assert.equal(data.authorize,true);state.plugin={...state.plugin,presentation:data.presentation,selection:data.selection,profileSaved:true,contextChanged:false,export:{status:'not_exported'}};return {plugin:state.plugin};}
  if(route==='plugin/export'){assert.equal(data.authorize,true);assert.equal(state.plugin.selection.mode,'create');state.plugin.export={status:'exported',filename:'styx-native.zip',sha256:'f'.repeat(64)};return {fixtureBinary:Buffer.from('PK\x03\x04UI ZIP contract fixture; not a real package')};}
  if(route==='plugin/record'){assert.equal(data.authorize,true);assert.match(data.pluginUrl,/^https:\/\/chatgpt\.com\//);state.plugin.selection.pluginUrl=data.pluginUrl;state.plugin.accountActions[data.stage]='user_confirmed';return {plugin:state.plugin};}
  if(route==='acceptance')return {acceptance:state.acceptance};
  if(route==='diagnostics')return {diagnostics:{schema:1,status:'observed'}};
  if(route==='create'){state.config=data;state.deployment=deployment(data);return {deployment:state.deployment};}
  if(route==='local-setup')return {workflow:{status:'prepared'}};
  if(route==='advance'){assert.equal(state.deployment.mode,'join-existing');assert.equal(data.authorize.length,1);const step=state.deployment.steps.find(step=>step.id===data.authorize[0]);step.status=step.id==='host.claim'&&!state.ownerApproved?'awaiting_approval':'succeeded';if(step.id==='host.request')step.fingerprint='c'.repeat(64);return {deployment:state.deployment};}
  if(route==='journey/background-preference'){state.background=data.background;return {preference:{background:data.background,configurationBound:true}};}
  if(route==='foreground'){assert.equal(data.authorize,true);state.foregroundStarted=true;return {foreground:{status:'started',ownership:'current_process',serviceMutation:'NONE'}};}
  if(route==='tunnel/configure'){if(state.tunnelShouldFail)throw Error('fixture_tunnel_refused');state.tunnel='configured';return {status:'configured'};}
  if(route==='tunnel/start'){state.tunnel='running';return {status:'running'};}
  if(route==='connection-handoff')return {handoff:{status:'prepared',connection:{tunnelId:'tunnel_fixture123'},authentication:{type:'bearer',modelCredential:secret},expiresAt:Date.now()+state.handoffExpires}};
  if(route==='acceptance/begin'){
   state.acceptance={...state.acceptance,status:'pending',challenge:{id:'d'.repeat(32),expiresAt:Date.now()+60000,prompt:'请通过 Styx 执行本次隔离验证请求。不要使用本地设置接口替代真实聊天。',command:'printf STYX_FIXTURE',environmentId:'fixture-device',desktopValue:'STYX_GUI_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'},desktop:{status:'pending'}};return {acceptance:state.acceptance};
  }
  if(route==='acceptance/desktop-readback'){state.desktopReadback=data;return {status:'recorded_not_verified'};}
  if(route==='acceptance/confirm'){
   assert.equal(state.acceptance.requestProof.status,'verified');assert.equal(state.acceptance.desktop.status,'verified');
   state.acceptance.targetChatConfirmation={status:'user_confirmed',providerIdentity:'not_verified'};state.acceptance.complete=true;return {acceptance:state.acceptance};
  }
  if(route==='pairing-link/inspect')return {inspectionId:'inspection-fixture',preview:{origin:'https://existing-gateway.example',expiresAt:Date.now()+60000,requiresCertificateApproval:true,caSha256:'b'.repeat(64)}};
  if(route==='pairing-link/accept')return {joinLinkId:'joined-link-fixture',status:'pairing_material_saved',origin:'https://existing-gateway.example'};
  throw Error('fixture_unknown_route');
 }
 return {state,secret,api};
}
async function browserFixture(t){
 const f=fixture(),profile=fs.mkdtempSync(path.join(os.tmpdir(),'styx-journey-browser-'));let browser,ws,closed,next=0;const pending=new Map();
 const server=http.createServer(async(req,res)=>{
  const send=(code,value,type='application/json')=>{res.writeHead(code,{'Content-Type':type,'Cache-Control':'no-store'});res.end(type==='application/json'?JSON.stringify(value):value)};
  if(req.url.startsWith('/api/')){let body='';for await(const chunk of req)body+=chunk;try{const result=await f.api(req.url.slice(5),body?JSON.parse(body):undefined);if(result.fixtureBinary){res.writeHead(200,{'Content-Type':'application/zip','Content-Disposition':'attachment; filename=styx-native.zip','Cache-Control':'no-store'});res.end(result.fixtureBinary)}else send(200,result)}catch{send(409,{error:'fixture_operation_refused'})}return;}
  const file=req.url==='/'?'index.html':req.url.startsWith('/ui/')?req.url.slice(4):null;
  if(!['index.html','app.mjs','style.css'].includes(file)){send(404,{});return;}
  send(200,fs.readFileSync(new URL(file,import.meta.url)),file.endsWith('.mjs')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
 const binary=process.env.STYX_ONBOARDING_BROWSER_BINARY;assert.ok(binary&&path.isAbsolute(binary));
 browser=spawn(binary,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','--user-data-dir='+profile,origin+'/#session=isolated-local-fixture-session'],{stdio:'ignore'});closed=new Promise(resolve=>browser.once('close',resolve));
 t.after(async()=>{if(ws?.readyState===1)ws.send(JSON.stringify({id:++next,method:'Browser.close'}));if(browser){await Promise.race([closed,sleep(3000)]);if(browser.exitCode===null&&browser.signalCode===null){browser.kill('SIGTERM');await closed}}for(const entry of pending.values())clearTimeout(entry.timer);ws?.close();await new Promise(resolve=>server.close(resolve));fs.rmSync(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100});});
 const active=path.join(profile,'DevToolsActivePort');await until(()=>fs.existsSync(active),'browser_not_started');const port=fs.readFileSync(active,'utf8').split('\n')[0];const targets=await(await fetch('http://127.0.0.1:'+port+'/json/list')).json();
 ws=new WebSocket(targets.find(page=>page.type==='page').webSocketDebuggerUrl);await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true})});
 const command=(method,params={})=>new Promise((resolve,reject)=>{const id=++next,timer=setTimeout(()=>{pending.delete(id);reject(Error('browser_timeout'))},12000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));});
 ws.addEventListener('message',event=>{const value=JSON.parse(event.data);if(value.method==='Page.javascriptDialogOpening'){void command('Page.handleJavaScriptDialog',{accept:true});return;}const entry=pending.get(value.id);if(entry){pending.delete(value.id);clearTimeout(entry.timer);value.error?entry.reject(Error('browser_protocol_error')):entry.resolve(value.result);}});
 await command('Page.enable');
 const downloadDir=path.join(profile,'downloads');fs.mkdirSync(downloadDir);await command('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:downloadDir});
 const evaluate=async expression=>{const r=await command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});assert.equal(r.exceptionDetails,undefined);return r.result.value;};
 await until(()=>evaluate("document.querySelector('#setup')?.hidden===false"),'ui_not_ready');
 return {...f,command,evaluate,origin,downloadDir};
}

test('real browser guides ordinary setup and keeps secret handoff, native readiness and chat proofs separate',{skip:!enabled,timeout:60000},async t=>{
 const f=await browserFixture(t),e=f.evaluate;
 assert.equal(await e("location.hash"),'');assert.equal(await e("document.querySelector('#artifacts').open"),false);
 assert.equal(await e("document.querySelector('#setup').elements.mode.value"),'create-local');
 assert.equal(await e("document.querySelector('#setup').elements.allowRemoteHosts.checked"),false);
 assert.equal(await e("document.querySelector('#gateway-address').offsetParent===null"),true);
 if(process.env.STYX_ONBOARDING_SCREENSHOT_DIR){const directory=process.env.STYX_ONBOARDING_SCREENSHOT_DIR;fs.mkdirSync(directory,{recursive:true});await f.command('Emulation.setDeviceMetricsOverride',{width:1440,height:1150,deviceScaleFactor:1,mobile:false});const shot=await f.command('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(directory,'journey-initial.png'),Buffer.from(shot.data,'base64'));}
 await e("(()=>{const form=document.querySelector('#setup');form.elements.computer.checked=true;form.elements.reviewed.checked=true;form.requestSubmit();return true})()");
 await until(()=>e("!document.querySelector('#progress').hidden"),'local_setup_not_saved');
 await until(()=>f.state.calls.some(call=>call.route==='local-setup'),'local_setup_not_run');
 assert.equal(f.state.config.mode,'create-local');assert.equal(f.state.config.gateway.allowRemoteHosts,undefined);
 assert.equal(await e("document.querySelector('#readiness-exec').textContent"),'设备连接已观察到');
 assert.equal(await e("document.querySelector('#readiness-desktop').textContent"),'尚未验收');
 assert.equal(await e("document.querySelector('#confirm-target-chat').disabled"),true);
 await e("document.querySelector('#keep-foreground').click();true");await until(()=>f.state.background==='foreground'&&f.state.calls.some(call=>call.route==='journey/background-preference'),'foreground_preference_not_recorded');
 await until(()=>f.state.foregroundStarted,'foreground_connection_not_started');
 await until(()=>e("!document.querySelector('#keep-foreground').disabled"),'foreground_action_not_settled');
 const foregroundIndex=f.state.calls.findIndex(call=>call.route==='foreground'),preferenceIndex=f.state.calls.findIndex(call=>call.route==='journey/background-preference');assert.ok(foregroundIndex>preferenceIndex);
 for(const selector of ['#open-platform','#open-chatgpt'])assert.equal(await e(`(()=>{const a=document.querySelector('${selector}');return a.target==='_blank'&&a.rel.includes('noopener')&&!a.href.includes('session')})()`),true);
 f.state.tunnelShouldFail=true;
 await e("(()=>{const form=document.querySelector('#tunnel-form');form.elements.tunnelId.value='tunnel_fixture123';form.elements.apiKey.value='RUNTIME_KEY_UI_ONLY';form.elements.authorize.checked=true;form.requestSubmit();return true})()");
 await until(()=>f.state.calls.some(call=>call.route==='tunnel/configure'),'tunnel_configure_not_called');
 await until(()=>e("document.querySelector('#tunnel-form').elements.apiKey.value===''"),'runtime_key_not_cleared_on_failure');
 await until(()=>e("document.querySelector('#notice').textContent.includes('连接未完成')"),'tunnel_failure_not_explained');
 assert.equal(await e("document.querySelector('#prepare-handoff').disabled"),true);
 f.state.tunnelShouldFail=false;
 await e("(()=>{const form=document.querySelector('#tunnel-form');form.elements.apiKey.value='RUNTIME_KEY_UI_RETRY';form.requestSubmit();return true})()");
 await until(()=>f.state.tunnel==='running','tunnel_retry_not_started');
 await until(()=>e("!document.querySelector('#prepare-handoff').disabled"),'handoff_not_ready_after_tunnel');
 await e("document.querySelector('#prepare-handoff').click();true");await until(()=>e("!document.querySelector('#connection-handoff').hidden"),'handoff_not_shown');
 assert.equal(await e("document.querySelector('#connection-credential').type"),'password');
 assert.equal(await e("document.body.innerText.includes('UI_TEST_MODEL_ONLY_CREDENTIAL')"),false);
 assert.equal(await e("JSON.stringify(Object.entries(sessionStorage)).includes('UI_TEST_MODEL_ONLY_CREDENTIAL')"),false);
 await e("document.querySelector('#clear-credential').click();true");assert.equal(await e("document.querySelector('#connection-credential').value"),'');
 await e("document.querySelector('#prepare-handoff').click();true");await until(()=>e("!document.querySelector('#connection-handoff').hidden"),'second_handoff_not_shown');
 await e("(()=>{Object.defineProperty(document,'hidden',{configurable:true,value:true});document.dispatchEvent(new Event('visibilitychange'));delete document.hidden;return true})()");
 assert.equal(await e("document.querySelector('#connection-credential').value"),'');
 f.state.handoffExpires=300;await e("document.querySelector('#prepare-handoff').click();true");await until(()=>e("document.querySelector('#connection-credential').value!==''"),'timed_handoff_not_shown');await until(()=>e("document.querySelector('#connection-credential').value===''"),'handoff_not_cleared_on_expiry');
 await e("document.querySelector('#begin-acceptance').click();true");await until(()=>e("!document.querySelector('#challenge-box').hidden"),'chat_challenge_not_created');
 assert.match(await e("document.querySelector('#desktop-acceptance-status').textContent"),/get_window_state.*同一窗口.*重新打开 Styx/);
 assert.equal(await e("document.querySelector('#confirm-target-chat').disabled"),true);
 // Simulate AX changing WKWebView value without dispatching input/change.
 await e("document.querySelector('#desktop-acceptance-input').value='STYX_GUI_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';true");
 assert.equal(f.state.desktopReadback,undefined);
 await e("document.querySelector('#refresh-acceptance').click();true");
 await until(()=>f.state.desktopReadback?.value==='STYX_GUI_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','explicit_check_missing_dom_readback');
 assert.equal(f.state.acceptance.requestProof.status,'pending');assert.equal(f.state.acceptance.desktop.status,'pending');
 await until(()=>e("!document.querySelector('#refresh-acceptance').disabled"),'explicit_readback_not_settled');
 assert.equal(await e("document.querySelector('#confirm-target-chat').disabled"),true);
 const priorReadbacks=f.state.calls.filter(call=>call.route==='acceptance/desktop-readback').length;
 await e("(()=>{const input=document.querySelector('#desktop-acceptance-input');input.value='STYX_GUI_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';input.dispatchEvent(new Event('input',{bubbles:true}));return true})()");
 await until(()=>f.state.calls.filter(call=>call.route==='acceptance/desktop-readback').length>priorReadbacks,'event_readback_not_submitted');
 await until(()=>f.state.desktopReadback?.value==='STYX_GUI_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','desktop_readback_not_submitted');
 assert.equal(f.state.acceptance.desktop.status,'pending');assert.equal(await e("document.querySelector('#confirm-target-chat').disabled"),true);
 // Fixture-controlled evidence states test rendering only; no native/chat proof
 // is fabricated or accepted by the UI test as product acceptance.
 f.state.acceptance.requestProof.status='verified';await e("document.querySelector('#refresh-acceptance').click();true");await until(()=>e("document.querySelector('#request-proof-status').textContent.includes('已收到并验证')"),'request_proof_not_separate');
 assert.equal(await e("document.querySelector('#desktop-acceptance-input').value"),'STYX_GUI_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
 assert.equal(await e("document.querySelector('#confirm-target-chat').disabled"),true);
 f.state.acceptance.desktop.status='verified';await e("document.querySelector('#refresh-acceptance').click();true");await until(()=>e("!document.querySelector('#observed-target-chat').disabled"),'desktop_proof_not_applied');
 await e("(()=>{const input=document.querySelector('#observed-target-chat');input.checked=true;input.dispatchEvent(new Event('change'));document.querySelector('#confirm-target-chat').click();return true})()");
 await until(()=>f.state.acceptance.complete,'target_chat_confirmation_missing');
 await until(()=>e("document.querySelector('#target-chat-status').textContent.includes('未认证账号平台身份')"),'user_attestation_misrepresented');
 await f.command('Emulation.setDeviceMetricsOverride',{width:390,height:1200,deviceScaleFactor:1,mobile:true});
 assert.equal(await e('document.documentElement.scrollWidth<=window.innerWidth'),true);
 if(process.env.STYX_ONBOARDING_SCREENSHOT_DIR){const directory=process.env.STYX_ONBOARDING_SCREENSHOT_DIR;fs.mkdirSync(directory,{recursive:true});for(const [name,width,height]of [['journey-mobile',390,1200],['journey-desktop',1440,1150]]){await f.command('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<700});await e('window.scrollTo(0,0);true');const shot=await f.command('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(directory,name+'.png'),Buffer.from(shot.data,'base64'));}}
});

test('real browser joins only after explicit invitation confirmation and returns account setup to its existing owner',{skip:!enabled,timeout:30000},async t=>{
 const f=await browserFixture(t),e=f.evaluate;
 await e("(()=>{const radio=document.querySelector('[value=join-existing]');radio.checked=true;radio.dispatchEvent(new Event('change',{bubbles:true}));document.querySelector('#pairing-link-input').value='styx://join#ISOLATED_PRIVATE_INVITATION';document.querySelector('#inspect-link').click();return true})()");
 await until(()=>e("!document.querySelector('#link-preview').hidden"),'join_preview_missing');assert.equal(await e("document.querySelector('#pairing-link-input').value"),'');
 assert.equal(f.state.calls.filter(call=>call.route==='create').length,0);
 await e("document.querySelector('#accept-link').click();true");await until(()=>e("document.querySelector('#link-import-result').textContent.includes('私有配对材料已保存')"),'join_not_confirmed');
 await e("(()=>{const form=document.querySelector('#setup');form.elements.reviewed.checked=true;form.requestSubmit();return true})()");
 await until(()=>f.state.deployment?.mode==='join-existing','join_not_saved');await until(()=>e("!document.querySelector('#join-account-note').hidden"),'join_owner_handoff_missing');
 await until(()=>f.state.deployment.steps.find(step=>step.id==='host.claim').status==='awaiting_approval','join_did_not_wait_for_owner');
 assert.match(await e("document.querySelector('#join-comparison').textContent"),/cccc cccc cccc cccc/);
 assert.equal(f.state.deployment.steps.find(step=>step.id==='host.doctor').status,'pending');
 assert.equal(f.state.config.joinLinkId,'joined-link-fixture');assert.equal(f.state.config.gateway.url,'https://existing-gateway.example');
 assert.equal(f.state.calls.filter(call=>call.route==='local-setup').length,0);
 assert.equal(f.state.calls.filter(call=>call.route.startsWith('plugin')).length,0);
 assert.equal(await e("document.querySelector('#account-connection').hidden"),true);
 assert.equal(await e("document.querySelector('#prepare-handoff').hidden"),true);
 assert.equal(await e("document.querySelector('#chat-request-proof').hidden"),true);
 assert.match(await e("document.querySelector('#join-account-note').textContent"),/无需另建隧道或重复添加账号/);
 f.state.ownerApproved=true;await e("document.querySelector('#continue-join').click();true");await until(()=>f.state.deployment.steps.find(step=>step.id==='host.doctor').status==='succeeded','join_did_not_continue_after_owner_approval');
 assert.ok(f.state.calls.filter(call=>call.route==='advance').every(call=>call.data.authorize.every(id=>id.startsWith('host.'))));
});


test('real browser customizes, exports and records plugin account actions separately, then reuses the same plugin',{skip:!enabled,timeout:60000},async t=>{
 const f=await browserFixture(t),e=f.evaluate;
 assert.equal(await e("document.querySelector('#package-review').textContent"),'允许 Styx 按以上选择设置这台电脑。');
 await e("(()=>{const form=document.querySelector('#setup');form.elements.reviewed.checked=true;form.requestSubmit();return true})()");
 await until(()=>e("!document.querySelector('#plugin-profile-fields').disabled"),'plugin_not_loaded');
 assert.equal(await e("document.querySelector('#plugin-profile-form').elements.displayName.value"),'Styx');
 assert.equal(await e("document.querySelector('#advanced-chat-auth').open"),false);
 await e("document.querySelector('#plugin-profile-form').requestSubmit();true");
 await until(()=>f.state.plugin.profileSaved,'default_plugin_choice_not_saved');
 await until(()=>e("document.querySelector('#plugin-profile-status').textContent.includes('已保存本机选择')&&!document.querySelector('#plugin-profile-fields').disabled"),'default_plugin_save_not_settled');
 assert.equal(f.state.plugin.presentation.icon,null);assert.equal(f.state.plugin.selection.mode,'create');
 assert.equal(await e("document.querySelector('#export-plugin').disabled"),true);
 assert.equal(await e("document.querySelector('#record-plugin-upload').disabled"),true);
 await e("(()=>{const form=document.querySelector('#plugin-profile-form');form.elements.shortDescription.value='😀'.repeat(31);form.elements.shortDescription.dispatchEvent(new Event('input',{bubbles:true}));return true})()");
 assert.equal(await e("document.querySelector('#plugin-profile-form').elements.shortDescription.validity.customError"),true);
 const saves=f.state.calls.filter(c=>c.route==='plugin/profile').length;
 await e("document.querySelector('#plugin-profile-form').requestSubmit();true");assert.equal(f.state.calls.filter(c=>c.route==='plugin/profile').length,saves);
 await e("(()=>{const form=document.querySelector('#plugin-profile-form');form.elements.displayName.value='我的 Styx';form.elements.accountLabel.value='个人工作区';form.elements.shortDescription.value='😀'.repeat(30);form.elements.longDescription.value='我的电脑连接工具\\n\\n明确授权后使用。';form.elements.shortDescription.dispatchEvent(new Event('input',{bubbles:true}));return true})()");
 async function pngFile(size){await e(`(async()=>{const canvas=document.createElement('canvas');canvas.width=canvas.height=${size};canvas.getContext('2d').fillRect(0,0,${size},${size});const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));const data=new DataTransfer();data.items.add(new File([blob],'test-icon.png',{type:'image/png'}));const input=document.querySelector('#plugin-icon-file');input.files=data.files;input.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)}
 await pngFile(32);await until(()=>e("document.querySelector('#plugin-icon-status').textContent.includes('图片未接受')"),'invalid_icon_accepted');
 await pngFile(64);await until(()=>e("document.querySelector('#plugin-icon-status').textContent.includes('64 × 64')"),'valid_icon_not_accepted');
 assert.equal(await e("document.querySelector('#plugin-profile-form').checkValidity()"),true);
 assert.equal(await e("document.querySelector('#plugin-profile-form').elements.displayName.value"),'我的 Styx');
 await e("document.querySelector('#plugin-profile-form').requestSubmit();true");
 await until(()=>f.state.plugin.presentation.displayName==='我的 Styx','custom_plugin_not_saved');
 assert.equal(Array.from(f.state.plugin.presentation.shortDescription).length,30);assert.equal(f.state.plugin.presentation.longDescription,'我的电脑连接工具\n\n明确授权后使用。');assert.equal(f.state.plugin.presentation.icon.mimeType,'image/png');assert.ok(f.state.plugin.presentation.icon.dataBase64.length>0);
 if(process.env.STYX_ONBOARDING_SCREENSHOT_DIR){await f.command('Emulation.setDeviceMetricsOverride',{width:1440,height:1200,deviceScaleFactor:1,mobile:false});await e("document.querySelector('#chatgpt-connect').scrollIntoView();true");const shot=await f.command('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(process.env.STYX_ONBOARDING_SCREENSHOT_DIR,'plugin-create-desktop.png'),Buffer.from(shot.data,'base64'));}
 f.state.tunnel='configured';await e("document.querySelector('#refresh').click();true");await until(()=>e("!document.querySelector('#export-plugin').disabled"),'plugin_export_not_enabled');
 await e("document.querySelector('#export-plugin').click();true");await until(()=>fs.existsSync(path.join(f.downloadDir,'styx-native.zip')),'plugin_zip_not_downloaded');
 await until(()=>e("!document.querySelector('#export-plugin').disabled"),'plugin_export_not_settled');
 assert.equal(f.state.plugin.accountActions.upload,'not_observed');assert.equal(f.state.plugin.accountActions.installation,'not_observed');
 assert.match(await e("document.querySelector('#plugin-export-status').textContent"),/本机认证.*不代表账号上传/);
 // A reply-capable native bridge contract fixture, not a native save proof.
 await e("window.webkit={messageHandlers:{styxPluginExport:{postMessage:async value=>{window.__pluginBridgePayload=value;return {status:'cancelled'}}}}};document.querySelector('#export-plugin').click();true");
 await until(()=>e("document.querySelector('#notice').textContent.includes('取消保存')"),'native_cancel_not_distinguished');
 assert.equal(await e("Object.keys(window.__pluginBridgePayload).join(',')"),'base64');
 assert.match(await e("window.__pluginBridgePayload.base64"),/^UEs/);
 await e("window.webkit.messageHandlers.styxPluginExport.postMessage=async()=>({status:'saved'});document.querySelector('#export-plugin').click();true");await until(()=>e("document.querySelector('#notice').textContent.includes('系统保存面板保存')"),'native_save_reply_not_displayed');
 assert.equal(f.state.plugin.accountActions.upload,'not_observed');
 f.state.plugin.contextChanged=true;await e("document.querySelector('#refresh').click();true");
 await until(()=>e("document.querySelector('#plugin-profile-status').textContent.includes('绑定已变化')"),'changed_plugin_target_not_disclosed');
 assert.equal(await e("document.querySelector('#record-plugin-upload').disabled"),true);
 assert.equal(await e("document.querySelector('#export-plugin').disabled"),true);
 await e("document.querySelector('#plugin-profile-form').requestSubmit();true");
 await until(()=>e("document.querySelector('#plugin-profile-status').textContent.includes('已保存本机选择')&&!document.querySelector('#export-plugin').disabled"),'plugin_target_not_reconfirmed');
 await e("document.querySelector('#export-plugin').click();true");await until(()=>e("!document.querySelector('#record-plugin-upload').disabled"),'reconfirmed_plugin_not_exported');
 await e("(()=>{document.querySelector('#plugin-returned-url').value='https://chatgpt.com/plugins/styx-fixture';document.querySelector('#plugin-upload-confirmed').checked=true;document.querySelector('#plugin-upload-form').requestSubmit();return true})()");
 await until(()=>f.state.plugin.accountActions.upload==='user_confirmed','plugin_upload_attestation_missing');
 await until(()=>e("!document.querySelector('#record-plugin-installation').disabled"),'saved_plugin_link_not_ready');
 assert.equal(await e("document.querySelector('#open-saved-plugin').href"),'https://chatgpt.com/plugins/styx-fixture');
 assert.equal(f.state.plugin.accountActions.connection,'not_verified');
 assert.equal(await e("document.querySelector('#plugin-returned-url').readOnly"),true);
 await e("(()=>{document.querySelector('#plugin-installed-confirmed').checked=true;document.querySelector('#plugin-install-form').requestSubmit();return true})()");await until(()=>f.state.plugin.accountActions.installation==='user_confirmed','plugin_install_attestation_missing');
 assert.equal(f.state.acceptance.complete,false);assert.equal(f.state.plugin.accountActions.connection,'not_verified');
 await until(()=>e("!document.querySelector('#plugin-profile-fields').disabled"),'plugin_profile_still_locked');
 const exports=f.state.calls.filter(c=>c.route==='plugin/export').length;
 await e("(()=>{const form=document.querySelector('#plugin-profile-form');form.elements.pluginMode.value='reuse';form.elements.existingPluginUrl.value='https://chatgpt.com/c/not-a-plugin';form.elements.existingPluginUrl.dispatchEvent(new Event('input',{bubbles:true}));return true})()");
 assert.equal(await e("document.querySelector('#plugin-profile-form').elements.existingPluginUrl.validity.customError"),true);
 await e("(()=>{const form=document.querySelector('#plugin-profile-form');form.elements.pluginMode.value='reuse';form.elements.existingPluginUrl.value='https://chatgpt.com/plugins';form.elements.existingPluginUrl.dispatchEvent(new Event('input',{bubbles:true}));return true})()");
 assert.equal(await e("document.querySelector('#plugin-profile-form').elements.existingPluginUrl.validity.customError"),true);
 await e("(()=>{const form=document.querySelector('#plugin-profile-form');form.elements.pluginMode.value='reuse';form.elements.existingPluginUrl.value='https://chatgpt.com/plugins/styx-fixture';form.elements.existingPluginUrl.dispatchEvent(new Event('input',{bubbles:true}));form.requestSubmit();return true})()");
 await until(()=>f.state.plugin.selection.mode==='reuse','plugin_reuse_not_saved');
 assert.equal(await e("document.querySelector('#plugin-create-path').hidden"),true);
 assert.equal(f.state.calls.filter(c=>c.route==='plugin/export').length,exports);
 assert.equal(await e("document.querySelector('#open-saved-plugin').href"),'https://chatgpt.com/plugins/styx-fixture');
 await f.command('Page.reload');await until(()=>e("document.querySelector('#plugin-profile-form').elements.pluginMode.value==='reuse'"),'plugin_reuse_not_restored');
 assert.equal(await e("document.querySelector('#plugin-profile-form').elements.existingPluginUrl.value"),'https://chatgpt.com/plugins/styx-fixture');
 await f.command('Emulation.setDeviceMetricsOverride',{width:390,height:1200,deviceScaleFactor:1,mobile:true});assert.equal(await e('document.documentElement.scrollWidth<=window.innerWidth'),true);
 if(process.env.STYX_ONBOARDING_SCREENSHOT_DIR){await e("document.querySelector('#chatgpt-connect').scrollIntoView();true");const shot=await f.command('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});fs.writeFileSync(path.join(process.env.STYX_ONBOARDING_SCREENSHOT_DIR,'plugin-reuse-mobile.png'),Buffer.from(shot.data,'base64'));}
 await e("(()=>{const form=document.querySelector('#plugin-profile-form');form.elements.pluginMode.value='create';form.elements.displayName.dispatchEvent(new Event('input',{bubbles:true}));form.requestSubmit();return true})()");
 await until(()=>f.state.plugin.selection.mode==='create'&&f.state.plugin.selection.pluginUrl==='','new_create_retained_old_plugin_url');
 await until(()=>e("document.querySelector('#plugin-profile-status').textContent.includes('已保存本机选择')&&document.querySelector('#plugin-returned-url').value===''"),'new_create_url_not_cleared_in_ui');
 assert.equal(await e("document.querySelector('#open-saved-plugin').hidden"),true);
});
