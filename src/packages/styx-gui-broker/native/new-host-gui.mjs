// New Styx.app only. The caller grants TCC manually before this runner is used.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,existsSync,mkdtempSync} from 'node:fs';
import {setTimeout as sleep} from 'node:timers/promises';
import {GuiBroker} from '../broker.mjs';
import {SdkClient} from '../sdk-client.mjs';
import {socketIdentity} from '../socket-policy.mjs';
const [base,initialRoot,app,driver,python,pythonPath]=process.argv.slice(2);
assert.ok([base,initialRoot,app,driver,python,pythonPath].every(x=>x?.startsWith('/')));
const executable=app+'/Contents/MacOS/Styx';
const identity=pid=>execFileSync(executable,['--identity',String(pid)],{encoding:'utf8'}).trim();
const wait=async f=>{for(let i=0;i<300;i++){if(await f())return true;await sleep(50);}return false;};
const records=[],runs=[],clients=[];
let root=initialRoot,receipt,window,broker,discovery;
const owner='new-styx-gui/scratch-chat';
const make=()=>new SdkClient({python,pythonPath,socket:root+'/driver.sock'});
const live=r=>identity(r.host_pid)===r.host_identity&&identity(r.daemon_pid)===r.daemon_identity;
const record=(test,data={})=>{records.push({test,pass:true,...data});console.log('PASS',test);};
async function inspect(){
 assert.ok(await wait(()=>existsSync(root+'/ready.json')));
 receipt=JSON.parse(readFileSync(root+'/ready.json','utf8'));runs.push({root,...receipt});
 assert.ok(live(receipt));assert.equal(receipt.process_group,receipt.host_pid);
 socketIdentity(root+'/driver.sock',root);
 discovery=make();
 const meta=await discovery.call('metadata');
 assert.equal(meta.pid,receipt.daemon_pid);assert.equal(meta.embedded,true);
 assert.equal(meta.host_bundle_id,'com.styx.prototype.guibroker20261017');
 const permissions=(await discovery.call('check_permissions',{prompt:false})).structuredContent;
 writeFileSync(base+'/permissions-after.json',JSON.stringify(permissions,null,2));
 assert.equal(permissions.accessibility,true,'Manual Accessibility grant required');
 assert.equal(permissions.screen_recording,true,'Manual Screen Recording grant required');
 assert.equal(permissions.source.responsible_ppid,receipt.host_pid);
 assert.equal(permissions.source.attribution,'host');assert.equal(permissions.source.disclaim_env,false);
 const health=(await discovery.call('health_report',{include:['session_active','bundle_identity']})).structuredContent;
 for(const name of ['session_active','bundle_identity'])assert.equal(health.checks.find(c=>c.name===name)?.status,'pass');
 assert.equal(health.checks.find(c=>c.name==='bundle_identity').data.parent_process_id,receipt.host_pid);
 const list=(await discovery.call('list_windows',{pid:receipt.host_pid})).structuredContent;
 const windows=list.windows.filter(w=>w.pid===receipt.host_pid&&w.title==='Styx GUI Broker Isolated Scratch 20261017');
 assert.equal(windows.length,1);window=windows[0].window_id;
 record('new_styx_embedded_identity_and_manual_permissions',{metadata:meta,permissions,health,host_pid:receipt.host_pid,window_id:window});
}
function binding(){
 assert.ok(live(receipt),'dead-generation');
 return {id:'isolated-gui',host:'isolated-macos',osUser:String(process.getuid()),sessionGeneration:'unlocked-pilot',
  appGeneration:receipt.host_identity,runtimeGeneration:receipt.daemon_identity,ready:true};
}
const observe=(screenshot=false)=>broker.observe({environment_id:'isolated-gui',pid:receipt.host_pid,window_id:window,include_screenshot:screenshot},owner);
const field=r=>{const e=r.structuredContent.elements.find(e=>e.role==='AXTextField');assert.ok(e);return e.element_token;};
const button=r=>{const e=r.structuredContent.elements.find(e=>e.role==='AXButton'&&e.label==='Styx Increment');assert.ok(e);return e.element_token;};
const hasValue=(r,v)=>r.structuredContent.elements.some(e=>e.role==='AXTextField'&&e.value===v);
try{
 await inspect();
 broker=new GuiBroker({
  resolve:async(id,caller)=>{assert.equal(caller,owner);assert.equal(id,'isolated-gui');return binding();},
  verifyTarget:async(b,pid,win)=>{assert.equal(pid,receipt.host_pid);assert.equal(win,window);assert.ok(live(receipt));return {generation:receipt.host_identity};},
  connect:async()=>{const c=make(),m=await c.call('metadata');assert.equal(m.pid,receipt.daemon_pid);clients.push(c);return c;}
 });
 const first=await observe(true);
 const image=first.content.find(c=>c.type==='image');
 assert.ok(image);assert.ok(Buffer.from(image.data,'base64').length>100);
 // Only a scratch-window image is retained, never a full desktop capture.
 writeFileSync(base+'/new-styx-scratch.png',Buffer.from(image.data,'base64'));
 record('new_styx_window_observation_and_capture',{elements_complete:first.structuredContent.elements_complete,image_bytes:Buffer.from(image.data,'base64').length});
 const old=field(first),second=await observe();
 await assert.rejects(broker.act('set_value',{element_token:old,value:'MUST_NOT_WRITE'},owner));
 record('superseded_gateway_token_refused');
 const result=await broker.act('set_value',{element_token:field(second),value:'新Styx验证_PASS'},owner);
 assert.equal(result.structuredContent.effect,'confirmed');
 const after=await observe();assert.ok(hasValue(after,'新Styx验证_PASS'));
 record('unicode_set_value_independent_readback',{native_effect:result.structuredContent.effect});
 const beforeCount=JSON.parse(readFileSync(root+'/fixture.json','utf8')).button_count;
 const click=await broker.act('click',{element_token:button(after)},owner);
 assert.ok(await wait(()=>JSON.parse(readFileSync(root+'/fixture.json','utf8')).button_count===beforeCount+1));
 const clicked=await observe();assert.ok(hasValue(clicked,'新Styx验证_PASS'));
 record('click_independent_fixture_counter',{native_effect:click.structuredContent.effect??'unknown',before:beforeCount,after:beforeCount+1});
 const preDisconnect=field(clicked);
 clients.at(-1).child.kill('SIGKILL');
 assert.ok(await wait(()=>clients.at(-1).closed));
 await assert.rejects(broker.act('set_value',{element_token:preDisconnect,value:'MUST_NOT_WRITE'},owner));
 const recovered=await observe();assert.ok(hasValue(recovered,'新Styx验证_PASS'));
 record('abrupt_sdk_disconnect_invalidates_tokens_and_recovers',{client_instances:clients.length});
 const preReconnect=field(recovered);
 await broker.reconnect('isolated-gui',owner);
 await assert.rejects(broker.act('set_value',{element_token:preReconnect,value:'MUST_NOT_WRITE'},owner));
 const fresh=await observe();
 await broker.act('set_value',{element_token:field(fresh),value:'新Styx重连_PASS'},owner);
 assert.ok(hasValue(await observe(),'新Styx重连_PASS'));
 record('explicit_reconnect_requires_fresh_observation');
 const expiring=field(await observe()),started=Date.now();
 await sleep(31000);
 await assert.rejects(broker.act('set_value',{element_token:expiring,value:'MUST_NOT_WRITE'},owner));
 assert.ok(hasValue(await observe(),'新Styx重连_PASS'));
 record('actual_30_second_gateway_token_expiry',{elapsed_ms:Date.now()-started,configured_ttl_ms:30000});
 const raw=(await discovery.call('get_window_state',{pid:receipt.host_pid,window_id:window,tree_format:'elements',include_screenshot:false})).structuredContent.elements.find(e=>e.role==='AXTextField').element_token;
 await discovery.call('get_window_state',{pid:receipt.host_pid,window_id:window,tree_format:'elements',include_screenshot:false});
 const refused=await discovery.call('set_value',{element_token:raw,value:'MUST_NOT_WRITE'});
 assert.ok(refused.isError||refused.structuredContent?.status==='refused');
 record('native_snapshot_token_refused_after_replacement');
 const deathToken=field(await observe()),previous={...receipt},previousRoot=root;
 await discovery.close();discovery=null;
 assert.equal(identity(receipt.host_pid),receipt.host_identity);
 process.kill(receipt.host_pid,'SIGKILL');
 assert.ok(await wait(()=>identity(previous.host_pid)==='absent'&&identity(previous.daemon_pid)==='absent'&&identity(previous.guard_pid)==='absent'&&!existsSync(previousRoot+'/driver.sock')));
 assert.equal((await broker.callTool('set_value',{element_token:deathToken,value:'MUST_NOT_WRITE'},owner)).isError,true);
 record('host_sigkill_cleans_daemon_guard_and_socket_and_refuses_token',{cleanup:JSON.parse(readFileSync(previousRoot+'/guard-cleanup.json','utf8'))});
 root=mkdtempSync('/private/tmp/styx-gb-');
 execFileSync('/usr/bin/open',['-n','-g','-a',app,'--args',root,driver]);
 await inspect();
 assert.notEqual(receipt.host_identity,previous.host_identity);
 assert.notEqual(receipt.daemon_identity,previous.daemon_identity);
 assert.equal((await broker.callTool('set_value',{element_token:deathToken,value:'MUST_NOT_WRITE'},owner)).isError,true);
 const newGeneration=await observe();assert.ok(hasValue(newGeneration,'styx_initial'));
 await broker.act('set_value',{element_token:field(newGeneration),value:'新宿主会话_PASS'},owner);
 assert.ok(hasValue(await observe(),'新宿主会话_PASS'));
 record('new_host_generation_rebinds_with_fresh_tokens_only');
}catch(error){
 records.push({test:'acceptance_failure',pass:false,error:String(error),stack:error.stack});
 throw error;
}finally{
 await broker?.close();await discovery?.close();
 for(const r of runs){
  if(identity(r.host_pid)===r.host_identity)process.kill(r.host_pid,'SIGTERM');
  assert.ok(await wait(()=>identity(r.host_pid)==='absent'&&identity(r.daemon_pid)==='absent'&&identity(r.guard_pid)==='absent'&&!existsSync(r.root+'/driver.sock')),'owned cleanup unresolved');
 }
 writeFileSync(base+'/new-styx-gui-results.json',JSON.stringify({records,runs,cleanup_confirmed:true,production_changes:false},null,2));
}
console.log(JSON.stringify({passed:records.filter(r=>r.pass).length,total:records.length,cleanup_confirmed:true}));
