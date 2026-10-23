import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,existsSync,lstatSync,realpathSync} from 'node:fs';
import {setTimeout as sleep} from 'node:timers/promises';
import {GuiBroker} from '../broker.mjs';import {SdkClient} from '../sdk-client.mjs';import {socketIdentity,removeStaleSocket} from '../socket-policy.mjs';
const [base,root,fixtureApp,python,pythonPath]=process.argv.slice(2);
assert.ok([base,root,fixtureApp,python,pythonPath].every(x=>typeof x==='string'&&x.startsWith('/')));
const socket=root+'/driver.sock';
const identity=pid=>execFileSync(base+'/Styx.app/Contents/MacOS/Styx',['--identity',String(pid)],{encoding:'utf8'}).trim();
const make=()=>new SdkClient({python,pythonPath,socket});
assert.equal(existsSync(socket),false,'Existing socket must not be reused');
const logOffset=readFileSync(root+'/host.log','utf8').length;
const launcher=spawn('/usr/bin/open',['-n','-g','-a',fixtureApp],{stdio:'ignore'});
let fixture=null;
let daemon=null,daemonStamp=null,receipt=null,broker=null,discovery=null;const records=[];
const wait=async pred=>{for(let i=0;i<120;i++){if(await pred())return true;await sleep(50);}return false;};
try{
 assert.ok(await wait(()=>existsSync(socket)),'scratch daemon socket not ready');
 const tail=readFileSync(root+'/host.log','utf8').slice(logOffset);
 const pid=Number(tail.match(/host_pid=(\d+)/)?.[1]);
 assert.ok(Number.isSafeInteger(pid)&&pid>1);
 fixture={pid,kill:signal=>process.kill(pid,signal)};
 receipt=socketIdentity(socket,root);
 discovery=make();const meta=await discovery.call('metadata');
 daemon=meta.pid;daemonStamp=identity(daemon);
 assert.equal(meta.embedded,true);assert.equal(meta.driver_version,'0.36.0');
 const hostStamp=identity(fixture.pid);
 const p=await discovery.call('check_permissions',{prompt:false});
 const perm=p.structuredContent;
 writeFileSync(base+'/native-permissions.json',JSON.stringify(perm,null,2));
 assert.equal(perm.accessibility,true);assert.equal(perm.screen_recording,true);
 assert.equal(perm.source.responsible_ppid,fixture.pid);assert.equal(perm.source.attribution,'host');
 const active=await discovery.call('health_report',{include:['session_active','bundle_identity']});
 assert.ok(active.structuredContent.checks.filter(x=>x.status!=='skip').every(x=>x.status==='pass'));
 const list=await discovery.call('list_windows',{pid:fixture.pid});
 const windows=list.structuredContent.windows.filter(w=>w.pid===fixture.pid&&w.title==='Styx Cua Pilot Scratch 20261017');
 assert.equal(windows.length,1);const window=windows[0].window_id;
 const owner='native-test/scratch-chat';
 const clients=[];
 const binding={id:'pilot',host:'native-pilot',osUser:String(process.getuid()),sessionGeneration:'same-unlocked-test-console',
  appGeneration:hostStamp,runtimeGeneration:daemonStamp,ready:true};
 broker=new GuiBroker({resolve:async(id,caller)=>{
  if(caller!==owner||id&&id!=='pilot')throw Error('denied');
  if(identity(fixture.pid)!==hostStamp||identity(daemon)!==daemonStamp)throw Error('dead-generation');
  return binding;
 },verifyTarget:async(b,pid,win)=>{
  assert.equal(pid,fixture.pid);assert.equal(win,window);return {generation:identity(pid)};
 },connect:async()=>{
  const c=make(),m=await c.call('metadata');
  assert.equal(m.pid,daemon);assert.equal(m.embedded,true);clients.push(c);return c;
 }});
 const observe=()=>broker.observe({environment_id:'pilot',pid:fixture.pid,window_id:window,include_screenshot:false},owner);
 const field=r=>r.structuredContent.elements.find(e=>e.role==='AXTextField').element_token;
 const first=await observe(),old=field(first),second=await observe();
 await assert.rejects(broker.act('set_value',{element_token:old,value:'MUST_NOT_WRITE'},owner));
 records.push({test:'new_observation_invalidates_old_token',pass:true});
 const set=await broker.act('set_value',{element_token:field(second),value:'Broker验证_PASS'},owner);
 assert.equal(set.structuredContent.effect,'confirmed');
 const after=await observe();assert.ok(after.structuredContent.elements.some(e=>e.value==='Broker验证_PASS'));
 records.push({test:'broker_unicode_readback',pass:true,native_effect:set.structuredContent.effect,elements_complete:after.structuredContent.elements_complete});
 const beforeReconnect=field(after);
 await broker.reconnect('pilot',owner);
 await assert.rejects(broker.act('set_value',{element_token:beforeReconnect,value:'MUST_NOT_WRITE'},owner));
 const fresh=await observe();
 await broker.act('set_value',{element_token:field(fresh),value:'Reconnect验证_PASS'},owner);
 const readback=await observe();assert.ok(readback.structuredContent.elements.some(e=>e.value==='Reconnect验证_PASS'));
 records.push({test:'disconnect_reconnect_rejects_old_and_accepts_fresh',pass:true,client_instances:clients.length});
 // Raw driver rejection is tested on its own persistent client, without using the broker's alias.
 const a=await discovery.call('get_window_state',{pid:fixture.pid,window_id:window,tree_format:'elements',include_screenshot:false});
 const raw=a.structuredContent.elements.find(e=>e.role==='AXTextField').element_token;
 await discovery.call('get_window_state',{pid:fixture.pid,window_id:window,tree_format:'elements',include_screenshot:false});
 const refused=await discovery.call('set_value',{element_token:raw,value:'MUST_NOT_WRITE'});
 assert.ok(refused.isError||refused.structuredContent?.status==='refused');
 records.push({test:'native_driver_rejects_superseded_snapshot',pass:true});
 const preDeath=await observe(),deathToken=field(preDeath);
 // Stop only this fixture's exact driver generation, then verify no capability survives.
 assert.equal(identity(daemon),daemonStamp);process.kill(daemon,'SIGTERM');
 assert.ok(await wait(()=>identity(daemon)==='absent'));
 const blocked=await broker.callTool('set_value',{element_token:deathToken,value:'MUST_NOT_WRITE'},owner);
 assert.equal(blocked.isError,true);
 records.push({test:'actual_driver_exit_blocks_old_capability',pass:true});
}finally{
 await broker?.close();await discovery?.close();
 if(daemon&&identity(daemon)===daemonStamp){process.kill(daemon,'SIGTERM');await wait(()=>identity(daemon)==='absent');}
 if(fixture&&identity(fixture.pid)!=='absent'){fixture.kill('SIGTERM');await wait(()=>identity(fixture.pid)==='absent');}
 if(receipt&&existsSync(socket))await removeStaleSocket({file:socket,root,receipt,proveDead:async()=>identity(daemon)==='absent'});
 const cleanup={host_exited:!fixture||identity(fixture.pid)==='absent',daemon_exited:daemon?identity(daemon)==='absent':true,socket_removed:!existsSync(socket)};
 writeFileSync(base+'/native-gui-cleanup.json',JSON.stringify(cleanup,null,2));
 assert.ok(Object.values(cleanup).every(Boolean));
}
writeFileSync(base+'/native-gui-results.json',JSON.stringify(records,null,2));
console.log(JSON.stringify({tests:records,all_passed:records.every(r=>r.pass)}));
