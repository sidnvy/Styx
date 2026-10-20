import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {beginDeploymentAcceptance,readDeploymentAcceptance,confirmDeploymentAcceptance,recordDeploymentDesktopReadback,readDeploymentConnectionHandoff,prepareDeploymentConnectionHandoff} from '../account-acceptance.mjs';
import {createAcceptanceObserver} from '../../shared/onboarding-evidence.mjs';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
function fixture(t,{desktop=false,browser=false,platform='linux'}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-account-acceptance-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const stateDir=path.join(root,'state'),base=path.join(root,'host');
 for(const dir of [stateDir,base,path.join(base,'device'),path.join(stateDir,'gateway'),path.join(stateDir,'gateway/enrollment'),path.join(stateDir,'tunnel')])fs.mkdirSync(dir,{mode:0o700});
 const put=(file,value)=>fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
 const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:8795'},host:{baseDir:base}},identity={device_id:'styx-'+'a'.repeat(24),fingerprint:'b'.repeat(64)};
 const target={id:identity.device_id,kind:'host',platform,generation:'paired-test',allowed:true,computer:{enabled:desktop},...(browser?{browser:{enabled:true,transport:'outbound'}}:{})};
 put(path.join(stateDir,'deployment.json'),config);put(path.join(base,'device/identity.json'),identity);put(path.join(base,'device/host.json'),{host_id:target.id});
 put(path.join(stateDir,'gateway/enrollment/state.json'),{version:1,devices:[{id:target.id,fingerprint:identity.fingerprint,status:'approved',target}]});
 put(path.join(stateDir,'gateway/certificate.pem'),'test-only-certificate');put(path.join(stateDir,'gateway/model.token'),'MODEL_ONLY_'+'m'.repeat(48));put(path.join(stateDir,'gateway/admin.token'),'ADMIN_NEVER_EXPORT_'+'a'.repeat(48));
 const observer=createAcceptanceObserver(stateDir),begin=()=>beginDeploymentAcceptance(stateDir,{authorize:true});
 function event(challenge,patch={}){return {name:'exec_command',args:{cmd:challenge.command,environment_id:target.id,login:false},result:{structuredContent:{output:'STYX_EXEC_'+JSON.parse(fs.readFileSync(path.join(stateDir,'account-acceptance.json'))).nonce+'\n',exit_code:0}},owner:'mcp-session:actual-test',target,...patch};}
 let browserOperation=0;
 function browserEvent(challenge,name='browser_navigate',patch={}){
  const page='### Page\n- Page URL: '+challenge.browser.url+'\n- Page Title: Styx Browser acceptance';
  const snapshot='\n### Snapshot\n```yaml\n- heading "'+challenge.browser.marker+'" [level=1] [ref=styx-'+ 'c'.repeat(32)+']\n```';
  return event(challenge,{name,args:{environment_id:target.id,...(name==='browser_navigate'?{url:challenge.browser.url}:{})},operationId:'browser-test-'+(++browserOperation),result:{content:[{type:'text',text:page+(name==='browser_snapshot'?snapshot:'')}]},...patch});
 }
 return {root,stateDir,base,target,put,begin,event,browserEvent,observer};
}
test('real authenticated HTTP MCP dispatch and real Codex output record execution proof, never account identity',{
 skip:process.env.STYX_LIVE_EXEC_TEST!=='1'||process.platform!=='linux'||process.arch!=='x64'
},async t=>{
 const f=fixture(t),binary=fileURLToPath(new URL('../../packages/styx-exec-adapter/.runtime/codex',import.meta.url));
 const home=path.join(f.root,'isolated-codex-home');fs.mkdirSync(home,{mode:0o700});
 const target={...f.target,cwd:f.root,shell:'/bin/sh',shells:['/bin/sh'],exec:{transport:'stdio',binary,home:f.root,env:{CODEX_HOME:home,PATH:'/usr/bin:/bin'}}};
 const hosts=[],gateway=createStyxGateway({catalog:{version:1,default_environment_id:target.id,targets:[target]},onToolResult:f.observer});
 const token='TEST_MODEL_ONLY_'+'t'.repeat(48),server=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts});
 hosts.push('127.0.0.1:'+server.address.port);
 const client=new Client({name:'isolated-onboarding-proof-test',version:'1'});
 t.after(async()=>{await client.close();await server.close()});
 const endpoint=new URL('http://127.0.0.1:'+server.address.port+'/mcp');
 assert.equal((await fetch(endpoint,{method:'POST'})).status,401);
 await client.connect(new StreamableHTTPClientTransport(endpoint,{requestInit:{headers:{Authorization:'Bearer '+token}}}));
 const a=f.begin(),args={cmd:a.challenge.command,environment_id:target.id,login:false,yield_time_ms:250};
 let result=await client.callTool({name:'exec_command',arguments:args}),output=result.structuredContent?.output??'';
 for(let i=0;result.structuredContent?.session_id&&i<20;i++){
  result=await client.callTool({name:'write_stdin',arguments:{session_id:result.structuredContent.session_id,chars:'',yield_time_ms:250}});
  output+=result.structuredContent?.output??'';
 }
 assert.ok(!result.isError,JSON.stringify(result));assert.equal(result.structuredContent.exit_code,0);assert.match(output,/STYX_EXEC_[a-f0-9]{32}/);
 const proof=readDeploymentAcceptance(f.stateDir);assert.equal(proof.requestProof.status,'verified');assert.equal(proof.complete,false);assert.equal(proof.targetChatConfirmation.providerIdentity,'not_verified');
 const confirmed=confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true});
 assert.equal(confirmed.complete,true);assert.equal(confirmed.targetChatConfirmation.source,'user_attested');
});
test('a user click cannot manufacture an executed request or export any administrative credential',t=>{
 const f=fixture(t);assert.throws(()=>beginDeploymentAcceptance(f.stateDir),/explicit_acceptance_authorization/);
 assert.equal(readDeploymentAcceptance(f.stateDir).complete,false);
 const a=f.begin();assert.throws(()=>confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true}),/actual_mcp_acceptance_evidence_required/);
 assert.ok(!JSON.stringify(a).includes('MODEL_ONLY'));assert.ok(!JSON.stringify(a).includes('ADMIN_NEVER_EXPORT'));
 assert.equal(readDeploymentConnectionHandoff(f.stateDir).status,'unavailable');
 f.put(path.join(f.stateDir,'tunnel/connection.json'),{schema:1,tunnelId:'tunnel_'+'a'.repeat(32)});
 assert.throws(()=>prepareDeploymentConnectionHandoff(f.stateDir),/explicit_acceptance_authorization/);
 const handoff=prepareDeploymentConnectionHandoff(f.stateDir,{authorize:true});assert.ok(handoff.authentication.modelCredential.startsWith('MODEL_ONLY_'));assert.ok(!JSON.stringify(handoff).includes('ADMIN_NEVER_EXPORT'));
 assert.ok(!JSON.stringify(readDeploymentConnectionHandoff(f.stateDir)).includes('MODEL_ONLY'));
 f.put(path.join(f.stateDir,'gateway/model.token'),fs.readFileSync(path.join(f.stateDir,'gateway/admin.token'),'utf8'));
 assert.throws(()=>prepareDeploymentConnectionHandoff(f.stateDir,{authorize:true}),/model_credential_separation_required/);
});
test('observed MCP command result and independent user source confirmation are separate gates',t=>{
 const f=fixture(t),a=f.begin();
 for(const patch of [{target:{...f.target,id:'other'}},{target:{...f.target,generation:'changed'}},{result:{isError:true,structuredContent:{exit_code:0,output:'ignored'}}},{args:{cmd:a.challenge.command,environment_id:f.target.id,login:true}}])f.observer(f.event(a.challenge,patch));
 assert.equal(readDeploymentAcceptance(f.stateDir).requestProof.status,'pending');
 f.observer(f.event(a.challenge));const seen=readDeploymentAcceptance(f.stateDir);assert.equal(seen.requestProof.status,'verified');assert.equal(seen.complete,false);
 assert.throws(()=>confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:'other',observedInTargetChat:true}),/target_chat_confirmation/);
 const complete=confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true});assert.equal(complete.complete,true);assert.equal(complete.targetChatConfirmation.providerIdentity,'not_verified');
 const file=path.join(f.stateDir,'account-acceptance.json'),record=JSON.parse(fs.readFileSync(file));record.expiresAt=Date.now()-1;f.put(file,record);assert.equal(readDeploymentAcceptance(f.stateDir).complete,true);
 f.put(path.join(f.stateDir,'gateway/model.token'),'rotated_'+ 'x'.repeat(48));assert.equal(readDeploymentAcceptance(f.stateDir).status,'acceptance_context_changed');
});
test('a yielded Exec proof can complete only through its owned empty poll',t=>{
 const f=fixture(t),a=f.begin(),event=f.event(a.challenge);event.result.structuredContent={output:'',session_id:73};f.observer(event);
 const output=f.event(a.challenge).result;
 f.observer(f.event(a.challenge,{name:'write_stdin',args:{session_id:73,chars:''},owner:'other-owner',result:output}));assert.equal(readDeploymentAcceptance(f.stateDir).requestProof.status,'pending');
 f.observer(f.event(a.challenge,{name:'write_stdin',args:{session_id:73,chars:''},result:output}));assert.equal(readDeploymentAcceptance(f.stateDir).requestProof.status,'verified');
});
test('desktop acceptance needs real observed action sequence plus controlled page readback',t=>{
 const f=fixture(t,{desktop:true}),a=f.begin();f.observer(f.event(a.challenge));
 // Synthetic native identity for this contract test only. Production derives
 // the PID from the installed App's fresh owner-private native descriptor.
 const file=path.join(f.stateDir,'account-acceptance.json'),r=JSON.parse(fs.readFileSync(file));r.desktopAppPid=123;f.put(file,r);
 assert.throws(()=>recordDeploymentDesktopReadback(f.stateDir,{authorize:true,challengeId:a.challenge.id,value:a.challenge.desktopValue}),/scope_mismatch/);
 recordDeploymentDesktopReadback(f.stateDir,{authorize:true,challengeId:a.challenge.id,value:a.challenge.desktopValue,pid:123,windowId:45});
 assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending');
 const image={content:[{type:'image',data:'synthetic-test-only',mimeType:'image/png'}],structuredContent:{snapshot_id:'s00000001',screenshot_frame_valid:true}};
 const observation={name:'get_window_state',args:{environment_id:f.target.id,pid:123,window_id:45},result:image};
 f.observer(f.event(a.challenge,observation));
 const action={name:'type_text',args:{environment_id:f.target.id,element_token:'s00000001:7',text:a.challenge.desktopValue},operationId:'real-dispatch-test-1',result:{content:[]}};
 // A different window cannot authorize the action, and an old manual DOM
 // value is cleared before a real correctly scoped action is dispatched.
 f.observer.before(f.event(a.challenge,{...action,args:{...action.args,pid:999,window_id:999}}));
 f.observer(f.event(a.challenge,action));assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending');
 f.observer.before(f.event(a.challenge,action));
 f.observer(f.event(a.challenge,action));
 f.observer(f.event(a.challenge,observation));assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending');
 // The UI event can arrive while Cua is still returning. A fresh attempt
 // clears old readback first, then both its successful result and new DOM
 // readback plus a subsequent image of that same window are required.
 action.operationId='real-dispatch-test-2';f.observer.before(f.event(a.challenge,action));
 recordDeploymentDesktopReadback(f.stateDir,{authorize:true,challengeId:a.challenge.id,value:a.challenge.desktopValue,pid:123,windowId:45});
 f.observer(f.event(a.challenge,action));
 assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending');
 f.observer(f.event(a.challenge,{...observation,owner:'other-owner'}));assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending');
 f.observer(f.event(a.challenge,{...observation,args:{...observation.args,window_id:99}}));assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending');
 f.observer(f.event(a.challenge,observation));assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'verified');
 recordDeploymentDesktopReadback(f.stateDir,{authorize:true,challengeId:a.challenge.id,value:a.challenge.desktopValue,pid:123,windowId:99});
 assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending','same-PID different window must not complete the native proof');
 recordDeploymentDesktopReadback(f.stateDir,{authorize:true,challengeId:a.challenge.id,value:a.challenge.desktopValue,pid:123,windowId:45});
 assert.equal(confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true}).complete,true);
});
test('expired, revoked, replaced and interrupted evidence never becomes accepted',t=>{
 for(const change of ['expiry','revoked','generation','guard']){
  const f=fixture(t),a=f.begin();
  if(change==='guard')f.put(path.join(f.stateDir,'account-acceptance.lock'),'foreign-owner');
  else if(change==='expiry'){const file=path.join(f.stateDir,'account-acceptance.json'),r=JSON.parse(fs.readFileSync(file));r.expiresAt=Date.now()-1;f.put(file,r)}
  else{const file=path.join(f.stateDir,'gateway/enrollment/state.json'),r=JSON.parse(fs.readFileSync(file));if(change==='revoked')r.devices[0].status='revoked';else r.devices[0].target.generation='new';f.put(file,r)}
  f.observer(f.event(a.challenge));assert.equal(readDeploymentAcceptance(f.stateDir).complete,false);assert.throws(()=>confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true}));
 }
});
test('production MCP dispatcher clears old DOM readback before a synthetic Cua action and records its result afterward',async t=>{
 const f=fixture(t,{desktop:true}),a=f.begin(),recordFile=path.join(f.stateDir,'account-acceptance.json');
 const initial=JSON.parse(fs.readFileSync(recordFile));initial.desktopAppPid=123;f.put(recordFile,initial);
 recordDeploymentDesktopReadback(f.stateDir,{authorize:true,challengeId:a.challenge.id,value:a.challenge.desktopValue,pid:123,windowId:45});
 const target={...f.target,cwd:f.root,shell:'/bin/sh',shells:['/bin/sh'],exec:{transport:'stdio',binary:'/bin/false'},computer:{enabled:true,transport:'stdio',binary:'/bin/false'}};
 let actions=0;
 const computer={async listTools(){return ['get_window_state','type_text'].map(name=>({name,inputSchema:{type:'object',properties:{},additionalProperties:true}}))},async callTool(name){
  if(name==='type_text'){
   actions++;assert.equal(JSON.parse(fs.readFileSync(recordFile)).desktop.readback,false,'the dispatcher must clear an old manual value before dispatch');
   recordDeploymentDesktopReadback(f.stateDir,{authorize:true,challengeId:a.challenge.id,value:a.challenge.desktopValue,pid:123,windowId:45});
   assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending','DOM input before a successful tool result is insufficient');
   return {content:[]};
  }
  return {content:[{type:'image',data:Buffer.from('synthetic-contract-fixture').toString('base64'),mimeType:'image/png'}],structuredContent:{snapshot_id:'s00000001',screenshot_frame_valid:true}};
 },async close(){}};
 const gateway=createStyxGateway({catalog:{version:1,default_environment_id:target.id,targets:[target]},computer,onToolResult:f.observer}),hosts=[],token='fixture_http_'+'c'.repeat(48);
 const server=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts});hosts.push('127.0.0.1:'+server.address.port);
 const client=new Client({name:'synthetic-cua-dispatch-contract',version:'1'});t.after(async()=>{await client.close();await server.close()});
 await client.connect(new StreamableHTTPClientTransport(new URL('http://127.0.0.1:'+server.address.port+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+token}}}));
 await client.callTool({name:'get_window_state',arguments:{environment_id:target.id,pid:123,window_id:45}});
 await client.callTool({name:'type_text',arguments:{environment_id:target.id,element_token:'s00000001:7',text:a.challenge.desktopValue}});
 assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'pending');
 await client.callTool({name:'get_window_state',arguments:{environment_id:target.id,pid:123,window_id:45}});
 assert.equal(actions,1);assert.equal(readDeploymentAcceptance(f.stateDir).desktop.status,'verified');assert.equal(readDeploymentAcceptance(f.stateDir).complete,false);
});


test('Browser navigation and snapshot are independent actual evidence without desktop grants',t=>{
 const f=fixture(t,{browser:true}),a=f.begin();
 assert.equal(a.browser.status,'pending');assert.equal(a.desktop.status,'not_required');assert.equal(a.requestProof.status,'pending');assert.match(a.challenge.browser.url,/^data:text\/html;charset=utf-8,/);
 assert.match(a.challenge.prompt,/browser_navigate/);assert.match(a.challenge.prompt,/browser_snapshot/);assert.doesNotMatch(a.challenge.prompt,/get_window_state|https?:\/\//);
 const navigate=f.browserEvent(a.challenge);f.observer.before(navigate);f.observer(navigate);
 assert.equal(readDeploymentAcceptance(f.stateDir).browser.status,'pending');
 const snapshot=f.browserEvent(a.challenge,'browser_snapshot');f.observer.before(snapshot);f.observer(snapshot);
 const browser=readDeploymentAcceptance(f.stateDir);assert.equal(browser.browser.status,'verified');assert.equal(browser.status,'request_observed');assert.equal(browser.browser.source,'authenticated_mcp_browser_result');assert.equal(browser.requestProof.status,'pending');assert.equal(browser.complete,false);
 assert.throws(()=>confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true}),/actual_mcp_acceptance_evidence_required/);
 f.observer(f.event(a.challenge));assert.equal(readDeploymentAcceptance(f.stateDir).complete,false);
 const complete=confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true});assert.equal(complete.complete,true);assert.equal(complete.requestProof.source,'authenticated_mcp_exec_result');assert.equal(complete.targetChatConfirmation.source,'user_attested');assert.equal(complete.targetChatConfirmation.providerIdentity,'not_verified');
});
test('Browser readiness, echoed URL, stale attempts, other owners and failed results cannot prove page readback',t=>{
 for(const invalid of ['ready','no_navigation','navigation_error','wrong_navigation_url','echoed_url_only','foreign_owner','foreign_generation','snapshot_file','old_snapshot_attempt']){
  const f=fixture(t,{browser:true}),a=f.begin(),navigate=f.browserEvent(a.challenge),snapshot=f.browserEvent(a.challenge,'browser_snapshot');
  if(invalid==='ready'){f.observer(f.event(a.challenge,{name:'get_execution_environment_status',args:{environment_id:f.target.id},result:{structuredContent:{browser:{configured:true,readiness:'ready_observed'}}}}));}
  else{
   if(invalid==='old_snapshot_attempt')f.observer.before(snapshot);
   if(invalid==='navigation_error')navigate.result.isError=true;
   if(invalid==='wrong_navigation_url')navigate.args.url='about:blank';
   if(invalid!=='no_navigation'){f.observer.before(navigate);f.observer(navigate);}
   if(invalid==='echoed_url_only')snapshot.result={content:[{type:'text',text:'### Page\n- Page URL: '+a.challenge.browser.url+'\n### Snapshot\n```yaml\n- heading "unrelated" [level=1] [ref=styx-'+ 'd'.repeat(32)+']\n```'}]};
   if(invalid==='foreign_owner')snapshot.owner='different-owner';
   if(invalid==='foreign_generation')snapshot.target={...f.target,generation:'different'};
   if(invalid==='snapshot_file')snapshot.args.filename='snapshot.yml';
   if(invalid!=='old_snapshot_attempt')f.observer.before(snapshot);f.observer(snapshot);
  }
  assert.equal(readDeploymentAcceptance(f.stateDir).browser.status,'pending',invalid);assert.equal(readDeploymentAcceptance(f.stateDir).complete,false,invalid);
 }
});
test('Browser evidence stays separate when desktop acceptance is still pending and old challenges expire',t=>{
 const f=fixture(t,{browser:true,desktop:true}),a=f.begin();
 for(const name of ['browser_navigate','browser_snapshot']){const event=f.browserEvent(a.challenge,name);f.observer.before(event);f.observer(event);}
 f.observer(f.event(a.challenge));const state=readDeploymentAcceptance(f.stateDir);assert.equal(state.browser.status,'verified');assert.equal(state.desktop.status,'pending');
 assert.throws(()=>confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true}),/actual_mcp_acceptance_evidence_required/);
 const next=f.begin();assert.notEqual(next.challenge.browser.marker,a.challenge.browser.marker);
 const old=f.browserEvent(a.challenge,'browser_snapshot');f.observer.before(old);f.observer(old);assert.equal(readDeploymentAcceptance(f.stateDir).browser.status,'pending');
 const file=path.join(f.stateDir,'account-acceptance.json'),record=JSON.parse(fs.readFileSync(file));record.expiresAt=Date.now()-1;f.put(file,record);
 const event=f.browserEvent(next.challenge);f.observer.before(event);f.observer(event);assert.equal(readDeploymentAcceptance(f.stateDir).status,'acceptance_expired');
});
test('legacy Exec and desktop acceptance records retain their original binding and meaning',t=>{
 const f=fixture(t),a=f.begin(),file=path.join(f.stateDir,'account-acceptance.json'),record=JSON.parse(fs.readFileSync(file));
 delete record.browserRequired;delete record.browser;f.put(file,record);f.observer(f.event(a.challenge));
 assert.equal(readDeploymentAcceptance(f.stateDir).requestProof.status,'verified');assert.equal(readDeploymentAcceptance(f.stateDir).browser.status,'not_required');
 assert.equal(confirmDeploymentAcceptance(f.stateDir,{authorize:true,challengeId:a.challenge.id,observedInTargetChat:true}).complete,true);
});
test('real native Browser data URL and snapshot reach the production MCP acceptance observer',{skip:process.env.STYX_LIVE_BROWSER_TEST!=='1',timeout:30000},async t=>{
 const f=fixture(t,{browser:true});
 const {HostBrowserSupervisor}=await import('../../packages/styx-browser-provider/host.mjs');
 const {InMemoryTransport}=await import('@modelcontextprotocol/sdk/inMemory.js');
 const browserWork=path.join(f.root,'browser-work');fs.mkdirSync(browserWork,{mode:0o700});
 const supervisor=new HostBrowserSupervisor({browser:{enabled:true,headless:true,profileRoot:path.join(f.root,'browser-profiles'),...(process.env.STYX_TEST_BROWSER_BINARY?{executablePath:process.env.STYX_TEST_BROWSER_BINARY}:{})},cwd:browserWork});
 const target={...f.target,cwd:f.root,shell:'/bin/sh',shells:['/bin/sh'],exec:{transport:'outbound',token_file:path.join(f.stateDir,'gateway/model.token')}};
 const gateway=createStyxGateway({catalog:{version:1,default_environment_id:target.id,targets:[target]},computer:null,onToolResult:f.observer});
 gateway.browser.connect=async()=>{const native=supervisor.createServer(),client=new Client({name:'native-browser-acceptance-transport',version:'1'}),[a,b]=InMemoryTransport.createLinkedPair();await native.connect(a);await client.connect(b);return client};
 const hosts=[],token='browser_acceptance_'+'x'.repeat(48),http=await createGatewayHttp(gateway,{token,port:0,allowedHosts:hosts});hosts.push('127.0.0.1:'+http.address.port);
 const client=new Client({name:'native-browser-acceptance-http',version:'1'});
 try{
  await client.connect(new StreamableHTTPClientTransport(new URL('http://127.0.0.1:'+http.address.port+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+token}}}));
  const a=f.begin();
  const navigate=await client.callTool({name:'browser_navigate',arguments:{url:a.challenge.browser.url,environment_id:target.id}});assert.notEqual(navigate.isError,true,JSON.stringify(navigate));
  assert.equal(readDeploymentAcceptance(f.stateDir).browser.status,'pending');
  const snapshot=await client.callTool({name:'browser_snapshot',arguments:{environment_id:target.id}});assert.notEqual(snapshot.isError,true,JSON.stringify(snapshot));
  assert.match(snapshot.content.filter(item=>item.type==='text').map(item=>item.text).join('\n'),/\[ref=styx-[a-f0-9]{32}\]/);
  const proof=readDeploymentAcceptance(f.stateDir);assert.equal(proof.browser.status,'verified');assert.equal(proof.browser.source,'authenticated_mcp_browser_result');assert.equal(proof.desktop.status,'not_required');assert.equal(proof.requestProof.status,'pending');assert.equal(proof.complete,false);assert.equal(proof.targetChatConfirmation.providerIdentity,'not_verified');
 }finally{await client.close();await http.close();await supervisor.close();}
});
