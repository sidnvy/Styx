import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import http from 'node:http';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {createOnboardingServer,publicDeployment,validateUiConfig,browserOrigin,gatewayServiceUiCapabilities,nativeBrowserPrepared,nativeLocalPrepared,nativeForegroundOwnsConnections} from '../server.mjs';
const config=()=>({schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:8795'},host:{bundle:'/private/bundle',publisherKeyFile:'/private/publisher.pem',publisherSha256:'a'.repeat(64),baseDir:'/private/new-host',label:'Owned test',computer:false}});
test('native reopen never starts an unprepared requested Browser alongside Exec',()=>{
 const deployment={roles:{browser:'requested'}};
 for(const browser of [null,{}, {configured:true,status:'not_prepared',approved:true},{configured:true,status:'preparation_blocked',approved:true},{configured:true,status:'prepared'},{configured:true,status:'prepared',approved:false},{configured:true,status:'not_approved',approved:true}])assert.equal(nativeBrowserPrepared(deployment,browser),false);
 assert.equal(nativeBrowserPrepared(deployment,{configured:true,status:'prepared',approved:true}),true);
 assert.equal(nativeBrowserPrepared(deployment,{configured:true,status:'not_approved',approved:false}),true);
 assert.equal(nativeBrowserPrepared({roles:{browser:'disabled'}},null),true);
});
test('native reopen preparation uses the same journal criteria without diagnostic scans',()=>{
 const prepared={steps:[{id:'host.prepare',status:'succeeded'},{id:'host.claim',status:'succeeded'},{id:'host.doctor',status:'succeeded'},{id:'host.service.install',status:'pending'}]};
 assert.equal(nativeLocalPrepared(prepared),true);
 for(const status of ['pending','blocked','running','uncertain','failed','awaiting_approval','skipped'])assert.equal(nativeLocalPrepared({...prepared,steps:prepared.steps.map(s=>s.id==='host.doctor'?{...s,status}:s)}),false);
 assert.equal(nativeLocalPrepared(null),false);assert.equal(nativeLocalPrepared({steps:[]}),false);
});
async function fixture(options={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-ui-test-'));let state=null,calls=0;
 const core={
  readDeployment(){if(!state)throw Error('not_configured');return structuredClone(state)},
  planDeployment(){return{steps:state?.steps.map((s,i)=>({...s,requires:state.steps.slice(0,i).map(p=>p.id)}))??[]}},
  createDeployment(file){const st=fs.statSync(file);assert.equal(st.mode&0o077,0);assert.equal(fs.statSync(path.dirname(file)).mode&0o077,0);JSON.parse(fs.readFileSync(file));calls++;state={mode:'create-local',activeStep:null,steps:[{id:'gateway.prepare',status:'pending'}]}},
  advanceDeployment(_dir,{authorize}){calls++;assert.deepEqual(authorize,['gateway.prepare']);state.steps[0].status='succeeded'},
  startDeploymentGateway(){calls++;state.gatewayRuntime={status:'running'}},
  stopDeploymentGateway(){if(state)state.gatewayRuntime={status:'stopped'}},
  ...options.core};
 const instance=await createOnboardingServer({...options,stateDir:path.join(root,'deployment'),core});
 const token=new URLSearchParams(new URL(instance.url).hash.slice(1)).get('session');
 const get=(route,headers={})=>fetch(instance.origin+route,{headers:{Authorization:'Bearer '+token,...headers}});
 const session=await(await get('/api/session')).json();
 const post=(route,data,headers={})=>fetch(instance.origin+route,{method:'POST',headers:{Authorization:'Bearer '+token,Origin:instance.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json',...headers},body:JSON.stringify(data)});
 return{...instance,root,get,post,session,token,get calls(){return calls},async cleanup(){await instance.close();fs.rmSync(root,{recursive:true,force:true})}};
}

test('Windows App lifecycle uses fresh native authority and rejects request-supplied registration',async()=>{
 let owned=true,writes=0;
 const authority=()=>({source:owned?'current_windows_native_app':'not_observed'});
 const resourceRoot=path.resolve('verified-package');
 const f=await fixture({nativeAppAuthority:authority,trustedWindowsApp:()=>({resourceRoot,authority:authority()}),core:{
  readDeploymentAppLifecycle:(_d,trusted)=>{assert.equal(trusted.trustedWindowsApp.resourceRoot,resourceRoot);return {status:'registered_unverified',systemApproval:'unknown'}},
  controlDeploymentAppLifecycle:(_d,data,trusted)=>{assert.deepEqual(data,{authorize:true,enabled:true,action:'login'});assert.equal(trusted.trustedWindowsApp.authority.source,'current_windows_native_app');writes++;return {status:'registered_unverified',systemApproval:'unknown'}}
 }});
 try{
  assert.equal(f.session.nativeAppLifecycleSupported,true);
  assert.equal((await f.get('/api/app/lifecycle')).status,200);
  assert.equal((await f.post('/api/app/login',{authorize:true,enabled:true})).status,200);assert.equal(writes,1);
  const forged=await f.post('/api/app/login',{authorize:true,enabled:true,registration:{resourceRoot:'/chosen'}});
  assert.notEqual(forged.status,200);assert.equal(writes,1);
  owned=false;
  assert.equal((await f.get('/api/app/lifecycle')).status,409);
  assert.notEqual((await f.post('/api/app/login',{authorize:true,enabled:true})).status,200);assert.equal(writes,1);
 }finally{await f.cleanup()}
});

test('native snapshot shares fresh observations for one response without promoting skipped service checks',async()=>{
 let generation=1;const reads={};const counted=(name,value)=>()=>{reads[name]=(reads[name]??0)+1;return typeof value==='function'?value():value};
 const foreground=()=>({schema:1,status:'connected',observation:'authenticated_foreground_owner',host:'foreground',gateway:'foreground',execConnection:generation===1?'connected':'disconnected',desktopConnection:'not_requested',toolHealth:'not_verified',ownerGeneration:String(generation)});
 const f=await fixture({core:{
  readDeployment:counted('deployment',{mode:'create-local',roles:{host:'local',gateway:'local',exec:'enabled',computer:'disabled',browser:'disabled'},steps:[{id:'host.doctor',status:'succeeded'}]}),
  readDeploymentForeground:counted('foreground',foreground),
  readDeploymentAcceptance:counted('acceptance',{status:'not_started',complete:false}),
  readDeploymentConnectionHandoff:counted('handoff',{status:'unavailable'}),
  readDeploymentPlugin:counted('plugin',{required:true,profileSaved:false,accountActions:{installation:'not_observed'}}),
 },backgroundRead:counted('background',{observation:'current',status:'running',host:'running',gateway:'running',hostConnection:'exec_connected'})});
 try{
  assert.equal((await fetch(f.origin+'/api/snapshot')).status,401);
  assert.equal((await f.get('/api/snapshot',{Origin:'https://foreign.invalid'})).status,403);
  const firstResponse=await f.get('/api/snapshot');assert.equal(firstResponse.status,200);assert.equal(firstResponse.headers.get('cache-control'),'no-store');
  const first=await firstResponse.json();
  assert.equal(first.status.foreground.ownerGeneration,'1');assert.equal(first.status.foreground.toolHealth,'not_verified');assert.equal(first.status.background,null);
  assert.equal(first.journey.background.observation,'not_observed');assert.equal(first.journey.readiness.exec.status,'connected');assert.equal(first.acceptance.complete,false);
  assert.deepEqual(reads,{foreground:1,deployment:1,acceptance:1,handoff:1,plugin:1});
  generation=2;const second=await(await f.get('/api/snapshot')).json();
  assert.equal(second.status.foreground.ownerGeneration,'2');assert.equal(second.journey.foreground.execConnection,'disconnected');assert.equal(second.acceptance.complete,false);
  assert.deepEqual(reads,{foreground:2,deployment:2,acceptance:2,handoff:2,plugin:2});
  // The detailed endpoint still observes services even for this live owner.
  assert.equal((await f.get('/api/status')).status,200);assert.equal(reads.background,1);
  assert.equal(f.calls,0);assert.equal(fs.existsSync(path.join(f.root,'deployment')),false);
 }finally{await f.cleanup()}
});

test('native snapshot keeps full service observations for reused, unobserved or uncertain owners',async()=>{
 const current={status:'connected',observation:'authenticated_foreground_owner',host:'foreground',gateway:'foreground'};
 for(const observation of ['current_process','authenticated_foreground_owner'])assert.equal(nativeForegroundOwnsConnections({...current,observation}),true);
 for(const foreground of [null,{}, {...current,observation:'cross_process'},{...current,host:'service'},{...current,gateway:'service'},{...current,status:'needs_attention'},{...current,status:'stopping'},{...current,status:'not_running'}]){
  assert.equal(nativeForegroundOwnsConnections(foreground),false);
  let reads=0;const f=await fixture({core:{readDeployment:()=>({mode:'create-local',roles:{host:'local'},steps:[]}),readDeploymentForeground:()=>foreground},backgroundRead:()=>{reads++;return {observation:'current',status:'needs_attention',host:'unknown',gateway:'unknown'}}});
  try{const response=await f.get('/api/snapshot');assert.equal(response.status,200);const snapshot=await response.json();assert.equal(reads,1);assert.equal(snapshot.status.background.status,'needs_attention');assert.equal(snapshot.journey.readiness.exec.status,'not_ready');assert.equal(snapshot.acceptance.complete,false)}finally{await f.cleanup()}
 }
});

test('native lifecycle observations stay fresh and authenticated when plugin page data is damaged',async()=>{
 let generation=1,computer=true,pluginReads=0,backgroundReads=0,foregroundReads=0;
 const f=await fixture({core:{
  readDeployment:()=>({mode:'create-local',roles:{host:'local',gateway:'local',computer:'requested'},steps:[]}),
  readDeploymentForeground:()=>{foregroundReads++;return {status:'connected',observation:'authenticated_foreground_owner',host:'foreground',gateway:'foreground',computerRequested:computer,ownerGeneration:String(generation),toolHealth:'not_verified'}},
  readDeploymentPlugin:()=>{pluginReads++;throw Error('SECRET_DAMAGED_PROFILE')},
  readDeploymentBrowser:()=>{throw Error('unrelated_browser_must_not_be_read')},
  readDeploymentConnectionHandoff:()=>{throw Error('unrelated_handoff_must_not_be_read')},
 },backgroundRead:()=>{backgroundReads++;return {status:'needs_attention',observation:'current'}}});
 try{
  assert.equal((await fetch(f.origin+'/api/native-status')).status,401);
  assert.equal((await f.get('/api/native-status',{Origin:'https://foreign.invalid'})).status,403);
  assert.equal(pluginReads,0);assert.equal(foregroundReads,0);
  const broken=await f.get('/api/snapshot');assert.equal(broken.status,409);assert.doesNotMatch(await broken.text(),/SECRET_DAMAGED_PROFILE/);assert.equal(pluginReads,1);
  for(const expectedComputer of [true,false]){
   computer=expectedComputer;generation++;
   const before=foregroundReads,response=await f.get('/api/native-status');assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');
   const status=await response.json();assert.equal(status.foreground.computerRequested,expectedComputer);assert.equal(status.foreground.ownerGeneration,String(generation));assert.equal(status.foreground.toolHealth,'not_verified');assert.equal(status.background,null);assert.equal(foregroundReads,before+1);assert.equal(pluginReads,1);
  }
  assert.equal(backgroundReads,0);assert.equal(f.calls,0);
 }finally{await f.cleanup()}
});

test('native lifecycle status retains full background observation for services and uncertain owners',async()=>{
 for(const foreground of [{status:'using_service',observation:'authenticated_foreground_owner',host:'service',gateway:'service'},{status:'needs_attention',observation:'cross_process',host:'not_owned',gateway:'not_owned'},null]){
  let backgroundReads=0;const f=await fixture({core:{readDeployment:()=>({mode:'create-local',roles:{host:'local'},steps:[]}),readDeploymentForeground:()=>foreground,readDeploymentPlugin:()=>{throw Error('plugin_must_not_be_read')}},backgroundRead:()=>{backgroundReads++;return {status:'needs_attention',observation:'current',host:'unknown'}}});
  try{const response=await f.get('/api/native-status');assert.equal(response.status,200);assert.equal((await response.json()).background.host,'unknown');assert.equal(backgroundReads,1)}finally{await f.cleanup()}
 }
});

test('loopback bootstrap serves real static UI but no unauthenticated state or mutation',async()=>{
 const f=await fixture();try{
  assert.equal(f.server.address().address,'127.0.0.1');
  const page=await fetch(f.origin+'/');assert.equal(page.status,200);assert.match(await page.text(),/id="setup"/);
  assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  assert.equal(page.headers.get('cache-control'),'no-store');
  assert.equal((await fetch(f.origin+'/api/status')).status,401);
  assert.equal((await fetch(f.origin+'/api/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config())})).status,401);
  assert.equal(await new Promise((resolve,reject)=>{const req=http.request(f.origin+'/api/status',{headers:{Host:'attacker.example',Authorization:'Bearer '+f.token}},res=>{res.resume();resolve(res.statusCode)});req.on('error',reject);req.end()}),403);
  assert.equal((await f.get('/api/status',{Origin:'https://attacker.example'})).status,403);
  assert.equal((await f.get('/private/state.json')).status,404);assert.equal(f.calls,0);
 }finally{await f.cleanup()}
});
test('fresh bundled-style server with a pinned tunnel closes before any deployment exists',async()=>{
 const f=await fixture({trustedTunnelClient:{binary:process.execPath,sha256:createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex')}});
 try{assert.equal((await fetch(f.origin+'/')).status,200);assert.equal(fs.existsSync(path.join(f.root,'deployment')),false);await Promise.all([f.close(),f.close()]);assert.equal(f.server.listening,false);assert.equal(fs.existsSync(path.join(f.root,'deployment')),false)}finally{await f.cleanup()}
});
test('a tunnel shutdown error cannot skip HTTP and foreground/Gateway cleanup or become success on retry',async()=>{
 const calls=[],f=await fixture({trustedTunnelClient:{binary:process.execPath,sha256:'a'.repeat(64)},core:{stopDeploymentForeground:()=>{calls.push('foreground')},stopDeploymentGateway:()=>{calls.push('gateway')}}});
 fs.mkdirSync(path.join(f.root,'deployment'),{mode:0o700}); // Deliberately corrupt local state after startup.
 try{await assert.rejects(f.close());assert.equal(f.server.listening,false);assert.deepEqual(calls,['foreground','gateway']);await assert.rejects(f.close());assert.deepEqual(calls,['foreground','gateway'])}finally{fs.rmSync(f.root,{recursive:true,force:true})}
});

test('shared journey and diagnostics are authenticated read-only whitelists, not account or permission shortcuts',async()=>{
 let mutations=0;
 const f=await fixture({core:{readDeployment:()=>({mode:'create-local',roles:{gateway:'local',host:'local',exec:'enabled',computer:'requested'},gatewayRuntime:{status:'running'},accountAcceptance:'NOT RUN',steps:[{id:'host.doctor',status:'succeeded',evidence:{token:'SECRET_JOURNAL'}}],config:{apiKey:'SECRET_CONFIG'}}),readDeploymentAcceptance:()=>({status:'request_observed',requestProof:{status:'verified'},targetChatConfirmation:{status:'pending'},desktop:{status:'pending'},complete:false,challenge:{prompt:'PRIVATE_CHALLENGE'}}),readDeploymentConnectionHandoff:()=>({status:'available',credentialAvailable:true,authentication:{modelCredential:'SECRET_CREDENTIAL'}}),readDeploymentOnboardingPreference:()=>({background:'foreground',configurationBound:true}),setDeploymentOnboardingPreference:()=>{mutations++}},backgroundRead:async()=>({observation:'last_recorded',status:'running',hostConnection:'exec_connected',raw:'SECRET_COOKIE'})});
 try{
  assert.equal(f.session.journeySupported,true);assert.equal(f.session.diagnosticsSupported,true);
  assert.equal((await fetch(f.origin+'/api/journey')).status,401);
  for(const route of ['/api/journey','/api/diagnostics']){const r=await f.get(route);assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');const text=await r.text();assert.doesNotMatch(text,/SECRET|PRIVATE_CHALLENGE|modelCredential|"config"/)}
  const j=(await(await f.get('/api/journey')).json()).journey;assert.equal(j.readiness.exec.status,'preflight_passed');assert.equal(j.readiness.desktop.status,'not_verified');assert.equal(j.account.status,'not_verified');assert.equal(j.background.status,'not_observed');assert.equal(mutations,0);assert.equal(fs.existsSync(path.join(f.root,'deployment')),false);
 }finally{await f.cleanup()}
});

test('connection handoff is an explicit owner CSRF-protected response and absent from all observation endpoints',async()=>{
 const secret='SECRET_LOCAL_MODEL_CREDENTIAL';let prepared=0;
 const f=await fixture({core:{readDeployment:()=>({mode:'create-local',roles:{gateway:'local',host:'local'},steps:[]}),readDeploymentConnectionHandoff:()=>({status:'available',credentialAvailable:true,modelCredential:secret}),prepareDeploymentConnectionHandoff:(_dir,options)=>{assert.deepEqual(options,{authorize:true});prepared++;return {status:'prepared',authentication:{type:'bearer',modelCredential:secret},connection:{tunnelId:'tunnel_abcdefgh'},expiresAt:Date.now()+60000}}},backgroundRead:async()=>null});
 try{
  assert.equal(f.session.connectionHandoffSupported,true);
  assert.equal((await f.get('/api/connection-handoff')).status,405);
  assert.equal((await f.post('/api/connection-handoff',{authorize:true},{'X-Styx-CSRF':''})).status,403);
  assert.equal((await f.post('/api/connection-handoff',{})).status,409);
  assert.equal((await f.post('/api/connection-handoff',{authorize:true,output:'/tmp/anything'})).status,409);assert.equal(prepared,0);
  const response=await f.post('/api/connection-handoff',{authorize:true});assert.equal(response.status,200);assert.equal((await response.json()).handoff.authentication.modelCredential,secret);assert.equal(prepared,1);
  for(const route of ['/api/session','/api/status','/api/journey','/api/diagnostics'])assert.doesNotMatch(await(await f.get(route)).text(),/SECRET_LOCAL_MODEL_CREDENTIAL/);
 }finally{await f.cleanup()}
});

test('acceptance and background choices call scoped Core hooks; browser cannot inject proof or mark account accepted',async()=>{
 const calls=[],challenge={id:'a'.repeat(32),expiresAt:Date.now()+60000,prompt:'Core fixed prompt',command:'Core fixed command',environmentId:'host_1',desktopValue:'STYX_GUI_'+'b'.repeat(32)};
 const pending={schema:1,status:'awaiting_chat_request',challenge,requestProof:{status:'pending'},targetChatConfirmation:{status:'pending'},desktop:{status:'pending'},complete:false};
 const hook=name=>(_dir,options)=>{calls.push({name,options});return pending};
 const f=await fixture({core:{readDeploymentAcceptance:()=>pending,beginDeploymentAcceptance:hook('begin'),confirmDeploymentAcceptance:hook('confirm'),recordDeploymentDesktopReadback:hook('readback'),setDeploymentOnboardingPreference:(_dir,options)=>{calls.push({name:'preference',options});return {background:options.background,configurationBound:true,raw:'SECRET'}}}});
 try{
  assert.equal(f.session.acceptanceSupported,true);
  assert.equal((await f.post('/api/acceptance/begin',{authorize:true},{'X-Styx-CSRF':''})).status,403);
  assert.equal((await f.post('/api/acceptance/begin',{authorize:true,requestProof:{status:'verified'}})).status,409);assert.equal(calls.length,0);
  const result=await(await f.post('/api/acceptance/begin',{authorize:true})).json();assert.deepEqual(result.acceptance.challenge,challenge);assert.equal(result.acceptance.complete,false);
  assert.equal((await f.post('/api/acceptance/confirm',{authorize:true,challengeId:challenge.id,observedInTargetChat:true})).status,200);
  assert.equal((await f.post('/api/acceptance/desktop-readback',{authorize:true,challengeId:challenge.id,value:challenge.desktopValue})).status,200);
  assert.equal((await f.post('/api/journey/background-preference',{background:'foreground',authorize:true,stopService:true})).status,409);
  assert.equal((await f.post('/api/journey/background-preference',{background:'foreground',authorize:false})).status,409);
  const preference=await(await f.post('/api/journey/background-preference',{background:'foreground',authorize:true})).json();assert.deepEqual(preference,{preference:{background:'foreground',configurationBound:true}});
  assert.deepEqual(calls.map(c=>c.name),['begin','confirm','readback','preference']);assert.equal(f.calls,0);
 }finally{await f.cleanup()}
});
test('foreground start is explicit and scoped; App shutdown settles Host before its owned Gateway',async()=>{
 const calls=[];
 const f=await fixture({core:{startDeploymentForeground:async(_dir,options)=>{assert.deepEqual(options,{authorize:true});calls.push('start');return {schema:1,status:'started',execConnection:'connecting',toolHealth:'not_verified'}},stopDeploymentForeground:async()=>{calls.push('host.stop')},stopDeploymentGateway:async()=>{calls.push('gateway.stop')}}});
 try{
  assert.equal(f.session.foregroundSupported,true);assert.equal((await f.get('/api/foreground')).status,405);
  assert.equal((await f.post('/api/foreground',{authorize:true},{'X-Styx-CSRF':''})).status,403);assert.equal((await f.post('/api/foreground',{})).status,409);assert.equal((await f.post('/api/foreground',{authorize:true,binary:'/arbitrary'})).status,409);assert.deepEqual(calls,[]);
  const result=await(await f.post('/api/foreground',{authorize:true})).json();assert.equal(result.foreground.status,'started');assert.equal(result.foreground.execConnection,'connecting');assert.equal(result.foreground.toolHealth,'not_verified');
  await f.close();assert.deepEqual(calls,['start','host.stop','gateway.stop']);
 }finally{await f.cleanup()}
});

test('authenticated mutation requires exact Origin plus separate CSRF; GET never mutates',async()=>{
 const f=await fixture();try{
  assert.equal((await f.post('/api/create',config(),{'X-Styx-CSRF':''})).status,403);
  assert.equal((await f.post('/api/create',config(),{Origin:'null'})).status,403);
  assert.equal((await f.post('/api/create',config(),{Origin:'http://127.0.0.1:9'})).status,403);
  assert.equal((await f.get('/api/create')).status,405);
  assert.equal((await f.get('/api/status')).status,200);assert.equal(f.calls,0);
  assert.equal((await f.post('/api/create',config())).status,200);assert.equal(f.calls,1);
  assert.equal((await f.post('/api/advance',{authorize:['gateway.prepare']})).status,200);assert.equal(f.calls,2);
  assert.equal((await f.post('/api/advance',{authorize:['host.arbitrary-exec']})).status,409);
  assert.equal((await f.post('/api/advance',{authorize:['gateway.prepare','host.prepare']})).status,409);
  const state=await(await f.get('/api/status')).json();assert.equal(state.deployment.steps[0].status,'succeeded');
  assert.equal((await f.post('/api/start',{})).status,200);assert.equal((await(await f.get('/api/status')).json()).deployment.gatewayRuntime,'running');
  assert.equal((await f.post('/api/pause',{})).status,200);assert.equal((await(await f.get('/api/status')).json()).deployment.gatewayRuntime,'stopped');
 }finally{await f.cleanup()}
});

test('browser cannot choose executable helpers or request arbitrary routes, and errors contain no secret details',async()=>{
 const f=await fixture({core:{advanceDeployment(){throw Error('Bearer SECRET_TOKEN /private/account/password')}}});try{
  const arbitrary=config();arbitrary.gateway.openssl='/tmp/untrusted';assert.equal((await f.post('/api/create',arbitrary)).status,409);
  const shell=config();shell.host.shell='/tmp/untrusted';assert.equal((await f.post('/api/create',shell)).status,409);
  assert.equal((await f.post('/api/exec',{cmd:'anything'})).status,404);
  assert.equal((await f.post('/api/create',config())).status,200);
  const failure=await f.post('/api/advance',{authorize:['gateway.prepare']});assert.equal(failure.status,409);assert.doesNotMatch(await failure.text(),/SECRET|password|private\/account/);
 }finally{await f.cleanup()}
});

test('joining snapshot exposes the request comparison code without private enrollment evidence',async()=>{
 const deployment={mode:'join-existing',activeStep:'host.request',gatewayRuntime:{status:'running'},config:{token:'secret'},steps:[{id:'host.request',status:'succeeded',evidence:{fingerprint:'b'.repeat(64),comparison_code:'0123-4567-89AB-CDEF',ownerApproval:'REQUIRED',invitation:'secret',token:'secret'}},{id:'host.claim',status:'awaiting_approval',error:'SECRET_TOKEN_VALUE'},{id:'host.doctor',status:'uncertain'},{id:'evil',status:'succeeded'}]};
 const value=publicDeployment(deployment);
 assert.equal(value.steps.length,3);assert.equal(value.steps[0].ownerApproval,'REQUIRED');assert.equal(value.steps[0].fingerprint,'b'.repeat(64));assert.equal(value.steps[0].comparison_code,'0123-4567-89AB-CDEF');assert.equal(value.steps[1].status,'awaiting_approval');assert.equal(value.steps[2].status,'uncertain');assert.doesNotMatch(JSON.stringify(value),/secret|SECRET|invitation|"config"|"evidence"/);
 const f=await fixture({core:{readDeployment:()=>deployment}});
 try{const response=await f.get('/api/status');assert.equal(response.status,200);const state=await response.json();assert.equal(state.deployment.steps[0].comparison_code,'0123-4567-89AB-CDEF');assert.doesNotMatch(JSON.stringify(state.deployment),/secret|SECRET|"evidence"/)}finally{await f.cleanup()}
});

test('blocked doctor exposes only known reasons and explicit safe recheck without leaking raw evidence',()=>{
 const out=publicDeployment({mode:'create-local',steps:[{id:'host.doctor',status:'blocked',evidence:{blockers:['codex_executor_unavailable','Bearer SECRET','/private/credential','codex_executor_unavailable'],stderr:'SECRET'}},{id:'host.pair',status:'blocked',evidence:{blockers:['codex_executor_unavailable']}},{id:'host.doctor',status:'uncertain',evidence:{blockers:['codex_executor_unavailable']}}]});
 assert.equal(out.steps[0].retryable,true);assert.deepEqual(out.steps[0].blockers,['codex_executor_unavailable']);assert.equal(out.steps[1].retryable,undefined);assert.equal(out.steps[2].retryable,undefined);
 assert.doesNotMatch(JSON.stringify(out),/SECRET|Bearer|private|stderr/);
});

test('trusted forwarding is explicit loopback only, configuration selection preserves safe capability types',()=>{
 assert.equal(browserOrigin('http://localhost:17895'),'http://localhost:17895');
 for(const url of ['http://0.0.0.0:1','http://example.com:1','https://localhost:1','http://localhost:1/path','http://user@localhost:1'])assert.throws(()=>browserOrigin(url));
 assert.equal(validateUiConfig(config(),{trustedOpenSSL:'/usr/bin/openssl'}).gateway.openssl,'/usr/bin/openssl');
 const join=config();join.mode='join-existing';join.invitationFile='/private/invitation';assert.equal(validateUiConfig(join).invitationFile,'/private/invitation');
 const bad=config();bad.host.computer='true';assert.throws(()=>validateUiConfig(bad,{trustedOpenSSL:'/usr/bin/openssl'}));
});

test('explicit trusted forwarding accepts only configured browser Host/Origin and still authenticates',async()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-forward-test-'));
 const instance=await createOnboardingServer({stateDir:path.join(root,'state'),trustedForwardOrigin:'http://localhost:17895',core:{readDeployment:()=>null,planDeployment:()=>({steps:[]})}});
 try{
  const token=new URLSearchParams(new URL(instance.url).hash.slice(1)).get('session');
  const request=(headers)=>new Promise((resolve,reject)=>{const req=http.request({host:'127.0.0.1',port:instance.server.address().port,path:'/api/session',headers},res=>{res.resume();resolve(res.statusCode)});req.on('error',reject);req.end()});
  assert.equal(await request({Host:'localhost:17895',Origin:'http://localhost:17895',Authorization:'Bearer '+token}),200);
  assert.equal(await request({Host:'localhost:17895',Origin:'http://attacker.example',Authorization:'Bearer '+token}),403);
  assert.equal(await request({Host:'localhost:17895',Origin:'http://localhost:17895'}),401);
  assert.equal(await request({Host:'localhost:17896',Authorization:'Bearer '+token}),403);
  assert.equal(instance.server.address().address,'127.0.0.1');
 }finally{await instance.close();fs.rmSync(root,{recursive:true,force:true})}
});

test('one mutation at a time prevents duplicate execution while status remains readable',async()=>{
 let release;const pending=new Promise(resolve=>{release=resolve});let started=false;
 const f=await fixture({core:{async advanceDeployment(){started=true;await pending}}});
 try{
  await f.post('/api/create',config());
  const first=f.post('/api/advance',{authorize:['gateway.prepare']});
  for(let i=0;!started&&i<50;i++)await new Promise(resolve=>setTimeout(resolve,5));assert.equal(started,true);
  const status=await(await f.get('/api/status')).json();assert.equal(status.busy,true);
  assert.equal((await f.post('/api/advance',{authorize:['gateway.prepare']})).status,409);
  release();assert.equal((await first).status,200);
 }finally{release();await f.cleanup()}
});

test('Gateway verification never echoes credential paths, tokens or verifier errors and remains CSRF protected',async()=>{
 let observed;
 const f=await fixture({verifyConnection:async config=>{observed=config;return{status:'gateway_verified',scope:'sdk_gateway',receipt:{token:'SECRET_VALUE',tokenFile:config.tokenFile},account_acceptance:'NOT RUN'}}});
 try{
  const request={url:'https://independent.invalid/mcp',tokenFile:'/private/SECRET_CREDENTIAL_PATH',independentStyx:true,freshConnection:true};
  assert.equal((await f.post('/api/verify-gateway',request,{'X-Styx-CSRF':''})).status,403);assert.equal(observed,undefined);
  const result=await f.post('/api/verify-gateway',request);assert.equal(result.status,200);const text=await result.text();assert.doesNotMatch(text,/SECRET|private|tokenFile/);assert.match(text,/sdk_gateway/);assert.match(text,/NOT RUN/);
  assert.equal((await f.post('/api/verify-gateway',{...request,command:'arbitrary'})).status,409);
 }finally{await f.cleanup()}
 const failed=await fixture({verifyConnection:async()=>{throw Error('SECRET_VALUE /private/SECRET_CREDENTIAL_PATH')}});
 try{const response=await failed.post('/api/verify-gateway',{url:'https://independent.invalid/mcp',tokenFile:'/private/secret',independentStyx:true,freshConnection:true});assert.equal(response.status,409);assert.doesNotMatch(await response.text(),/SECRET|\/private|tokenFile/)}finally{await failed.cleanup()}
});

test('safe defaults are fresh local suggestions; trusted artifact file cannot smuggle credentials',async()=>{
 const f=await fixture();try{
  assert.match(f.session.defaults.gatewayUrl,/^https:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(path.dirname(f.session.defaults.baseDir),f.root);assert.equal(fs.existsSync(f.session.defaults.baseDir),false);
  assert.equal(f.session.defaults.bundle,undefined);
 }finally{await f.cleanup()}
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-artifact-defaults-'));
 try{
  const defaults=path.join(root,'artifacts.json');fs.writeFileSync(defaults,JSON.stringify({bundle:'/trusted/bundle',publisherKeyFile:'/trusted/key.pem',publisherSha256:'a'.repeat(64),token:'SECRET_VALUE'}),{mode:0o600});
  await assert.rejects(createOnboardingServer({stateDir:path.join(root,'state'),core:{},artifactDefaultsFile:defaults}),/invalid_configuration_fields/);
 }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('local device pairing requires explicit structured owner approval; ordinary steps cannot carry approval',async()=>{
 let seen;
 const f=await fixture({core:{async advanceDeployment(_dir,options){seen=options}}});
 try{
  await f.post('/api/create',config());
  assert.equal((await f.post('/api/advance',{authorize:['host.pair']})).status,409);assert.equal(seen,undefined);
  const approval={approve:true,gatewayUrl:'https://127.0.0.1:8795',label:'Owned test',enableComputer:false};
  assert.equal((await f.post('/api/advance',{authorize:['host.pair'],ownerApproval:approval})).status,200);assert.deepEqual(seen,{authorize:['host.pair'],ownerApproval:approval});
  seen=undefined;assert.equal((await f.post('/api/advance',{authorize:['host.doctor'],ownerApproval:approval})).status,409);assert.equal(seen,undefined);
  assert.equal((await f.post('/api/advance',{authorize:['host.pair'],ownerApproval:{...approval,approve:false}})).status,409);
  assert.equal((await f.post('/api/verify-gateway',{url:'https://independent.invalid/mcp',tokenFile:'/private/token',independentStyx:false,freshConnection:true})).status,409);
 }finally{await f.cleanup()}
});

test('service controls accept only explicit fixed scoped actions and redact results',async()=>{
 let called;
 const f=await fixture({core:{controlDeploymentHostService:async(_dir,data)=>{called=data;return{status:'reported',state:'stopped',persistence:'disabled',stdout:'SECRET_VALUE',serviceConfigFile:'/private/SECRET_PATH'}}},gatewayService:async(_dir,data)=>{called=data;return{active:'inactive',enabled:'disabled',pid:0}}});
 try{
  await f.post('/api/create',config());
  assert.equal((await f.post('/api/service',{role:'host',action:'start',authorize:false})).status,409);assert.equal(called,undefined);
  assert.equal((await f.post('/api/service',{role:'host',action:'exec',authorize:true})).status,409);assert.equal(called,undefined);
  assert.equal((await f.post('/api/service',{role:'host',action:'status',authorize:true,serviceId:'someone-else'})).status,409);
  const response=await f.post('/api/service',{role:'host',action:'status',authorize:true});assert.equal(response.status,200);assert.deepEqual(called,{action:'status',authorize:true});assert.doesNotMatch(await response.text(),/SECRET|private|stdout|serviceConfigFile/);
  assert.equal((await(await f.get('/api/status')).json()).services.host.persistence,'disabled');
  if(process.platform==='linux'){
   await f.post('/api/start',{});called=undefined;assert.equal((await f.post('/api/service',{role:'gateway',action:'start',authorize:true})).status,409);assert.equal(called,undefined);
   await f.post('/api/pause',{});assert.equal((await f.post('/api/service',{role:'gateway',action:'status',authorize:true})).status,200);
  }
 }finally{await f.cleanup()}
});

test('pairing-link inspection/acceptance isolates secrets from public responses and binds later join config',async()=>{
 const secret='styx://join#SECRET_ONE_USE_INVITATION';let saved;
 const origin='https://independent.invalid';const expiresAt=Date.now()+60000;
 const pairingLinks={inspectPairingLink(link){assert.equal(link,secret);return{origin,expiresAt,requiresCertificateApproval:false,invitation:'SECRET_ONE_USE_INVITATION'}},acceptPairingLink(link,{stateDir,approvedGatewayOrigin}){assert.equal(link,secret);assert.equal(approvedGatewayOrigin,origin);fs.mkdirSync(stateDir,{mode:0o700});const invitationFile=path.join(stateDir,'invitation');fs.writeFileSync(invitationFile,'SECRET_ONE_USE_INVITATION',{mode:0o600});fs.writeFileSync(path.join(stateDir,'pairing.json'),JSON.stringify({schema:1,gatewayOrigin:origin,expiresAt,invitationFile}),{mode:0o600});saved=stateDir;return{status:'pairing_material_saved',origin,expiresAt,invitationFile,invitation:'SECRET_ONE_USE_INVITATION'}}};
 const f=await fixture({pairingLinks});try{
  const inspected=await f.post('/api/pairing-link/inspect',{link:secret});const preview=await inspected.json();assert.doesNotMatch(JSON.stringify(preview),/SECRET|invitation/);
  assert.equal((await f.post('/api/pairing-link/accept',{inspectionId:preview.inspectionId,approvedGatewayOrigin:'https://wrong.invalid'})).status,409);
  const accepted=await(await f.post('/api/pairing-link/accept',{inspectionId:preview.inspectionId,approvedGatewayOrigin:origin})).json();assert.doesNotMatch(JSON.stringify(accepted),/SECRET|invitationFile|private|styx-pairing/);assert.equal(accepted.status,'pairing_material_saved');
  const join=config();join.mode='join-existing';join.gateway={url:origin};join.joinLinkId=accepted.joinLinkId;assert.equal((await f.post('/api/create',join)).status,200);
  const status=await(await f.get('/api/status')).text();assert.doesNotMatch(status,/SECRET|styx:\/\/join|invitation/);
 }finally{await f.cleanup();assert.equal(fs.existsSync(saved),false)}
});

test('current request comparison code confirms identity without repeating capability selection',async()=>{
 let approved;
 const id='c'.repeat(32),fingerprint='0123456789abcdef'+'b'.repeat(48),comparison_code='ABCD-0123-EF45-6789';
 const f=await fixture({core:{listDeploymentPending:async()=>[{request_id:id,fingerprint,comparison_code,computer_requested:true,browser_requested:true}],approveDeploymentPending:async(_dir,request)=>{approved=request;return{status:'approved'}}}});
 try{
  await f.post('/api/create',config());
  assert.equal((await f.post('/api/pending/approve',{authorize:true,requestId:id,comparisonCodeConfirmation:'FFFF-FFFF-FFFF-FFFF'})).status,409);assert.equal(approved,undefined);
  assert.equal((await f.post('/api/pending/approve',{authorize:true,requestId:id,fingerprintConfirmation:fingerprint.slice(0,16)})).status,409);assert.equal(approved,undefined);
  assert.equal((await f.post('/api/pending/approve',{authorize:true,requestId:id,comparisonCodeConfirmation:'abcd 0123 ef45 6789'})).status,200);assert.deepEqual(approved,{authorize:true,requestId:id,fingerprint});
  const lan=config();lan.gateway.url='https://192.0.2.10:8795';lan.gateway.listenHost='192.0.2.10';assert.equal((await f.post('/api/create',lan)).status,409);
  lan.gateway.allowRemoteHosts=true;assert.equal((await f.post('/api/create',lan)).status,409);
 }finally{await f.cleanup()}
});


test('Gateway service UI capabilities reflect native platform coupling without asserting installation',()=>{
 assert.deepEqual(gatewayServiceUiCapabilities('linux',true),{supported:true,startEnablesStartup:true,enableCanTriggerRecovery:false});
 for(const platform of ['darwin','win32'])assert.deepEqual(gatewayServiceUiCapabilities(platform,true),{supported:true,startEnablesStartup:true,enableCanTriggerRecovery:platform==='win32'});
 assert.equal(gatewayServiceUiCapabilities('freebsd',true).supported,false);assert.equal(gatewayServiceUiCapabilities('darwin',false).supported,false);
 const state=publicDeployment({mode:'create-local',gatewayRuntime:{status:'running',persistentService:'NOT OBSERVED'},steps:[]});assert.equal(state.gatewayRuntime,'running');assert.equal(JSON.stringify(state).includes('NOT INSTALLED'),false);
});

test('aggregate setup preserves one exact owner scope and stops before background startup',async()=>{
 const scope={gatewayUrl:'https://127.0.0.1:8795',label:'Owned test',enableComputer:false};
 const steps=['gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.doctor','host.service.install'].map(id=>({id,status:'pending'}));
 const calls=[];
 const f=await fixture({core:{readDeployment:()=>({mode:'create-local',steps}),planDeployment:()=>({ownerPairingScope:scope,steps}),advanceDeployment:(_d,args)=>{calls.push(args);steps.find(s=>s.id===args.authorize[0]).status='succeeded'}}});
 try{
  const approval={approve:true,...scope};
  assert.equal((await f.post('/api/local-setup',{ownerApproval:{...approval,enableComputer:true}})).status,409);assert.equal(calls.length,0);
  assert.equal((await f.post('/api/local-setup',{ownerApproval:approval},{'X-Styx-CSRF':''})).status,403);
  const res=await f.post('/api/local-setup',{ownerApproval:approval});assert.equal(res.status,200);
  const result=await res.json();assert.equal(result.workflow.status,'local_preparation_complete');assert.equal(calls.length,6);assert.equal(steps[6].status,'pending');assert.deepEqual(calls[4].ownerApproval,approval);
 }finally{await f.cleanup()}
});

test('background aggregate needs explicit CSRF-protected consent and returns separate observation',async()=>{
 let calls=0;
 const f=await fixture({backgroundControl:async(_d,options)=>{assert.deepEqual(options,{authorize:true});calls++;return {status:'running',accountAcceptance:'NOT RUN'}},backgroundRead:()=>({status:'not_configured'})});
 try{
  assert.equal((await f.post('/api/background',{})).status,409);
  assert.equal((await f.post('/api/background',{authorize:true,command:'injected'})).status,409);
  assert.equal((await f.post('/api/background',{authorize:true},{'X-Styx-CSRF':''})).status,403);assert.equal(calls,0);
  const r=await f.post('/api/background',{authorize:true});assert.equal(r.status,200);assert.equal((await r.json()).background.accountAcceptance,'NOT RUN');assert.equal(calls,1);
 }finally{await f.cleanup()}
});

test('account runtime endpoints cannot accept executable paths or reveal credentials when unavailable',async()=>{
 const f=await fixture();try{
  for(const data of [{tunnelId:'tunnel_ownedtest',apiKey:'sk-secret-not-real',authorize:true},{binary:'/tmp/arbitrary',authorize:true}]){
   const r=await f.post('/api/tunnel/configure',data);assert.equal(r.status,409);assert.doesNotMatch(await r.text(),/sk-secret|arbitrary/);
  }
  assert.equal((await f.post('/api/capabilities',{authorize:true,computer:true,trustedMacPreviewApp:{path:'/tmp/evil'}})).status,409);
 }finally{await f.cleanup()}
});
test('reviewed runtime and migration routes stay owner authenticated and bound to server state',async()=>{
 const calls=[];const core={};
 for(const name of ['planGatewayRuntimeChange','applyGatewayRuntimeChange','recoverGatewayRuntimeChange','readGatewayRuntimeChange'])core[name]=options=>{assert.equal(options.stateDir,path.join(f.root,'deployment'));calls.push([name,options]);return {status:'reviewable'}};
 for(const name of ['planNativeSupervisorMigration','applyNativeSupervisorMigration','rollbackNativeSupervisorMigration'])core[name]=(dir,options)=>{assert.equal(dir,path.join(f.root,'deployment'));calls.push([name,options]);return {status:'reviewable'}};
 const f=await fixture({core});try{
  for(const [route,data]of [['runtime-change/plan',{bundle:'/owned/bundle'}],['runtime-change/apply',{plan:{},authorize:true}],['runtime-change/recover',{transactionId:'a'.repeat(32),authorize:true}],['runtime-change/status',{}],['native-migration/plan',{nativeApp:{path:'/Applications/Styx.app',teamID:'ABCDEFGHIJ'}}],['native-migration/apply',{plan:{},authorize:true}],['native-migration/rollback',{transactionId:'a'.repeat(64),authorize:true}]]){
   assert.equal((await f.post('/api/'+route,data,{'X-Styx-CSRF':''})).status,403);
   assert.equal((await f.post('/api/'+route,{...data,stateDir:'/other'})).status,409);
   assert.equal((await f.post('/api/'+route,data)).status,200);
  }
  assert.equal(calls.length,7);
 }finally{await f.cleanup()}
});


test('local API accepts bounded Browser intent and exposes only its requested role',async()=>{
 const browser={enabled:true,headless:true,executablePath:process.execPath};
 assert.deepEqual(validateUiConfig({...config(),host:{...config().host,browser}},{trustedOpenSSL:'/usr/bin/openssl'}).host.browser,browser);
 for(const value of [{enabled:true,profileRoot:'/foreign'},{enabled:true,command:'/foreign'},{enabled:true,headless:'yes'},{enabled:true,executablePath:'relative'}])assert.throws(()=>validateUiConfig({...config(),host:{...config().host,browser:value}},{trustedOpenSSL:'/usr/bin/openssl'}));
 const projected=publicDeployment({mode:'create-local',roles:{gateway:'local',host:'local',exec:'enabled',computer:'disabled',browser:'requested'},browser:{profileRoot:'/private/profile'},steps:[]});
 assert.equal(projected.roles.browser,'requested');assert.equal(projected.roles.readiness,'not_inferred');assert.doesNotMatch(JSON.stringify(projected),/profileRoot|private\/profile/);
});
test('HTTP owner confirms identity without reselecting capabilities; unprepared local changes stay refused',async()=>{
 const id='a'.repeat(32),fingerprint='b'.repeat(64);let approved;
 const f=await fixture({core:{listDeploymentPending:()=>[{request_id:id,fingerprint,browser_requested:true,computer_requested:false}],approveDeploymentPending:(_dir,options)=>{approved=options;return {status:'approved'}}}});
 try{
  const data={authorize:true,requestId:id,fingerprint,enableComputer:false};
  assert.equal((await f.post('/api/pending/approve',{...data,enableBrowser:false})).status,409);assert.equal(approved,undefined);
  assert.equal((await f.post('/api/pending/approve',{authorize:true,requestId:id,fingerprint})).status,200);assert.equal(approved.enableBrowser,undefined);assert.equal(approved.enableComputer,undefined);
  const blocked=await f.post('/api/capabilities',{authorize:true,browser:true});assert.equal(blocked.status,409);assert.equal((await blocked.json()).error,'operation_failed_check_status');
 }finally{await f.cleanup()}
});


test('Browser preparation routes are passive for status and accept only explicit fixed Core preparation',async()=>{
 let reads=0,prepares=0;const f=await fixture({core:{readDeploymentBrowser:()=>{reads++;return {schema:1,configured:true,status:'not_prepared',readiness:'not_verified',accountAcceptance:'NOT RUN'}},prepareDeploymentBrowser:(_dir,options)=>{assert.deepEqual(options,prepares===0?{authorize:true}:{authorize:true,recover:true});prepares++;return {schema:1,configured:true,status:'prepared',readiness:'not_verified',accountAcceptance:'NOT RUN'}}}});
 try{
  assert.equal(f.session.browserPreparationSupported,true);assert.equal((await(await f.get('/api/browser')).json()).browser.status,'not_prepared');assert.equal(reads,1);assert.equal(prepares,0);
  assert.equal((await f.post('/api/browser/prepare',{})).status,409);assert.equal((await f.post('/api/browser/prepare',{authorize:true,profileRoot:'/foreign'})).status,409);assert.equal((await f.post('/api/browser/prepare',{authorize:true},{'X-Styx-CSRF':''})).status,403);assert.equal(prepares,0);
  const result=await f.post('/api/browser/prepare',{authorize:true});assert.equal(result.status,200);assert.equal((await result.json()).browser.accountAcceptance,'NOT RUN');assert.equal(prepares,1);
  assert.equal((await f.post('/api/browser/prepare',{authorize:true,recover:'yes'})).status,409);assert.equal(prepares,1);
  assert.equal((await f.post('/api/browser/prepare',{authorize:true,recover:true})).status,200);assert.equal(prepares,2);
 }finally{await f.cleanup()}
});
test('acceptance HTTP projection preserves the independent Browser source and fixed data challenge',async()=>{
 const {browserAcceptanceChallenge}=await import('../../shared/onboarding-evidence.mjs'),browser=browserAcceptanceChallenge('e'.repeat(32));
 const f=await fixture({core:{readDeploymentAcceptance:()=>({status:'request_observed',requestProof:{status:'pending'},targetChatConfirmation:{status:'pending'},desktop:{status:'not_required'},browser:{status:'verified',required:true,source:'authenticated_mcp_browser_result'},complete:false,challenge:{id:'a'.repeat(32),expiresAt:Date.now()+5000,prompt:'fixed generated challenge',command:'fixed exec command',environmentId:'device_123',browser},ownerHash:'PRIVATE_OWNER_HASH'})}});
 try{const value=(await(await f.get('/api/acceptance')).json()).acceptance;assert.equal(value.browser.status,'verified');assert.equal(value.requestProof.status,'pending');assert.deepEqual(value.challenge.browser,browser);assert.equal(value.complete,false);assert.equal(value.targetChatConfirmation.providerIdentity,'not_verified');assert.doesNotMatch(JSON.stringify(value),/PRIVATE_OWNER_HASH/);}finally{await f.cleanup()}
});


test('capability rollback uses the same Core and rejects foreign state or unauthenticated writes',async()=>{
 let calls=0;
 const f=await fixture({core:{rollbackDeploymentCapabilities:(dir,options)=>{calls++;assert.equal(dir,path.join(f.root,'deployment'));assert.deepEqual(options,{authorize:true,transactionId:'a'.repeat(32)});return {status:'rolled_back'}}}});
 try{
  const data={authorize:true,transactionId:'a'.repeat(32)};
  assert.equal((await f.post('/api/capabilities/rollback',data,{'X-Styx-CSRF':''})).status,403);
  assert.equal((await f.post('/api/capabilities/rollback',{...data,stateDir:'/other'})).status,409);
  assert.equal(calls,0);
  assert.equal((await f.post('/api/capabilities/rollback',data)).status,200);assert.equal(calls,1);
 }finally{await f.cleanup()}
});


test('a web manager cannot suspend an App foreground even with valid session and CSRF',async()=>{
 let called=0;const f=await fixture({core:{stopOwnedDeploymentForeground:async()=>{called++;return {status:'stopped',observation:'current_process',foregroundRestartRequired:true}}}});
 try{
  assert.equal((await f.post('/api/foreground/stop',{authorize:true},{'X-Styx-CSRF':''})).status,403);
  assert.equal((await f.post('/api/foreground/stop',{authorize:true})).status,409);
  assert.equal(called,0);
 }finally{await f.cleanup()}
});

test('status distinguishes the authenticated public foreground from the current manager owner',async()=>{
 const f=await fixture({core:{readDeployment:()=>({mode:'join-existing',steps:[]}),readDeploymentForeground:async()=>({status:'connected',observation:'authenticated_foreground_owner',host:'foreground'}),readOwnedDeploymentForeground:()=>({status:'needs_attention',observation:'current_process',host:'not_owned'})}});
 try{
  const {foreground,ownedForeground}=await(await f.get('/api/status')).json();
  assert.equal(foreground.observation,'authenticated_foreground_owner');assert.equal(ownedForeground.host,'not_owned');
 }finally{await f.cleanup()}
});

test('add-computer API keeps exact Core authority, requires consent, and cannot accept TLS paths or foreign state',async()=>{
 const calls=[];const hook=name=>(directory,options)=>{calls.push({name,directory,options});return {schema:1,status:'applied'}};
 const f=await fixture({core:{prepareDeploymentDeviceIngress:hook('prepare'),recoverDeploymentDeviceIngress:hook('recover'),closeDeploymentPairingWindow:hook('close'),readDeploymentDeviceIngressSetup:hook('status')}});
 try{
  assert.equal((await f.post('/api/device-ingress/prepare',{authorize:true,listenHost:'192.0.2.10'},{'X-Styx-CSRF':''})).status,403);
  for(const input of [{authorize:false},{authorize:true,tlsPrivateKeyFile:'/foreign/key'},{authorize:true,stateDir:'/foreign'}])assert.equal((await f.post('/api/device-ingress/prepare',input)).status,409);
  assert.equal(calls.length,0);
  assert.equal((await f.post('/api/device-ingress/prepare',{authorize:true,listenHost:'192.0.2.10'})).status,200);
  assert.equal((await f.post('/api/device-ingress/recover',{authorize:true,action:'rollback',overwrite:true})).status,409);
  assert.equal((await f.post('/api/device-ingress/recover',{authorize:true,action:'rollback'})).status,200);
  assert.equal((await f.post('/api/pairing-link/close',{authorize:true})).status,200);
  assert.equal((await f.post('/api/device-ingress/status',{})).status,200);
  assert.deepEqual(calls.map(x=>x.name),['prepare','recover','close','status']);
  for(const call of calls)assert.equal(call.directory,path.join(f.root,'deployment'));
 }finally{await f.cleanup()}
});

test('Host payload API uses bundled candidate and a one-shot reviewed plan; it cannot import a publisher or stop work',async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-payload-api-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const artifacts={bundle:path.join(root,'host-bundle'),publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64)},defaults=path.join(root,'artifacts.json');
 fs.writeFileSync(defaults,JSON.stringify(artifacts),{mode:0o600});
 let planned,blocked=false,applied=0,rolledBack=0,stopped=0;
 const f=await fixture({artifactDefaultsFile:defaults,core:{
  planHostPayloadMigration(input){if(blocked)return {status:'blocked',reason:'native_owned_process_present'};planned={...input,planId:'review-1',status:'offline_reviewable',current:{version:'old'},target:{version:'new'},publisherChange:true,privateInternalEvidence:'not-public'};return planned},
  applyHostPayloadMigration(input){assert.equal(input.stateDir,planned.stateDir);assert.equal(input.plan,planned);assert.equal(input.authorize,true);applied++;return {status:'applied_stopped',runtimeHealth:'NOT RUN'}},
  rollbackHostPayloadMigration(input){assert.equal(input.stateDir,planned.stateDir);assert.equal(input.authorize,true);assert.equal(input.transactionId,'a'.repeat(32));rolledBack++;return {status:'rolled_back_stopped'}},
  readHostPayloadMigration(){return {status:'not_started'}},
  stopOwnedDeploymentForeground(){stopped++;return {status:'stopped'}}
 }});
 try{
  const post='/api/host-payload/plan';assert.equal((await fetch(f.origin+post,{method:'POST'})).status,401);
  assert.notEqual((await f.post(post,{}, {'X-Styx-CSRF':'wrong'})).status,200);
  assert.notEqual((await f.post(post,{bundle:'/foreign',publisherSha256:'b'.repeat(64)})).status,200);
  const r=await f.post(post,{});assert.equal(r.status,200);const body=await r.json();assert.equal(body.upgrade.planId,'review-1');assert.equal(body.upgrade.current.version,'old');assert.equal(body.upgrade.target.version,'new');assert.equal(body.upgrade.publisherChange,true);assert.equal(planned.bundle,artifacts.bundle);assert.equal(planned.stateDir,path.join(f.root,'deployment'));assert.equal(JSON.stringify(body).includes('privateInternalEvidence'),false);assert.equal(JSON.stringify(body).includes(root),false);
  assert.notEqual((await f.post('/api/host-payload/apply',{authorize:true,planId:'foreign'})).status,200);
  assert.notEqual((await f.post('/api/host-payload/apply',{authorize:false,planId:'review-1'})).status,200);
  assert.notEqual((await f.post('/api/host-payload/apply',{authorize:true,planId:'review-1',plan:{stateDir:'/foreign'}})).status,200);
  const updated=await f.post('/api/host-payload/apply',{authorize:true,planId:'review-1'});assert.equal(updated.status,200);assert.equal((await updated.json()).upgrade.status,'applied_stopped');assert.equal(applied,1);
  assert.notEqual((await f.post('/api/host-payload/apply',{authorize:true,planId:'review-1'})).status,200);assert.equal(applied,1);
  assert.notEqual((await f.post('/api/host-payload/rollback',{authorize:false,transactionId:'a'.repeat(32)})).status,200);
  assert.equal((await f.post('/api/host-payload/rollback',{authorize:true,transactionId:'a'.repeat(32)})).status,200);assert.equal(rolledBack,1);
  assert.equal((await f.post('/api/host-payload/status',{})).status,200);assert.equal(stopped,0);
  blocked=true;const denied=await (await f.post(post,{})).json();assert.equal(denied.upgrade.status,'blocked');assert.equal(denied.upgrade.reason,'native_owned_process_present');assert.equal(denied.upgrade.planId,undefined);
  assert.notEqual((await f.post('/api/host-payload/apply',{authorize:true})).status,200);assert.equal(applied,1);
 }finally{await f.cleanup()}
});
