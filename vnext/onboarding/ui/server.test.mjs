import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import http from 'node:http';
import path from 'node:path';
import {createOnboardingServer,publicDeployment,validateUiConfig,browserOrigin} from '../server.mjs';
const config=()=>({schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:8795'},host:{bundle:'/private/bundle',publisherKeyFile:'/private/publisher.pem',publisherSha256:'a'.repeat(64),baseDir:'/private/new-host',label:'Owned test',computer:false}});
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

test('state projection maps known journal states, owner approval and live Gateway without leaking evidence/config',()=>{
 const value=publicDeployment({mode:'join-existing',activeStep:'host.request',gatewayRuntime:{status:'running'},config:{token:'secret'},steps:[{id:'host.request',status:'succeeded',evidence:{fingerprint:'b'.repeat(64),ownerApproval:'REQUIRED',invitation:'secret',token:'secret'}},{id:'host.claim',status:'awaiting_approval',error:'SECRET_TOKEN_VALUE'},{id:'host.doctor',status:'uncertain'},{id:'evil',status:'succeeded'}]});
 assert.equal(value.steps.length,3);assert.equal(value.steps[0].ownerApproval,'REQUIRED');assert.equal(value.steps[0].fingerprint,'b'.repeat(64));assert.equal(value.steps[1].status,'awaiting_approval');assert.equal(value.steps[2].status,'uncertain');assert.doesNotMatch(JSON.stringify(value),/secret|SECRET|invitation|"config"/);
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
