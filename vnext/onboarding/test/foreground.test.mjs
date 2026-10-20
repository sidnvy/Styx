import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {createHash,createPublicKey,generateKeyPairSync,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {startDeploymentForeground,stopDeploymentForeground,readDeploymentForeground,observeDeploymentForeground} from '../foreground.mjs';
import {createDeployment,advanceDeployment,planDeployment,readDeployment,stopDeploymentGateway} from '../core.mjs';
import {stageSignedRelease,activateRelease} from '../../host/installer.mjs';
import {ensurePrivateDirectory,writePrivateFile} from '../../host/private-storage.mjs';
import {gatewayFetch} from '../connection.mjs';
const sha=v=>createHash('sha256').update(v).digest('hex');
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function until(check){const end=Date.now()+10000;while(Date.now()<end){if(await check())return;await wait(30)}throw Error('foreground_connection_timeout')}
async function fixture(t,{mode='join-existing',live=false,computer=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-foreground-'));ensurePrivateDirectory(root);const stateDir=path.join(root,'state'),base=path.join(root,'host'),bundle=path.join(root,'bundle'),publisher=path.join(root,'publisher.pem');
 t.after(async()=>{await stopDeploymentForeground(stateDir);await stopDeploymentGateway(stateDir);fs.rmSync(root,{recursive:true,force:true})});
 for(const d of [bundle,path.join(bundle,'bin'),path.join(bundle,'host')])ensurePrivateDirectory(d);
 const {privateKey,publicKey}=generateKeyPairSync('ed25519'),pem=publicKey.export({type:'spki',format:'pem'});writePrivateFile(publisher,pem);
 const contents={};
 if(live){
  for(const f of ['private-storage.mjs','installer.mjs','launch.mjs'])contents['host/'+f]=fs.readFileSync(new URL('../../host/'+f,import.meta.url));
  for(const f of ['enroll.mjs','doctor.mjs','setup-native.mjs','linux-service.mjs'])contents['host/'+f]=Buffer.from('// signed test helper, not executed');
  contents['bin/node']=fs.readFileSync(process.execPath);contents['bin/codex']=fs.readFileSync(new URL('../../packages/styx-exec-adapter/.runtime/codex',import.meta.url));
 }else contents['bin/codex']=Buffer.from('#!/bin/sh\nexit 0\n');
 contents['bin/cua-driver']=Buffer.from('#!/bin/sh\nexit 0\n');
 const manifest={schema:1,version:'0.1.0-foreground-test',platform:process.platform,arch:process.arch,files:Object.entries(contents).map(([name,bytes])=>{writePrivateFile(path.join(bundle,name),bytes,{mode:name.startsWith('bin/')?0o700:0o600});return {path:name,size:bytes.length,sha256:sha(bytes),executable:name.startsWith('bin/')};})};
 const bytes=JSON.stringify(manifest);writePrivateFile(path.join(bundle,'manifest.json'),bytes);writePrivateFile(path.join(bundle,'manifest.sig'),sign(null,Buffer.from(bytes),privateKey).toString('base64url'));
 const reserve=net.createServer();await new Promise(r=>reserve.listen(0,'127.0.0.1',r));const port=reserve.address().port;await new Promise(r=>reserve.close(r));
 const config={schema:1,mode,gateway:{url:mode==='create-local'?'https://127.0.0.1:'+port:'https://owner.invalid',...(mode==='create-local'?{openssl:'/usr/bin/openssl'}:{})},host:{bundle,publisherKeyFile:publisher,publisherSha256:sha(createPublicKey(pem).export({type:'spki',format:'der'})),baseDir:base,label:'Isolated foreground',computer}};
 const input=path.join(root,'input.json');writePrivateFile(input,JSON.stringify(config));createDeployment(input,{stateDir});
 if(live){
  await advanceDeployment(stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare']});
  await advanceDeployment(stateDir,{authorize:['host.pair'],ownerApproval:{approve:true,...planDeployment(stateDir).ownerPairingScope}});
  await advanceDeployment(stateDir,{authorize:['host.doctor']});assert.equal(readDeployment(stateDir).steps.find(s=>s.id==='host.doctor').status,'succeeded');
 }else{
  for(const d of [base,path.join(base,'device'),path.join(base,'work')])ensurePrivateDirectory(d);writePrivateFile(path.join(base,'publisher.pem'),pem);
  stageSignedRelease({sourceDir:bundle,installRoot:path.join(base,'install'),publicKeyPem:pem});activateRelease(path.join(base,'install'),manifest.version,pem);
  const identityKey=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey,identity={device_id:'styx-fixture',fingerprint:sha(createPublicKey(identityKey).export({type:'spki',format:'der'}))};
  writePrivateFile(path.join(base,'device/identity.json'),JSON.stringify(identity));writePrivateFile(path.join(base,'device/identity.pem'),identityKey.export({type:'pkcs8',format:'pem'}));writePrivateFile(path.join(base,'device/host.token'),'a'.repeat(48));
  const host={host_id:identity.device_id,gateway_ws_url:config.gateway.url.replace('https:','wss:')+'/',token_file:path.join(base,'device/host.token'),exec:{binary:'/untrusted/path/ignored',cwd:path.join(base,'work')},...(computer?{computer:{enabled:true,binary:'/untrusted/path/ignored'}}:{})};writePrivateFile(path.join(base,'device/host.json'),JSON.stringify(host));
  const file=path.join(stateDir,'state.json'),state=JSON.parse(fs.readFileSync(file));for(const s of state.steps)if(['host.prepare','host.claim','host.doctor'].includes(s.id))s.status='succeeded';fs.writeFileSync(file,JSON.stringify(state));
 }
 const runCalls=[];
 const runner=async(config,{signal,onReady})=>{runCalls.push(config);onReady();await new Promise(resolve=>{if(signal.aborted)return resolve();signal.addEventListener('abort',()=>setTimeout(resolve,40),{once:true})})};
 const ops={hostStatus:async()=>({status:'reported',state:'not_installed',installed:false}),gatewayStatus:async()=>({status:'not_installed'}),runHost:runner,runComputer:runner,guiAvailable:async()=>false};
 return {root,stateDir,base,config,runCalls,ops};
}
test('join foreground owns direct connectors, derives signed executor, distinguishes started/connected and awaits abort', {skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),before=fs.readFileSync(path.join(f.base,'device/identity.json'));
 const started=await startDeploymentForeground(f.stateDir,{authorize:true},f.ops);assert.equal(started.gateway,'external');assert.ok(['started','connected'].includes(started.status));await until(()=>readDeploymentForeground(f.stateDir).status==='connected');
 assert.match(f.runCalls[0].exec.binary,/install\/releases\/0\.1\.0-foreground-test\/bin\/codex$/);assert.equal(fs.existsSync(path.join(f.stateDir,'gateway')),false);assert.equal(readDeploymentForeground(f.stateDir).toolHealth,'not_verified');
 const stopped=stopDeploymentForeground(f.stateDir);assert.equal(readDeploymentForeground(f.stateDir).status,'stopping');await stopped;assert.equal(readDeploymentForeground(f.stateDir).status,'not_running');assert.equal(fs.existsSync(path.join(f.stateDir,'foreground.lock')),false);assert.deepEqual(fs.readFileSync(path.join(f.base,'device/identity.json')),before);
 await startDeploymentForeground(f.stateDir,{authorize:true},f.ops);assert.equal(f.runCalls.length,2);
});
test('unknown service, uncertain journal, foreign lock, changed publisher or signed payload fail before connector startup',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);await assert.rejects(startDeploymentForeground(f.stateDir,{},f.ops),/authorization_required/);
 await assert.rejects(startDeploymentForeground(f.stateDir,{authorize:true},{...f.ops,hostStatus:async()=>({status:'reported',state:'unknown'})}),/service_state_unknown/);assert.equal(f.runCalls.length,0);
 writePrivateFile(path.join(f.stateDir,'foreground.lock'),'foreign-owner');await assert.rejects(startDeploymentForeground(f.stateDir,{authorize:true},f.ops),/owned_or_interrupted/);assert.equal(fs.readFileSync(path.join(f.stateDir,'foreground.lock'),'utf8'),'foreign-owner');fs.unlinkSync(path.join(f.stateDir,'foreground.lock'));
 writePrivateFile(path.join(f.stateDir,'capabilities.json'),JSON.stringify({status:'uncertain',computer:false}));await assert.rejects(startDeploymentForeground(f.stateDir,{authorize:true},f.ops),/capability_state_uncertain/);fs.unlinkSync(path.join(f.stateDir,'capabilities.json'));
 fs.appendFileSync(path.join(f.base,'install/releases/0.1.0-foreground-test/bin/codex'),'changed');await assert.rejects(startDeploymentForeground(f.stateDir,{authorize:true},f.ops),/hash|size|metadata/);assert.equal(f.runCalls.length,0);
});
test('an observed running service is reused; headless foreground never starts a Cua connector',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t,{computer:true});
 const reused=await startDeploymentForeground(f.stateDir,{authorize:true},{...f.ops,hostStatus:async()=>({status:'reported',state:'running',installed:true})});assert.equal(reused.status,'using_service');assert.equal(reused.execConnection,'not_observed');assert.equal(f.runCalls.length,0);const observed=await observeDeploymentForeground(f.stateDir);assert.equal(observed.status,'using_service');assert.equal(observed.execConnection,'not_observed');await stopDeploymentForeground(f.stateDir);
 const result=await startDeploymentForeground(f.stateDir,{authorize:true},f.ops);assert.equal(result.computerRequested,true);assert.equal(result.desktopConnection,'session_unavailable_or_unobserved');assert.equal(f.runCalls.length,1);
});
test('stop during deferred GUI startup retains ownership until startup and child settlement finish',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t,{computer:true});let release;const pending=new Promise(r=>{release=r});
 const start=startDeploymentForeground(f.stateDir,{authorize:true},{...f.ops,guiAvailable:()=>pending}),cancelled=assert.rejects(start,/foreground_start_cancelled/);
 await until(()=>readDeploymentForeground(f.stateDir).execConnection==='connected');let settled=false;
 const stop=stopDeploymentForeground(f.stateDir).then(v=>{settled=true;return v});await wait(30);assert.equal(settled,false);assert.equal(fs.existsSync(path.join(f.stateDir,'foreground.lock')),true);
 release(true);await cancelled;await stop;assert.equal(readDeploymentForeground(f.stateDir).status,'not_running');assert.equal(f.runCalls.length,1);assert.equal(fs.existsSync(path.join(f.stateDir,'foreground.lock')),false);
});
test('current configuration drift withdraws connected status and repeated start cannot duplicate its connector',{skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t);await startDeploymentForeground(f.stateDir,{authorize:true},f.ops);await until(()=>readDeploymentForeground(f.stateDir).execConnection==='connected');await startDeploymentForeground(f.stateDir,{authorize:true},f.ops);assert.equal(f.runCalls.length,1);
 fs.appendFileSync(path.join(f.stateDir,'deployment.json'),' ');assert.equal(readDeploymentForeground(f.stateDir).status,'needs_attention');assert.equal(readDeploymentForeground(f.stateDir).execConnection,'not_observed');await assert.rejects(startDeploymentForeground(f.stateDir,{authorize:true},f.ops),/foreground_scope_changed/);
});
test('real signed-generation Codex Exec over paired TLS foreground survives stop/restart with unchanged identity', {skip:process.env.STYX_LIVE_EXEC_TEST!=='1'||process.platform!=='linux'||process.arch!=='x64',timeout:60000},async t=>{
 const f=await fixture(t,{mode:'create-local',live:true}),hostFile=path.join(f.base,'device/host.json'),identity=fs.readFileSync(path.join(f.base,'device/identity.json')),credential=fs.readFileSync(path.join(f.base,'device/host.token'));
 const ops={hostStatus:f.ops.hostStatus,gatewayStatus:f.ops.gatewayStatus};
 const start=await startDeploymentForeground(f.stateDir,{authorize:true},ops);assert.ok(['started','connected'].includes(start.status));await until(()=>readDeploymentForeground(f.stateDir).execConnection==='connected');
 const endpoint=new URL('/mcp',f.config.gateway.url),client=new Client({name:'isolated-foreground-real-exec',version:'1'}),transport=new StreamableHTTPClientTransport(endpoint,{fetch:gatewayFetch(endpoint.href,{ca:fs.readFileSync(path.join(f.stateDir,'gateway/certificate.pem'))}),requestInit:{headers:{Authorization:'Bearer '+fs.readFileSync(path.join(f.stateDir,'gateway/model.token'),'utf8').trim()}}});
 t.after(()=>client.close());await client.connect(transport);const host=JSON.parse(fs.readFileSync(hostFile));
 let result=await client.callTool({name:'exec_command',arguments:{environment_id:host.host_id,cmd:"printf '%s' foreground-real-exec; exit 7",login:false,yield_time_ms:250}}),output=result.structuredContent?.output??'';
 for(let i=0;result.structuredContent?.session_id&&i<20;i++){result=await client.callTool({name:'write_stdin',arguments:{session_id:result.structuredContent.session_id,chars:'',yield_time_ms:250}});output+=result.structuredContent?.output??''}
 assert.equal(result.structuredContent.exit_code,7);assert.match(output,/foreground-real-exec/);assert.equal(readDeployment(f.stateDir).accountAcceptance,'NOT RUN');
 await transport.terminateSession();await client.close();await stopDeploymentForeground(f.stateDir);assert.equal(readDeploymentForeground(f.stateDir).status,'not_running');
 await startDeploymentForeground(f.stateDir,{authorize:true},ops);await until(()=>readDeploymentForeground(f.stateDir).execConnection==='connected');assert.deepEqual(fs.readFileSync(path.join(f.base,'device/identity.json')),identity);assert.deepEqual(fs.readFileSync(path.join(f.base,'device/host.token')),credential);
});

function childMessage(child,expected){return new Promise((resolve,reject)=>{
 const timer=setTimeout(()=>{cleanup();reject(Error('foreground_child_timeout'))},10000);
 const cleanup=()=>{clearTimeout(timer);child.off('message',message);child.off('error',error);child.off('exit',exit)};
 const message=value=>{if(value?.type===expected){cleanup();resolve(value)}else if(value?.type==='error'){cleanup();reject(Error(value.message))}};
 const error=value=>{cleanup();reject(value)},exit=code=>{cleanup();reject(Error('foreground_child_exited_'+code))};
 child.on('message',message);child.on('error',error);child.on('exit',exit);
})}
test('another process observes live authenticated owner; config drift and stop withdraw readiness',{skip:process.platform!=='linux'},async t=>{
 let child;t.after(async()=>{if(child?.connected){const stopped=childMessage(child,'stopped');child.send('stop');await stopped.catch(()=>child.kill())}else if(child&&child.exitCode===null)child.kill()});
 const f=await fixture(t),module=new URL('../foreground.mjs',import.meta.url).href;
 const script=`import {startDeploymentForeground,stopDeploymentForeground} from ${JSON.stringify(module)};
 const d=process.argv[1];const runner=async(c,{signal,onReady})=>{onReady();await new Promise(resolve=>{if(signal.aborted)return resolve();signal.addEventListener('abort',resolve,{once:true})})};
 process.on('message',async value=>{if(value==='stop'){try{await stopDeploymentForeground(d);process.send({type:'stopped'});process.disconnect()}catch(e){process.send({type:'error',message:e.message})}}});
 try{await startDeploymentForeground(d,{authorize:true},{hostStatus:async()=>({status:'reported',state:'not_installed'}),runHost:runner,guiAvailable:async()=>false});process.send({type:'ready'})}catch(e){process.send({type:'error',message:e.message})}`;
 child=spawn(process.execPath,['--input-type=module','-e',script,f.stateDir],{stdio:['ignore','ignore','pipe','ipc']});child.stderr.resume();await childMessage(child,'ready');
 assert.equal(readDeploymentForeground(f.stateDir).status,'needs_attention');
 const live=await observeDeploymentForeground(f.stateDir);assert.equal(live.status,'connected');assert.equal(live.observation,'authenticated_foreground_owner');assert.equal(live.toolHealth,'not_verified');assert.equal(live.accountAcceptance,'NOT RUN');assert.match(live.ownerGeneration,/^[a-f0-9]{64}$/);
 assert.doesNotMatch(JSON.stringify(live),/secret|configurationHash|127\.0\.0\.1|Authorization/);
 const configFile=path.join(f.stateDir,'deployment.json'),before=fs.readFileSync(configFile);fs.appendFileSync(configFile,' ');
 assert.equal((await observeDeploymentForeground(f.stateDir)).reason,'foreground_scope_changed');assert.equal(fs.existsSync(path.join(f.stateDir,'foreground.lock')),true);
 fs.writeFileSync(configFile,before);
 const stopped=childMessage(child,'stopped');child.send('stop');await stopped;
 assert.equal((await observeDeploymentForeground(f.stateDir)).status,'not_running');assert.equal(fs.existsSync(path.join(f.stateDir,'foreground-observer.json')),false);
});
test('killed owner leaves a stale receipt and lock without PID-based adoption or cleanup',{skip:process.platform!=='linux'},async t=>{
 let child;t.after(()=>{if(child&&child.exitCode===null)child.kill('SIGKILL')});
 const f=await fixture(t),module=new URL('../foreground.mjs',import.meta.url).href;
 const script=`import {startDeploymentForeground} from ${JSON.stringify(module)};await startDeploymentForeground(process.argv[1],{authorize:true},{hostStatus:async()=>({status:'reported',state:'not_installed'}),runHost:async(c,{onReady})=>{onReady();await new Promise(()=>{})}});process.send({type:'ready'})`;
 child=spawn(process.execPath,['--input-type=module','-e',script,f.stateDir],{stdio:['ignore','ignore','pipe','ipc']});child.stderr.resume();await childMessage(child,'ready');
 const file=path.join(f.stateDir,'foreground-observer.json'),lock=path.join(f.stateDir,'foreground.lock'),receipt=fs.readFileSync(file),lockBefore=fs.readFileSync(lock);
 const exited=new Promise(resolve=>child.once('exit',resolve));child.kill('SIGKILL');await exited;
 const status=await observeDeploymentForeground(f.stateDir);assert.equal(status.status,'needs_attention');assert.equal(status.execConnection,'not_observed');assert.deepEqual(fs.readFileSync(file),receipt);assert.deepEqual(fs.readFileSync(lock),lockBefore);
 const reused=JSON.parse(receipt);reused.pid=process.pid;fs.writeFileSync(file,JSON.stringify(reused));
 assert.equal((await observeDeploymentForeground(f.stateDir)).status,'needs_attention');
 await assert.rejects(startDeploymentForeground(f.stateDir,{authorize:true},f.ops),/owned_or_interrupted/);
});
