import test from 'node:test';
import assert from 'node:assert/strict';
import {gatewayServiceIdentity,controlGatewayService} from '../gateway-service.mjs';
import path from 'node:path';
import os from 'node:os';
test('persistent Gateway identity is stable per deployment and distinct between deployments',()=>{
 const a=path.join(os.tmpdir(),'deployment-a'),b=path.join(os.tmpdir(),'deployment-b');
 assert.match(gatewayServiceIdentity(a),/^styx-gateway-[a-f0-9]{12}\.service$/);
 assert.equal(gatewayServiceIdentity(a),gatewayServiceIdentity(a));assert.notEqual(gatewayServiceIdentity(a),gatewayServiceIdentity(b));
 assert.throws(()=>gatewayServiceIdentity('../relative'),/absolute_state_directory_required/);
});
test('unsupported commands and unapproved mutations refuse before filesystem/service operations',()=>{
 assert.throws(()=>controlGatewayService('/absent',{action:'shell'}),/invalid_gateway_service_action/);
 assert.throws(()=>controlGatewayService('/absent',{action:'install'}),/authorization_required|platform_not_supported/);
});
import fs from 'node:fs';
import net from 'node:net';
import {randomUUID,generateKeyPairSync,createPublicKey,createHash} from 'node:crypto';
import {buildHostRelease} from '../../host/build-host-release.mjs';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
import {createDeployment,advanceDeployment,stopDeploymentGateway} from '../core.mjs';
import {gatewayServicePlan} from '../gateway-service.mjs';
import {verifyGatewayConnection} from '../connection.mjs';
const live=process.env.STYX_ONBOARDING_GATEWAY_SERVICE_TEST==='1'&&process.platform==='linux';
test('owned persistent Gateway survives installer exit boundary and uninstalls without deleting device state',{skip:!live,timeout:60000},async t=>{
 const dir=path.join(os.tmpdir(),'styx-gateway-service-'+randomUUID());ensurePrivateDirectory(dir);
 const state=path.join(dir,'state');let installed=false;
 t.after(async()=>{await stopDeploymentGateway(state);if(installed)controlGatewayService(state,{action:'uninstall',authorize:true});fs.rmSync(dir,{recursive:true,force:true})});
 const {privateKey,publicKey}=generateKeyPairSync('ed25519',{privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
 const priv=path.join(dir,'sign.key'),pub=path.join(dir,'publisher.pub');fs.writeFileSync(priv,privateKey,{mode:0o600});fs.writeFileSync(pub,publicKey,{mode:0o600});
 const bundle=path.join(dir,'bundle');buildHostRelease({destination:bundle,version:'0.1.0-gateway-service-test',privateKeyFile:priv,nodeBinary:process.env.STYX_ONBOARDING_NODE_BINARY,codexBinary:process.env.STYX_ONBOARDING_CODEX_BINARY,cuaBinary:process.env.STYX_ONBOARDING_CUA_BINARY});
 const listener=net.createServer();await new Promise(r=>listener.listen(0,'127.0.0.1',r));const port=listener.address().port;await new Promise(r=>listener.close(r));
 const input=path.join(dir,'input.json');fs.writeFileSync(input,JSON.stringify({schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl'},host:{bundle,publisherKeyFile:pub,publisherSha256:createHash('sha256').update(createPublicKey(publicKey).export({type:'spki',format:'der'})).digest('hex'),baseDir:path.join(dir,'host'),label:'owned-service',computer:false}}),{mode:0o600});
 createDeployment(input,{stateDir:state});const prepared=await advanceDeployment(state,{authorize:['gateway.prepare','gateway.start','gateway.verify','host.prepare']});
 assert.equal(prepared.steps.find(s=>s.id==='host.prepare').status,'succeeded');
 assert.throws(()=>controlGatewayService(state,{action:'start',authorize:true}),/stop_foreground_gateway_before_service_start/);
 await stopDeploymentGateway(state);
 const plan=gatewayServicePlan(state);assert.ok(plan.unit.includes('gateway-runner.mjs'));assert.ok(!plan.unit.includes('admin.token'));
 assert.equal(controlGatewayService(state,{action:'status'}).status,'not_installed');
 controlGatewayService(state,{action:'install',authorize:true});installed=true;controlGatewayService(state,{action:'start',authorize:true});
 let verified;for(let n=0;n<40;n++){try{verified=await verifyGatewayConnection({url:'https://127.0.0.1:'+port+'/mcp',tokenFile:path.join(state,'gateway/model.token'),caFile:path.join(state,'gateway/certificate.pem'),independentStyx:true,freshConnection:true});break}catch{await new Promise(r=>setTimeout(r,100))}}
 assert.equal(verified?.status,'gateway_verified');assert.equal(controlGatewayService(state,{action:'status'}).active,'active');
 controlGatewayService(state,{action:'stop',authorize:true});assert.equal(controlGatewayService(state,{action:'status'}).active,'inactive');
 controlGatewayService(state,{action:'uninstall',authorize:true});installed=false;
 assert.equal(controlGatewayService(state,{action:'status'}).status,'not_installed');assert.ok(fs.existsSync(path.join(state,'deployment.json')));
});
import {verifyGatewayServiceDefinition} from '../gateway-service.mjs';
import {buildGatewayRuntimeRelease,prepareGatewayRuntime} from '../gateway-runtime.mjs';
test('same ownership marker cannot authorize a changed service executable',{skip:process.platform==='win32'},t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-unit-binding-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const file=path.join(dir,'unit.service'),plan={marker:'# Styx test binding',unit:'# Styx test binding\nExecStart=/trusted/node /trusted/runner\n'};
 fs.writeFileSync(file,plan.unit,{mode:0o600});assert.doesNotThrow(()=>verifyGatewayServiceDefinition(file,plan));
 fs.writeFileSync(file,plan.unit.replace('/trusted/runner','/other/program'));
 assert.throws(()=>verifyGatewayServiceDefinition(file,plan),/gateway_service_definition_changed/);
});

function gatewayOnlyFixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-gateway-only-plan-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const keys=generateKeyPairSync('ed25519'),priv=path.join(root,'sign.pem'),pub=path.join(root,'public.pem'),binary=path.join(root,'node-source'),license=path.join(root,'LICENSE');
 fs.writeFileSync(priv,keys.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});fs.writeFileSync(pub,keys.publicKey.export({format:'pem',type:'spki'}),{mode:0o600});fs.writeFileSync(binary,'not executed: signed service-plan fixture\n');fs.writeFileSync(license,'Fixture license\n');
 const bundle=path.join(root,'bundle'),built=buildGatewayRuntimeRelease({destination:bundle,version:'1.0.0-service-plan',privateKeyFile:priv,nodeBinary:binary,nodeLicenseFile:license});
 const runtime={bundle,publisherKeyFile:pub,publisherSha256:built.publisherSha256,baseDir:path.join(root,'runtime')};
 const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:18795',openssl:process.execPath,runtime}},input=path.join(root,'input.json'),state=path.join(root,'state');
 fs.writeFileSync(input,JSON.stringify(config),{mode:0o600});createDeployment(input,{stateDir:state});
 return {root,runtime,state,config,input};
}
function succeedSteps(state,ids){
 // Selection tests supply completed Core journal entries; no native service
 // command or network readiness is claimed by this fixture.
 const file=path.join(state,'state.json'),journal=JSON.parse(fs.readFileSync(file,'utf8'));
 for(const step of journal.steps)if(ids.includes(step.id))step.status='succeeded';
 fs.writeFileSync(file,JSON.stringify(journal),{mode:0o600});
}
test('Gateway-only service plan verifies its independent runtime without Host preparation',t=>{
 const f=gatewayOnlyFixture(t),prepared=prepareGatewayRuntime(f.runtime);succeedSteps(f.state,['gateway.runtime.prepare','gateway.prepare']);
 const plan=gatewayServicePlan(f.state);assert.equal(plan.runtimeSource,'gateway');assert.equal(plan.nodeBinary,prepared.nodeBinary);assert.ok(plan.unit.includes('gateway-runner.mjs'));
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.state,'deployment.json'),'utf8')).host,undefined);
 assert.equal(fs.existsSync(path.join(f.root,'host')),false);
 fs.appendFileSync(prepared.nodeBinary,'unsigned');assert.throws(()=>gatewayServicePlan(f.state),/service_node_hash_mismatch/);
});
test('existing files and configured runtime cannot substitute for completed preparation steps',t=>{
 const f=gatewayOnlyFixture(t);prepareGatewayRuntime(f.runtime);
 assert.throws(()=>gatewayServicePlan(f.state),/gateway_preparation_required/);
 succeedSteps(f.state,['gateway.prepare']);assert.throws(()=>gatewayServicePlan(f.state),/gateway_runtime_preparation_required/);
});
test('legacy Host-sourced signed Node remains supported without silently migrating identity',t=>{
 const f=gatewayOnlyFixture(t),prepared=prepareGatewayRuntime(f.runtime);
 const legacy={...f.config,gateway:{url:f.config.gateway.url,openssl:process.execPath},host:{...f.runtime,label:'Existing Host',computer:false}};
 const input=path.join(f.root,'legacy-input.json'),state=path.join(f.root,'legacy-state');fs.writeFileSync(input,JSON.stringify(legacy),{mode:0o600});createDeployment(input,{stateDir:state});
 succeedSteps(state,['gateway.prepare','host.prepare']);const plan=gatewayServicePlan(state);assert.equal(plan.runtimeSource,'legacy_host');assert.equal(plan.nodeBinary,prepared.nodeBinary);
});
test('Linux Gateway start/stop consistently enable/disable persistence before process changes',{skip:process.platform!=='linux'},t=>{
 const f=gatewayOnlyFixture(t);prepareGatewayRuntime(f.runtime);succeedSteps(f.state,['gateway.runtime.prepare','gateway.prepare']);
 const home=path.join(f.root,'home');fs.mkdirSync(home,{mode:0o700});let active=false,enabled=false;const calls=[];
 const options={home,run(binary,args){assert.equal(binary,'/usr/bin/systemctl');assert.equal(args[0],'--user');calls.push(args[1]);if(args[1]==='start')active=true;if(args[1]==='stop')active=false;if(args[1]==='enable')enabled=true;if(args[1]==='disable')enabled=false;return 'ActiveState='+(active?'active':'inactive')+'\nSubState='+(active?'running':'dead')+'\nUnitFileState='+(enabled?'enabled':'disabled')+'\nMainPID='+(active?123:0)+'\n';}};
 assert.equal(controlGatewayService(f.state,{action:'status'},options).status,'not_installed');assert.equal(calls.length,0);
 assert.equal(controlGatewayService(f.state,{action:'install',authorize:true},options).status,'installed_not_started');
 const started=controlGatewayService(f.state,{action:'start',authorize:true},options);assert.equal(started.active,'active');assert.equal(started.enabled,'enabled');
 const stopped=controlGatewayService(f.state,{action:'stop',authorize:true},options);assert.equal(stopped.active,'inactive');assert.equal(stopped.enabled,'disabled');
 assert.deepEqual(calls,['daemon-reload','enable','start','show','disable','stop','show']);
 const bytes=fs.readFileSync(path.join(home,'.config/systemd/user',gatewayServiceIdentity(f.state)));calls.length=0;
 controlGatewayService(f.state,{action:'status'},options);assert.deepEqual(calls,['show']);assert.deepEqual(fs.readFileSync(path.join(home,'.config/systemd/user',gatewayServiceIdentity(f.state))),bytes);
});
test('Linux Gateway partial start failure is surfaced without automatic retry',{skip:process.platform!=='linux'},t=>{
 const f=gatewayOnlyFixture(t);prepareGatewayRuntime(f.runtime);succeedSteps(f.state,['gateway.runtime.prepare','gateway.prepare']);
 const home=path.join(f.root,'home');fs.mkdirSync(home,{mode:0o700});const calls=[];
 const options={home,run(binary,args){calls.push(args[1]);if(args[1]==='start')throw Error('native failure');return '';}};
 controlGatewayService(f.state,{action:'install',authorize:true},options);calls.length=0;
 assert.throws(()=>controlGatewayService(f.state,{action:'start',authorize:true},options),/gateway_service_operation_failed/);assert.deepEqual(calls,['enable','start']);
});
