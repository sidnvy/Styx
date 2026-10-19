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
 assert.equal(prepared.steps.find(s=>s.id==='host.prepare').status,'succeeded');await stopDeploymentGateway(state);
 const plan=gatewayServicePlan(state);assert.ok(plan.unit.includes('gateway-runner.mjs'));assert.ok(!plan.unit.includes('admin.token'));
 assert.equal(controlGatewayService(state,{action:'status'}).status,'not_installed');
 controlGatewayService(state,{action:'install',authorize:true});installed=true;controlGatewayService(state,{action:'start',authorize:true});
 let verified;for(let n=0;n<40;n++){try{verified=await verifyGatewayConnection({url:'https://127.0.0.1:'+port+'/mcp',tokenFile:path.join(state,'gateway/model.token'),caFile:path.join(state,'gateway/certificate.pem'),independentStyx:true,freshConnection:true});break}catch{await new Promise(r=>setTimeout(r,100))}}
 assert.equal(verified?.status,'gateway_verified');assert.equal(controlGatewayService(state,{action:'status'}).active,'active');
 controlGatewayService(state,{action:'stop',authorize:true});assert.equal(controlGatewayService(state,{action:'status'}).active,'inactive');
 controlGatewayService(state,{action:'uninstall',authorize:true});installed=false;
 assert.equal(controlGatewayService(state,{action:'status'}).status,'not_installed');assert.ok(fs.existsSync(path.join(state,'deployment.json')));
});
