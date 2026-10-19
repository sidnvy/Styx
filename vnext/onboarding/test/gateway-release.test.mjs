import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import {generateKeyPairSync} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {GATEWAY_SOURCE_FILES,gatewayApplicationFile} from '../gateway-release-contract.mjs';
import {buildGatewayRelease} from '../gateway-release.mjs';
import {verifyGatewayRuntimeRelease,readGatewayRuntime} from '../gateway-runtime.mjs';
import {createDeployment,advanceDeployment} from '../core.mjs';
import {gatewayServicePlan} from '../gateway-service.mjs';
import {readGatewayDeployment} from '../gateway-deployment-reader.mjs';
import {verifyGatewayConnection} from '../connection.mjs';
import {planGatewayRuntimeChange,applyGatewayRuntimeChange} from '../gateway-runtime-update.mjs';
const source=fileURLToPath(new URL('../../',import.meta.url));
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-gateway-release-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const keys=generateKeyPairSync('ed25519'),privateKeyFile=path.join(root,'private.pem'),publisherKeyFile=path.join(root,'publisher.pem'),nodeLicenseFile=path.join(root,'NODE-LICENSE');
 fs.writeFileSync(privateKeyFile,keys.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});fs.writeFileSync(publisherKeyFile,keys.publicKey.export({format:'pem',type:'spki'}),{mode:0o600});
 fs.writeFileSync(nodeLicenseFile,'Only a test fixture; not a redistributable runtime license.\n');
 const publisherSource=path.join(root,'publisher-source');fs.mkdirSync(publisherSource,{mode:0o700});
 for(const name of [...GATEWAY_SOURCE_FILES,'package.json','package-lock.json','licenses/styx-LICENSE']){
  const to=path.join(publisherSource,name);fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});fs.copyFileSync(path.join(source,name),to);
 }
 execFileSync('git',['init','-q',publisherSource]);execFileSync('git',['-C',publisherSource,'add','.']);
 const options={destination:path.join(root,'bundle'),version:'1.0.0-signed-gateway-test',privateKeyFile,nodeBinary:process.execPath,nodeLicenseFile,sourceRoot:publisherSource,dependenciesRoot:path.join(source,'node_modules')};
 return {root,keys,options,publisherKeyFile,publisherSource};
}
test('contained Gateway build accepts only tracked source and locked production dependencies',t=>{
 const f=fixture(t),result=buildGatewayRelease(f.options),pub=f.keys.publicKey.export({format:'pem',type:'spki'});
 const manifest=JSON.parse(fs.readFileSync(path.join(f.options.destination,'manifest.json'),'utf8'));assert.deepEqual(manifest.files.filter(e=>!e.path.startsWith('bin/')&&!gatewayApplicationFile(e.path)).map(e=>e.path),[]);
 const verified=verifyGatewayRuntimeRelease(f.options.destination,pub);assert.equal(verified.manifest.component,'gateway-application');assert.ok(result.dependencies>2);
 assert.ok(!verified.manifest.files.some(e=>e.executable&&!/^bin\/node(?:\.exe)?$/.test(e.path)));
 assert.ok(!verified.manifest.files.some(e=>/(?:^|\/)(?:test|tests|fixtures|__tests__|__fixtures__|examples)(?:\/|$)|bin\/(?:codex|cua-driver)/.test(e.path)));
 assert.equal(verified.manifest.files.filter(e=>e.path.startsWith('app/host/')).length,1);
 assert.ok(!fs.existsSync(path.join(f.options.destination,'app/onboarding/core.mjs')));
 const provenance=JSON.parse(fs.readFileSync(path.join(f.options.destination,'provenance/gateway-build.json'),'utf8'));assert.equal(provenance.nativePlatformAcceptance,'NOT RUN');
 const other=path.join(f.root,'untracked-build');execFileSync('git',['-C',f.publisherSource,'rm','--cached','onboarding/gateway-deployment-reader.mjs']);
 assert.throws(()=>buildGatewayRelease({...f.options,destination:other}),/untracked_gateway_release_source/);assert.equal(fs.existsSync(other),false);
});
test('signed Gateway runs authenticated MCP after its publisher checkout and original bundle are removed',{timeout:30000},async t=>{
 const f=fixture(t),built=buildGatewayRelease(f.options),second=path.join(f.root,'second-bundle');buildGatewayRelease({...f.options,destination:second,version:'2.0.0-signed-gateway-test'});
 const probe=net.createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
 const runtime={bundle:f.options.destination,publisherKeyFile:f.publisherKeyFile,publisherSha256:built.publisherSha256,baseDir:path.join(f.root,'runtime')};
 const stateDir=path.join(f.root,'deployment'),input=path.join(f.root,'input.json');fs.writeFileSync(input,JSON.stringify({schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl',runtime}}),{mode:0o600});
 createDeployment(input,{stateDir});const prepared=await advanceDeployment(stateDir,{authorize:['gateway.runtime.prepare','gateway.prepare']});assert.ok(prepared.steps.slice(0,2).every(s=>s.status==='succeeded'));
 const descriptor=gatewayServicePlan(stateDir);assert.equal(descriptor.application,'signed_application');assert.ok(descriptor.runner.startsWith(path.join(runtime.baseDir,'install/releases')));
 fs.rmSync(f.publisherSource,{recursive:true});fs.rmSync(f.options.destination,{recursive:true});fs.unlinkSync(f.publisherKeyFile);
 assert.equal(readGatewayRuntime(runtime).application,'signed_application');
 const child=spawn(descriptor.nodeBinary,[descriptor.runner,stateDir],{cwd:f.root,env:{...process.env,NODE_PATH:'',NODE_OPTIONS:''},stdio:['ignore','pipe','pipe']});let output='',error='';child.stdout.on('data',bytes=>output+=bytes);child.stderr.on('data',bytes=>error+=bytes);
 t.after(async()=>{if(child.exitCode===null){child.kill('SIGTERM');await once(child,'exit');}});
 const started=Date.now();while(!output.includes('Styx signed Gateway running.')){if(child.exitCode!==null)assert.fail('signed runner exited: '+error);if(Date.now()-started>10000)assert.fail('signed runner startup timeout: '+error);await new Promise(r=>setTimeout(r,20));}
 const verified=await verifyGatewayConnection({url:'https://127.0.0.1:'+port+'/mcp',tokenFile:path.join(stateDir,'gateway/model.token'),caFile:path.join(stateDir,'gateway/certificate.pem'),independentStyx:true,freshConnection:true});
 assert.equal(verified.status,'gateway_verified');assert.equal(verified.receipt.toolCall.environmentCount,0);assert.equal(verified.account_acceptance,'NOT RUN');
 const exit=once(child,'exit');child.kill('SIGTERM');assert.equal((await exit)[0],0);
 const beforeCertificate=fs.readFileSync(path.join(stateDir,'gateway/certificate.pem')),beforeCredential=fs.readFileSync(path.join(stateDir,'gateway/model.token'));
 const change=planGatewayRuntimeChange({stateDir,bundle:second});assert.equal(change.target.application,'signed_application');assert.notEqual(change.target.runner,change.current.runner);
 applyGatewayRuntimeChange({stateDir,plan:change,authorize:true},{observeQuiescence:()=>({service:'not_installed',processes:'none'})});
 const next=gatewayServicePlan(stateDir);assert.equal(next.runner,change.target.runner);
 const restarted=spawn(next.nodeBinary,[next.runner,stateDir],{cwd:f.root,env:{...process.env,NODE_PATH:'',NODE_OPTIONS:''},stdio:['ignore','pipe','pipe']});let nextOutput='',nextError='';restarted.stdout.on('data',bytes=>nextOutput+=bytes);restarted.stderr.on('data',bytes=>nextError+=bytes);
 t.after(async()=>{if(restarted.exitCode===null){restarted.kill('SIGTERM');await once(restarted,'exit');}});
 const restartAt=Date.now();while(!nextOutput.includes('Styx signed Gateway running.')){if(restarted.exitCode!==null)assert.fail('updated signed runner exited: '+nextError);if(Date.now()-restartAt>10000)assert.fail('updated signed runner timeout: '+nextError);await new Promise(r=>setTimeout(r,20));}
 assert.equal((await verifyGatewayConnection({url:'https://127.0.0.1:'+port+'/mcp',tokenFile:path.join(stateDir,'gateway/model.token'),caFile:path.join(stateDir,'gateway/certificate.pem'),independentStyx:true,freshConnection:true})).status,'gateway_verified');
 const nextExit=once(restarted,'exit');restarted.kill('SIGTERM');assert.equal((await nextExit)[0],0);
 const rollback=planGatewayRuntimeChange({stateDir,rollback:true});applyGatewayRuntimeChange({stateDir,plan:rollback,authorize:true},{observeQuiescence:()=>({service:'not_installed',processes:'none'})});
 assert.equal(gatewayServicePlan(stateDir).runner,descriptor.runner);assert.deepEqual(fs.readFileSync(path.join(stateDir,'gateway/certificate.pem')),beforeCertificate);assert.deepEqual(fs.readFileSync(path.join(stateDir,'gateway/model.token')),beforeCredential);
 const evidence=readGatewayDeployment(stateDir);assert.equal(evidence.runtime.url,'https://127.0.0.1:'+port);
 const file=path.join(stateDir,'gateway/runtime.json'),before=fs.readFileSync(file,'utf8');fs.writeFileSync(file,before+'\n');assert.throws(()=>readGatewayDeployment(stateDir),/completed_gateway_evidence_changed/);
});
