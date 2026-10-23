import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {execFileSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {GATEWAY_SOURCE_FILES,LEGACY_GATEWAY_SOURCE_FILES,gatewayApplicationFile} from '../gateway-release-contract.mjs';
import {buildGatewayRelease} from '../gateway-release.mjs';
import {verifyGatewayRuntimeRelease,prepareGatewayRuntime,readGatewayRuntime} from '../gateway-runtime.mjs';
import {createDeployment,advanceDeployment} from '../core.mjs';
import {gatewayServicePlan} from '../gateway-service.mjs';
import {readGatewayDeployment} from '../gateway-deployment-reader.mjs';
import {verifyGatewayConnection} from '../connection.mjs';
import {stageSignedRelease,activateRelease} from '../../host/installer.mjs';
import {planGatewayRuntimeChange,applyGatewayRuntimeChange} from '../gateway-runtime-update.mjs';
const source=fileURLToPath(new URL('../../',import.meta.url));
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
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
function writeManifest(bundle,manifest,key){
 const raw=JSON.stringify(manifest,null,2)+'\n';fs.writeFileSync(path.join(bundle,'manifest.json'),raw);fs.writeFileSync(path.join(bundle,'manifest.sig'),sign(null,Buffer.from(raw),key).toString('base64url')+'\n');
}
// Copy actual historical product bytes, not current source with missing files
// or a new manifest relabeled as legacy. Dependencies retain their signed tree.
function historicalBundle(f,revision,version){
 const bundle=path.join(f.root,'historical-'+revision);fs.cpSync(f.options.destination,bundle,{recursive:true});
 const gitFile=name=>execFileSync('git',['-C',source,'show',revision+':vnext/'+name],{maxBuffer:4*1024*1024});
 const contract=gitFile('onboarding/gateway-release-contract.mjs').toString('utf8');
 const names=[...contract.slice(0,contract.indexOf('export const GATEWAY_ENTRYPOINT')).matchAll(/'([^']+\.(?:mjs|json|html))'/g)].map(match=>match[1]);
 const allowed=new Set(names.map(name=>'app/'+name));
 const manifest=JSON.parse(fs.readFileSync(path.join(bundle,'manifest.json')));
 for(const entry of manifest.files){
  if(entry.path.startsWith('app/')&&!entry.path.startsWith('app/node_modules/')&&!['app/package.json','app/package-lock.json'].includes(entry.path)&&!allowed.has(entry.path))fs.unlinkSync(path.join(bundle,entry.path));
 }
 manifest.files=manifest.files.filter(entry=>!entry.path.startsWith('app/')||entry.path.startsWith('app/node_modules/')||['app/package.json','app/package-lock.json'].includes(entry.path)||allowed.has(entry.path));
 for(const name of [...names,'package.json','package-lock.json']){
  const bytes=gitFile(name),member='app/'+name;fs.writeFileSync(path.join(bundle,member),bytes);
  const entry=manifest.files.find(entry=>entry.path===member);entry.sha256=digest(bytes);entry.size=bytes.length;
 }
 delete manifest.sourceContract;manifest.version=version;writeManifest(bundle,manifest,f.keys.privateKey);
 return {bundle,manifest,names};
}
test('contained Gateway build accepts only tracked source and locked production dependencies',t=>{
 const f=fixture(t),result=buildGatewayRelease(f.options),pub=f.keys.publicKey.export({format:'pem',type:'spki'});
 const manifest=JSON.parse(fs.readFileSync(path.join(f.options.destination,'manifest.json'),'utf8'));assert.deepEqual(manifest.files.filter(e=>!e.path.startsWith('bin/')&&!gatewayApplicationFile(e.path)).map(e=>e.path),[]);
 const verified=verifyGatewayRuntimeRelease(f.options.destination,pub);assert.equal(verified.manifest.component,'gateway-application');assert.equal(verified.manifest.sourceContract,4);assert.ok(result.dependencies>2);
 assert.ok(!verified.manifest.files.some(e=>e.executable&&!/^bin\/node(?:\.exe)?$/.test(e.path)));
 assert.ok(!verified.manifest.files.some(e=>!e.path.startsWith('app/node_modules/')&&/(?:^|\/)(?:test|tests|fixtures|__tests__|__fixtures__|examples)(?:\/|$)|^bin\/(?:codex|cua-driver)/.test(e.path)));
 for(const entry of manifest.files){const bytes=fs.readFileSync(path.join(f.options.destination,entry.path));assert.equal(bytes.length,entry.size,entry.path);assert.equal(digest(bytes),entry.sha256,entry.path);}
 for(const name of ['gateway/conversation-owners.mjs','onboarding/tunnel-context.mjs'])assert.ok(manifest.files.some(e=>e.path==='app/'+name),name);
 assert.equal(verified.manifest.files.filter(e=>e.path.startsWith('app/host/')).length,1);
 assert.ok(!fs.existsSync(path.join(f.options.destination,'app/onboarding/core.mjs')));
 const provenance=JSON.parse(fs.readFileSync(path.join(f.options.destination,'provenance/gateway-build.json'),'utf8'));assert.equal(provenance.nativePlatformAcceptance,'NOT RUN');
 const other=path.join(f.root,'untracked-build');execFileSync('git',['-C',f.publisherSource,'rm','--cached','onboarding/gateway-deployment-reader.mjs']);
 assert.throws(()=>buildGatewayRelease({...f.options,destination:other}),/untracked_gateway_release_source/);assert.equal(fs.existsSync(other),false);
});
test('source contract 3 refuses every missing required application source',t=>{
 const f=fixture(t);buildGatewayRelease(f.options);const file=path.join(f.options.destination,'manifest.json'),original=fs.readFileSync(file),manifest=JSON.parse(original),signature=fs.readFileSync(path.join(f.options.destination,'manifest.sig'));
 for(const name of GATEWAY_SOURCE_FILES.map(name=>'app/'+name)){
  const member=path.join(f.options.destination,name),bytes=fs.readFileSync(member),incomplete={...manifest,files:manifest.files.filter(e=>e.path!==name)},raw=JSON.stringify(incomplete)+'\n';
  fs.unlinkSync(member);fs.writeFileSync(file,raw);fs.writeFileSync(path.join(f.options.destination,'manifest.sig'),sign(null,Buffer.from(raw),f.keys.privateKey).toString('base64url'));
  assert.throws(()=>verifyGatewayRuntimeRelease(f.options.destination,f.keys.publicKey.export({format:'pem',type:'spki'})),/complete_signed_gateway_application_required/,name);
  fs.writeFileSync(member,bytes,{mode:0o600});fs.writeFileSync(file,original);fs.writeFileSync(path.join(f.options.destination,'manifest.sig'),signature);
 }
});
test('locked runtime imports survive test, tests and fixtures directories without private state',t=>{
 const f=fixture(t),dependenciesRoot=path.join(f.root,'locked-dependencies'),pkg=JSON.parse(fs.readFileSync(path.join(f.publisherSource,'package.json'))),packages={'':{dependencies:pkg.dependencies}};
 const put=(name,data)=>{const file=path.join(dependenciesRoot,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,data);};
 for(const name of ['@modelcontextprotocol/sdk','ws']){
  const version=pkg.dependencies[name];packages['node_modules/'+name]={version,integrity:'sha512-dGVzdA=='};
  put(name+'/package.json',JSON.stringify({name,version,type:'commonjs',main:'index.cjs'}));put(name+'/index.cjs',name==='ws'?'module.exports = {};':'module.exports = require("./test/loader.cjs");');
 }
 put('@modelcontextprotocol/sdk/test/loader.cjs','module.exports = require("../tests/runtime.cjs");');
 put('@modelcontextprotocol/sdk/tests/runtime.cjs','module.exports = require("../fixtures/value.json");');
 put('@modelcontextprotocol/sdk/fixtures/value.json',JSON.stringify({status:'locked runtime executed'}));
 for(const name of ['.cache/private.json','profiles/private.json','.env.local.json','runtime.log','runtime.tmp'])put('@modelcontextprotocol/sdk/'+name,'PRIVATE_STATE_DO_NOT_SHIP');
 fs.writeFileSync(path.join(f.publisherSource,'package-lock.json'),JSON.stringify({lockfileVersion:3,packages}));
 buildGatewayRelease({...f.options,dependenciesRoot});
 const output=path.join(f.options.destination,'app/node_modules/@modelcontextprotocol/sdk'),manifest=JSON.parse(fs.readFileSync(path.join(f.options.destination,'manifest.json')));
 for(const name of ['test/loader.cjs','tests/runtime.cjs','fixtures/value.json'])assert.ok(manifest.files.some(e=>e.path==='app/node_modules/@modelcontextprotocol/sdk/'+name),name);
 for(const name of ['.cache','profiles','.env.local.json','runtime.log','runtime.tmp'])assert.equal(fs.existsSync(path.join(output,name)),false,name);
 if(process.platform!=='win32'){
  const redirect=path.join(dependenciesRoot,'@modelcontextprotocol/sdk/tests/redirect.cjs');fs.symlinkSync(path.join(output,'index.cjs'),redirect);
  const destination=path.join(f.root,'redirected');assert.throws(()=>buildGatewayRelease({...f.options,dependenciesRoot,destination}),/gateway_dependency_symlink_forbidden/);assert.equal(fs.existsSync(destination),false);fs.unlinkSync(redirect);
 }
 fs.rmSync(f.publisherSource,{recursive:true});fs.rmSync(dependenciesRoot,{recursive:true});
 const observed=JSON.parse(execFileSync(process.execPath,['-e','console.log(JSON.stringify(require(process.argv[1])))',output],{cwd:f.root,encoding:'utf8',env:{...process.env,NODE_PATH:'',NODE_OPTIONS:''}}));
 assert.deepEqual(observed,{status:'locked runtime executed'});
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


test('real unversioned 26/28-file applications remain readable without relaxing signed import closure',t=>{
 const f=fixture(t),pub=f.keys.publicKey.export({format:'pem',type:'spki'});buildGatewayRelease(f.options);
 const prior=historicalBundle(f,'4c91cfc','99.0.0-legacy-28'),older=historicalBundle(f,'f09d0ad','100.0.0-legacy-26');
 assert.equal(prior.names.length,28);assert.equal(older.names.length,26);assert.deepEqual(new Set(older.names),new Set(LEGACY_GATEWAY_SOURCE_FILES));
 assert.equal(verifyGatewayRuntimeRelease(prior.bundle,pub).version,'99.0.0-legacy-28');
 assert.equal(verifyGatewayRuntimeRelease(older.bundle,pub).version,'100.0.0-legacy-26');
 // Optional in the historical minimum, but required by this actual 28-file
 // generation's static and dynamic imports.
 for(const name of ['app/gateway/conversation-owners.mjs','app/onboarding/tunnel-context.mjs']){
  const file=path.join(prior.bundle,name),bytes=fs.readFileSync(file);fs.unlinkSync(file);
  writeManifest(prior.bundle,{...prior.manifest,files:prior.manifest.files.filter(entry=>entry.path!==name)},f.keys.privateKey);
  assert.throws(()=>verifyGatewayRuntimeRelease(prior.bundle,pub),/complete_signed_gateway_source_imports_required/,name);
  fs.writeFileSync(file,bytes);writeManifest(prior.bundle,prior.manifest,f.keys.privateKey);
 }
 const runner='app/onboarding/gateway-signed-runner.mjs',file=path.join(older.bundle,runner),original=fs.readFileSync(file);
 for(const statement of ["import './missing-source.mjs';","export * from './missing-source.mjs';","await import('./missing-source.mjs');","import '../../../../unknown-bootstrap.mjs';"]){
  const bytes=Buffer.concat([Buffer.from(statement+'\n'),original]);fs.writeFileSync(file,bytes);
  const manifest=structuredClone(older.manifest),entry=manifest.files.find(entry=>entry.path===runner);entry.size=bytes.length;entry.sha256=digest(bytes);writeManifest(older.bundle,manifest,f.keys.privateKey);
  assert.throws(()=>verifyGatewayRuntimeRelease(older.bundle,pub),/complete_signed_gateway_source_imports_required/,statement);
 }
 fs.writeFileSync(file,original);writeManifest(older.bundle,older.manifest,f.keys.privateKey);
 for(const sourceContract of [0,1,5,'4',null]){
  writeManifest(older.bundle,{...older.manifest,sourceContract},f.keys.privateKey);
  assert.throws(()=>verifyGatewayRuntimeRelease(older.bundle,pub),/unsupported_gateway_source_contract/);
 }
 writeManifest(older.bundle,older.manifest,f.keys.privateKey);
 const unknown='app/onboarding/unknown.mjs',bytes=Buffer.from('export {};');fs.writeFileSync(path.join(older.bundle,unknown),bytes);
 writeManifest(older.bundle,{...older.manifest,files:[...older.manifest.files,{path:unknown,sha256:digest(bytes),size:bytes.length,executable:false}]},f.keys.privateKey);
 assert.throws(()=>verifyGatewayRuntimeRelease(older.bundle,pub),/gateway_runtime_contains_host_or_unknown_payload/);
});

test('actual historical signed payload installs, upgrades and rolls back through current runtime verification',t=>{
 const f=fixture(t),built=buildGatewayRelease(f.options),pub=f.keys.publicKey.export({format:'pem',type:'spki'});
 const legacy=historicalBundle(f,'4c91cfc','99.0.0-actual-legacy');
 const config={bundle:legacy.bundle,publisherKeyFile:f.publisherKeyFile,publisherSha256:built.publisherSha256,baseDir:path.join(f.root,'legacy-runtime')};
 const installed=prepareGatewayRuntime(config),oldManifest=readGatewayRuntime(config).manifestSha256;
 assert.equal(installed.version,legacy.manifest.version);
 stageSignedRelease({sourceDir:f.options.destination,installRoot:installed.installRoot,publicKeyPem:pub});
 activateRelease(installed.installRoot,built.version,pub);
 assert.equal(readGatewayRuntime(config).version,built.version);
 activateRelease(installed.installRoot,legacy.manifest.version,pub);
 const rolledBack=readGatewayRuntime(config);assert.equal(rolledBack.version,legacy.manifest.version);assert.equal(rolledBack.manifestSha256,oldManifest);
 fs.rmSync(legacy.bundle,{recursive:true});fs.rmSync(f.options.destination,{recursive:true});
 assert.equal(readGatewayRuntime(config).manifestSha256,oldManifest);
});

// A prior contract must retain its original minimum when a new interlock is added.
test('actual contract 2 payload remains verifiable after contract 3 adds Host migration interlock',t=>{
 const f=fixture(t);buildGatewayRelease(f.options);const pub=f.keys.publicKey.export({format:'pem',type:'spki'});
 const prior=historicalBundle(f,'77d73a0','100.0.0-contract-2');prior.manifest.sourceContract=2;writeManifest(prior.bundle,prior.manifest,f.keys.privateKey);
 assert.equal(verifyGatewayRuntimeRelease(prior.bundle,pub).manifest.sourceContract,2);
 assert.equal(prior.manifest.files.some(e=>e.path==='app/onboarding/host-payload-start-guard.mjs'),false);
});

test('actual contract 3 payload remains verifiable after work admission extends the signed closure',t=>{
 const f=fixture(t);buildGatewayRelease(f.options);const pub=f.keys.publicKey.export({format:'pem',type:'spki'});
 const prior=historicalBundle(f,'70fbeb6','101.0.0-contract-3');prior.manifest.sourceContract=3;writeManifest(prior.bundle,prior.manifest,f.keys.privateKey);
 assert.equal(verifyGatewayRuntimeRelease(prior.bundle,pub).manifest.sourceContract,3);
 assert.equal(prior.manifest.files.some(e=>e.path==='app/shared/work-admission.mjs'),false);
});
