import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {createHash,createPublicKey,generateKeyPairSync,sign} from 'node:crypto';
import {createDeployment,planDeployment,readDeployment,advanceDeployment,stopDeploymentGateway,controlDeploymentHostService,controlDeploymentService} from '../core.mjs';
import {main} from '../cli.mjs';
import {publicDeployment,validateUiConfig,createOnboardingServer} from '../server.mjs';
import {gatewayServicePlan} from '../gateway-service.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
async function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-role-matrix-'));fs.chmodSync(root,0o700);
 const stateDir=path.join(root,'deployment');t.after(async()=>{await stopDeploymentGateway(stateDir);fs.rmSync(root,{force:true,recursive:true})});
 const probe=net.createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const bundle=path.join(root,'bundle');fs.mkdirSync(bundle);fs.mkdirSync(path.join(bundle,'bin'));
 const bytes=fs.readFileSync(process.execPath),node=process.platform==='win32'?'node.exe':'node';fs.writeFileSync(path.join(bundle,'bin',node),bytes);
 const manifest=JSON.stringify({schema:1,version:'0.1.0-runtime-test',platform:process.platform,arch:process.arch,files:[{path:'bin/'+node,sha256:sha(bytes),size:bytes.length,executable:true}]});
 fs.writeFileSync(path.join(bundle,'manifest.json'),manifest);fs.writeFileSync(path.join(bundle,'manifest.sig'),sign(null,Buffer.from(manifest),privateKey).toString('base64url'));
 const publisherKeyFile=path.join(root,'publisher.pem');fs.writeFileSync(publisherKeyFile,publicKey.export({type:'spki',format:'pem'}),{mode:0o600});
 const runtime={bundle,publisherKeyFile,publisherSha256:sha(publicKey.export({type:'spki',format:'der'})),baseDir:path.join(root,'gateway-runtime')};
 const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl',runtime}};
 const configFile=path.join(root,'input.json');fs.writeFileSync(configFile,JSON.stringify(config),{mode:0o600});
 return {root,stateDir,configFile,config,runtime};
}
test('Gateway-only prepares signed Node, serves actual MCP TLS and never creates Host/Exec/Cua state',async t=>{
 const f=await fixture(t);const created=await main(['create',f.configFile,f.stateDir]);
 assert.deepEqual(created.roles,{gateway:'local',host:'disabled',exec:'disabled',computer:'disabled',deviceIngress:'loopback_only',readiness:'not_inferred'});
 assert.deepEqual(publicDeployment(created).roles,created.roles);
 assert.equal(planDeployment(f.stateDir).ownerPairingScope,null);assert.equal(planDeployment(f.stateDir).service.configFile,null);
 assert.deepEqual(created.steps.map(s=>s.id),['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify']);
 const result=await main(['advance',f.stateDir,...created.steps.map(s=>s.id)]);
 assert.ok(result.steps.every(s=>s.status==='succeeded'),JSON.stringify(result));
 assert.equal(result.steps.at(-1).evidence.status,'gateway_verified');assert.equal(result.accountAcceptance,'NOT RUN');
 const plan=gatewayServicePlan(f.stateDir);assert.equal(plan.runtimeSource,'gateway');
 const files=[];const walk=d=>{for(const entry of fs.readdirSync(d,{withFileTypes:true})){const file=path.join(d,entry.name);if(entry.isDirectory())walk(file);else files.push(file)}};walk(f.runtime.baseDir);
 assert.ok(!files.some(f=>/codex|cua|host\.json|enrollment\.json|service\.json/.test(f)));
 await assert.rejects(controlDeploymentHostService(f.stateDir,{action:'install',authorize:true}),/local_host_not_configured/);
 await stopDeploymentGateway(f.stateDir);
 assert.equal(readDeployment(f.stateDir).gatewayRuntime.status,'not_owned_by_current_process');
 assert.equal(readDeployment(f.stateDir).steps.at(-1).status,'succeeded');
});
test('role combinations share config projection; joining cannot specify a local runtime',async t=>{
 const f=await fixture(t);
 const host={bundle:f.runtime.bundle,publisherKeyFile:f.runtime.publisherKeyFile,publisherSha256:f.runtime.publisherSha256,baseDir:path.join(f.root,'host'),label:'matrix',computer:false};
 for(const [mode,computer]of [['create-local',false],['create-local',true],['join-existing',false],['join-existing',true]]){
  const config={schema:1,mode,gateway:mode==='create-local'?f.config.gateway:{url:'https://known.example'},host:{...host,computer}};
  const file=path.join(f.root,mode+'-'+computer+'.json'),stateDir=path.join(f.root,mode+'-'+computer);fs.writeFileSync(file,JSON.stringify(config),{mode:0o600});
  const result=createDeployment(file,{stateDir});
  assert.deepEqual(publicDeployment(result).roles,(await main(['status',stateDir])).roles);
  assert.equal(result.roles.computer,computer?'requested':'disabled');
  assert.equal(result.roles.readiness,'not_inferred');
  if(mode==='join-existing')assert.ok(!result.steps.some(s=>s.id.startsWith('gateway.')));
 }
 const invalid={schema:1,mode:'join-existing',host,gateway:{url:'https://known.example',runtime:f.runtime}};
 fs.writeFileSync(f.configFile,JSON.stringify(invalid),{mode:0o600});assert.throws(()=>createDeployment(f.configFile,{stateDir:f.stateDir}),/join_cannot_prepare_gateway/);
 const ui=structuredClone(f.config);delete ui.gateway.openssl;
 assert.deepEqual(validateUiConfig(ui,{trustedOpenSSL:'/usr/bin/openssl'}),f.config);
});
test('headless computer request blocks Host preparation while Gateway stays independent', {skip:process.platform!=='linux'},async t=>{
 const f=await fixture(t),saved={DISPLAY:process.env.DISPLAY,WAYLAND_DISPLAY:process.env.WAYLAND_DISPLAY};
 delete process.env.DISPLAY;delete process.env.WAYLAND_DISPLAY;
 t.after(()=>{for(const [k,v]of Object.entries(saved))if(v===undefined)delete process.env[k];else process.env[k]=v});
 f.config.host={...f.runtime,baseDir:path.join(f.root,'headless-host'),label:'desktop requested',computer:true};
 fs.writeFileSync(f.configFile,JSON.stringify(f.config),{mode:0o600});createDeployment(f.configFile,{stateDir:f.stateDir});
 const result=await advanceDeployment(f.stateDir,{authorize:['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify','host.prepare']});
 assert.equal(result.gatewayRuntime.status,'running');assert.equal(result.roles.computer,'requested');
 const host=result.steps.find(s=>s.id==='host.prepare');assert.equal(host.status,'blocked');assert.equal(host.evidence.desktop,'unavailable');
 assert.equal(fs.existsSync(f.config.host.baseDir),false);
});
test('read-only service observation preserves journal; uncertain mutation cannot be replayed',async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 await advanceDeployment(f.stateDir,{authorize:['gateway.runtime.prepare','gateway.prepare']});
 const before=fs.readFileSync(path.join(f.stateDir,'state.json'),'utf8');
 await main(['gateway-service',f.stateDir,'status']);assert.equal(fs.readFileSync(path.join(f.stateDir,'state.json'),'utf8'),before);
 const state=JSON.parse(before);state.gatewayMaintenance=[{action:'start',status:'uncertain'}];fs.writeFileSync(path.join(f.stateDir,'state.json'),JSON.stringify(state),{mode:0o600});
 await assert.rejects(main(['gateway-service',f.stateDir,'start','--authorize']),/uncertain_gateway_service_action_requires_reconciliation/);
});

test('App HTTP and CLI advance the same Gateway-only deployment and return identical roles',async t=>{
 const f=await fixture(t),app=await createOnboardingServer({stateDir:f.stateDir});t.after(()=>app.close());
 const token=new URLSearchParams(new URL(app.url).hash.slice(1)).get('session');
 const headers={Authorization:'Bearer '+token};const session=await(await fetch(app.origin+'/api/session',{headers})).json();
 const post=(route,data)=>fetch(app.origin+'/api/'+route,{method:'POST',headers:{...headers,Origin:app.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json'},body:JSON.stringify(data)});
 const input=structuredClone(f.config);delete input.gateway.openssl;
 assert.equal((await post('create',input)).status,200);
 for(const id of ['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify'])assert.equal((await post('advance',{authorize:[id]})).status,200);
 const status=await(await fetch(app.origin+'/api/status',{headers})).json(),cli=await main(['status',f.stateDir]);
 assert.deepEqual(status.deployment.roles,cli.roles);assert.deepEqual(status.deployment.steps.map(s=>[s.id,s.status]),cli.steps.map(s=>[s.id,s.status]));
 assert.equal(status.deployment.gatewayRuntime,'running');assert.equal(status.deployment.roles.exec,'disabled');
 const ingress=await(await post('device-ingress/plan',{})).json();assert.equal(ingress.ingress.status,'loopback_only');
 assert.equal((await(await post('device-ingress/verify',{url:f.config.gateway.url})).json()).ingress.remoteUsable,false);
});
test('service command success cannot replace observed readiness; uncertain stop remains available',async t=>{
 const f=await fixture(t);createDeployment(f.configFile,{stateDir:f.stateDir});
 const missed=await controlDeploymentService(f.stateDir,{role:'gateway',action:'start',authorize:true},{gateway:()=>({active:'inactive',pid:null,enabled:'enabled'})});
 assert.equal(missed.status,'needs_attention');assert.equal(readDeployment(f.stateDir).gatewayServiceMaintenance.hasUncertainMutation,true);
 const stop=await controlDeploymentService(f.stateDir,{role:'gateway',action:'stop',authorize:true},{gateway:()=>({active:'inactive',pid:null,enabled:'disabled'})});
 assert.equal(stop.active,'inactive');
 await assert.rejects(controlDeploymentService(f.stateDir,{role:'gateway',action:'start',authorize:true},{gateway:()=>{throw Error('must not replay')}}),/requires_reconciliation/);
});
