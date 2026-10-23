import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {generateKeyPairSync,createHash,verify,constants,sign} from 'node:crypto';
import {capabilityPayload} from '../../shared/enrollment-protocol.mjs';
import {changeDeploymentCapabilities,readDeploymentCapabilities,rollbackDeploymentCapabilities} from '../capabilities.mjs';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {EnrollmentController} from '../../gateway/enrollment.mjs';
import {requestEnrollment,claimEnrollment} from '../../host/enroll.mjs';
import {stageSignedRelease,activateRelease} from '../../host/installer.mjs';
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-capabilities-'));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,'deployment.json'),'{}',{mode:0o600});
 const keys=generateKeyPairSync('rsa',{modulusLength:3072});
 const publicKey=keys.publicKey.export({type:'spki',format:'pem'}),key=keys.privateKey.export({type:'pkcs8',format:'pem'});
 const identity={device_id:'styx-'+'a'.repeat(24),fingerprint:createHash('sha256').update(keys.publicKey.export({type:'spki',format:'der'})).digest('hex')};
 const host={host_id:identity.device_id,token_file:'unchanged',exec:{binary:'unchanged'}};
 const hostFile=path.join(dir,'host.json');fs.writeFileSync(hostFile,JSON.stringify(host),{mode:0o600});
 let generation=0,enabled=false,running=true;const calls=[];
 const ops={prepare:()=>({identity,key,publicKey,host:JSON.parse(fs.readFileSync(hostFile)),hostFile,computer:{enabled:true,binary:'/verified/cua',connections:1},owner:{},serviceConfigFile:'fixed'}),
  hostStatus:async()=>({status:'reported',state:running?'running':'stopped',installed:true}),
  hostControl:async(d,{action})=>{calls.push(action);running=action==='start';return {status:'reported',state:running?'running':'stopped'}},
  owner:async(owner,command,args)=>{
   if(command==='devices')return [{...identity,status:'approved',generation:String(generation),capabilities:{exec:true,computer:enabled}}];
   const body=args[0];assert.equal(body.generation,String(generation));assert.ok(verify('sha256',Buffer.from(capabilityPayload(body)),{key:publicKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(body.signature,'base64url')));
   enabled=body.enable_computer;generation++;calls.push('computer.'+enabled);
   return {status:'updated',...identity,generation:String(generation),capabilities:{exec:true,computer:enabled}};
  }};
 return {dir,hostFile,ops,calls};
}
test('local capability enable and disable preserve identity and exec config without reenrollment',async t=>{
 const f=fixture(t);
 const enabled=await changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops);
 assert.equal(enabled.status,'updated');assert.equal(enabled.computer,true);
 assert.deepEqual(f.calls,['computer.false','stop','computer.true','start']);
 let host=JSON.parse(fs.readFileSync(f.hostFile));assert.equal(host.exec.binary,'unchanged');assert.equal(host.token_file,'unchanged');assert.equal(host.computer.enabled,true);
 f.calls.length=0;await changeDeploymentCapabilities(f.dir,{authorize:true,computer:false},f.ops);
 assert.deepEqual(f.calls,['computer.false','stop','start']);host=JSON.parse(fs.readFileSync(f.hostFile));assert.equal(host.computer,undefined);
 assert.equal(readDeploymentCapabilities(f.dir).computer,false);
});
test('lost capability response stops local Host, disables its config and never replays uncertain transaction',async t=>{
 const f=fixture(t),owner=f.ops.owner;
 f.ops.owner=async(...args)=>{const result=await owner(...args);if(args[1]==='capabilities'&&args[2][0].enable_computer)throw Error('lost_response');return result};
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/lost_response/);
 assert.equal(f.calls.at(-1),'computer.false');assert.equal(f.calls.at(-2),'stop');assert.equal(JSON.parse(fs.readFileSync(f.hostFile)).computer,undefined);
 assert.equal(readDeploymentCapabilities(f.dir).status,'uncertain');assert.equal(readDeploymentCapabilities(f.dir).computer,false);const n=f.calls.length;
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/uncertain_requires_reconciliation/);assert.equal(f.calls.length,n);
});
test('no permission means no state or native mutation',async t=>{
 const f=fixture(t);await assert.rejects(changeDeploymentCapabilities(f.dir,{computer:true},f.ops),/authorization_required/);
 assert.equal(f.calls.length,0);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false);
});
test('capability scope is checked before owned foreground stops and explicit resume is recorded',async t=>{
 const f=fixture(t);f.ops.readForeground=()=>({status:'connected'});
 f.ops.stopOwnedForeground=async()=>{const j=JSON.parse(fs.readFileSync(path.join(f.dir,'capabilities.json')));assert.equal(j.phase,'stop_owned_foreground');assert.equal(j.status,'running');f.calls.push('owned.stop');return {status:'stopped',foregroundRestartRequired:true}};
 const result=await changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops);assert.equal(result.foregroundRestartRequired,true);assert.equal(f.calls[0],'owned.stop');assert.equal(f.calls.filter(x=>x==='owned.stop').length,1);
});
test('unknown external owner or failed scope cannot stop foreground or mutate capabilities',async t=>{
 const f=fixture(t);let stopped=0;f.ops.stopOwnedForeground=async()=>{stopped++;return {status:'stopped'}};f.ops.readForeground=()=>({status:'needs_attention'});
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/foreground_owned_or_interrupted/);assert.equal(stopped,0);assert.equal(f.calls.length,0);
 f.ops.readForeground=()=>({status:'connected'});f.ops.prepare=()=>{throw Error('scope_refused')};await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/scope_refused/);assert.equal(stopped,0);assert.equal(f.calls.length,0);
});


test('Browser changes require explicit authorization before any transaction',async t=>{
 const f=fixture(t),before=fs.readFileSync(f.hostFile);
 await assert.rejects(changeDeploymentCapabilities(f.dir,{browser:true},f.ops),/explicit_browser_capability_authorization_required/);
 assert.equal(f.calls.length,0);assert.deepEqual(fs.readFileSync(f.hostFile),before);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false);
});

const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const writeJSON=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{mode:0o600});
const signedPreparation=`import fs from 'node:fs';import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
export const readManagedBrowser=()=>({status:'prepared'});
export async function prepareManagedBrowser({profileRoot,authorize}){if(authorize!==true)throw Error('authorization_required');fs.writeFileSync(path.join(profileRoot,'fixture-receipt.json'),JSON.stringify({scope:'unit_fixture_only'}),{mode:0o600});return {status:'prepared',playwright:'signed-fixture',executablePath:'/not-an-acceptance-result'};}`;
function browserFixture(t,{withBrowser=true,headless=true}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-browser-capabilities-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const dir=path.join(root,'deployment'),base=path.join(root,'host'),bundle=path.join(root,'bundle'),install=path.join(base,'install'),device=path.join(base,'device');
 for(const p of [dir,base,bundle,device,path.join(dir,'gateway'),path.join(base,'browser'),path.join(base,'browser','profiles')])fs.mkdirSync(p,{mode:0o700});
 const publisher=generateKeyPairSync('ed25519'),pub=publisher.publicKey.export({format:'pem',type:'spki'}),keys=generateKeyPairSync('rsa',{modulusLength:2048});
 const key=keys.privateKey.export({format:'pem',type:'pkcs8'}),publicKey=keys.publicKey.export({format:'pem',type:'spki'});
 const identity={device_id:'styx-'+'b'.repeat(24),fingerprint:digest(keys.publicKey.export({format:'der',type:'spki'}))};
 const files={'bin/codex':Buffer.from('fixture-never-executed'),'bin/cua-driver':Buffer.from('fixture-never-executed')};
 if(withBrowser)for(const name of ['host/browser.mjs','packages/styx-browser-provider/host.mjs','packages/styx-browser-provider/config.mjs','packages/styx-browser-provider/prepare.mjs','packages/styx-browser-provider/installed.mjs','packages/styx-browser-provider/login-state.mjs','packages/styx-browser-provider/contract.mjs','packages/styx-browser-provider/playwright-contract-0.0.83.json','packages/styx-browser-provider/node_modules/@playwright/mcp/package.json'])files[name]=Buffer.from(name.endsWith('/prepare.mjs')?signedPreparation:name.endsWith('.json')?'{}':'// signed unit fixture; never run');
 const manifest={schema:1,version:'browser-cap-test',platform:process.platform,arch:process.arch,files:Object.entries(files).map(([name,bytes])=>{fs.mkdirSync(path.dirname(path.join(bundle,name)),{recursive:true,mode:0o700});fs.writeFileSync(path.join(bundle,name),bytes,{mode:0o600});return {path:name,sha256:digest(bytes),size:bytes.length,executable:name.startsWith('bin/')};})};
 const raw=Buffer.from(JSON.stringify(manifest));fs.writeFileSync(path.join(bundle,'manifest.json'),raw);fs.writeFileSync(path.join(bundle,'manifest.sig'),sign(null,raw,publisher.privateKey).toString('base64url'));
 fs.writeFileSync(path.join(base,'publisher.pem'),pub,{mode:0o600});stageSignedRelease({sourceDir:bundle,installRoot:install,publicKeyPem:pub});activateRelease(install,manifest.version,pub);
 writeJSON(path.join(device,'identity.json'),identity);fs.writeFileSync(path.join(device,'identity.pem'),key,{mode:0o600});fs.writeFileSync(path.join(device,'host.token'),'kept-enrolled-token',{mode:0o600});
 const hostFile=path.join(device,'host.json'),host={host_id:identity.device_id,gateway_ws_url:'wss://127.0.0.1:23123/',token_file:path.join(device,'host.token'),exec:{binary:path.join(install,'releases',manifest.version,'bin/codex')}};writeJSON(hostFile,host);
 const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:23123',openssl:'/usr/bin/openssl'},host:{bundle,publisherKeyFile:path.join(base,'publisher.pem'),publisherSha256:digest(publisher.publicKey.export({type:'spki',format:'der'})),baseDir:base,label:'Browser fixture',computer:false,browser:{enabled:false,headless}}};
 writeJSON(path.join(dir,'deployment.json'),config);writeJSON(path.join(base,'service.json'),{unitName:'fixture-host.service'});
 writeJSON(path.join(base,'enrollment.json'),{gateway_url:config.gateway.url,storage_dir:device,browser_requested:false,computer_requested:false});
 const state={schema:1,mode:config.mode,configSha256:digest(fs.readFileSync(path.join(dir,'deployment.json'))),steps:[{id:'host.prepare',status:'succeeded',evidence:{enrollment:{path:path.join(base,'enrollment.json'),sha256:digest(fs.readFileSync(path.join(base,'enrollment.json')))}}},{id:'host.pair',status:'succeeded',evidence:{host:{path:hostFile,sha256:digest(fs.readFileSync(hostFile))}}},{id:'host.doctor',status:'succeeded'}]};writeJSON(path.join(dir,'state.json'),state);
 writeJSON(path.join(dir,'background.json'),{schema:1,status:'not_configured',configSha256:state.configSha256,operations:[]});
 const owner={gateway_url:config.gateway.url,gateway_ca_file:path.join(dir,'gateway/certificate.pem'),admin_token_file:path.join(dir,'gateway/admin.token')};writeJSON(path.join(dir,'gateway/owner.json'),owner);
 for(const name of ['certificate.pem','admin.token','model.token'])fs.writeFileSync(path.join(dir,'gateway',name),'preserved-'+name,{mode:0o600});
 fs.writeFileSync(path.join(base,'browser/profiles/existing-login'),'saved-site-session',{mode:0o600});
 let generation=0,browser=false,computer=false;const calls=[];
 const snapshot=()=>({...identity,status:'approved',generation:String(generation),capabilities:{exec:true,browser,computer},online:false,connections:{exec:false,computer:false,browser:false}});
 const ops={readForeground:()=>({status:'not_running'}),hostStatus:async()=>({status:'reported',state:'stopped',installed:false,persistence:'none'}),owner:async(_owner,command,args)=>{
  if(command==='devices')return [snapshot()];
  assert.equal(command,'capabilities');const body=args[0];assert.equal(body.generation,String(generation));
  assert.ok(verify('sha256',Buffer.from(capabilityPayload(body)),{key:publicKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(body.signature,'base64url')));
  if(Object.hasOwn(body,'enable_browser'))browser=body.enable_browser;if(Object.hasOwn(body,'enable_computer'))computer=body.enable_computer;
  calls.push({browser,computer});generation++;return {...snapshot(),status:'updated'};
 }};
 return {root,dir,base,hostFile,config,ops,calls,snapshot,identity,profile:path.join(base,'browser/profiles/existing-login')};
}

test('real Browser capability scope rejects changed native signer before capability or profile mutations',async t=>{
 const f=browserFixture(t),app={path:'/Applications/Styx.app',cdhash:'a'.repeat(40)},local={...app,certificateSha1:'b'.repeat(40),certificateSha256:'c'.repeat(64)};
 const configFile=path.join(f.dir,'deployment.json'),hostBefore=fs.readFileSync(f.hostFile),profileBefore=fs.readFileSync(f.profile);
 for(const [registered,current,error]of [[local,app,/registered_certificate_changed/],[local,{...local,certificateSha256:'d'.repeat(64)},/registered_certificate_changed/],[app,local,/certificate_migration_required/]]){
  f.config.host.macPreviewApp=registered;writeJSON(configFile,f.config);const before=fs.readFileSync(configFile);
  await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},{...f.ops,trustedMacPreviewApp:current}),error);
  assert.deepEqual(f.calls,[]);assert.deepEqual(fs.readFileSync(configFile),before);assert.deepEqual(fs.readFileSync(f.hostFile),hostBefore);assert.deepEqual(fs.readFileSync(f.profile),profileBefore);
  assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false);assert.equal(fs.existsSync(path.join(f.dir,'capability-transactions')),false);
 }
});

test('Browser enable/disable migrates one authoritative config and retains signed identity and profile',async t=>{
 const f=browserFixture(t),kept=['identity.json','identity.pem','host.token'].map(n=>[path.join(f.base,'device',n),fs.readFileSync(path.join(f.base,'device',n))]);
 const result=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops);
 assert.equal(result.status,'updated');assert.equal(result.browser,true);assert.equal(result.computer,false);assert.match(result.transactionId,/^[a-f0-9]{32}$/);
 let host=JSON.parse(fs.readFileSync(f.hostFile)),config=JSON.parse(fs.readFileSync(path.join(f.dir,'deployment.json'))),state=JSON.parse(fs.readFileSync(path.join(f.dir,'state.json')));
 assert.equal(host.browser.enabled,true);assert.equal(host.browser.headless,true);assert.equal(host.computer,undefined);assert.equal(config.host.browser.enabled,true);assert.equal(state.configSha256,digest(fs.readFileSync(path.join(f.dir,'deployment.json'))));
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.dir,'background.json'))).configSha256,state.configSha256);
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.base,'enrollment.json'))).browser_requested,true);
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.base,'browser/fixture-receipt.json'))).scope,'unit_fixture_only');
 await changeDeploymentCapabilities(f.dir,{authorize:true,browser:false},f.ops);
 host=JSON.parse(fs.readFileSync(f.hostFile));config=JSON.parse(fs.readFileSync(path.join(f.dir,'deployment.json')));assert.equal(host.browser,undefined);assert.equal(config.host.browser.enabled,false);assert.equal(fs.readFileSync(f.profile,'utf8'),'saved-site-session');
 for(const [file,before]of kept)assert.deepEqual(fs.readFileSync(file),before);
 assert.deepEqual(f.calls,[{browser:true,computer:false},{browser:false,computer:false}]);assert.equal(readDeploymentCapabilities(f.dir).browser,false);
 assert.equal(fs.existsSync(path.join(f.dir,'advance.lock')),false);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.lock')),false);
});

test('explicit Browser rollback restores exact config bytes, grants and profiles',async t=>{
 const f=browserFixture(t),files=[path.join(f.dir,'deployment.json'),path.join(f.dir,'state.json'),f.hostFile,path.join(f.base,'enrollment.json'),path.join(f.dir,'background.json')],before=files.map(file=>fs.readFileSync(file));
 const enabled=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops);
 await assert.rejects(rollbackDeploymentCapabilities(f.dir,{transactionId:enabled.transactionId},f.ops),/authorization_required/);
 const result=await rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:enabled.transactionId},f.ops);assert.equal(result.status,'rolled_back');assert.equal(result.browser,false);
 for(let i=0;i<files.length;i++)assert.deepEqual(fs.readFileSync(files[i]),before[i]);assert.equal(fs.readFileSync(f.profile,'utf8'),'saved-site-session');
 assert.equal(f.snapshot().capabilities.browser,false);assert.equal(fs.existsSync(path.join(f.base,'browser/fixture-receipt.json')),true,'prepared cache remains available, profile is not removed');
});

test('Browser mutation refuses active or unknown lanes and never stops services or foreground work',async t=>{
 for(const kind of ['foreground','service','enabled-service','unknown-persistence','exec','computer','browser','unknown','update-lock','foreign-lock']){
  const f=browserFixture(t),owner=f.ops.owner;let stopped=0;f.ops.stopOwnedForeground=()=>{stopped++;throw Error('must_not_stop')};f.ops.hostControl=()=>{stopped++;throw Error('must_not_stop')};
  if(kind==='foreground')f.ops.readForeground=()=>({status:'connected'});
  if(kind==='service')f.ops.hostStatus=async()=>({status:'reported',state:'running'});
  if(kind==='enabled-service')f.ops.hostStatus=async()=>({status:'reported',state:'stopped',installed:true,persistence:'enabled'});
  if(kind==='unknown-persistence')f.ops.hostStatus=async()=>({status:'reported',state:'stopped',installed:true,persistence:'unknown'});
  if(['exec','computer','browser','unknown'].includes(kind))f.ops.owner=async(...args)=>{const rows=await owner(...args);if(args[1]==='devices'){if(kind==='unknown')delete rows[0].connections;else rows[0].connections[kind]=true}return rows};
  if(kind==='update-lock')fs.writeFileSync(path.join(f.base,'install/.health-update-lock'),'foreign',{mode:0o600});
  if(kind==='foreign-lock')fs.writeFileSync(path.join(f.dir,'foreground.lock'),'foreign',{mode:0o600});
  await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops));
  assert.equal(stopped,0,kind);assert.equal(f.calls.length,0,kind);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false,kind);
 }
});

test('old signed Host requires reviewed Browser-capable update instead of alternate installation',async t=>{
 const f=browserFixture(t,{withBrowser:false});await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/browser_enabled_host_update_required/);
 assert.equal(f.calls.length,0);assert.equal(fs.existsSync(path.join(f.base,'browser/fixture-receipt.json')),false);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false);
});

test('preparation failure restores configuration and leaves existing profiles intact',async t=>{
 const f=browserFixture(t),before=fs.readFileSync(path.join(f.dir,'deployment.json'));f.ops.prepareBrowser=async()=>{throw Error('browser_runtime_download_failed')};
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/browser_runtime_download_failed/);
 assert.deepEqual(fs.readFileSync(path.join(f.dir,'deployment.json')),before);assert.equal(f.calls.length,0);assert.equal(readDeploymentCapabilities(f.dir).status,'rolled_back');assert.equal(fs.readFileSync(f.profile,'utf8'),'saved-site-session');
});

test('stale configuration and changed preserved identity are never overwritten',async t=>{
 for(const kind of ['config','identity']){
  const f=browserFixture(t),file=kind==='config'?path.join(f.dir,'deployment.json'):path.join(f.base,'device/identity.json');
  f.ops.prepareBrowser=async()=>{fs.appendFileSync(file,' ');return {status:'prepared'}};
  await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/capability_(review_changed|preserved_identity_changed)/);
  assert.equal(fs.readFileSync(file,'utf8').endsWith(' '),true);assert.equal(f.calls.length,0);assert.equal(readDeploymentCapabilities(f.dir).status,'uncertain');
 }
});

test('lost Browser approval reply fails closed and requires explicit rollback, never reenrollment or replay',async t=>{
 const f=browserFixture(t),owner=f.ops.owner;let lost=false;
 f.ops.owner=async(...args)=>{const result=await owner(...args);if(args[1]==='capabilities'&&args[2][0].enable_browser&&!lost){lost=true;throw Error('lost_browser_reply')}return result};
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/lost_browser_reply/);
 const state=readDeploymentCapabilities(f.dir);assert.equal(state.status,'uncertain');assert.equal(state.browser,false);assert.deepEqual(f.calls.map(x=>x.browser),[true,false]);
 const n=f.calls.length;await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/uncertain_requires_reconciliation/);assert.equal(f.calls.length,n);
 const restored=await rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:state.transactionId},f.ops);assert.equal(restored.status,'rolled_back');assert.equal(JSON.parse(fs.readFileSync(f.hostFile)).host_id,f.identity.device_id);
});

test('Browser rollback refuses changed backup, later file edits and stale transaction identity',async t=>{
 const f=browserFixture(t),result=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops);
 await assert.rejects(rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:'f'.repeat(32)},f.ops),/binding_changed/);
 fs.appendFileSync(f.hostFile,' ');const changed=fs.readFileSync(f.hostFile);
 await assert.rejects(rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:result.transactionId},f.ops),/review_changed/);assert.deepEqual(fs.readFileSync(f.hostFile),changed);
});

test('headless Browser remains separate from Computer Use and preserves an explicit headed selection',async t=>{
 for(const headless of [true,false]){
  const f=browserFixture(t,{headless});f.ops.prepare=()=>{throw Error('must_not_prepare_cua')};
  const result=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true,computer:false},f.ops);
  assert.equal(JSON.parse(fs.readFileSync(f.hostFile)).browser.headless,headless);assert.equal(JSON.parse(fs.readFileSync(f.hostFile)).computer,undefined);assert.equal(result.nativePermissions,'not_checked');assert.equal(result.accountAcceptance,'NOT RUN');
 }
});

test('signed provider tamper and profile redirection refuse migration without touching enrolled identity',async t=>{
 for(const reason of ['signed-member','profile-root']){
  const f=browserFixture(t),identity=fs.readFileSync(path.join(f.base,'device/identity.pem'));
  if(reason==='signed-member')fs.appendFileSync(path.join(f.base,'install/releases/browser-cap-test/packages/styx-browser-provider/prepare.mjs'),'\n// tampered');
  else{const host=JSON.parse(fs.readFileSync(f.hostFile));host.browser={enabled:false,profileRoot:path.join(f.root,'foreign')};writeJSON(f.hostFile,host);}
  await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops));assert.equal(f.calls.length,0);assert.deepEqual(fs.readFileSync(path.join(f.base,'device/identity.pem')),identity);
 }
});

test('explicit rollback recovers only dead same-transaction management locks',async t=>{
 for(const live of [false,true]){
  const f=browserFixture(t),enabled=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops);
  const child=spawnSync(process.execPath,['-e','process.exit(0)']);assert.equal(child.status,0);
  const owner=live?process.pid:child.pid;
  for(const name of ['advance.lock','capabilities.lock'])writeJSON(path.join(f.dir,name),{schema:1,kind:'browser-capabilities-v1',transactionId:enabled.transactionId,pid:owner});
  if(live){await assert.rejects(rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:enabled.transactionId},f.ops),/management_owner_alive/);assert.equal(fs.existsSync(path.join(f.dir,'advance.lock')),true);assert.equal(f.snapshot().capabilities.browser,true);}
  else{assert.equal((await rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:enabled.transactionId},f.ops)).status,'rolled_back');assert.equal(fs.existsSync(path.join(f.dir,'advance.lock')),false);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.lock')),false);}
 }
});

test('rollback validates private backup hashes before any grant mutation',async t=>{
 const f=browserFixture(t),result=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),calls=f.calls.length;
 const backup=path.join(f.dir,'capability-transactions',result.transactionId,'0.before');fs.appendFileSync(backup,' ');
 await assert.rejects(rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:result.transactionId},f.ops),/backup_changed/);
 assert.equal(f.calls.length,calls);assert.equal(f.snapshot().capabilities.browser,true);assert.equal(readDeploymentCapabilities(f.dir).status,'uncertain');
});

test('same generation approval and final offline recheck prevent stale grants after browser preparation',async t=>{
 const f=browserFixture(t),owner=f.ops.owner;let readings=0;
 f.ops.owner=async(...args)=>{const result=await owner(...args);if(args[1]==='devices'&&++readings>1)result[0].generation='changed-externally';return result};
 const before=fs.readFileSync(f.hostFile);
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/capability_revision_changed/);
 assert.equal(f.calls.length,0);assert.deepEqual(fs.readFileSync(f.hostFile),before);assert.equal(readDeploymentCapabilities(f.dir).status,'rolled_back');
});


test('unresolved browser preparation ownership stays uncertain after configuration restoration',async t=>{
 const f=browserFixture(t),before=fs.readFileSync(f.hostFile),runtime=path.join(f.base,'browser/runtime'),lock=path.join(runtime,'prepare.lock');
 f.ops.prepareBrowser=async()=>{fs.mkdirSync(runtime,{mode:0o700});writeJSON(lock,{pid:process.pid,status:'unresolved'});throw Error('browser_runtime_download_failed')};
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/browser_runtime_download_failed/);
 const state=readDeploymentCapabilities(f.dir);assert.equal(state.status,'uncertain');assert.equal(state.reason,'browser_preparation_owner_requires_reconciliation');assert.deepEqual(fs.readFileSync(f.hostFile),before);assert.equal(fs.existsSync(lock),true);assert.equal(f.calls.length,0);
 await assert.rejects(rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:state.transactionId},f.ops),/browser_preparation_in_progress/);assert.equal(fs.existsSync(lock),true);assert.equal(f.calls.length,0);
});

test('existing enrolled Host selects installed browser and login persistence through one guarded transaction',async t=>{
 const f=browserFixture(t),identityBefore=fs.readFileSync(path.join(f.base,'device/identity.json')),profileBefore=fs.readFileSync(f.profile);
 let prepared;
 await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true,browserChannel:'msedge',persistLogin:true},{...f.ops,prepareBrowser:async scope=>{prepared=scope.browser;return {status:'prepared',readiness:'not_verified'}}});
 assert.equal(prepared.channel,'msedge');assert.equal(prepared.persistLogin,true);
 const host=JSON.parse(fs.readFileSync(f.hostFile)),config=JSON.parse(fs.readFileSync(path.join(f.dir,'deployment.json'))),enrollment=JSON.parse(fs.readFileSync(path.join(f.base,'enrollment.json')));
 for(const browser of [host.browser,config.host.browser,enrollment.browser_config]){assert.equal(browser.channel,'msedge');assert.equal(browser.persistLogin,true);}
 assert.deepEqual(fs.readFileSync(path.join(f.base,'device/identity.json')),identityBefore);assert.deepEqual(fs.readFileSync(f.profile),profileBefore);
 await rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:readDeploymentCapabilities(f.dir).transactionId},f.ops);
 assert.equal(JSON.parse(fs.readFileSync(path.join(f.dir,'deployment.json'))).host.browser.channel,undefined);
});

test('installed browser selection requires explicit Browser intent and rejects unbounded selection values',async t=>{
 const f=browserFixture(t);
 for(const selection of [{authorize:true,browserChannel:'chrome'},{authorize:true,browser:false,persistLogin:true},{authorize:true,browser:true,browserChannel:'firefox'},{authorize:true,browser:true,persistLogin:'yes'}])await assert.rejects(changeDeploymentCapabilities(f.dir,selection,f.ops));
 assert.equal(f.calls.length,0);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false);
});

async function joinedFixture(t){
 const f=browserFixture(t),cert=path.join(f.root,'ca.pem'),tlsKey=path.join(f.root,'tls.pem'),admin=path.join(f.root,'admin.token');
 fs.writeFileSync(admin,'a'.repeat(48),{mode:0o600});
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-keyout',tlsKey,'-out',cert,'-subj','/CN=capabilities-test','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});fs.chmodSync(cert,0o600);
 const gateway=createStyxGateway({catalog:{version:1,targets:[]}}),controller=new EnrollmentController({rootDir:path.join(f.root,'gateway-state'),adminTokenFile:admin,registry:gateway.registry,relay:gateway.relay}),hosts=[];
 const server=await createGatewayHttp(gateway,{token:'m'.repeat(48),port:0,allowedHosts:hosts,enrollment:controller,tlsCertificateFile:cert,tlsPrivateKeyFile:tlsKey});hosts.push('127.0.0.1:'+server.address.port);t.after(()=>server.close());
 const origin='https://127.0.0.1:'+server.address.port,device=path.join(f.base,'device');
 for(const n of ['identity.json','identity.pem','host.token','host.json'])fs.unlinkSync(path.join(device,n));
 const enrollment={gateway_url:origin,gateway_ca_file:cert,storage_dir:device,label:'Joined fixture',cwd:f.root,shell:'/bin/sh',exec_binary:path.join(f.base,'install/releases/browser-cap-test/bin/codex'),computer_requested:false,browser_requested:false};
 const invitation=controller.invite({}),pending=await requestEnrollment(enrollment,invitation.invitation);
 controller.approve({request_id:pending.request_id,fingerprint:pending.fingerprint,enable_computer:false,enable_browser:false});await claimEnrollment(enrollment);
 f.config={...f.config,mode:'join-existing',gateway:{url:origin,caFile:cert}};writeJSON(path.join(f.dir,'deployment.json'),f.config);writeJSON(path.join(f.base,'enrollment.json'),enrollment);
 const state=JSON.parse(fs.readFileSync(path.join(f.dir,'state.json')));state.mode='join-existing';state.configSha256=digest(fs.readFileSync(path.join(f.dir,'deployment.json')));
 for(const step of state.steps){if(step.id==='host.pair')step.id='host.claim';for(const item of Object.values(step.evidence??{}))if(item.path)item.sha256=digest(fs.readFileSync(item.path));}
 writeJSON(path.join(f.dir,'state.json'),state);writeJSON(path.join(f.dir,'background.json'),{schema:1,status:'not_configured',configSha256:state.configSha256,operations:[]});
 // A joined device has no local Gateway owner credential, even in the fixture.
 fs.rmSync(path.join(f.dir,'gateway'),{recursive:true});delete f.ops.owner;
 const preserved=['identity.json','identity.pem','host.token'].map(n=>[path.join(device,n),fs.readFileSync(path.join(device,n))]);
 return {...f,controller,gateway,preserved,unchanged:()=>{for(const [file,bytes]of preserved)assert.deepEqual(fs.readFileSync(file),bytes)}};
}
test('joined Host uses real TLS self-device capabilities without admin credentials or new pairing',async t=>{
 const f=await joinedFixture(t),first=await changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops);
 assert.equal(first.status,'updated');assert.equal(first.computer,true);assert.equal(first.browser,false);
 assert.equal(first.nativePermissions,'not_checked');assert.equal(first.foregroundRestartRequired,true);f.unchanged();
 const config=JSON.parse(fs.readFileSync(path.join(f.dir,'deployment.json')));assert.equal(config.mode,'join-existing');assert.equal(config.host.computer,true);
 const both=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops);assert.equal(both.browser,true);assert.equal(both.computer,true);f.unchanged();
 const back=await rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:both.transactionId},f.ops);assert.equal(back.status,'rolled_back');assert.equal(back.computer,true);assert.equal(back.browser,false);f.unchanged();
});
test('joined self-device denied token and connected lane reject before configuration mutation',async t=>{
 const f=await joinedFixture(t),before=fs.readFileSync(path.join(f.dir,'deployment.json')),token=f.preserved.at(-1)[0],original=fs.readFileSync(token);
 fs.writeFileSync(token,'x'.repeat(48),{mode:0o600});await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/device_unauthorized/);assert.deepEqual(fs.readFileSync(path.join(f.dir,'deployment.json')),before);fs.writeFileSync(token,original);
 f.ops.readForeground=()=>({status:'running'});await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/foreground_must_be_stopped/);assert.deepEqual(fs.readFileSync(path.join(f.dir,'deployment.json')),before);f.unchanged();
});
test('joined accepted response lost is reconciled by authenticated read, never replayed, rollback preserves identity',async t=>{
 const f=await joinedFixture(t),original=f.controller.selfCapabilities.bind(f.controller);let posts=0;
 f.controller.selfCapabilities=(id,auth,body)=>{const result=original(id,auth,body);if(body){posts++;throw Error('response_lost_after_commit')}return result;};
 const result=await changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops);
 assert.equal(result.status,'updated');assert.equal(result.reconciliation,'current_self_state_matches_requested');assert.equal(result.remoteOutcome,'unknown');assert.equal(posts,1);f.unchanged();
 f.controller.selfCapabilities=original;const back=await rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:result.transactionId},f.ops);assert.equal(back.browser,false);f.unchanged();
});
test('joined lost response with unavailable reconciliation remains uncertain without compensation or replay',async t=>{
 const f=await joinedFixture(t),original=f.controller.selfCapabilities.bind(f.controller);let posts=0,lost=false;
 f.controller.selfCapabilities=(id,auth,body)=>{if(lost)throw Error('gateway_unavailable');const result=original(id,auth,body);if(body){posts++;lost=true;throw Error('response_lost_after_commit')}return result;};
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/enrollment_internal_error/);
 const state=readDeploymentCapabilities(f.dir);assert.equal(state.status,'uncertain');assert.equal(posts,1);assert.equal(JSON.parse(fs.readFileSync(f.hostFile)).browser,undefined);f.unchanged();
 f.controller.selfCapabilities=original;const back=await rollbackDeploymentCapabilities(f.dir,{authorize:true,transactionId:state.transactionId},f.ops);assert.equal(back.status,'rolled_back');assert.equal(back.browser,false);f.unchanged();
});

test('joined local preparation failure restores bytes without sending capability mutation',async t=>{
 const f=await joinedFixture(t),files=['deployment.json','state.json'].map(n=>[path.join(f.dir,n),fs.readFileSync(path.join(f.dir,n))]);let posts=0;
 const original=f.controller.selfCapabilities.bind(f.controller);f.controller.selfCapabilities=(id,auth,body)=>{if(body)posts++;return original(id,auth,body)};
 f.ops.prepareBrowser=async()=>{throw Error('browser_runtime_download_failed')};
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/browser_runtime_download_failed/);
 assert.equal(readDeploymentCapabilities(f.dir).status,'rolled_back');assert.equal(posts,0);for(const [file,bytes]of files)assert.deepEqual(fs.readFileSync(file),bytes);f.unchanged();
});
