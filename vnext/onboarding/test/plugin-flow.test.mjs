import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {execFileSync} from 'node:child_process';
import {createDeployment,advanceDeployment,stopDeploymentGateway,readDeploymentPlugin,setDeploymentPluginProfile,exportDeploymentPlugin,recordDeploymentPluginAction} from '../core.mjs';
import {createOnboardingServer} from '../server.mjs';
import {main} from '../cli.mjs';
const options={authorize:true,presentation:{displayName:'我的 Styx',shortDescription:'我的电脑助手',longDescription:'使用明确授权的终端与桌面能力。',icon:null},selection:{mode:'create',accountLabel:'Personal account',pluginUrl:''}};
async function fixture(t,{joined=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-plugin-flow-'));t.after(()=>fs.rmSync(root,{force:true,recursive:true}));
 const stateDir=path.join(root,'deployment'),file=path.join(root,'config.json');
 const probe=net.createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
 const config={schema:1,mode:joined?'join-existing':'create-local',gateway:joined?{url:'https://known.unit.test'}:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl'},host:{bundle:path.join(root,'bundle'),publisherKeyFile:path.join(root,'publisher.pem'),publisherSha256:'a'.repeat(64),baseDir:path.join(root,'host'),label:'test',computer:false}};
 fs.writeFileSync(file,JSON.stringify(config),{mode:0o600});createDeployment(file,{stateDir});
 return {root,stateDir,config,file};
}
test('App and CLI share persisted presentation and explicit reuse without new Gateway or upload',async t=>{
 const f=await fixture(t,{joined:false});const before=fs.readFileSync(path.join(f.stateDir,'deployment.json'),'utf8');
 assert.equal(readDeploymentPlugin(f.stateDir).profileSaved,false);
 await assert.rejects(setDeploymentPluginProfile(f.stateDir,{...options,authorize:false}),/explicit_plugin_authorization_required/);
 const reuse={...options,selection:{mode:'reuse',accountLabel:'Existing workspace',pluginUrl:'https://chatgpt.com/plugins/styx-owned'}};
 const input=path.join(f.root,'profile.json');fs.writeFileSync(input,JSON.stringify({presentation:reuse.presentation,selection:reuse.selection}),{mode:0o600});
 await main(['plugin-profile',f.stateDir,input,'--authorize']);
 const saved=readDeploymentPlugin(f.stateDir);assert.equal(saved.selection.mode,'reuse');assert.equal(saved.presentation.displayName,'我的 Styx');
 assert.deepEqual(await main(['plugin',f.stateDir]),saved);
 await assert.rejects(exportDeploymentPlugin(f.stateDir,{authorize:true}),/new_plugin_profile_required/);
 const a=await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation',pluginUrl:reuse.selection.pluginUrl});
 assert.equal(a.accountActions.installation,'user_confirmed');assert.equal(a.accountActions.connection,'not_verified');assert.equal(a.accountActions.providerIdentity,'not_verified');
 await assert.rejects(recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'upload',pluginUrl:reuse.selection.pluginUrl}),/does_not_require_upload/);
 assert.equal(fs.readFileSync(path.join(f.stateDir,'deployment.json'),'utf8'),before);assert.equal(fs.existsSync(path.join(f.stateDir,'gateway')),false);
});
test('joining computer cannot create/export/account-install another plugin',async t=>{
 const f=await fixture(t,{joined:true});assert.equal(readDeploymentPlugin(f.stateDir).required,false);
 await assert.rejects(setDeploymentPluginProfile(f.stateDir,options),/plugin_managed_by_gateway_owner/);
 await assert.rejects(exportDeploymentPlugin(f.stateDir,{authorize:true}),/plugin_managed_by_gateway_owner/);
 assert.equal(fs.existsSync(path.join(f.stateDir,'onboarding-plugin.json')),false);assert.equal(fs.existsSync(path.join(f.stateDir,'gateway')),false);
});
test('real TLS MCP discovery exports only customized plugin files; account upload/install remain separate',{skip:process.platform==='win32',timeout:30000},async t=>{
 const f=await fixture(t);t.after(()=>stopDeploymentGateway(f.stateDir));
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify']});
 fs.mkdirSync(path.join(f.stateDir,'tunnel'),{mode:0o700});fs.writeFileSync(path.join(f.stateDir,'tunnel','connection.json'),JSON.stringify({schema:1,tunnelId:'tunnel_'+'a'.repeat(32),keyFile:'key-'+'a'.repeat(32),autoStart:false}),{mode:0o600});
 await setDeploymentPluginProfile(f.stateDir,options);
 const result=await exportDeploymentPlugin(f.stateDir,{authorize:true});
 assert.equal(result.accountConnection,'NOT RUN');assert.equal(result.verificationSource,'authenticated_local_gateway_discovery');
  const zip=path.join(f.root,'styx-native.zip');fs.writeFileSync(zip,result.archive);
  const ui=await createOnboardingServer({stateDir:f.stateDir});t.after(()=>ui.close());
  const uiToken=new URLSearchParams(new URL(ui.url).hash.slice(1)).get('session'),headers={Authorization:'Bearer '+uiToken};
  const uiSession=await(await fetch(ui.origin+'/api/session',{headers})).json();
  const download=await fetch(ui.origin+'/api/plugin/export',{method:'POST',headers:{...headers,Origin:ui.origin,'X-Styx-CSRF':uiSession.csrf,'Content-Type':'application/json'},body:JSON.stringify({authorize:true})});
  assert.equal(download.status,200);assert.equal(download.headers.get('content-type'),'application/zip');assert.match(download.headers.get('content-disposition'),/styx-native.zip/);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()),result.archive);
  const cliZip=path.join(f.root,'cli.zip'),cliResult=await main(['plugin-export',f.stateDir,cliZip,'--authorize']);
  assert.equal(cliResult.status,'exported_not_uploaded');assert.deepEqual(fs.readFileSync(cliZip),result.archive);
  assert.equal((fs.statSync(cliZip).mode&0o077),0);
 const inspected=JSON.parse(execFileSync('python3',['-c',`import json,zipfile,sys
with zipfile.ZipFile(sys.argv[1]) as z:
 print(json.dumps({'names':z.namelist(),'manifest':json.loads(z.read('styx-native/plugin.json')),'mcp':json.loads(z.read('styx-native/mcp.json'))}))`,zip],{encoding:'utf8'}));
 assert.equal(inspected.manifest.extensions['com.openai'].interface.displayName,'我的 Styx');assert.ok(inspected.names.every(n=>n.startsWith('styx-native/')));
 const combined=result.archive.toString('latin1');for(const secret of ['model.token','admin.token',fs.readFileSync(path.join(f.stateDir,'gateway/model.token'),'utf8').trim(),fs.readFileSync(path.join(f.stateDir,'gateway/admin.token'),'utf8').trim()])assert.ok(!combined.includes(secret));
 assert.equal(readDeploymentPlugin(f.stateDir).accountActions.installation,'not_observed');
 const url='https://chatgpt.com/plugins/styx-my-private';
 const direct=await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation',pluginUrl:url});
 assert.equal(direct.accountActions.installation,'user_confirmed');assert.equal(direct.accountActions.upload,'not_observed');
 await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'upload',pluginUrl:url});
  const saved=await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation',pluginUrl:url});
  assert.equal(saved.accountActions.installation,'user_confirmed');assert.equal(saved.accountActions.connection,'not_verified');
  await exportDeploymentPlugin(f.stateDir,{authorize:true});assert.equal(readDeploymentPlugin(f.stateDir).accountActions.installation,'user_confirmed');
 await setDeploymentPluginProfile(f.stateDir,{...options,presentation:{...options.presentation,displayName:'Changed'}});
 assert.equal(readDeploymentPlugin(f.stateDir).accountActions.installation,'not_observed');assert.equal(readDeploymentPlugin(f.stateDir).export.status,'not_exported');
 const previous=fs.readFileSync(path.join(f.stateDir,'onboarding-plugin.json'));await stopDeploymentGateway(f.stateDir);
 await assert.rejects(exportDeploymentPlugin(f.stateDir,{authorize:true}),/gateway_verification_failed/);assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'onboarding-plugin.json')),previous);
});
test('profile refuses credential URLs, arbitrary fields, unsafe image data and tampered context',async t=>{
 const f=await fixture(t);
 for(const url of ['https://evil.test/plugins/x','http://chatgpt.com/plugins/x','https://chatgpt.com/plugins','https://chatgpt.com/c/a-chat','https://chatgpt.com/auth/login','https://chatgpt.com/plugins/x?token=secret','https://user@chatgpt.com/plugins/x'])await assert.rejects(setDeploymentPluginProfile(f.stateDir,{...options,selection:{mode:'reuse',accountLabel:'',pluginUrl:url}}));
 await assert.rejects(setDeploymentPluginProfile(f.stateDir,{...options,presentation:{...options.presentation,icon:{mimeType:'image/svg+xml',dataBase64:'AAAA'}}}));
 await assert.rejects(setDeploymentPluginProfile(f.stateDir,{...options,token:'secret'}),/invalid_plugin_options/);
 await setDeploymentPluginProfile(f.stateDir,{...options,selection:{mode:'reuse',accountLabel:'',pluginUrl:'https://chatgpt.com/plugins/old'}});
 const config=JSON.parse(fs.readFileSync(path.join(f.stateDir,'deployment.json')));config.gateway.url='https://127.0.0.1:9999';fs.writeFileSync(path.join(f.stateDir,'deployment.json'),JSON.stringify(config),{mode:0o600});
 assert.equal(readDeploymentPlugin(f.stateDir).contextChanged,true);
 await assert.rejects(recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation',pluginUrl:'https://chatgpt.com/plugins/old'}),/plugin_context_changed/);
});
test('real local HTTP plugin routes require session, CSRF and explicit authorization',async t=>{
 const f=await fixture(t),instance=await createOnboardingServer({stateDir:f.stateDir});t.after(()=>instance.close());
 const token=new URLSearchParams(new URL(instance.url).hash.slice(1)).get('session');
 const headers={Authorization:'Bearer '+token};const session=await(await fetch(instance.origin+'/api/session',{headers})).json();
 assert.equal((await fetch(instance.origin+'/api/plugin')).status,401);
 const post=(route,data,csrf=session.csrf)=>fetch(instance.origin+route,{method:'POST',headers:{...headers,Origin:instance.origin,'X-Styx-CSRF':csrf,'Content-Type':'application/json'},body:JSON.stringify(data)});
 assert.equal((await post('/api/plugin/profile',options,'')).status,403);
 assert.equal((await post('/api/plugin/profile',{...options,authorize:false})).status,409);
 assert.equal((await post('/api/plugin/profile',options)).status,200);
 const observed=(await(await fetch(instance.origin+'/api/plugin',{headers})).json()).plugin;assert.deepEqual(observed,await main(['plugin',f.stateDir]));
 assert.equal((await post('/api/plugin/export',{authorize:true,token:'invalid'})).status,409);
 assert.equal((await post('/api/plugin/record',{authorize:true,stage:'connection',pluginUrl:'https://chatgpt.com/plugins/x'})).status,409);
});

test('official create and reuse work without an archive or a plugin management URL',async t=>{
 for(const mode of ['create','reuse']){
  const f=await fixture(t),before=fs.readFileSync(path.join(f.stateDir,'deployment.json'));
  await setDeploymentPluginProfile(f.stateDir,{...options,selection:{mode,accountLabel:'Target workspace'}});
  const state=await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation'});
  assert.equal(state.selection.pluginUrl,'');assert.equal(state.export.status,'not_exported');
  assert.equal(state.accountActions.upload,'not_observed');assert.equal(state.accountActions.installation,'user_confirmed');
  assert.equal(state.accountActions.connection,'not_verified');assert.equal(state.accountActions.providerIdentity,'not_verified');
  assert.equal(state.externalDiscovery,'not_performed');assert.equal(state.requiresAccountAction,true);
  const receipt=JSON.parse(fs.readFileSync(path.join(f.stateDir,'onboarding-plugin.json'))).accountActions.installation;
  assert.equal(receipt.method,'official_page');assert.equal(receipt.source,'user_attested');
  assert.equal(fs.existsSync(path.join(f.stateDir,'gateway')),false);
  assert.deepEqual(fs.readFileSync(path.join(f.stateDir,'deployment.json')),before);
  // An unchanged save and restart/read preserve the attestation; another account
  // or profile must get its own confirmation.
  await setDeploymentPluginProfile(f.stateDir,{...options,selection:{mode,accountLabel:'Target workspace'}});
  assert.equal(readDeploymentPlugin(f.stateDir).accountActions.installation,'user_confirmed');
  await setDeploymentPluginProfile(f.stateDir,{...options,selection:{mode,accountLabel:'Another workspace'}});
  assert.equal(readDeploymentPlugin(f.stateDir).accountActions.installation,'not_observed');
 }
});
test('direct attestation rejects forged evidence, unauthorized changes and wrong management URLs',async t=>{
 const f=await fixture(t);await setDeploymentPluginProfile(f.stateDir,options);
 for(const action of [
  {authorize:false,stage:'installation'},
  {authorize:true,stage:'connection'},
  {authorize:true,stage:'installation',source:'provider_verified'},
  {authorize:true,stage:'installation',method:'official_page'},
  {authorize:true,stage:'installation',pluginUrl:null},
  {authorize:true,stage:'installation',pluginUrl:'https://chatgpt.com/plugins/x?key=secret'},
  {authorize:true,stage:'upload',pluginUrl:'https://chatgpt.com/plugins/x'}
 ])await assert.rejects(recordDeploymentPluginAction(f.stateDir,action));
 assert.equal(readDeploymentPlugin(f.stateDir).accountActions.installation,'not_observed');
 const url='https://chatgpt.com/plugins/original';
 await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation',pluginUrl:url});
 await assert.rejects(recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation',pluginUrl:'https://chatgpt.com/plugins/other'}),/plugin_url_mismatch/);
 assert.equal((await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation'})).selection.pluginUrl,url);
 const joined=await fixture(t,{joined:true});
 await assert.rejects(recordDeploymentPluginAction(joined.stateDir,{authorize:true,stage:'installation'}),/plugin_managed_by_gateway_owner/);
});
test('legacy schema 1 URL receipts survive unchanged and remain user assertions',async t=>{
 const f=await fixture(t),url='https://chatgpt.com/plugins/legacy';
 await setDeploymentPluginProfile(f.stateDir,{...options,selection:{...options.selection,pluginUrl:url}});
 await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation',pluginUrl:url});
 const file=path.join(f.stateDir,'onboarding-plugin.json'),legacy=JSON.parse(fs.readFileSync(file));
 delete legacy.accountActions.installation.method;
 legacy.accountActions.upload={...legacy.accountActions.installation};
 legacy.export={sha256:'a'.repeat(64),binding:legacy.binding,profileHash:legacy.accountActions.installation.profileHash,filename:'styx-native.zip',verificationSource:'authenticated_local_gateway_discovery',at:Date.now()};
 fs.writeFileSync(file,JSON.stringify(legacy),{mode:0o600});
 const state=readDeploymentPlugin(f.stateDir);
 assert.equal(state.export.status,'exported');assert.equal(state.accountActions.upload,'user_confirmed');assert.equal(state.accountActions.installation,'user_confirmed');assert.equal(state.accountActions.providerIdentity,'not_verified');
 await setDeploymentPluginProfile(f.stateDir,{...options,selection:{...options.selection,pluginUrl:url}});
 assert.deepEqual(JSON.parse(fs.readFileSync(file)),legacy);
 // A connection identity change invalidates old archive and account receipts.
 fs.mkdirSync(path.join(f.stateDir,'tunnel'),{mode:0o700});
 fs.writeFileSync(path.join(f.stateDir,'tunnel','connection.json'),JSON.stringify({tunnelId:'tunnel_'+'b'.repeat(32)}),{mode:0o600});
 assert.equal(readDeploymentPlugin(f.stateDir).contextChanged,true);
 assert.equal(readDeploymentPlugin(f.stateDir).accountActions.installation,'not_observed');
 assert.equal(readDeploymentPlugin(f.stateDir).export.status,'stale');
 await assert.rejects(recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation'}),/plugin_context_changed/);
});
test('official no-URL confirmation crosses the real App and CLI routes with authorization intact',async t=>{
 const f=await fixture(t),instance=await createOnboardingServer({stateDir:f.stateDir});t.after(()=>instance.close());
 const token=new URLSearchParams(new URL(instance.url).hash.slice(1)).get('session'),headers={Authorization:'Bearer '+token};
 const session=await(await fetch(instance.origin+'/api/session',{headers})).json();
 const post=(route,body)=>fetch(instance.origin+route,{method:'POST',headers:{...headers,Origin:instance.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json'},body:JSON.stringify(body)});
 assert.equal((await post('/api/plugin/profile',{...options,selection:{mode:'reuse',accountLabel:'Selected account'}})).status,200);
 const response=await post('/api/plugin/record',{authorize:true,stage:'installation'});
 assert.equal(response.status,200);assert.equal((await response.json()).plugin.accountActions.installation,'user_confirmed');
 const file=path.join(f.root,'action.json');fs.writeFileSync(file,JSON.stringify({stage:'installation'}),{mode:0o600});
 const cli=await main(['plugin-record',f.stateDir,file,'--authorize']);
 assert.equal(cli.accountActions.installation,'user_confirmed');assert.equal(cli.accountActions.connection,'not_verified');
});
test('optional first archive export does not invalidate direct official-page confirmation',{skip:process.platform==='win32',timeout:30000},async t=>{
 const f=await fixture(t);t.after(()=>stopDeploymentGateway(f.stateDir));
 await advanceDeployment(f.stateDir,{authorize:['gateway.prepare','gateway.start','gateway.verify']});
 fs.mkdirSync(path.join(f.stateDir,'tunnel'),{mode:0o700});fs.writeFileSync(path.join(f.stateDir,'tunnel','connection.json'),JSON.stringify({schema:1,tunnelId:'tunnel_'+'c'.repeat(32),keyFile:'key-'+'c'.repeat(32),autoStart:false}),{mode:0o600});
 await setDeploymentPluginProfile(f.stateDir,options);
 await recordDeploymentPluginAction(f.stateDir,{authorize:true,stage:'installation'});
 await exportDeploymentPlugin(f.stateDir,{authorize:true});
 const state=readDeploymentPlugin(f.stateDir);assert.equal(state.export.status,'exported');assert.equal(state.accountActions.upload,'not_observed');assert.equal(state.accountActions.installation,'user_confirmed');assert.equal(state.accountActions.connection,'not_verified');
});
