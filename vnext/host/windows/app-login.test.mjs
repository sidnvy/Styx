import test from 'node:test';
import assert from 'node:assert/strict';
import {readWindowsAppLogin,planWindowsAppLogin,controlWindowsAppLogin,reconcileWindowsAppLogin} from './app-login.mjs';
const stateDir='C:\\Users\\Test\\Styx\\deployment',shortcutPath='C:\\Users\\Test\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Styx.lnk';
const ownerSid='S-1-5-21-111-222-333-1001';
const operations=value=>({platform:'win32',run:(file,args)=>{assert.equal(file,'powershell.exe');const ps=Buffer.from(args.at(-1),'base64').toString('utf16le');assert(!ps.includes('StartupApproved'));return JSON.stringify({ownerSid,shortcutPath,...value});}});
test('unregistered CLI observation is honest and does not create an entry',async()=>{
 const read=await readWindowsAppLogin({stateDir},operations({present:false}));assert.equal(read.status,'not_registered');assert.equal(read.systemApproval,'unknown');assert.equal(read.registration.owned,false);
 await assert.rejects(planWindowsAppLogin({stateDir,enabled:true},operations({present:false})),/app_login_native_registration_required/);
});
test('an existing unregistered shortcut is foreign, never adopted or removed',async()=>{
 const op=operations({present:true,sha256:'a'.repeat(64),target:'C:\\Other.exe',arguments:'',workingDirectory:'C:\\'});
 assert.equal((await readWindowsAppLogin({stateDir},op)).status,'needs_attention');
 await assert.rejects(planWindowsAppLogin({stateDir,enabled:false},op),/app_login_shortcut_foreign/);
});
test('external/replayed plan cannot mutate a startup entry',async()=>{
 const op=operations({present:false});const plan=await planWindowsAppLogin({stateDir,enabled:false},op);
 await assert.rejects(controlWindowsAppLogin(structuredClone(plan),{authorize:true,...op}),/app_login_current_plan_required/);
 const result=await controlWindowsAppLogin(plan,{authorize:true,...op});assert.equal(result.status,'not_registered');assert.deepEqual(result.registration,{present:false,owned:false,targetMatches:false});
 await assert.rejects(controlWindowsAppLogin(plan,{authorize:true,...op}),/app_login_current_plan_required/);
});
test('registration cannot redirect user state or describe an arbitrary executable tree',async()=>{
 const bad={schema:1,kind:'windows-startup-shortcut',ownerSid,shortcutPath,installRoot:'C:\\Bad',resourceRoot:'C:\\Bad\\other',packageSha256:'a'.repeat(64),appSha256:'b'.repeat(64),stateDir};
 await assert.rejects(readWindowsAppLogin({stateDir,registration:bad},operations({present:false})),/app_login_installation_invalid/);
 await assert.rejects(readWindowsAppLogin({stateDir,registration:{...bad,stateDir:'C:\\Other'}},operations({present:false})),/app_login_registration_invalid/);
});

test('Azure AD user SID is accepted as a live identity without assuming a local account',async()=>{
 const read=await readWindowsAppLogin({stateDir},operations({present:false,ownerSid:'S-1-12-1-111-222-333-444'}));assert.equal(read.status,'not_registered');
});

test('native App and Inno directory separators identify the same owned startup target',{skip:process.platform!=='win32'},async t=>{
 const fs=await import('node:fs'),path=await import('node:path'),os=await import('node:os'),{createHash}=await import('node:crypto');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'styx-login-path-'));t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const hash=b=>createHash('sha256').update(b).digest('hex'),app=Buffer.from('data-only native path fixture'),runtime=Buffer.from('{}');
 const manifest=JSON.stringify({schema:1,compiled:true,files:[{path:'StyxPreview.exe',sha256:hash(app)},{path:'windows-runtime.json',sha256:hash(runtime)}]}),pin=hash(manifest),root=path.join(temp,'versions',pin);
 fs.mkdirSync(root,{recursive:true});fs.writeFileSync(path.join(root,'StyxPreview.exe'),app);fs.writeFileSync(path.join(root,'windows-runtime.json'),runtime);fs.writeFileSync(path.join(root,'windows-package.json'),manifest);
 const sd=path.join(temp,'state','deployment'),authority={source:'current_windows_native_app',nativeAppPid:123,nativeAppGeneration:'test-seam'};
 for(const trailing of [false,true]){
  const reg={schema:1,kind:'windows-startup-shortcut',ownerSid,shortcutPath,installRoot:temp,resourceRoot:root+'\\',packageSha256:pin,appSha256:hash(app),stateDir:sd};
  const op={...operations({present:true,sha256:'a'.repeat(64),target:path.join(root,'StyxPreview.exe'),arguments:'--startup --state-dir "'+path.dirname(sd)+'"',workingDirectory:root+(trailing?'\\':'')}),observeApp:()=>authority};
  const view=await readWindowsAppLogin({stateDir:sd,registration:reg,trustedApp:{resourceRoot:root+'\\',authority}},op);
  assert.equal(view.registration.owned,true);assert.equal(view.registration.targetMatches,true);
 }
});

test('native startup reconciliation verifies fresh bindings and avoids only an unchanged registration rescan',{skip:process.platform!=='win32'},async t=>{
 const fs=await import('node:fs'),path=await import('node:path'),os=await import('node:os'),{createHash}=await import('node:crypto');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'styx-login-reconcile-'));t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const hash=b=>createHash('sha256').update(b).digest('hex'),sd=path.join(temp,'state','deployment');
 const authority={source:'current_windows_native_app',nativeAppPid:123,nativeAppGeneration:'native-authority-test-seam'};
 function pkg(label){
  const contents={'StyxPreview.exe':'app '+label,'windows-runtime.json':'{}','runtime/node.exe':'node fixture','install-windows-preview.mjs':'verifier fixture'};
  const files=Object.entries(contents).map(([name,value])=>({path:name,sha256:hash(value)}));
  const manifest=JSON.stringify({schema:1,compiled:true,files}),pin=hash(manifest),root=path.join(temp,'versions',pin);
  for(const [name,value]of Object.entries(contents)){const file=path.join(root,...name.split('/'));fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,value);}
  fs.writeFileSync(path.join(root,'windows-package.json'),manifest);
  return {root,registration:{schema:1,kind:'windows-startup-shortcut',ownerSid,shortcutPath,resourceRoot:root,installRoot:temp,packageSha256:pin,appSha256:hash(contents['StyxPreview.exe']),stateDir:sd}};
 }
 function fixture(current,registration=current.registration,change={}){
  const observed={present:true,sha256:'a'.repeat(64),target:path.join(current.root,'StyxPreview.exe'),arguments:'--startup --state-dir "'+path.dirname(sd)+'"',workingDirectory:current.root,...change};
  let full=0,live=0,reads=0;
  const op={platform:'win32',observeApp:()=>{live++;return authority},run:(file,args)=>{
   if(file==='powershell.exe'){reads++;return operations(observed).run(file,args);}
   assert.equal(file,path.join(current.root,'runtime/node.exe'));assert.deepEqual(args,[path.join(current.root,'install-windows-preview.mjs'),'verify']);full++;return '';
  }};
  return {input:{stateDir:sd,registration,trustedApp:{resourceRoot:current.root,authority}},op,counts:()=>({full,live,reads})};
 }
 await t.test('identical fields in any property order skip rescan, never propose a state write or claim readiness',async()=>{
  const p=pkg('unchanged'),f=fixture(p,Object.fromEntries(Object.entries(p.registration).reverse()));
  const result=await reconcileWindowsAppLogin(f.input,f.op);
  assert.deepEqual(f.counts(),{full:0,live:1,reads:1});assert.equal(result.status,'registered_unverified');assert.equal(result.systemApproval,'unknown');assert.equal(result.reconciledRegistration,undefined);assert.equal(result.registration.targetMatches,true);
 });
 await t.test('a new package still runs the full verifier and returns the new registration',async()=>{
  const old=pkg('old'),next=pkg('new'),f=fixture(next,old.registration),result=await reconcileWindowsAppLogin(f.input,f.op);
  assert.equal(f.counts().full,1);assert.equal(f.counts().live,2);assert.deepEqual(result.reconciledRegistration,next.registration);
 });
 await t.test('a changed shortcut cannot enter the fast path or authorize a rebind',async()=>{
  const p=pkg('link'),f=fixture(p,p.registration,{arguments:'--startup --state-dir "C:\\Other"'}),result=await reconcileWindowsAppLogin(f.input,f.op);
  assert.equal(f.counts().full,1);assert.equal(result.status,'needs_attention');assert.equal(result.registration.owned,false);assert.equal(result.reconciledRegistration,undefined);
 });
 await t.test('a changed live owner is rejected before any registration update',async()=>{
  const p=pkg('owner'),f=fixture(p,p.registration,{ownerSid:'S-1-12-1-1-2-3-4'});
  await assert.rejects(reconcileWindowsAppLogin(f.input,f.op),/app_login_owner_changed/);
 });
 await t.test('a changed executable is rejected even when the registration fields match',async()=>{
  const p=pkg('exe'),f=fixture(p);fs.appendFileSync(path.join(p.root,'StyxPreview.exe'),'tamper');
  await assert.rejects(reconcileWindowsAppLogin(f.input,f.op),/app_login_package_changed/);
 });
 await t.test('a changed manifest is rejected even when the registration fields match',async()=>{
  const p=pkg('manifest'),f=fixture(p);fs.appendFileSync(path.join(p.root,'windows-package.json'),' ');
  await assert.rejects(reconcileWindowsAppLogin(f.input,f.op),/app_login_installed_package_required/);
 });
});
