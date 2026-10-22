import test from 'node:test';
import assert from 'node:assert/strict';
import {readWindowsAppLogin,planWindowsAppLogin,controlWindowsAppLogin} from './app-login.mjs';
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
