import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {previewSigningIdentity} from '../setup-launcher.mjs';
import {verifyMacPreviewApp} from '../../macos-preview-trust.mjs';
import {createOnboardingServer} from '../../../onboarding/server.mjs';

// Opt-in native evidence: a previously built local-certificate App, real
// codesign verification and HTTP transport. Core lifecycle calls are injected;
// no deployment services, desktop actions, TCC or accounts are exercised.
test('real local-signed App verifies and native server enforces registered signer/migration boundary', {skip:process.platform!=='darwin'||!process.env.STYX_LOCAL_SIGNING_APP,timeout:60000},async t=>{
 const app=fs.realpathSync(process.env.STYX_LOCAL_SIGNING_APP),current=previewSigningIdentity({app});
 assert.match(current.certificateSha256,/^[a-f0-9]{64}$/);
 assert.equal(verifyMacPreviewApp(current).trust,'local_certificate_preview_not_notarized');
 assert.throws(()=>verifyMacPreviewApp({...current,certificateSha256:'f'.repeat(64)}),/pin_mismatch/);
 for(const mode of ['migration','same-certificate','changed-certificate']){
  const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-real-signing-boundary-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const stateDir=path.join(root,'deployment');fs.mkdirSync(stateDir,{mode:0o700});let starts=0,mutations=0;
  const registered=mode==='migration'?{path:app,cdhash:'a'.repeat(40)}:{...current,cdhash:'a'.repeat(40),...(mode==='changed-certificate'?{certificateSha256:'f'.repeat(64)}:{})};
  fs.writeFileSync(path.join(stateDir,'deployment.json'),JSON.stringify({host:{macPreviewApp:registered}}),{mode:0o600});
  const core={
   readDeployment:()=>({mode:'create-local',roles:{host:'local',gateway:'local',computer:'disabled',browser:'disabled'},steps:['host.prepare','host.pair','host.doctor'].map(id=>({id,status:'succeeded'}))}),
   planDeployment:()=>({steps:[]}),
   readDeploymentForeground:()=>({status:'not_running',observation:'current_process'}),
   startDeploymentForeground:async()=>{starts++;return{status:'started',observation:'current_process'}},
   stopDeploymentForeground:async()=>{},stopDeploymentGateway:async()=>{},
   setDeploymentPluginProfile:async()=>{mutations++;return{}},
  };
  const create=()=>createOnboardingServer({stateDir,core,trustedMacPreviewApp:current,backgroundRead:async()=>({status:'not_running'})});
  if(mode==='changed-certificate'){await assert.rejects(create(),/registered_certificate_changed/);assert.equal(starts,0);continue}
  const instance=await create();
  try{
   const token=new URLSearchParams(new URL(instance.url).hash.slice(1)).get('session'),headers={Authorization:'Bearer '+token};
   const session=await(await fetch(instance.origin+'/api/session',{headers})).json();
   const response=await fetch(instance.origin+'/api/plugin/profile',{method:'POST',headers:{...headers,Origin:instance.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json'},body:JSON.stringify({authorize:true,presentation:{},selection:{}})});
   if(mode==='migration'){
    assert.equal(starts,0);assert.equal(mutations,0);assert.equal(response.status,409);assert.equal((await response.json()).error,'native_signing_registration_required');
   }else{assert.equal(starts,1);assert.equal(mutations,1);assert.equal(response.status,200)}
  }finally{await instance.close()}
 }
});
