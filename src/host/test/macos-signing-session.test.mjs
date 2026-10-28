import test from 'node:test';
import assert from 'node:assert/strict';
import {executeMacPreviewSigningPlan} from '../build-macos-preview.mjs';
import {macLocalSigningPlan} from '../build-macos-app.mjs';
test('real signing plan uses tuple command argv and stops immediately on failure',()=>{
 const localSigning={identitySha1:'c'.repeat(40),certificateSha256:'d'.repeat(64),keychain:'/private/build/keychain'};
 const app='/private/build/Styx.app',plan=macLocalSigningPlan({app,localSigning,files:[app+'/Contents/MacOS/Styx']}),seen=[];
 executeMacPreviewSigningPlan(plan,{run:(command,args)=>seen.push([command,args])});assert.deepEqual(seen,plan);
 let count=0;assert.throws(()=>executeMacPreviewSigningPlan(plan,{run:()=>{count++;throw Error('signature_denied')}}),/signature_denied/);assert.equal(count,1);
 assert.throws(()=>executeMacPreviewSigningPlan(['/usr/bin/codesign',['--verify']],{run:()=>assert.fail('malformed plan executed')}),/invalid_preview_signing_plan/);
});
