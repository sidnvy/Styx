import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {readLoginState,writeLoginState} from '../login-state.mjs';
const principal='a'.repeat(64),other='b'.repeat(64);
test('login snapshots are private, principal-scoped and reject path input, foreign modes and nonweb origins',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-login-test-'));fs.chmodSync(root,0o700);t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const state={cookies:[],origins:[{origin:'https://example.test',localStorage:[{name:'login',value:'test-fixture'}]}]};
  assert.equal(readLoginState(root,principal),null);writeLoginState(root,principal,state);
  assert.deepEqual(readLoginState(root,principal),state);assert.equal(readLoginState(root,other),null);
  assert.throws(()=>writeLoginState(root,'../../outside',state),/browser_profile_owner_required/);
  assert.throws(()=>writeLoginState(root,principal,{cookies:[],origins:[{origin:'file:///private'}]}),/browser_login_state_invalid/);
  assert.throws(()=>writeLoginState(root,principal,{cookies:[],origins:[{origin:'https://example.test',localStorage:[{name:'large',value:'x'.repeat(16*1024*1024)}]}]}),/browser_login_state_limit/);
  const file=path.join(root,'login-state',principal+'.json');
  if(process.platform!=='win32'){fs.chmodSync(file,0o644);assert.throws(()=>readLoginState(root,principal),/private_file_permissions/);fs.chmodSync(file,0o600);}
  fs.unlinkSync(file);fs.symlinkSync(path.join(root,'foreign'),file);
  assert.throws(()=>readLoginState(root,principal),/private_file_not_regular/);
});
