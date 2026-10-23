import test from 'node:test';
import assert from 'node:assert/strict';
import {assertMacPreviewContinuity} from '../../host/macos-preview-trust.mjs';
import {selectMacPreviewForCapabilities} from '../capabilities.mjs';

const adhoc={path:'/Applications/Styx.app',cdhash:'a'.repeat(40)};
const local={...adhoc,certificateSha1:'b'.repeat(40),certificateSha256:'c'.repeat(64)};

test('registered local certificate permits rebuilt bytes and refuses signer removal or replacement',()=>{
 assert.deepEqual(assertMacPreviewContinuity(local,{...local,cdhash:'d'.repeat(40)}),{migrationRequired:false});
 for(const current of [adhoc,{...local,certificateSha1:'d'.repeat(40)},{...local,certificateSha256:'d'.repeat(64)},undefined])
  assert.throws(()=>assertMacPreviewContinuity(local,current),/registered_certificate_changed|registered_path_changed/);
 assert.throws(()=>assertMacPreviewContinuity(local,{...local,path:'/elsewhere/Styx.app'}),/registered_path_changed/);
});

test('partial or malformed certificate registrations cannot downgrade to ad-hoc',()=>{
 for(const invalid of [{certificateSha1:local.certificateSha1},{certificateSha256:local.certificateSha256},{certificateSha1:undefined},{certificateSha1:local.certificateSha1,certificateSha256:undefined},{certificateSha1:'B'.repeat(40),certificateSha256:local.certificateSha256}]){
  assert.throws(()=>assertMacPreviewContinuity({...adhoc,...invalid},adhoc),/invalid_local_signing_descriptor/);
  assert.throws(()=>assertMacPreviewContinuity(adhoc,{...adhoc,...invalid}),/invalid_local_signing_descriptor/);
 }
});

test('first ad-hoc to certificate migration is explicit while ad-hoc compatibility remains',()=>{
 assert.deepEqual(assertMacPreviewContinuity(adhoc,local),{migrationRequired:true});
 assert.deepEqual(assertMacPreviewContinuity(adhoc,{...adhoc,cdhash:'d'.repeat(40)}),{migrationRequired:false});
 assert.deepEqual(assertMacPreviewContinuity(undefined,local),{migrationRequired:false});
 assert.throws(()=>assertMacPreviewContinuity(adhoc,{...local,path:'/other/Styx.app'}),/registered_path_changed/);
});

test('capability override selection enforces persisted signer and blocks implicit first migration',()=>{
 const rebuilt={...local,cdhash:'d'.repeat(40)};
 assert.equal(selectMacPreviewForCapabilities(local,rebuilt),rebuilt);
 assert.equal(selectMacPreviewForCapabilities(local),local);
 assert.equal(selectMacPreviewForCapabilities(undefined,local),local);
 assert.deepEqual(selectMacPreviewForCapabilities(adhoc,{...adhoc}),adhoc);
 assert.throws(()=>selectMacPreviewForCapabilities(adhoc,local),/certificate_migration_required/);
 assert.throws(()=>selectMacPreviewForCapabilities(local,adhoc),/registered_certificate_changed/);
 assert.throws(()=>selectMacPreviewForCapabilities(local,{...local,certificateSha256:'d'.repeat(64)}),/registered_certificate_changed/);
});
