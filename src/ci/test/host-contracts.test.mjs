import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {hostContractSelection,runHostContracts} from '../host-contracts.mjs';

test('each existing Host contract is scheduled on every applicable OS without losing shared Windows coverage',()=>{
  const plans=['linux','darwin','win32'].map(platform=>hostContractSelection(platform));
  const all=new Set(plans[0].inventory.map(entry=>entry.file));
  assert.equal(all.size,plans[0].inventory.length);
  assert.deepEqual(new Set(plans.flatMap(plan=>plan.selected)),all);
  for(const plan of plans){
    assert.equal(plan.selected.length+plan.notApplicable.length,all.size);
    for(const file of ['private-file','private-storage','private-storage-batch','installer',
      'health-update','service-update','setup-native','native-runtime-release','cross-platform-acceptance']){
      assert(plan.selected.includes(`host/test/${file}.test.mjs`),`${plan.platform}: ${file}`);
    }
    for(const entry of plan.inventory)assert.equal(plan.selected.includes(entry.file),entry.platforms.includes(plan.platform));
  }
  // Names describe the implementation being tested, not necessarily fixture OS needs.
  for(const file of ['macos-app','macos-local-signing','macos-native-launcher',
    'macos-preview','linux-service','linux-desktop','linux-cli-acceptance']){
    assert(!plans[2].selected.includes(`host/test/${file}.test.mjs`),`Windows cannot run ${file} fixture`);
  }
  const signingSession='host/test/macos-signing-session.test.mjs';
  assert(plans[0].selected.includes(signingSession),'POSIX signing-session lock coverage belongs on Linux');
  assert(plans[1].selected.includes(signingSession));
  assert(!plans[2].selected.includes(signingSession),'Python fcntl fixture is not available on Windows');
  assert(plans[2].selected.includes('host/windows/private-storage-native.test.mjs'));
  assert(plans[2].selected.includes('host/windows/platform-update/product.test.mjs'));
  assert.throws(()=>hostContractSelection('unsupported'),/unsupported_host_contract_platform/);
});

test('new unclassified contracts default to all platforms, not silently excluded',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-selection-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  for(const {file} of hostContractSelection('linux').inventory){fs.mkdirSync(path.dirname(path.join(root,file)),{recursive:true});fs.writeFileSync(path.join(root,file),'');}
  fs.writeFileSync(path.join(root,'host/test/new-security.test.mjs'),'');
  for(const platform of ['linux','darwin','win32'])assert(hostContractSelection(platform,{sourceRoot:root}).selected.includes('host/test/new-security.test.mjs'));
  fs.rmSync(path.join(root,'host/test/linux-service.test.mjs'));
  assert.throws(()=>hostContractSelection('linux',{sourceRoot:root}),/stale_host_contract_classification/);
});

test('runner preserves selected files and failed TAP evidence, without treating zero-exit empty output as passing',t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-host-ci-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  let args;
  const receipt=runHostContracts(root,{run:(_node,argv,{stdio})=>{args=argv;fs.writeSync(stdio[1],'TAP version 13\n');return {status:0};}});
  assert.equal(receipt.status,'FAIL');assert(args.includes('--test-concurrency=4'));
  assert.deepEqual(args.slice(3),hostContractSelection(process.platform).selected);
  assert.equal(JSON.parse(fs.readFileSync(path.join(root,'receipt.json'))).status,'FAIL');
  assert.equal(fs.readFileSync(path.join(root,'contracts.tap'),'utf8'),'TAP version 13\n');
});
