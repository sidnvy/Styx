import test from 'node:test';
import assert from 'node:assert/strict';
import {managedSoakOptions,runManagedServiceSoak} from '../managed-service-soak.mjs';
const options={directory:'/tmp/styx-owned-soak',unitName:'styx-rc20261019-owned-soaktest.service',
  nodeBinary:'/trusted/node',codexBinary:'/trusted/codex',cuaBinary:'/trusted/cua'};
test('managed soak defaults to bounded 24h/60s and rejects unlimited or invalid durations',()=>{
  assert.equal(managedSoakOptions(options).durationSeconds,86400);
  assert.equal(managedSoakOptions(options).intervalSeconds,60);
  for(const durationSeconds of [0,-1,172801,Infinity,1.5])
    assert.throws(()=>managedSoakOptions({...options,durationSeconds}),/bounded_managed_soak_duration/);
  assert.throws(()=>managedSoakOptions({...options,intervalSeconds:0}),/bounded_managed_soak_interval/);
  assert.throws(()=>managedSoakOptions({...options,unitName:'styx-rc20261019-owned-update1.service'}),/managed_soak_unit/);
});
test('managed soak refuses mutation without its distinct opt-in',async()=>{
  await assert.rejects(runManagedServiceSoak(options,{optIn:'0'}),/explicit_opt_in/);
});
test('already-aborted managed soak cannot inspect binaries or mutate services',async()=>{
  const controller=new AbortController();controller.abort();
  await assert.rejects(runManagedServiceSoak(options,{optIn:'1',signal:controller.signal}),/managed_pilot_aborted/);
});
