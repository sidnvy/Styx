import test from 'node:test';
import assert from 'node:assert/strict';
import {runManagedLinuxUpdatePilot,updatePilotOptions} from '../managed-update-pilot.mjs';
const options={directory:'/tmp/styx-update-owned',unitName:'styx-rc20261019-owned-update1.service',
  alternateNodeBinary:'/trusted/alternate-node',nodeBinary:'/trusted/node',codexBinary:'/trusted/codex',cuaBinary:'/trusted/cua'};
test('native update pilot refuses service mutation without its distinct opt-in',async()=>{
  await assert.rejects(runManagedLinuxUpdatePilot(options,{optIn:'0'}),/explicit_opt_in/);
});
test('native update pilot requires a fresh suffixed owned unit, excluding the old lifecycle unit',()=>{
  assert.equal(updatePilotOptions(options).unitName,options.unitName);
  assert.throws(()=>updatePilotOptions({...options,unitName:'styx-rc20261019-owned.service'}),/suffixed_update/);
  assert.throws(()=>updatePilotOptions({...options,unitName:'styx-production.service'}),/explicit_owned/);
});
