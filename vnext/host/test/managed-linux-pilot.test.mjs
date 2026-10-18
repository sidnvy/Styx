import test from 'node:test';
import assert from 'node:assert/strict';
import {pilotOptions,graphicalEnvironment,runManagedLinuxPilot,confirmedInactiveDisabled} from '../managed-linux-pilot.mjs';
const options={directory:'/tmp/styx-owned-pilot',unitName:'styx-rc20261019-owned.service',
  nodeBinary:'/trusted/node',codexBinary:'/trusted/codex',cuaBinary:'/trusted/cua'};
test('pilot import and refused opt-in cannot touch a service',async()=>{
  await assert.rejects(runManagedLinuxPilot(options,{optIn:'0'}),/explicit_opt_in/);
});
test('pilot cannot target ordinary services or ambiguous output paths',()=>{
  for(const unitName of ['ssh.service','styx-production.service','styx-rc20261019-owned.service\nother'])
    assert.throws(()=>pilotOptions({...options,unitName}),/explicit_owned/);
  assert.throws(()=>pilotOptions({...options,directory:'relative'}),/absolute_safe/);
  assert.throws(()=>pilotOptions({...options,nodeBinary:'node'}),/absolute_pinned/);
});
test('graphical environment selection excludes every unrelated session value',()=>{
  assert.deepEqual(graphicalEnvironment('WAYLAND_DISPLAY=wayland-1\nSECRET=value\nDISPLAY=:0\nDBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1/bus\nPATH=/private\n'),
    {WAYLAND_DISPLAY:'wayland-1',DISPLAY:':0',DBUS_SESSION_BUS_ADDRESS:'unix:path=/run/user/1/bus'});
});

test('offline attestation rejects unknown or transient unit and enablement states',()=>{
  const stopped={status:'reported',load:'loaded',active:'inactive',pid:0,enabled:'disabled'};
  assert.equal(confirmedInactiveDisabled(stopped),true);
  assert.equal(confirmedInactiveDisabled({...stopped,active:'failed'}),true);
  for(const patch of [{status:'unavailable'},{load:'not-found'},{active:'deactivating'},
    {active:'activating'},{active:'unknown'},{enabled:'enabled-runtime'},{enabled:null},{pid:1}])
    assert.equal(confirmedInactiveDisabled({...stopped,...patch}),false);
});
