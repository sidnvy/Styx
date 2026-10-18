import test from 'node:test';
import assert from 'node:assert/strict';
import {appInfoPlist,macSigningPlan,buildMacApp,MAC_BUNDLE_ID} from '../build-macos-app.mjs';

test('stable macOS bundle identity and version reject injected plist values',()=>{
  const plist=appInfoPlist('0.1.0');
  assert.ok(plist.includes(`<string>${MAC_BUNDLE_ID}</string>`));
  assert.ok(plist.includes('<key>CFBundleExecutable</key><string>Styx</string>'));
  assert.ok(plist.includes('<key>LSUIElement</key><true/>'));
  for(const bad of ['0.1.0<dict>','0.1','v0.1.0','0.1.0-rc.1',null])
    assert.throws(()=>appInfoPlist(bad),/invalid_app_version/);
});
test('publisher plan signs nested Cua then host and verifies exact team identity',()=>{
  const plan=macSigningPlan({app:'/build/Styx.app',identity:'Developer ID Application: Example (A123456789)',teamID:'A123456789',notaryProfile:'styx-release'});
  assert.equal(plan[0][1].at(-1),'/build/Styx.app/Contents/MacOS/cua-driver');
  assert.equal(plan[1][1].at(-1),'/build/Styx.app');
  assert.ok(plan[3][1].some(arg=>arg.includes('identifier "app.styx.host"')));
  assert.equal(plan.filter(([,args])=>args.includes('--deep')&&args.includes('--sign')).length,0);
  assert.ok(plan.some(([,args])=>args[0]==='notarytool'&&args.includes('--wait')));
  assert.ok(plan.some(([,args])=>args[0]==='stapler'&&args[1]==='validate'));
  assert.equal(plan.at(-1)[0],'/usr/sbin/spctl');
});
test('signing fails closed for ad-hoc identity, wrong team and unsafe profile',()=>{
  const valid={app:'/build/Styx.app',identity:'Developer ID Application: Example (A123456789)',teamID:'A123456789'};
  assert.throws(()=>macSigningPlan({...valid,identity:'-'}),/developer_id/);
  assert.throws(()=>macSigningPlan({...valid,teamID:'B123456789'}),/signing_team/);
  assert.throws(()=>macSigningPlan({...valid,app:'/build/Other.app'}),/invalid_styx/);
  assert.throws(()=>macSigningPlan({...valid,notaryProfile:'release\n--password'}),/invalid_notary/);
  assert.equal(macSigningPlan(valid).length,4);
});
test('Linux cannot accidentally produce a macOS signing receipt',{skip:process.platform==='darwin'},()=>{
  assert.throws(()=>buildMacApp({}),/native_macos_build_required/);
});
