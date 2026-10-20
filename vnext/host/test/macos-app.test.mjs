import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {deflateSync} from 'node:zlib';
import {crc32,normalizePresentation} from '../../plugin/package.mjs';
import {appInfoPlist,macSigningPlan,macDevelopmentSigningPlan,buildMacApp,macSwiftBuildArguments,prepareMacPluginIcon,MAC_BUNDLE_ID} from '../build-macos-app.mjs';

test('packaged sips PNG metadata is removed before the real Core plugin profile validates it',()=>{
  const chunk=(type,data)=>{const head=Buffer.alloc(8);head.writeUInt32BE(data.length);head.write(type,4);const sum=Buffer.alloc(4);sum.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type),data])));return Buffer.concat([head,data,sum])};
  const header=Buffer.alloc(13);header.writeUInt32BE(48);header.writeUInt32BE(48,4);header[8]=8;header[9]=6;
  const image=[Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',header),chunk('IDAT',deflateSync(Buffer.alloc(48*(48*4+1)))),chunk('IEND',Buffer.alloc(0))];
  const plain=Buffer.concat(image),withMetadata=Buffer.concat([image[0],image[1],chunk('iCCP',Buffer.from('source profile')),chunk('eXIf',Buffer.from('source metadata')),image[2],image[3]]);
  assert.throws(()=>normalizePresentation({icon:{mimeType:'image/png',dataBase64:withMetadata.toString('base64')}}),/unsupported_png_chunk/);
  assert.deepEqual(prepareMacPluginIcon(withMetadata),plain);
  assert.equal(normalizePresentation({icon:{mimeType:'image/png',dataBase64:prepareMacPluginIcon(withMetadata).toString('base64')}}).icon.mimeType,'image/png');
  const damaged=Buffer.from(withMetadata);damaged[45]^=1;
  assert.throws(()=>prepareMacPluginIcon(damaged),/invalid_packaged_plugin_png/);
  assert.throws(()=>prepareMacPluginIcon(withMetadata.subarray(0,-1)),/invalid_packaged_plugin_png/);
});

test('per-build SDK and module cache are passed as fixed Swift argv without changing the system toolchain',()=>{
  const input={source:'/source with spaces/Styx.swift',output:'/build/Styx.app/Contents/MacOS/Styx',arch:'arm64',sdkPath:'/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk',moduleCachePath:'/build/Module Cache'};
  const args=macSwiftBuildArguments(input);
  assert.equal(args[args.indexOf('-sdk')+1],input.sdkPath);assert.equal(args[args.indexOf('-module-cache-path')+1],input.moduleCachePath);
  assert.equal(args[args.indexOf('-target')+1],'arm64-apple-macosx13.0');assert.ok(args.includes(input.source));assert.ok(args.includes('-warnings-as-errors'));assert.ok(!args.includes('-D'));
  assert.equal(macSwiftBuildArguments({...input,arch:'x64'})[args.indexOf('-target')+1],'x86_64-apple-macosx13.0');
  for(const patch of [{sdkPath:'relative'},{sdkPath:'/sdk/../other'},{sdkPath:'/sdk\nother'},{moduleCachePath:'relative'},{moduleCachePath:undefined},{arch:'unsupported'}])assert.throws(()=>macSwiftBuildArguments({...input,...patch}));
});

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

test('explicit local-development signing allows distinct CN user id and OU team without distribution claims',()=>{
  const plan=macDevelopmentSigningPlan({app:'/scratch/Styx.app',identity:'Apple Development: Example (U123456789)',teamID:'T123456789'});
  assert.equal(plan[0][1].at(-1),'/scratch/Styx.app/Contents/MacOS/cua-driver');
  assert.ok(plan[0][1].includes('--timestamp=none'));
  assert.ok(plan[3][1].some(arg=>arg.includes('T123456789')));
  assert.ok(!plan.some(([,args])=>args.includes('notarytool')));
  assert.throws(()=>macSigningPlan({app:'/scratch/Styx.app',identity:'Apple Development: Example (U123456789)',teamID:'T123456789'}),/developer_id_application_required/);
});
test('local-development signing rejects ad-hoc identities and absent team',()=>{
  assert.throws(()=>macDevelopmentSigningPlan({app:'/scratch/Styx.app',identity:'-',teamID:'T123456789'}),/apple_development_identity_required/);
  assert.throws(()=>macDevelopmentSigningPlan({app:'/scratch/Styx.app',identity:'Apple Development: Example (U123456789)'}),/development_signing_team_required/);
});

test('symlinked CLI entrypoint cannot silently report a successful no-op',{skip:process.platform==='win32'},t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-mac-cli-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const cli=path.join(dir,'linked-builder.mjs'),config=path.join(dir,'build.json');
  fs.symlinkSync(fileURLToPath(new URL('../build-macos-app.mjs',import.meta.url)),cli);
  fs.writeFileSync(config,'{}');
  const result=spawnSync(process.execPath,[cli,config],{encoding:'utf8',timeout:5000});
  assert.equal(result.status,2);
  assert.ok(result.stderr.includes('Styx macOS app:'));
});

 test('codesign inline requirements use equals prefix rather than a requirement filename',()=>{
  for(const make of [macSigningPlan,macDevelopmentSigningPlan]){
    const identity=make===macSigningPlan?'Developer ID Application: Example (A123456789)':'Apple Development: Example (A123456789)';
    const plan=make({app:'/build/Styx.app',identity,teamID:'A123456789'});
    const args=plan.find(([,args])=>args.includes('-R'))[1];
    assert.ok(args[args.indexOf('-R')+1].startsWith('=anchor apple generic'));
  }
});

test('native codesign parses an inline requirement and rejects a mismatched identifier',{skip:process.platform!=='darwin'},()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-requirement-'));
  try{
    const binary=path.join(dir,'fixture');fs.copyFileSync('/usr/bin/true',binary);
    let result=spawnSync('/usr/bin/codesign',['--force','--sign','-','--identifier','app.styx.requirement.fixture',binary],{encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    result=spawnSync('/usr/bin/codesign',['--verify','--strict','-R','=identifier "app.styx.requirement.fixture"',binary],{encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    result=spawnSync('/usr/bin/codesign',['--verify','--strict','-R','=identifier "app.styx.requirement.wrong"',binary],{encoding:'utf8'});
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/does not satisfy|failed to satisfy|requirement failed/i);
  }finally{fs.rmSync(dir,{recursive:true,force:true})}
});
