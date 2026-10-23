import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {deflateSync} from 'node:zlib';
import {createHash,X509Certificate} from 'node:crypto';
import {rootCertificates} from 'node:tls';
import {crc32,normalizePresentation} from '../../plugin/package.mjs';
import {appInfoPlist,macAppBuildMetadata,macSigningPlan,macDevelopmentSigningPlan,macLocalSigningPlan,normalizeMacLocalSigning,publicMacLocalSigning,verifyMacLocalSigning,buildMacApp,macSwiftBuildArguments,prepareMacPluginIcon,MAC_BUNDLE_ID} from '../build-macos-app.mjs';

const localSigning={identitySha1:'a'.repeat(40),certificateSha256:'b'.repeat(64),keychain:'/private/build/signing.keychain-db'};
test('persistent local signing rejects weak, ambiguous or injected configuration and publishes no keychain path',()=>{
  assert.deepEqual(normalizeMacLocalSigning(localSigning),localSigning);
  assert.deepEqual(publicMacLocalSigning(localSigning),{schema:1,certificateSha1:localSigning.identitySha1,certificateSha256:localSigning.certificateSha256});
  for(const bad of [undefined,null,[],{},Object.assign(Object.create(null),localSigning),
    {...localSigning,identitySha1:'-'},{...localSigning,identitySha1:'A'.repeat(40)},
    {...localSigning,identitySha1:'a'.repeat(39)},{...localSigning,identitySha1:'a'.repeat(40)+'\n'},
    {...localSigning,certificateSha256:'B'.repeat(64)},{...localSigning,certificateSha256:'b'.repeat(63)},
    {...localSigning,keychain:'relative.keychain-db'},{...localSigning,keychain:'/private/build/../other.keychain-db'},
    {...localSigning,keychain:'/private/build/keychain\n--sign'},{...localSigning,identity:'-'},
    {...localSigning,notaryProfile:'local'},{...localSigning,teamID:'A123456789'}])
    assert.throws(()=>normalizeMacLocalSigning(bad));
});
test('local certificate plan pins the exact leaf and stable code identifiers before outer seal',()=>{
  const app='/build/Styx.app',files=[app+'/Contents/MacOS/Styx',app+'/Contents/MacOS/cua-driver',app+'/Contents/Resources/host-bundle/bin/node',app+'/Contents/Resources/runtime/node'];
  const plan=macLocalSigningPlan({app,files,localSigning});
  const signed=plan.filter(([,args])=>args.includes('--sign'));
  assert.equal(signed.length,files.length+1);
  assert.equal(signed[0][1].at(-1),files[2]);
  assert.equal(signed.at(-1)[1].at(-1),app);
  for(const [,args]of signed){
    const identifier=args[args.indexOf('--identifier')+1],requirement=args[args.indexOf('--requirements')+1];
    assert.equal(args[args.indexOf('--keychain')+1],localSigning.keychain);
    assert.equal(args[args.indexOf('--sign')+1],localSigning.identitySha1);
    assert.equal(requirement,`=designated => identifier "${identifier}" and certificate leaf = H"${localSigning.identitySha1}"`);
    assert.ok(args.includes('--timestamp=none'));assert.ok(!args.includes('--deep'));
    assert.ok(!args.includes('-'));assert.ok(!args.includes('--options'));
    const verification=plan.find(([,a])=>a.includes('-R')&&a.at(-1)===args.at(-1));
    assert.equal(verification[1][verification[1].indexOf('-R')+1],requirement.replace('designated => ',''));
  }
  for(const file of [app,files[0]])assert.equal(signed.find(([,args])=>args.at(-1)===file)[1].find((_,i,a)=>a[i-1]==='--identifier'),MAC_BUNDLE_ID);
  const identifiers=signed.filter(([,a])=>a.at(-1)!==app&&a.at(-1)!==files[0]).map(([,a])=>a[a.indexOf('--identifier')+1]);
  assert.equal(new Set(identifiers).size,identifiers.length); // Runtime and Host Node stay distinct.
  const relocated=macLocalSigningPlan({app:'/next/Styx.app',files:files.map(f=>f.replace('/build/','/next/')),localSigning});
  assert.deepEqual(relocated.filter(([,a])=>a.includes('--sign')).map(([,a])=>a[a.indexOf('--identifier')+1]),signed.map(([,a])=>a[a.indexOf('--identifier')+1]));
  assert.equal(macLocalSigningPlan({app,files,localSigning,sealApp:false}).some(([,a])=>a.at(-1)===app),false);
  assert.equal(plan.at(-1)[1].includes('--deep'),true);
  for(const patch of [{app:'/build/../Styx.app'},{app:'/build/Other.app'},{files:['/outside/node']},{files:[files[0],files[0]]},{files:[app+'/Contents/../escape']},{files:[app+'/Contents/file\n']},{sealApp:'true'},{localSigning:undefined}])
    assert.throws(()=>macLocalSigningPlan({app,files,localSigning,...patch}));
});
test('selected local keychain certificate must match both fingerprints before any signing',t=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-keychain-input-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const keychain=path.join(dir,'local.keychain-db');fs.writeFileSync(keychain,'fixture, not a real keychain');
  const certificate=new X509Certificate(rootCertificates[0]),input={keychain,identitySha1:createHash('sha1').update(certificate.raw).digest('hex'),certificateSha256:createHash('sha256').update(certificate.raw).digest('hex')},calls=[];
  const run=(command,args,options)=>{calls.push({command,args,options});return rootCertificates[0]};
  assert.deepEqual(verifyMacLocalSigning(input,{run}),publicMacLocalSigning(input));
  assert.equal(calls[0].command,'/usr/bin/security');assert.deepEqual(calls[0].args,['find-certificate','-a','-p',keychain]);
  assert.throws(()=>verifyMacLocalSigning({...input,certificateSha256:'0'.repeat(64)},{run}),/fingerprint_mismatch/);
  assert.throws(()=>verifyMacLocalSigning({...input,identitySha1:'0'.repeat(40)},{run}),/fingerprint_mismatch/);
  assert.throws(()=>verifyMacLocalSigning(input,{run(){return ''}}),/fingerprint_mismatch/);
  assert.throws(()=>verifyMacLocalSigning(input,{run(){throw Error('locked_keychain')}}),/locked_keychain/);
  fs.unlinkSync(keychain);fs.mkdirSync(keychain);assert.throws(()=>verifyMacLocalSigning(input,{run}),/regular_local_signing_keychain/);
});

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
test('publisher plan signs nested Cua and updater before host and verifies exact team identity',()=>{
  const plan=macSigningPlan({app:'/build/Styx.app',identity:'Developer ID Application: Example (A123456789)',teamID:'A123456789',notaryProfile:'styx-release'});
  assert.equal(plan[0][1].at(-1),'/build/Styx.app/Contents/MacOS/cua-driver');
  assert.equal(plan[1][1].at(-1),'/build/Styx.app/Contents/MacOS/StyxUpdater');
  assert.equal(plan[2][1].at(-1),'/build/Styx.app');
  assert.ok(plan[4][1].some(arg=>arg.includes('identifier "app.styx.host"')));
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
  assert.equal(macSigningPlan(valid).length,5);
});
test('Linux cannot accidentally produce a macOS signing receipt',{skip:process.platform==='darwin'},()=>{
  assert.throws(()=>buildMacApp({}),/native_macos_build_required/);
});

test('explicit local-development signing allows distinct CN user id and OU team without distribution claims',()=>{
  const plan=macDevelopmentSigningPlan({app:'/scratch/Styx.app',identity:'Apple Development: Example (U123456789)',teamID:'T123456789'});
  assert.equal(plan[0][1].at(-1),'/scratch/Styx.app/Contents/MacOS/cua-driver');
  assert.ok(plan[0][1].includes('--timestamp=none'));
  assert.ok(plan[4][1].some(arg=>arg.includes('T123456789')));
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


test('successive update builds keep marketing version but emit distinct explicit bundle versions',()=>{
  const first=appInfoPlist('0.3.0',{buildNumber:'1008',updateRelease:true});
  const second=appInfoPlist('0.3.0',{buildNumber:'1009',updateRelease:true});
  for(const plist of [first,second])assert.match(plist,/<key>CFBundleShortVersionString<\/key><string>0\.3\.0<\/string>/);
  assert.match(first,/<key>CFBundleVersion<\/key><string>1008<\/string>/);
  assert.match(second,/<key>CFBundleVersion<\/key><string>1009<\/string>/);
  assert.match(second,/<key>StyxUpdateRelease<\/key><true\/>/);
  assert.throws(()=>appInfoPlist('0.3.0',{updateRelease:true}),/macos_update_release_build_number_required/);
});
test('build numbers use bounded canonical Apple numeric components, never Host prerelease semver',()=>{
  for(const buildNumber of ['1','1008','9999.99.99','1008.1','1008.1.0'])
    assert.equal(macAppBuildMetadata({version:'0.3.0',buildNumber,updateRelease:true}).buildNumber,buildNumber);
  for(const buildNumber of [null,0,1008,'','0','01','1.01','1.00.1','10000','1.100','1.1.100','1.2.3.4','1\n','1-rc.7','0.3.0-rc.20261022.7','9'.repeat(200),'<x>','1.2.'])
    assert.throws(()=>appInfoPlist('0.3.0',{buildNumber,updateRelease:true}),/invalid_macos_build_number/);
  assert.throws(()=>appInfoPlist('0.3.0',{buildNumber:'1008',updateRelease:'true'}),/invalid_macos_update_release/);
});
test('legacy development builds are explicitly excluded from update releases',()=>{
  assert.deepEqual(macAppBuildMetadata({version:'0.3.0'}),{marketingVersion:'0.3.0',buildNumber:'0',updateRelease:false,buildNumberSource:'development_sentinel_not_for_updates'});
  const plist=appInfoPlist('0.3.0');
  assert.match(plist,/<key>CFBundleVersion<\/key><string>0<\/string>/);
  assert.match(plist,/<key>StyxUpdateRelease<\/key><false\/>/);
  assert.equal(macAppBuildMetadata({version:'0.3.0',buildNumber:'1008'}).updateRelease,false);
});
