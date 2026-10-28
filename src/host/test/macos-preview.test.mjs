import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {macAdhocSigningPlan,macSigningPlan,macLocalSigningPlan,publicMacLocalSigning} from '../build-macos-app.mjs';
import {buildMacPreview,machOFiles,preparedPreviewInventory,assertNativeMacAppInventory,withNativeMacDmgMount} from '../build-macos-preview.mjs';
import {authenticateNativeMacRuntimeEnvelope} from '../build-macos-native-runtime.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
function scratch(t){const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-preview-test-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
test('ad-hoc preview signs all contained nested code before final app, separate from Developer ID',()=>{
 const app='/build/Styx.app',files=[app+'/Contents/MacOS/Styx',app+'/Contents/Resources/host-bundle/bin/node'];
 const steps=macAdhocSigningPlan({app,files});assert.equal(steps[0][1].at(-1),files[1]);assert.equal(steps.at(-2)[1].at(-1),app);
 assert.equal(steps.some(s=>s[1].includes('--options')||s[1].includes('--timestamp')),false);
 assert.throws(()=>macAdhocSigningPlan({app,files:['/outside/node']}));assert.throws(()=>macAdhocSigningPlan({app,files:[files[0],files[0]]}));
 assert.throws(()=>macSigningPlan({app,identity:'-',teamID:'ABCDEFGHIJ'}),/developer_id_application_required/);
});
test('local certificate plan covers every detected Mach-O payload including nested native dependencies',t=>{
 const root=scratch(t),app=path.join(root,'Styx.app'),localSigning={identitySha1:'c'.repeat(40),certificateSha256:'d'.repeat(64),keychain:'/private/build/local.keychain-db'};
 const members=['Contents/MacOS/Styx','Contents/MacOS/cua-driver','Contents/Resources/runtime/node','Contents/Resources/host-bundle/bin/codex','Contents/Resources/onboarding/vnext/node_modules/addon/build/addon.node'];
 for(const name of members){const file=path.join(app,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,Buffer.from('cffaedfe00000000','hex'));}
 fs.writeFileSync(path.join(app,'Contents/Resources/public.json'),'{}');
 const files=machOFiles(app);assert.deepEqual(files,members.map(name=>path.join(app,name)).sort());
 const plan=macLocalSigningPlan({app,files,localSigning,sealApp:false}),signed=plan.filter(([,args])=>args.includes('--sign'));
 assert.deepEqual(signed.map(([,args])=>args.at(-1)).sort(),files);
 assert.ok(signed.every(([,args])=>args[args.indexOf('--sign')+1]===localSigning.identitySha1&&args[args.indexOf('--keychain')+1]===localSigning.keychain));
 assert.ok(signed.every(([,args])=>args[args.indexOf('--requirements')+1].includes('certificate leaf = H"'+localSigning.identitySha1+'"')));
});
test('symlinked preview CLI entry reports a refused build instead of silent success',{skip:process.platform==='win32'},t=>{
 const root=scratch(t),entry=path.join(root,'preview.mjs'),config=path.join(root,'config.json');
 fs.symlinkSync(fileURLToPath(new URL('../build-macos-preview.mjs',import.meta.url)),entry);fs.writeFileSync(config,'{}');
 const result=spawnSync(process.execPath,[entry,config],{encoding:'utf8',timeout:5000});
 assert.equal(result.status,2);assert.match(result.stderr,/Styx developer preview build failed/);
});

test('Intel unsigned helper is signed before the main executable in both preview modes',()=>{
 const app='/build/Styx.app',main=app+'/Contents/MacOS/Styx',helper=app+'/Contents/MacOS/StyxUpdater';
 const localSigning={identitySha1:'c'.repeat(40),certificateSha256:'d'.repeat(64),keychain:'/private/build/local.keychain-db'};
 for(const plan of [macAdhocSigningPlan({app,files:[main,helper],sealApp:false}),macLocalSigningPlan({app,files:[main,helper],sealApp:false,localSigning})]){
  const signed=plan.filter(([,args])=>args.includes('--sign')).map(([,args])=>args.at(-1));
  assert.deepEqual(signed,[helper,main]);
 }
});

// Pure preservation and cryptographic bootstrap checks; no platform signing,
// hdiutil mount or installed-App acceptance is claimed by these tests.
test('native archive inventory rejects changed bytes, execution modes, extra files and links',t=>{
 const root=scratch(t),app=path.join(root,'Styx.app'),file=path.join(app,'Contents/MacOS/Styx');
 fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,'sealed app',{mode:0o700});
 const expected=preparedPreviewInventory(app);assertNativeMacAppInventory(app,expected);
 fs.writeFileSync(file,'changed app');assert.throws(()=>assertNativeMacAppInventory(app,expected),/native_archive_app_inventory_changed/);
 fs.writeFileSync(file,'sealed app');fs.chmodSync(file,0o600);assert.throws(()=>assertNativeMacAppInventory(app,expected),/native_archive_app_inventory_changed/);fs.chmodSync(file,0o700);
 const extra=path.join(app,'extra');fs.writeFileSync(extra,'unexpected');assert.throws(()=>assertNativeMacAppInventory(app,expected),/native_archive_app_inventory_changed/);fs.unlinkSync(extra);
 fs.symlinkSync(file,extra);assert.throws(()=>assertNativeMacAppInventory(app,expected),/distribution_symlink_forbidden/);
});
test('native reader envelopes bind signed schemas4/5/6 without upgrading old declarations',t=>{
 const root=scratch(t),payload=path.join(root,'native'),publisher=path.join(root,'publisher.pem');
 fs.chmodSync(root,0o700);fs.mkdirSync(payload,{mode:0o700});fs.mkdirSync(path.join(payload,'bin'),{mode:0o700});
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');fs.writeFileSync(publisher,publicKey.export({type:'spki',format:'pem'}),{mode:0o600});
 const image=Buffer.alloc(32);image.writeUInt32LE(0xfeedfacf,0);image.writeUInt32LE(0x01000007,4);image.writeUInt32LE(2,12);
 fs.writeFileSync(path.join(payload,'bin/styx'),image,{mode:0o700});
 const input={payloadDir:payload,publisherFile:publisher,expectedPublisher:hash(publicKey.export({type:'spki',format:'der'}))};
 const manifest={schema:2,runtime_format:'native_rust_v1',scope:'runtime_candidate',component:'styx',minimum_reader:'native_service_runtime_selected_v1',contracts:{control:1,management_state:5},target:'x86_64-apple-darwin',entrypoint:'bin/styx',files:[{path:'bin/styx',size:image.length,sha256:hash(image),executable:true}]};
 const seal=()=>{const raw=Buffer.from(JSON.stringify(manifest));fs.writeFileSync(path.join(payload,'manifest.json'),raw,{mode:0o600});fs.writeFileSync(path.join(payload,'manifest.sig'),sign(null,raw,privateKey),{mode:0o600});};
 seal();assert.equal(authenticateNativeMacRuntimeEnvelope(input,'x64').manifest.minimum_reader,'native_service_runtime_selected_v1');
 manifest.contracts.management_state=4;seal();assert.throws(()=>authenticateNativeMacRuntimeEnvelope(input,'x64'),/native_macos_c08_required/);
 manifest.minimum_reader='native_app_runtime_selected_v1';seal();assert.equal(authenticateNativeMacRuntimeEnvelope(input,'x64').manifest.contracts.management_state,4);
 manifest.contracts.management_state=5;seal();assert.throws(()=>authenticateNativeMacRuntimeEnvelope(input,'x64'),/native_macos_c08_required/);
 manifest.minimum_reader='native_app_service_transferred_v1';seal();assert.throws(()=>authenticateNativeMacRuntimeEnvelope(input,'x64'),/native_macos_c08_required/);
 manifest.contracts.management_state=6;seal();assert.equal(authenticateNativeMacRuntimeEnvelope(input,'x64').manifest.minimum_reader,'native_app_service_transferred_v1');
 manifest.minimum_reader='native_service_runtime_selected_v1';seal();assert.throws(()=>authenticateNativeMacRuntimeEnvelope(input,'x64'),/native_macos_c08_required/);
});

test('failed DMG attach detaches only a structured exact image and fresh mount match',t=>{
 const root=scratch(t),image=path.join(root,'candidate.dmg'),mount=path.join(root,'mount');
 fs.writeFileSync(image,'fixture image');fs.mkdirSync(mount);const calls=[],verification={};
 const failure=Object.assign(Error('fixture_attach_nonzero_after_mount'),{status:1});
 const run=(command,args,timeout,input)=>{
  calls.push([command,args]);
  if(args[0]==='attach')throw failure;
  if(args[0]==='info')return Buffer.from('fixed plist fixture');
  if(command==='/usr/bin/plutil'){assert.equal(input.toString(),'fixed plist fixture');return JSON.stringify({images:[{'image-path':image,'system-entities':[{'mount-point':mount}]}]});}
  assert.deepEqual([command,args],['/usr/bin/hdiutil',['detach',mount]]);return Buffer.alloc(0);
 };
 assert.throws(()=>withNativeMacDmgMount({image,mount,verification,run},()=>assert.fail('attach did not succeed')),error=>error===failure);
 assert.equal(verification.failedAttachObservation,'exact_owned_image_mounted');assert.equal(verification.detached,true);
 assert.equal(calls.filter(([,args])=>args[0]==='detach').length,1);assert.equal(fs.existsSync(mount),false);
 assert.ok(calls.every(([,args])=>!args.includes('-force')));
});
test('failed DMG attach with unknown or foreign mapping never detaches or hides original failure',t=>{
 for(const mapping of ['invalid-json',{images:[{'image-path':'/different/image.dmg','system-entities':[{'mount-point':'CURRENT'}]}]}]){
  const root=scratch(t),image=path.join(root,'candidate.dmg'),mount=path.join(root,'mount');fs.writeFileSync(image,'fixture');fs.mkdirSync(mount);
  const verification={},calls=[],failure=Object.assign(Error('fixture_attach_timeout'),{status:null,signal:'SIGTERM'});
  const run=(command,args)=>{calls.push([command,args]);if(args[0]==='attach')throw failure;if(args[0]==='info')return 'plist';assert.equal(command,'/usr/bin/plutil');return typeof mapping==='string'?mapping:JSON.stringify(mapping).replace('CURRENT',mount);};
  assert.throws(()=>withNativeMacDmgMount({image,mount,verification,run},()=>assert.fail()),error=>error===failure);
  assert.equal(verification.failedAttachObservation,'unknown');assert.equal(verification.detachAttempted,false);assert.equal(verification.detached,false);
  assert.equal(calls.some(([,args])=>args[0]==='detach'),false);assert.equal(fs.existsSync(mount),true);
 }
});

test('Mac builds require the Rust payload before inspecting paths or invoking tools',()=>{
 assert.throws(()=>buildMacPreview({}),/native_runtime_required_for_product_app/);
});
