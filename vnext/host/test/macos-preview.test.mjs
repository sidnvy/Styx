import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {macAdhocSigningPlan,macSigningPlan,macLocalSigningPlan,publicMacLocalSigning} from '../build-macos-app.mjs';
import {copyOfflineDependencies,copyPreviewDependencies,finalizePreviewHostBundle,machOFiles,previewSourceFiles,verifyPreviewTunnelInput,previewSigningReceipt} from '../build-macos-preview.mjs';
import {verifySignedRelease} from '../installer.mjs';
import {verifyMacPreviewApp} from '../macos-preview-trust.mjs';
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
test('offline production dependency copy is lock-bound, excludes dev/local material and rejects symlinks',t=>{
 const root=scratch(t),deps=path.join(root,'deps'),lock=path.join(root,'lock.json');fs.mkdirSync(deps);
 const packages={};for(const [name,dev]of [['@modelcontextprotocol/sdk',false],['ws',false],['dev-only',true]]){const d=path.join(deps,name);fs.mkdirSync(d,{recursive:true});fs.writeFileSync(path.join(d,'package.json'),JSON.stringify({name,version:'1.0.0'}));fs.writeFileSync(path.join(d,'LICENSE'),'public');fs.writeFileSync(path.join(d,'.npmrc'),'never copied');packages['node_modules/'+name]={version:'1.0.0',integrity:'sha512-example',...(dev?{dev:true}:{})};}
 fs.writeFileSync(lock,JSON.stringify({lockfileVersion:3,packages}));const dest=path.join(root,'out');const records=copyOfflineDependencies({lockFile:lock,dependenciesDir:deps,destination:dest});assert.equal(records.length,2);assert.equal(fs.existsSync(path.join(dest,'node_modules/dev-only')),false);assert.equal(fs.existsSync(path.join(dest,'node_modules/ws/.npmrc')),false);
 fs.symlinkSync('/tmp',path.join(deps,'ws','escape'));assert.throws(()=>copyOfflineDependencies({lockFile:lock,dependenciesDir:deps,destination:path.join(root,'bad')}),/distribution_symlink_forbidden/);
});
test('source snapshot uses clean tracked files only and excludes tests and runtime caches',{skip:process.platform==='win32'},t=>{
 const root=scratch(t);for(const name of ['onboarding/core.mjs','onboarding/ui/browser.test.mjs','host/test/private.pem','host/.runtime/node','work/private.json']){const p=path.join(root,name);fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,name);}
 const git=args=>execFileSync('/usr/bin/git',['-C',root,...args],{encoding:'utf8',stdio:['ignore','pipe','pipe']});git(['init','-q']);git(['add','-A']);git(['-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','fixture']);const revision=git(['rev-parse','HEAD']).trim();
 fs.writeFileSync(path.join(root,'host/untracked-private.pem'),'not copied');assert.deepEqual(previewSourceFiles(root,{revision}),['onboarding/core.mjs']);fs.appendFileSync(path.join(root,'onboarding/core.mjs'),'changed');assert.throws(()=>previewSourceFiles(root,{revision}));
});
test('final Host manifest signs transformed native bytes and retains original Node provenance',t=>{
 const root=scratch(t),{publicKey,privateKey}=generateKeyPairSync('ed25519');fs.mkdirSync(path.join(root,'bin'));fs.mkdirSync(path.join(root,'provenance'));const bytes=Buffer.from('transformed-native-fixture');fs.writeFileSync(path.join(root,'bin/node'),bytes);const upstream={schema:1,version:'22.23.3',binary_sha256:'a'.repeat(64)};fs.writeFileSync(path.join(root,'provenance/node.json'),JSON.stringify(upstream));fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify({schema:1,version:'0.1.0-test',platform:process.platform,arch:process.arch,files:[{path:'bin/node',executable:true}]}));finalizePreviewHostBundle(root,privateKey);verifySignedRelease(root,publicKey.export({type:'spki',format:'pem'}));const transformed=JSON.parse(fs.readFileSync(path.join(root,'provenance/node.json')));assert.equal(transformed.binary_sha256,hash(bytes));assert.equal(transformed.upstream_binary_sha256,upstream.binary_sha256);assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root,'provenance/node-upstream.json'))),upstream);fs.appendFileSync(path.join(root,'bin/node'),'tamper');assert.throws(()=>verifySignedRelease(root,publicKey.export({type:'spki',format:'pem'})));
});
test('local certificate Host manifest binds transformed code and public provenance without keychain disclosure',t=>{
 const root=scratch(t),localSigning={identitySha1:'c'.repeat(40),certificateSha256:'d'.repeat(64),keychain:'/private/builder/persistent.keychain-db'};
 const app=path.join(root,'Styx.app'),bundle=path.join(app,'Contents/Resources/host-bundle');fs.mkdirSync(path.join(bundle,'bin'),{recursive:true});fs.mkdirSync(path.join(bundle,'provenance'));
 const originalNode=Buffer.from('upstream native bytes'),signedNode=Buffer.from('certificate transformed bytes');
 const upstream={schema:1,version:'22.23.3',binary_sha256:hash(originalNode)};
 fs.writeFileSync(path.join(bundle,'bin/node'),originalNode);fs.writeFileSync(path.join(bundle,'provenance/node.json'),JSON.stringify(upstream));
 fs.writeFileSync(path.join(bundle,'manifest.json'),JSON.stringify({schema:1,version:'0.1.0-test',platform:process.platform,arch:process.arch,files:[{path:'bin/node',executable:true}]}));
 const plan=macLocalSigningPlan({app,files:[path.join(bundle,'bin/node')],localSigning,sealApp:false});
 assert.ok(plan.some(([,args])=>args.includes('--sign')));assert.ok(!plan.some(([,args])=>args.at(-1)===app));
 // Model codesign's byte transformation only; no native signing success claim.
 fs.writeFileSync(path.join(bundle,'bin/node'),signedNode);
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');finalizePreviewHostBundle(bundle,privateKey,{localSigning});
 const pem=publicKey.export({type:'spki',format:'pem'});verifySignedRelease(bundle,pem);
 const provenance=JSON.parse(fs.readFileSync(path.join(bundle,'provenance/macos-preview.json'))),node=JSON.parse(fs.readFileSync(path.join(bundle,'provenance/node.json')));
 assert.equal(node.binary_sha256,hash(signedNode));assert.equal(node.upstream_binary_sha256,hash(originalNode));
 assert.equal(node.transformation,'macos_local_certificate_codesign_after_verified_upstream_input');
 assert.equal(provenance.signing,'local_certificate_preview');assert.equal(provenance.notarization,'NOT RUN');
 assert.deepEqual(provenance.local_signing,publicMacLocalSigning(localSigning));
 const receipt=previewSigningReceipt(localSigning);
 assert.deepEqual(receipt,{signing:'local_certificate_preview',notarization:'NOT RUN',external_publisher_identity:'NOT ESTABLISHED',private_key_in_artifact:false,local_signing:publicMacLocalSigning(localSigning)});
 assert.doesNotMatch(JSON.stringify({provenance,receipt}),/keychain|persistent|PRIVATE KEY|developer_id_verified/);
 assert.equal(macLocalSigningPlan({app,files:[],sealApp:true,localSigning})[0][1].at(-1),app);
 fs.appendFileSync(path.join(bundle,'provenance/macos-preview.json'),'tamper');assert.throws(()=>verifySignedRelease(bundle,pem));
 assert.throws(()=>previewSigningReceipt({...localSigning,notaryProfile:'unsafe'}));
 assert.equal(previewSigningReceipt().signing,'adhoc_preview');
});
test('explicit preview trust checks whole app, exact ad-hoc CDHash and app identifier',t=>{
 const root=scratch(t),app=path.join(root,'Styx.app');fs.mkdirSync(app);const cdhash='a'.repeat(40),calls=[];
 const run=(command,args)=>{calls.push(args);return {status:0,stderr:args[0]==='-d'?`Identifier=app.styx.host\nSignature=adhoc\nCDHash=${cdhash}\n`:''}};
 assert.equal(verifyMacPreviewApp({path:app,cdhash},{platform:'darwin',run}).trust,'local_adhoc_preview_not_notarized');assert.deepEqual(calls[0].slice(0,3),['--verify','--deep','--strict']);assert.throws(()=>verifyMacPreviewApp({path:app,cdhash:'b'.repeat(40)},{platform:'darwin',run}),/adhoc_preview_identity_mismatch/);assert.throws(()=>verifyMacPreviewApp({path:app,cdhash},{platform:'linux',run}));
});

test('symlinked preview CLI entry reports a refused build instead of silent success',{skip:process.platform==='win32'},t=>{
 const root=scratch(t),entry=path.join(root,'preview.mjs'),config=path.join(root,'config.json');
 fs.symlinkSync(fileURLToPath(new URL('../build-macos-preview.mjs',import.meta.url)),entry);fs.writeFileSync(config,'{}');
 const result=spawnSync(process.execPath,[entry,config],{encoding:'utf8',timeout:5000});
 assert.equal(result.status,2);assert.match(result.stderr,/Styx developer preview build failed/);
});

test('tunnel packaging rejects unpinned binaries before distribution',t=>{
 const root=scratch(t),binary=path.join(root,'tunnel-client');fs.writeFileSync(binary,'untrusted binary');
 assert.throws(()=>verifyPreviewTunnelInput(binary),/verified_original_tunnel_input_required/);
 assert.throws(()=>verifyPreviewTunnelInput('relative'),/absolute_tunnel_binary_required/);
});


test('preview includes the independently locked foreground Browser dependency closure',t=>{
 const root=scratch(t),sourceRoot=fileURLToPath(new URL('../../',import.meta.url)),destination=path.join(root,'onboarding/vnext');
 const provider='packages/styx-browser-provider';
 // Copy the real production provider, without workspace ancestors or installed
 // Host resources: Node must resolve every import within the packaged tree.
 for(const name of ['host/private-storage.mjs',...['host.mjs','prepare.mjs','config.mjs','contract.mjs','playwright-contract-0.0.83.json'].map(name=>provider+'/'+name)]){
  const target=path.join(destination,name);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(sourceRoot,name),target);
 }
 copyOfflineDependencies({lockFile:path.join(sourceRoot,'package-lock.json'),dependenciesDir:path.join(sourceRoot,'node_modules'),destination});
 const command=['--input-type=module','-e',"const api=await import('./packages/styx-browser-provider/host.mjs');if(typeof api.HostBrowserSupervisor!=='function')process.exit(3);"];
 const options={cwd:destination,encoding:'utf8',timeout:15000,env:{PATH:path.dirname(process.execPath)}};
 const before=spawnSync(process.execPath,command,options);assert.notEqual(before.status,0);assert.match(before.stderr,/ERR_MODULE_NOT_FOUND/);
 const records=copyPreviewDependencies({sourceRoot,destination});
 const after=spawnSync(process.execPath,command,options);assert.equal(after.status,0,after.stderr);
 const lock=JSON.parse(fs.readFileSync(path.join(sourceRoot,provider,'package-lock.json'),'utf8'));
 for(const name of ['@playwright/mcp','playwright','playwright-core']){
  const record=records.find(record=>record.path===provider+'/node_modules/'+name);
  assert.equal(record?.lockFile,provider+'/package-lock.json');assert.equal(record?.version,lock.packages['node_modules/'+name].version);
  assert.equal(record?.integrity,lock.packages['node_modules/'+name].integrity);
 }
 assert.equal(records.find(record=>record.path==='node_modules/ws')?.lockFile,'package-lock.json');
 assert.equal(fs.existsSync(path.join(destination,provider,'node_modules/.bin')),false);
 // A missing required nested package must fail the same build helper, even
 // when the top-level MCP/ws dependencies are fully available.
 const incomplete=path.join(root,'incomplete');fs.mkdirSync(incomplete);
 fs.copyFileSync(path.join(sourceRoot,'package-lock.json'),path.join(incomplete,'package-lock.json'));
 fs.mkdirSync(path.join(incomplete,provider),{recursive:true});
 fs.copyFileSync(path.join(sourceRoot,provider,'package-lock.json'),path.join(incomplete,provider,'package-lock.json'));
 assert.throws(()=>copyPreviewDependencies({sourceRoot:incomplete,dependenciesDir:path.join(sourceRoot,'node_modules'),destination:path.join(root,'failed')}),/required_production_dependency_missing/);
});
