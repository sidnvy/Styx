import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {macAdhocSigningPlan,macSigningPlan} from '../build-macos-app.mjs';
import {copyOfflineDependencies,finalizePreviewHostBundle,machOFiles,previewSourceFiles} from '../build-macos-preview.mjs';
import {verifySignedRelease} from '../installer.mjs';
import {verifyMacPreviewApp} from '../macos-preview-trust.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
function scratch(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-preview-test-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return root;}
test('ad-hoc preview signs all contained nested code before final app, separate from Developer ID',()=>{
 const app='/build/Styx.app',files=[app+'/Contents/MacOS/Styx',app+'/Contents/Resources/host-bundle/bin/node'];
 const steps=macAdhocSigningPlan({app,files});assert.equal(steps[0][1].at(-1),files[1]);assert.equal(steps.at(-2)[1].at(-1),app);
 assert.equal(steps.some(s=>s[1].includes('--options')||s[1].includes('--timestamp')),false);
 assert.throws(()=>macAdhocSigningPlan({app,files:['/outside/node']}));assert.throws(()=>macAdhocSigningPlan({app,files:[files[0],files[0]]}));
 assert.throws(()=>macSigningPlan({app,identity:'-',teamID:'ABCDEFGHIJ'}),/developer_id_application_required/);
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
