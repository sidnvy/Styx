// Native self-contained precompiled developer preview. No Apple Developer account,
// notarization, existing application installation or private-key distribution.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,generateKeyPairSync,createPublicKey,createPrivateKey,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {MAC_BUNDLE_ID,buildMacApp,macNativeSwiftSources,macAppBuildMetadata,macAdhocSigningPlan,macLocalSigningPlan,normalizeMacLocalSigning,publicMacLocalSigning,verifyMacLocalSigning} from './build-macos-app.mjs';
import {isSparkleFrameworkLink} from './macos/platform-update/sparkle-build.mjs';
import {prepareCoreHelper} from './macos/core-helper.mjs';
import {buildHostRelease} from './build-host-release.mjs';
import {verifySignedRelease} from './installer.mjs';
import {requirePrivateFile} from './private-storage.mjs';
import {verifyNativeMacRuntime,copyNativeMacRuntime,authenticateNativeMacRuntimeEnvelope} from './build-macos-native-runtime.mjs';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
const assert=(x,code)=>{if(!x)throw Error(code)};
const sha=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const ABS=p=>typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p;
const SKIP=new Set(['node_modules','.runtime','test','acceptance','__pycache__']);
function tree(source,destination,{skip=()=>false}={}){
 const st=fs.lstatSync(source);assert(!st.isSymbolicLink(),'distribution_symlink_forbidden');
 if(st.isDirectory()){fs.mkdirSync(destination,{recursive:true});for(const name of fs.readdirSync(source).sort())if(!skip(name))tree(path.join(source,name),path.join(destination,name),{skip});}
 else{assert(st.isFile(),'distribution_regular_files_required');fs.mkdirSync(path.dirname(destination),{recursive:true});if(fs.existsSync(destination))assert(sha(source)===sha(destination),'distribution_copy_collision');else fs.copyFileSync(source,destination,fs.constants.COPYFILE_EXCL);}
}
export function previewSourceFiles(sourceRoot,{revision}={}){
 assert(execFileSync('/usr/bin/git',['-C',sourceRoot,'rev-parse','HEAD'],{encoding:'utf8'}).trim()===revision,'source_revision_mismatch');
 execFileSync('/usr/bin/git',['-C',sourceRoot,'diff','--quiet','HEAD','--','.'],{stdio:'pipe'});
 const files=execFileSync('/usr/bin/git',['-C',sourceRoot,'ls-files','-z','--','.'],{encoding:'utf8'}).split('\0').filter(Boolean);
 const tops=new Set(['onboarding','gateway','host','shared','packages','licenses','plugin','assets']);
 return files.filter(name=>{const parts=name.split('/');assert(parts.every(x=>x&&x!=='.'&&x!=='..')&&!name.includes('\\'),'invalid_source_snapshot_path');return (tops.has(parts[0])||['package.json','package-lock.json'].includes(name))&&!name.endsWith('.test.mjs')&&!parts.some(p=>p.startsWith('.')||SKIP.has(p));}).sort();
}
function scanPrivateMaterial(root,{allowSparkle=false}={}){
 function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(e.isSymbolicLink()&&allowSparkle&&isSparkleFrameworkLink(root,file))continue;assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(file);else{assert(!['admin.token','model.token','device.token','identity.pem','publisher-private.pem'].includes(e.name),'private_material_filename_in_distribution');const bytes=fs.readFileSync(file);assert(!/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]/.test(bytes.toString('utf8')),'private_key_in_distribution');}}}walk(root);
}
export function copyOfflineDependencies({lockFile,dependenciesDir,destination,requiredPackages=['@modelcontextprotocol/sdk','ws']}){
 const lock=JSON.parse(fs.readFileSync(lockFile,'utf8'));assert(lock.lockfileVersion===3&&lock.packages,'locked_npm_graph_required');
 const selected=Object.entries(lock.packages).filter(([name,p])=>name&&name.startsWith('node_modules/')&&!p.dev).sort(([a],[b])=>a.localeCompare(b));
 const records=[];
 for(const [name,pin]of selected){
  assert(name.split('/').every(x=>x&&x!=='.'&&x!=='..')&&!name.includes('\\'),'invalid_locked_package_path');
  const relative=name.slice('node_modules/'.length),source=path.join(dependenciesDir,...relative.split('/'));
  if(!fs.existsSync(source)){assert(pin.optional,'required_production_dependency_missing');continue;}
  assert(!pin.link&&typeof pin.integrity==='string'&&typeof pin.version==='string','registry_locked_dependency_required');
  const pkg=JSON.parse(fs.readFileSync(path.join(source,'package.json'),'utf8'));assert(pkg.version===pin.version,'installed_dependency_version_mismatch');
  // Registry packages may import runtime files from directories named test.
  // The lock selects production packages; directory names cannot classify code.
  tree(source,path.join(destination,...name.split('/')),{skip:n=>n==='node_modules'||n.startsWith('.')});
  records.push({path:name,version:pin.version,integrity:pin.integrity});
 }
 for(const name of requiredPackages)assert(records.some(r=>r.path==='node_modules/'+name),'onboarding_production_dependency_missing');
 return records;
}
// Foreground Browser runs in the onboarding process, independently of the
// installed Host bundle. Each module tree needs its own locked closure.
export function copyPreviewDependencies({sourceRoot,dependenciesDir=path.join(sourceRoot,'node_modules'),destination}){
 const roots=[{relative:'',dependenciesDir},{relative:'packages/styx-browser-provider',dependenciesDir:path.join(sourceRoot,'packages/styx-browser-provider/node_modules')}];
 return roots.flatMap(({relative,dependenciesDir})=>{
  const lockFile=path.posix.join(relative,'package-lock.json');
  const records=copyOfflineDependencies({lockFile:path.join(sourceRoot,lockFile),dependenciesDir,destination:path.join(destination,relative),...(relative?{requiredPackages:['@modelcontextprotocol/sdk','@playwright/mcp','playwright','playwright-core']}:{})});
  return records.map(record=>({...record,path:path.posix.join(relative,record.path),lockFile}));
 });
}

export function machOFiles(root,{preserveSparkle=false}={}){
 const files=[];
 function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(preserveSparkle&&file===path.join(root,'Contents/Frameworks/Sparkle.framework'))continue;assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(file);else{assert(e.isFile(),'distribution_regular_files_required');const fd=fs.openSync(file,'r'),head=Buffer.alloc(8);let n;try{n=fs.readSync(fd,head,0,8,0)}finally{fs.closeSync(fd)}if(n>=4&&['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca'].includes(head.subarray(0,4).toString('hex')))files.push(file);}}}
 walk(root);return files.sort();
}
export function previewSigningReceipt(localSigning){
 return {signing:localSigning===undefined?'adhoc_preview':'local_certificate_preview',notarization:'NOT RUN',external_publisher_identity:'NOT ESTABLISHED',private_key_in_artifact:false,
  ...(localSigning===undefined?{}:{local_signing:publicMacLocalSigning(localSigning)})};
}
// A stable App identity must never silently rotate the Host publisher on each
// package build. Ad-hoc fixtures may still explicitly use ephemeral keys.
export function previewReleasePublisher({localSigning,hostPublisher}={}){
 if(localSigning!==undefined){
  normalizeMacLocalSigning(localSigning);
  assert(hostPublisher?.mode==='persistent','stable_app_requires_persistent_host_publisher');
 }
 return hostPublisher;
}
// Release signing is separate from the App codesign certificate. Keep the
// external publisher untouched and use an owned private snapshot for the existing
// file-based Host builder, so both manifest passes use the same key bytes.
export function withPreviewHostPublisher(hostPublisher,build,{excludedRoots=[]}={}){
 const selection=hostPublisher??{mode:'ephemeral'};
 assert(selection&&typeof selection==='object'&&!Array.isArray(selection)&&Object.keys(selection).every(k=>['mode','privateKeyFile'].includes(k))&&['ephemeral','persistent'].includes(selection.mode),'invalid_host_publisher_configuration');
 let privateKey;
 if(selection.mode==='persistent'){
  const file=selection.privateKeyFile;assert(ABS(file),'absolute_host_publisher_key_required');
  const info=requirePrivateFile(file);assert(info.nlink===1&&info.size>0&&info.size<=16384,'invalid_host_publisher_key_file');
  const real=fs.realpathSync(file);
  for(const root of excludedRoots){assert(ABS(root),'absolute_host_publisher_exclusion_required');const base=fs.existsSync(root)?fs.realpathSync(root):root;assert(real!==base&&!real.startsWith(base+path.sep),'host_publisher_key_in_package_inputs');}
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{const opened=fs.fstatSync(fd);assert(opened.dev===info.dev&&opened.ino===info.ino&&opened.size===info.size,'host_publisher_key_changed');
   try{privateKey=createPrivateKey(fs.readFileSync(fd));}catch{throw Error('invalid_host_publisher_private_key');}
  }finally{fs.closeSync(fd)}
  assert(privateKey.asymmetricKeyType==='ed25519','ed25519_host_publisher_key_required');
 }else{
  assert(selection.privateKeyFile===undefined,'ephemeral_host_publisher_key_forbidden');
  privateKey=generateKeyPairSync('ed25519').privateKey;
 }
 const publicKey=createPublicKey(privateKey),publicPem=publicKey.export({type:'spki',format:'pem'});
 const fingerprint=createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
 const privateRoot=fs.mkdtempSync(path.join(os.tmpdir(),'styx-preview-publisher-'));fs.chmodSync(privateRoot,0o700);
 try{
  const privateFile=path.join(privateRoot,'publisher-private.pem');
  fs.writeFileSync(privateFile,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
  return build({privateKey,privateFile,publicPem,fingerprint,publisherMode:selection.mode});
 }finally{fs.rmSync(privateRoot,{recursive:true,force:true});}
}
export function finalizePreviewHostBundle(root,privateKey,{localSigning,publisherMode='ephemeral'}={}){
 if(localSigning!==undefined)normalizeMacLocalSigning(localSigning);
 assert(['ephemeral','persistent'].includes(publisherMode),'invalid_host_publisher_mode');
 const m=JSON.parse(fs.readFileSync(path.join(root,'manifest.json'),'utf8'));
 const provenance=path.join(root,'provenance/node.json'),original=JSON.parse(fs.readFileSync(provenance,'utf8'));
 fs.writeFileSync(path.join(root,'provenance/node-upstream.json'),JSON.stringify(original,null,2)+'\n',{flag:'wx'});
 fs.writeFileSync(provenance,JSON.stringify({...original,upstream_binary_sha256:original.binary_sha256,binary_sha256:sha(path.join(root,'bin/node')),transformation:localSigning===undefined?'macos_adhoc_codesign_after_verified_upstream_input':'macos_local_certificate_codesign_after_verified_upstream_input',upstream_verification_record:'node-upstream.json'},null,2)+'\n');
 fs.writeFileSync(path.join(root,'provenance/macos-preview.json'),JSON.stringify({schema:1,signing:localSigning===undefined?'adhoc':'local_certificate_preview',notarization:'NOT RUN',publisher_trust:publisherMode==='persistent'?'persistent_local_build_key_not_developer_id':'ephemeral_local_build_key_not_developer_id',publisher_mode:publisherMode,native_binary_transformation:'codesign_before_final_release_manifest',...(localSigning===undefined?{}:{local_signing:publicMacLocalSigning(localSigning)})},null,2)+'\n',{flag:'wx'});
 const names=[];function walk(dir,prefix=''){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const rel=prefix+e.name;assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(path.join(dir,e.name),rel+'/');else{assert(e.isFile(),'distribution_regular_files_required');if(!['manifest.json','manifest.sig'].includes(rel))names.push(rel);}}}walk(root);
 const prior=new Map(m.files.map(x=>[x.path,x]));
 m.files=names.sort().map(name=>({path:name,sha256:sha(path.join(root,...name.split('/'))),size:fs.statSync(path.join(root,...name.split('/'))).size,executable:prior.get(name)?.executable??false}));
 const raw=JSON.stringify(m,null,2)+'\n';fs.writeFileSync(path.join(root,'manifest.json'),raw);fs.writeFileSync(path.join(root,'manifest.sig'),sign(null,Buffer.from(raw),privateKey).toString('base64url')+'\n');
 return m;
}
// Verified from openai/tunnel-client v0.0.16 darwin-arm64 release archive.
export const TUNNEL_PREVIEW_PIN=Object.freeze({version:'0.0.16',platform:'darwin',arch:'arm64',archive_sha256:'a160820d45089b5253d8d671fe2a689bde0f73d78c135d1497a7b33f28a3ac62',binary_sha256:'6f1e8d5494d6c4d6c45cd4f6e07b5291459c0b23f4b8cd8266c7a64be3d9a2a0',source:'https://github.com/openai/tunnel-client/releases/tag/v0.0.16'});
const TUNNEL_NOTICES=Object.freeze({'LICENSE':'f4c1d7ba32ef5bcf5cf03e2eefec5825ebafedf50fa330a36700a49c605c1ef4','NOTICE':'1364c020d86ecf948b78b7c655175032068203d13aece70fb0bfe112d7802dc2','tunnel-client-v0.0.16-darwin-arm64-licenses.txt':'88cb2f313e4d12adc110cc5ebd9d626a5b4aae3874bb4abf386fdda59c215062','tunnel-client-v0.0.16-darwin-arm64.spdx.json':'2d116935e74f5571a0880e7d1ccda1ffe57332ab8b8b5f0a1fe447b58502457a'});
export const MAC_PREVIEW_NODE_PINS=Object.freeze({arm64:'23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53',x64:'8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8'});
export function macPreviewInputs(arch){
 assert(Object.hasOwn(MAC_PREVIEW_NODE_PINS,arch),'unsupported_macos_preview_arch');
 return arch==='arm64'?{nodeArchive:MAC_PREVIEW_NODE_PINS.arm64,tunnel:TUNNEL_PREVIEW_PIN,notices:TUNNEL_NOTICES}:{
  nodeArchive:MAC_PREVIEW_NODE_PINS.x64,
  tunnel:{...TUNNEL_PREVIEW_PIN,arch:'x64',archive_sha256:'57b3dd73f2d042c7aeb5664681f7538078359f55538b9e048640f1df71a0c83f',binary_sha256:'e2a96aa858c9cba1ca8f20d7dd0c2c0a2a468b98471e620a2c9703589c2d26aa'},
  notices:{LICENSE:TUNNEL_NOTICES.LICENSE,NOTICE:TUNNEL_NOTICES.NOTICE,'tunnel-client-v0.0.16-darwin-amd64-licenses.txt':'9cb81b39cb09acb80061708c6a2f26968e89393269581288629f2f65e93f2612','tunnel-client-v0.0.16-darwin-amd64.spdx.json':'fa952e475063847760afcacfa864d5fa20e5d2524346fd73e5786e592123b687'}
 };
}
export function verifyPreviewTunnelInput(binary,{arch=process.arch}={}){
 const inputs=macPreviewInputs(arch);

 assert(ABS(binary),'absolute_tunnel_binary_required');
 for(const [file,pin] of [[binary,inputs.tunnel.binary_sha256],...Object.entries(inputs.notices).map(([name,pin])=>[path.join(path.dirname(binary),name),pin])]){
  const st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&sha(file)===pin,'verified_original_tunnel_input_required');
 }
 return {...inputs.tunnel};
}
function publicModes(root,{app=root,allowSparkle=false}={}){for(const e of fs.readdirSync(root,{withFileTypes:true})){const f=path.join(root,e.name);if(e.isSymbolicLink()&&allowSparkle&&isSparkleFrameworkLink(app,f))continue;assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory()){fs.chmodSync(f,0o755);publicModes(f,{app,allowSparkle})}else fs.chmodSync(f,fs.statSync(f).mode&0o111?0o755:0o644);}}
export function buildMacPreview(config){
 if(config?.nativeRuntime!==undefined)return prepareNativeMacPreview(config);
 assert(config&&typeof config==='object'&&!Object.keys(config).some(k=>!['destination','version','buildNumber','updateRelease','platformUpdate','releaseVersion','sourceRevision','nodeBinary','codexBinary','cuaBinary','sourceRoot','dependenciesDir','createDmg','tunnelBinary','sdkPath','moduleCachePath','localSigning','hostPublisher','prepareOnly'].includes(k)),'invalid_preview_configuration');
 const {destination,version,buildNumber,updateRelease=false,prepareOnly=false,platformUpdate,releaseVersion,sourceRevision,nodeBinary,codexBinary,cuaBinary,tunnelBinary,sdkPath,moduleCachePath,localSigning,hostPublisher,sourceRoot=ROOT,dependenciesDir=path.join(sourceRoot,'node_modules'),createDmg=true}=config;
 assert(typeof prepareOnly==='boolean','invalid_preview_prepare_mode');
 assert(!prepareOnly||(localSigning===undefined&&hostPublisher===undefined&&platformUpdate===undefined),'prepared_preview_requires_unsigned_native_inputs');
 const appMetadata=macAppBuildMetadata({version,buildNumber,updateRelease});
 // Current product Swift requires native metadata. Preserve the pure input
 // errors above, then refuse old new-build recipes before output/key/tool IO.
 assert(config.nativeRuntime!==undefined,'native_runtime_required_for_product_app');
 assert(process.platform==='darwin','native_macos_preview_build_required');
 const arch=process.arch,inputs=macPreviewInputs(arch);
 previewReleasePublisher({localSigning,hostPublisher});
 const signingReceipt=previewSigningReceipt(localSigning);
 for(const p of [destination,nodeBinary,codexBinary,cuaBinary,sourceRoot,dependenciesDir])assert(ABS(p),'absolute_preview_paths_required');
 assert(/^[a-f0-9]{40}$/.test(sourceRevision??'')&&typeof createDmg==='boolean','preview_revision_and_archive_selection_required');
 assert(!fs.existsSync(destination),'fresh_preview_destination_required');
 const sourceFiles=previewSourceFiles(sourceRoot,{revision:sourceRevision});
 const tunnelRecord=tunnelBinary===undefined?null:verifyPreviewTunnelInput(tunnelBinary);
 const nodeRecord=JSON.parse(fs.readFileSync(path.join(path.dirname(nodeBinary),'node-provenance.json'),'utf8'));
 assert(nodeRecord.version==='22.23.3'&&nodeRecord.platform==='darwin'&&nodeRecord.arch===arch&&nodeRecord.archive_sha256===inputs.nodeArchive&&nodeRecord.binary_sha256===sha(nodeBinary),'verified_original_node_input_required');
 return withPreviewHostPublisher(hostPublisher,({privateKey,privateFile,publicPem,fingerprint,publisherMode})=>{
 fs.mkdirSync(destination,{mode:0o700});const image=path.join(destination,'image-root');fs.mkdirSync(image);
 const app=path.join(image,'Styx.app'),resources=path.join(app,'Contents/Resources');
  const appBuild=buildMacApp({app,cuaBinary,version,buildNumber,updateRelease,platformUpdate,sdkPath,moduleCachePath:moduleCachePath??path.join(destination,'swift-module-cache'),...(localSigning===undefined?{}:{localSigning})});
  const source=path.join(resources,'onboarding/vnext');fs.mkdirSync(source,{recursive:true});
  for(const name of sourceFiles)tree(path.join(sourceRoot,...name.split('/')),path.join(source,...name.split('/')));
  fs.writeFileSync(path.join(resources,'source-files.json'),JSON.stringify({schema:1,revision:sourceRevision,files:sourceFiles.map(name=>({path:name,sha256:sha(path.join(sourceRoot,...name.split('/')))}))},null,2)+'\n');
  const dependencies=copyPreviewDependencies({sourceRoot,dependenciesDir,destination:source});
  const runtime=path.join(resources,'runtime');fs.mkdirSync(runtime);
  const coreHelper=prepareCoreHelper({app,nodeBinary,version,buildNumber:String(appMetadata.buildNumber)});
  fs.copyFileSync(path.join(path.dirname(nodeBinary),'LICENSE'),path.join(runtime,'LICENSE'));fs.copyFileSync(path.join(path.dirname(nodeBinary),'node-provenance.json'),path.join(runtime,'node-upstream.json'));
  const bundle=path.join(resources,'host-bundle');buildHostRelease({destination:bundle,version:releaseVersion,privateKeyFile:privateFile,codexBinary,cuaBinary,nodeBinary,sourceRoot,browserRuntime:true});
  fs.writeFileSync(path.join(resources,'publisher.pem'),publicPem);fs.writeFileSync(path.join(resources,'artifact-defaults.json'),JSON.stringify({bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256:fingerprint},null,2)+'\n');
  for(const name of sourceFiles.filter(n=>n.startsWith('licenses/')))tree(path.join(sourceRoot,...name.split('/')),path.join(resources,...name.split('/')));
  fs.copyFileSync(path.join(runtime,'LICENSE'),path.join(resources,'licenses/node-LICENSE'));
  if(tunnelRecord){
   fs.copyFileSync(tunnelBinary,path.join(runtime,'tunnel-client'));fs.chmodSync(path.join(runtime,'tunnel-client'),0o755);
   const notices=path.join(resources,'licenses/tunnel-client');fs.mkdirSync(notices);
   for(const name of Object.keys(inputs.notices))fs.copyFileSync(path.join(path.dirname(tunnelBinary),name),path.join(notices,name));
  }
  fs.writeFileSync(path.join(resources,'production-dependencies.json'),JSON.stringify({schema:1,sourceRevision,graph:'npm-package-lock-production',packages:dependencies},null,2)+'\n');
  const metadata={schema:1,kind:'prepared_native_preview',sourceRevision,version,buildNumber:appMetadata.buildNumber,updateRelease,releaseVersion,arch,appBuild,dependencies,nodeRecord,tunnelRecord,createDmg};
  if(prepareOnly){
   scanPrivateMaterial(app);const receipt={...metadata,files:preparedPreviewInventory(app),delivery:'NOT FINALIZED'};
   fs.writeFileSync(path.join(destination,'prepared-preview.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});return receipt;
  }
  return finishMacPreview({destination,app,metadata,localSigning,platformUpdate},{privateKey,publicPem,fingerprint,publisherMode});
 },{excludedRoots:[sourceRoot,dependenciesDir,destination]});
}
export function executeMacPreviewSigningPlan(steps,{run=execFileSync}={}){
 assert(Array.isArray(steps)&&steps.every(step=>Array.isArray(step)&&step.length===2&&step[0]==='/usr/bin/codesign'&&Array.isArray(step[1])&&step[1].every(arg=>typeof arg==='string')),'invalid_preview_signing_plan');
 for(const [command,args]of steps)run(command,args,{stdio:'pipe',timeout:30000});
}

// No executing target binaries is permitted when the signer is another architecture.
function finishMacPreview({destination,app,metadata,localSigning,platformUpdate},{privateKey,publicPem,fingerprint,publisherMode}){
 const {sourceRevision,version,buildNumber,updateRelease,releaseVersion,arch,appBuild,dependencies,nodeRecord,tunnelRecord,createDmg=true}=metadata;
 const appMetadata=macAppBuildMetadata({version,buildNumber,updateRelease}),signingReceipt=previewSigningReceipt(localSigning);
 const image=path.dirname(app),resources=path.join(app,'Contents/Resources'),runtime=path.join(resources,'runtime'),bundle=path.join(resources,'host-bundle');
 const coreHelper={executable:path.join(app,'Contents/Helpers/Styx Core.app/Contents/MacOS/Styx Core')};
 if(localSigning!==undefined)fs.writeFileSync(path.join(resources,'local-signing.json'),JSON.stringify(verifyMacLocalSigning(localSigning),null,2)+'\n');
 fs.writeFileSync(path.join(resources,'publisher.pem'),publicPem);
 fs.writeFileSync(path.join(resources,'artifact-defaults.json'),JSON.stringify({bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256:fingerprint},null,2)+'\n');
 for(const file of machOFiles(app,{preserveSparkle:platformUpdate!==undefined})){
  const actual=execFileSync('/usr/bin/lipo',['-archs',file],{encoding:'utf8',timeout:10000}).trim().split(/\s+/);
  assert(actual.includes(arch==='x64'?'x86_64':arch),'prepared_native_architecture_mismatch');
 }
  // One signing/finalization path for native and transported native builds.
  const plan=options=>localSigning===undefined?macAdhocSigningPlan(options):macLocalSigningPlan({...options,localSigning});
  const native=machOFiles(app,{preserveSparkle:platformUpdate!==undefined});executeMacPreviewSigningPlan(plan({app,files:native,sealApp:false}));
  const transformation=localSigning===undefined?'macos_adhoc_codesign':'macos_local_certificate_codesign';
  fs.writeFileSync(path.join(runtime,'node-provenance.json'),JSON.stringify({...nodeRecord,upstream_binary_sha256:nodeRecord.binary_sha256,binary_sha256:sha(coreHelper.executable),transformation,upstream_verification_record:'node-upstream.json'},null,2)+'\n');
  if(tunnelRecord)fs.writeFileSync(path.join(resources,'tunnel-client.json'),JSON.stringify({...tunnelRecord,path:'runtime/tunnel-client',upstream_binary_sha256:tunnelRecord.binary_sha256,binary_sha256:sha(path.join(runtime,'tunnel-client')),transformation},null,2)+'\n');
  finalizePreviewHostBundle(bundle,privateKey,{localSigning,publisherMode});verifySignedRelease(bundle,publicPem,{platform:'darwin',arch});
  scanPrivateMaterial(app,{allowSparkle:platformUpdate!==undefined});publicModes(app,{allowSparkle:platformUpdate!==undefined});executeMacPreviewSigningPlan(plan({app,files:[],sealApp:true}));
  if(arch===process.arch)execFileSync(coreHelper.executable,['--version'],{stdio:'pipe',timeout:10000});
  fs.writeFileSync(path.join(image,'READ-ME.txt'),'Styx developer preview — '+(localSigning===undefined?'ad-hoc signed':'signed with a persistent local development certificate')+', NOT notarized.\nMove Styx.app to /Applications before launching. macOS may require an explicit Open Anyway action.\nNo Apple Developer identity, automatic TCC grants, paid signing or public account connection is claimed.\nThe app includes runtime, offline dependencies and a local-build signed Host payload.\n');
  fs.symlinkSync('/Applications',path.join(image,'Applications'));
  const zip='Styx-'+releaseVersion+'-macos-'+arch+'.zip';execFileSync('/usr/bin/ditto',['-c','-k','--keepParent',app,path.join(destination,zip)],{stdio:'pipe',timeout:180000});
  const artifacts=[zip];if(createDmg){const dmg='Styx-'+releaseVersion+'-macos-'+arch+'.dmg';execFileSync('/usr/bin/hdiutil',['create','-volname','Styx Developer Preview','-srcfolder',image,'-format','UDZO',path.join(destination,dmg)],{stdio:'pipe',timeout:300000});artifacts.push(dmg);}
  const receipt={schema:1,kind:'precompiled_developer_preview',sourceRevision,version,buildNumber:appMetadata.buildNumber,buildNumberSource:appMetadata.buildNumberSource,updateRelease:appMetadata.updateRelease,releaseVersion,platform:'darwin',arch,...signingReceipt,compiler:appBuild.compiler,platformUpdate:appBuild.platformUpdate,publisher_spki_sha256:fingerprint,host_publisher_mode:publisherMode,production_packages:dependencies.length,browser_production_packages:dependencies.filter(record=>record.lockFile==='packages/styx-browser-provider/package-lock.json').length,tunnel_client:tunnelRecord?{version:tunnelRecord.version,archive_sha256:tunnelRecord.archive_sha256}:null,native_code_files:native.map(p=>path.relative(app,p).split(path.sep).join('/')),artifacts:artifacts.map(name=>({name,sha256:sha(path.join(destination,name)),bytes:fs.statSync(path.join(destination,name)).size})),native_ui_acceptance:'NOT RUN',cold_install:'NOT RUN',runtime_execution:arch===process.arch?'native_node_version_passed':'NOT RUN: target architecture differs from signing machine'};
  verifyPreviewArchives({destination,app,artifacts});
  fs.writeFileSync(path.join(destination,'preview-receipt.json'),JSON.stringify(receipt,null,2)+'\n');return receipt;
}

export function preparedPreviewInventory(app){
 assert(ABS(app)&&fs.realpathSync(app)===app&&fs.lstatSync(app).isDirectory(),'canonical_prepared_app_required');
 const files=[];
 function walk(dir,relative=''){for(const name of fs.readdirSync(dir).sort()){
  const file=path.join(dir,name),rel=relative?relative+'/'+name:name,st=fs.lstatSync(file);
  assert(!st.isSymbolicLink(),'distribution_symlink_forbidden');
  if(st.isDirectory()){files.push({path:rel,kind:'directory'});walk(file,rel)}
  else{assert(st.isFile(),'distribution_regular_files_required');files.push({path:rel,kind:'file',size:st.size,executable:!!(st.mode&0o111),sha256:sha(file)})}
 }}walk(app);return files;
}
export function verifyPreparedPreview(source,receiptSha256){
 assert(ABS(source)&&/^[a-f0-9]{64}$/.test(receiptSha256??''),'prepared_preview_pin_required');
 const file=path.join(source,'prepared-preview.json'),st=fs.lstatSync(file);
 assert(st.isFile()&&!st.isSymbolicLink()&&sha(file)===receiptSha256,'prepared_preview_receipt_changed');
 const metadata=JSON.parse(fs.readFileSync(file,'utf8')),app=path.join(source,'image-root/Styx.app');
 assert(metadata.schema===1&&metadata.kind==='prepared_native_preview'&&metadata.delivery==='NOT FINALIZED'&&/^[a-f0-9]{40}$/.test(metadata.sourceRevision??'')&&['arm64','x64'].includes(metadata.arch),'invalid_prepared_preview');
 assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'prepared_preview_contents_changed');
 const snapshot=JSON.parse(fs.readFileSync(path.join(app,'Contents/Resources/source-files.json'),'utf8'));
 assert(snapshot.revision===metadata.sourceRevision,'prepared_source_revision_mismatch');
 const host=path.join(app,'Contents/Resources/host-bundle'),publisher=fs.readFileSync(path.join(app,'Contents/Resources/publisher.pem'));
 const manifest=verifySignedRelease(host,publisher,{platform:'darwin',arch:metadata.arch});
 assert(manifest.version===metadata.releaseVersion,'prepared_host_version_mismatch');
 assert(!fs.existsSync(path.join(host,'provenance/node-upstream.json')),'prepared_preview_already_finalized');
 return {app,metadata};
}
function verifyPreviewArchives({destination,app,artifacts}){
 execFileSync('/usr/bin/codesign',['--verify','--deep','--strict',app],{stdio:'pipe',timeout:30000});
 for(const name of artifacts){
  const artifact=path.join(destination,name);
  if(name.endsWith('.zip'))execFileSync('/usr/bin/unzip',['-tq',artifact],{stdio:'pipe',timeout:180000});
  else{
   execFileSync('/usr/bin/hdiutil',['verify',artifact],{stdio:'pipe',timeout:180000});
   const mount=fs.mkdtempSync(path.join(destination,'verify-image-'));let attached=false;
   try{execFileSync('/usr/bin/hdiutil',['attach','-readonly','-nobrowse','-mountpoint',mount,artifact],{stdio:'pipe',timeout:90000});attached=true;
    execFileSync('/usr/bin/codesign',['--verify','--deep','--strict',path.join(mount,'Styx.app')],{stdio:'pipe',timeout:30000});
    assert(sha(path.join(mount,'Styx.app/Contents/Resources/source-files.json'))===sha(path.join(app,'Contents/Resources/source-files.json')),'mounted_preview_source_changed');
   }finally{if(attached)execFileSync('/usr/bin/hdiutil',['detach',mount],{stdio:'pipe',timeout:90000});fs.rmdirSync(mount)}
  }
 }
}
export function finalizeMacPreview(config){
 assert(process.platform==='darwin','native_macos_signing_required');
 assert(config&&Object.keys(config).every(k=>['preparedSource','preparedReceiptSha256','destination','localSigning','hostPublisher','expectedPublisherSha256','createDmg'].includes(k)),'invalid_preview_finalization_configuration');
 const {preparedSource,preparedReceiptSha256,destination,localSigning,hostPublisher,expectedPublisherSha256,createDmg=true}=config;
 assert(ABS(destination)&&!fs.existsSync(destination)&&typeof createDmg==='boolean','fresh_preview_destination_required');
 assert(localSigning!==undefined&&hostPublisher?.mode==='persistent'&&/^[a-f0-9]{64}$/.test(expectedPublisherSha256??''),'stable_preview_signing_required');
 previewReleasePublisher({localSigning,hostPublisher});
 const relative=path.relative(preparedSource,destination),reverse=path.relative(destination,preparedSource);
 const outside=p=>p==='..'||p.startsWith('..'+path.sep)||path.isAbsolute(p);
 assert(outside(relative)&&outside(reverse),'prepared_preview_destination_overlap');
 const {app:preparedApp,metadata}=verifyPreparedPreview(preparedSource,preparedReceiptSha256);
 return withPreviewHostPublisher(hostPublisher,keys=>{
  assert(keys.fingerprint===expectedPublisherSha256,'prepared_publisher_pin_mismatch');
  fs.mkdirSync(destination,{mode:0o700});const app=path.join(destination,'image-root/Styx.app');tree(preparedApp,app);
  assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'prepared_preview_copy_changed');
  return finishMacPreview({destination,app,metadata:{...metadata,createDmg},localSigning},keys);
 },{excludedRoots:[preparedSource,destination]});
}

// Native payload branch: no Node management, old worker manifest, publisher
// private key, legacy updater data or installer is adopted. Prepared output is
// unsigned, and cannot satisfy ProductOwnedCore's installed-App requirement.
export function prepareNativeMacPreview(config){
 assert(config&&Object.keys(config).every(k=>['destination','version','buildNumber','sourceRevision','cuaBinary','sdkPath','moduleCachePath','nativeRuntime','prepareOnly'].includes(k)),'invalid_native_app_configuration');
 const {destination,version,buildNumber,sourceRevision,cuaBinary,sdkPath,moduleCachePath,nativeRuntime,prepareOnly}=config;
 assert(prepareOnly===true&&process.platform==='darwin','native_app_prepare_only_required');
 assert(ABS(destination)&&!fs.existsSync(destination)&&/^[a-f0-9]{40}$/.test(sourceRevision??''),'fresh_native_app_destination_required');
 assert(nativeRuntime.expectedPublisher==='ebb36f9dff7022d8921443bdc30c6236d18dd0535aa2cdce838d1c5b327bab67','original_native_app_publisher_required');
 const observedSources=macNativeSwiftSources(),sourceFiles=Object.fromEntries([observedSources.source,...observedSources.additionalSources,path.join(ROOT,'host/macos/StyxUpdater.swift'),path.join(ROOT,'host/macos/render-brand-icons.swift')].map(file=>[path.relative(ROOT,file).split(path.sep).join('/'),sha(file)]));
 const verified=verifyNativeMacRuntime(nativeRuntime,process.arch);
 assert(sourceRevision===verified.report.source_revision,'native_app_source_revision_mismatch');
 fs.mkdirSync(destination,{mode:0o700});const app=path.join(destination,'image-root/Styx.app');
 const appBuild=buildMacApp({app,nativeRuntime:true,cuaBinary,version,buildNumber,sdkPath,moduleCachePath:moduleCachePath??path.join(destination,'swift-module-cache')});
 const resources=path.join(app,'Contents/Resources');
 const metadata={schema:1,nativeRuntime:copyNativeMacRuntime(nativeRuntime,resources,process.arch)};
 fs.writeFileSync(path.join(resources,'macos-runtime.json'),JSON.stringify(metadata,null,2)+'\n',{flag:'wx',mode:0o600});
 scanPrivateMaterial(app);
 const receipt={schema:1,kind:'prepared_native_rust_app',delivery:'NOT FINALIZED',sourceRevision,version,buildNumber,arch:process.arch,appBuild,
  sourceFiles,nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:verified.signatureSha256,runtimeSourceRevision:verified.report.source_revision,
  nativeUpdater:'native_handoff_blocked_no_legacy_core',readerActualWait:true,readerExitCode:0,files:preparedPreviewInventory(app),signing:'NOT RUN',native_gui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN'};
 assert(Object.entries(sourceFiles).every(([name,digest])=>sha(path.join(ROOT,...name.split('/')))===digest),'native_app_source_changed');
 fs.writeFileSync(path.join(destination,'prepared-native-app.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});return receipt;
}
// Artifact creation is after the App and C08 seals. No code is signed or
// changed here; mounting is verification, never an installation or App launch.
export function assertNativeMacAppInventory(app,expected){
 assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(expected),'native_archive_app_inventory_changed');
}
// A nonzero/timeout attach can still have mounted the image. Consult the
// platform's structured inventory before cleaning only our exact fresh mount.
export function withNativeMacDmgMount({image,mount,verification,run},inspect){
 const initial=fs.lstatSync(image,{bigint:true});
 assert(initial.isFile()&&!initial.isSymbolicLink(),'native_dmg_regular_image_required');
 const imageSha=sha(image);
 const parent=fs.lstatSync(mount,{bigint:true});
 assert(parent.isDirectory()&&!parent.isSymbolicLink()&&fs.readdirSync(mount).length===0,'native_dmg_fresh_mountpoint_required');
 verification.mountpoint=mount;verification.detachAttempted=false;verification.detached=false;
 let attached=false;
 try{
  run('/usr/bin/hdiutil',['attach','-readonly','-nobrowse','-mountpoint',mount,image],90000);attached=true;
  inspect();
 }finally{
  if(!attached){
   verification.failedAttachObservation='unknown';
   try{
    const plist=run('/usr/bin/hdiutil',['info','-plist'],30000);
    const info=JSON.parse(run('/usr/bin/plutil',['-convert','json','-o','-','-'],30000,plist));
    assert(info&&Array.isArray(info.images)&&info.images.length<=1024,'native_dmg_info_invalid');
    const matches=[];
    for(const entry of info.images){
     assert(entry&&typeof entry==='object'&&Array.isArray(entry['system-entities']),'native_dmg_info_invalid');
     for(const entity of entry['system-entities']){
      assert(entity&&typeof entity==='object','native_dmg_info_invalid');
      if(entity['mount-point']===mount)matches.push(entry);
     }
    }
    const current=fs.lstatSync(image,{bigint:true});
    assert(['dev','ino','size','mtimeNs','ctimeNs'].every(k=>current[k]===initial[k])&&sha(image)===imageSha,'native_dmg_image_changed');
    if(matches.length===1&&matches[0]['image-path']===image){
     verification.failedAttachObservation='exact_owned_image_mounted';attached=true;
    }else if(matches.length===0){
     const currentMount=fs.lstatSync(mount,{bigint:true});
     assert(currentMount.dev===parent.dev&&currentMount.ino===parent.ino&&fs.readdirSync(mount).length===0,'native_dmg_mountpoint_changed');
     verification.failedAttachObservation='not_mounted';
    }
   }catch{
    // Unknown is retained, not permission to detach some other image or force.
    verification.failedAttachObservation='unknown';
   }
  }
  if(attached){
   verification.detachAttempted=true;
   run('/usr/bin/hdiutil',['detach',mount],90000);
   verification.detached=true;
   fs.rmdirSync(mount);
  }
 }
}
function nativeMacArtifacts({destination,app,metadata,expectedPublisherSha256,createDmg=true}){
 assert(typeof createDmg==='boolean','invalid_native_create_dmg');
 const files=preparedPreviewInventory(app),observations=[];
 const verification={schema:1,status:'FAIL',readonlyMount:true,appLaunched:false,observations};
 const run=(command,args,timeout=30000,input)=>{
  const fact={command:[command,...args],actualWait:false,exitCode:null};observations.push(fact);
  try{const output=execFileSync(command,args,{stdio:'pipe',timeout,input,maxBuffer:1048576});fact.actualWait=true;fact.exitCode=0;return output;}
  catch(error){fact.actualWait=Number.isInteger(error.status);fact.exitCode=error.status??null;fact.signal=error.signal??null;throw error;}
 };
 const inputFor=target=>({payloadDir:path.join(target,'Contents/Resources/native'),publisherFile:path.join(target,'Contents/Resources/native-publisher.pem'),expectedPublisher:expectedPublisherSha256});
 const original=authenticateNativeMacRuntimeEnvelope(inputFor(app),metadata.arch);
 const check=target=>{
  assertNativeMacAppInventory(target,files);
  run('/usr/bin/codesign',['--verify','--deep','--strict',target]);
  run('/usr/bin/codesign',['--verify','--strict','-R',`=identifier "${MAC_BUNDLE_ID}" and certificate leaf = H"cb50cee601419f28b43756f4fc8aefdbf60abae2"`,target]);
  const copied=authenticateNativeMacRuntimeEnvelope(inputFor(target),metadata.arch);
  assert(copied.manifestSha256===original.manifestSha256&&copied.signatureSha256===original.signatureSha256&&copied.cliSha256===original.cliSha256&&copied.publisherSha256===original.publisherSha256,'native_archive_c08_changed');
  assertNativeMacAppInventory(target,files);
 };
 try{
  check(app);
  const zip='Styx-'+metadata.version+'-native-macos-'+metadata.arch+'.zip';
  run('/usr/bin/ditto',['-c','-k','--keepParent',app,path.join(destination,zip)],180000);
  run('/usr/bin/unzip',['-tq',path.join(destination,zip)],180000);
  const names=[zip];let primaryArtifact=zip;
  if(createDmg){
   const image=path.dirname(app);
   fs.symlinkSync('/Applications',path.join(image,'Applications'));
   fs.writeFileSync(path.join(image,'READ-ME.txt'),'Drag Styx.app to Applications, then open it from Applications.\nThis development build uses the original local signing identity and is not notarized.\nPKG is only for explicit advanced persistent-service installation or repair.\n',{flag:'wx',mode:0o644});
   const dmg='Styx-'+metadata.version+'-native-macos-'+metadata.arch+'.dmg';
   run('/usr/bin/hdiutil',['create','-volname','Styx','-srcfolder',image,'-format','UDZO',path.join(destination,dmg)],300000);
   run('/usr/bin/hdiutil',['verify',path.join(destination,dmg)],180000);
   const mount=fs.mkdtempSync(path.join(destination,'verify-native-image-'));
   withNativeMacDmgMount({image:path.join(destination,dmg),mount,verification,run},()=>{
    const link=path.join(mount,'Applications');assert(fs.lstatSync(link).isSymbolicLink()&&fs.readlinkSync(link)==='/Applications','native_dmg_applications_link_changed');
    assert(fs.readFileSync(path.join(mount,'READ-ME.txt'),'utf8')===fs.readFileSync(path.join(image,'READ-ME.txt'),'utf8'),'native_dmg_instructions_changed');
    check(path.join(mount,'Styx.app'));
   });
   names.push(dmg);primaryArtifact=dmg;
  }
  assertNativeMacAppInventory(app,files);
  verification.status='PASS';
  return {primaryArtifact,installMethod:createDmg?'drag_to_applications':'internal_transport_only',artifacts:names.map(name=>({name,sha256:sha(path.join(destination,name)),bytes:fs.statSync(path.join(destination,name)).size})),archiveVerification:verification};
 }finally{
  fs.writeFileSync(path.join(destination,'native-archive-verification.json'),JSON.stringify(verification,null,2)+'\n',{flag:'wx',mode:0o600});
 }
}
export function finalizeNativeMacPreview(config){
 assert(process.platform==='darwin','native_macos_signing_required');
 assert(config&&Object.keys(config).every(k=>['nativePreparedSource','preparedReceiptSha256','destination','localSigning','expectedPublisherSha256','crossArchSignOnly','createDmg'].includes(k)),'invalid_native_app_finalization');
 const {nativePreparedSource,preparedReceiptSha256,destination,localSigning,expectedPublisherSha256,crossArchSignOnly=false,createDmg=true}=config;
 assert(typeof crossArchSignOnly==='boolean'&&typeof createDmg==='boolean','invalid_cross_arch_sign_only');
 assert(ABS(nativePreparedSource)&&ABS(destination)&&!fs.existsSync(destination)&&/^[a-f0-9]{64}$/.test(preparedReceiptSha256??'')&&/^[a-f0-9]{64}$/.test(expectedPublisherSha256??''),'native_app_finalization_inputs_required');
 const relative=path.relative(nativePreparedSource,destination),reverse=path.relative(destination,nativePreparedSource),outside=p=>p==='..'||p.startsWith('..'+path.sep)||path.isAbsolute(p);
 assert(outside(relative)&&outside(reverse),'native_app_destination_overlap');
 const local=normalizeMacLocalSigning(localSigning);
 // This bridge preserves the exact retained rc12 identity; no replacement
 // signing certificate or new publisher is inferred from candidate bytes.
 assert(local.identitySha1==='cb50cee601419f28b43756f4fc8aefdbf60abae2'&&local.certificateSha256==='90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e'&&expectedPublisherSha256==='ebb36f9dff7022d8921443bdc30c6236d18dd0535aa2cdce838d1c5b327bab67','original_native_app_identity_required');
 const receiptPath=path.join(nativePreparedSource,'prepared-native-app.json');assert(sha(receiptPath)===preparedReceiptSha256,'prepared_native_app_receipt_changed');
 const metadata=JSON.parse(fs.readFileSync(receiptPath,'utf8')),originalApp=path.join(nativePreparedSource,'image-root/Styx.app');
 assert(metadata.schema===1&&metadata.kind==='prepared_native_rust_app'&&metadata.delivery==='NOT FINALIZED'&&(crossArchSignOnly?metadata.arch==='x64'&&process.arch==='arm64':metadata.arch===process.arch)&&metadata.readerActualWait===true&&metadata.readerExitCode===0&&metadata.nativeRuntime.publisherSpkiSha256===expectedPublisherSha256&&JSON.stringify(preparedPreviewInventory(originalApp))===JSON.stringify(metadata.files),'prepared_native_app_changed');
 const inputFor=app=>({payloadDir:path.join(app,'Contents/Resources/native'),publisherFile:path.join(app,'Contents/Resources/native-publisher.pem'),expectedPublisher:expectedPublisherSha256});
 const inspect=crossArchSignOnly?authenticateNativeMacRuntimeEnvelope:verifyNativeMacRuntime;
 const protectedNative=app=>preparedPreviewInventory(app).filter(row=>row.path==='Contents/Resources/native'||row.path.startsWith('Contents/Resources/native/')||row.path==='Contents/Resources/native-publisher.pem'||row.path==='Contents/Resources/macos-runtime.json');
 const nativeInventory=protectedNative(originalApp);
 const original=inspect(inputFor(originalApp),metadata.arch);
 assert(original.manifestSha256===metadata.nativeRuntime.manifestSha256&&original.signatureSha256===metadata.nativeSignatureSha256,'prepared_native_manifest_changed');
 fs.mkdirSync(destination,{mode:0o700});const app=path.join(destination,'image-root/Styx.app');tree(originalApp,app);
 // Historical tree() does not retain file modes; restore exact prepared mode
 // metadata explicitly below (snapshot contains execute bits, no public chmod).
 fs.chmodSync(path.join(app,'Contents/Resources'),0o700);
 for(const row of metadata.files){const file=path.join(app,...row.path.split('/'));if(row.kind==='directory')fs.chmodSync(file,row.path.startsWith('Contents/Resources')?0o700:0o755);else fs.chmodSync(file,row.executable?0o700:0o600);}
 assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'prepared_native_copy_changed');
 const resources=path.join(app,'Contents/Resources'),nativeRoot=path.join(resources,'native');
 verifyMacLocalSigning(localSigning);
 fs.writeFileSync(path.join(resources,'local-signing.json'),JSON.stringify(publicMacLocalSigning(localSigning),null,2)+'\n',{flag:'wx',mode:0o600});
 const native=machOFiles(app),sealed=native.filter(file=>file.startsWith(nativeRoot+path.sep)),unsigned=native.filter(file=>!file.startsWith(nativeRoot+path.sep));
 // A publisher-sealed runtime is immutable. All nested Mach-O must already have
 // the original platform signature; reject instead of codesigning sealed bytes.
 for(const file of sealed)execFileSync('/usr/bin/codesign',['--verify','--strict','-R',`=certificate leaf = H"${local.identitySha1}"`,file],{stdio:'pipe',timeout:30000});
 executeMacPreviewSigningPlan(macLocalSigningPlan({app,localSigning,files:unsigned,sealApp:false}));
 const copied=inspect(inputFor(app),metadata.arch);
 assert(copied.manifestSha256===original.manifestSha256&&copied.signatureSha256===original.signatureSha256&&copied.cliSha256===original.cliSha256,'sealed_native_payload_changed');
 scanPrivateMaterial(app);executeMacPreviewSigningPlan(macLocalSigningPlan({app,localSigning,files:[],sealApp:true}));
 const after=inspect(inputFor(app),metadata.arch);
 assert(after.manifestSha256===original.manifestSha256&&after.signatureSha256===original.signatureSha256,'sealed_native_payload_changed');
 assert(JSON.stringify(protectedNative(app))===JSON.stringify(nativeInventory),'sealed_native_inventory_changed');
 if(crossArchSignOnly){
  // No foreign CLI executes on this machine. This receipt is deliberately
  // pending and cannot be consumed as a final native App delivery.
  const pending={schema:1,kind:'signed_native_rust_app_pending_native_verification',status:'SIGNED_PENDING_NATIVE_VERIFICATION',delivery:'NOT FINALIZED',
   sourceRevision:metadata.sourceRevision,runtimeSourceRevision:metadata.runtimeSourceRevision,sourceFiles:metadata.sourceFiles,
   arch:metadata.arch,version:metadata.version,buildNumber:metadata.buildNumber,compiler:metadata.appBuild.compiler,
   nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:after.signatureSha256,preparedReceiptSha256,
   ...previewSigningReceipt(localSigning),files:preparedPreviewInventory(app),
   sealedRuntimeCodesign:'verified_only_never_resigned',coreManagementRuntime:'owned_rust_stdio_no_node_core',
   nativeReaderActualWait:false,nativeReaderExitCode:null,native_ui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN',installation:'NOT RUN'};
  fs.writeFileSync(path.join(destination,'signed-pending-app.json'),JSON.stringify(pending,null,2)+'\n',{flag:'wx',mode:0o600});return pending;
 }
 const archives=nativeMacArtifacts({destination,app,metadata,expectedPublisherSha256,createDmg});
 const receipt={schema:1,kind:'native_rust_local_certificate_preview',app,sourceRevision:metadata.sourceRevision,runtimeSourceRevision:metadata.runtimeSourceRevision,
  sourceFiles:metadata.sourceFiles,nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:after.signatureSha256,...previewSigningReceipt(localSigning),compiler:metadata.appBuild.compiler,
  sealedRuntimeCodesign:'verified_only_never_resigned',coreManagementRuntime:'owned_rust_stdio_no_node_core',nativeReaderActualWait:true,nativeReaderExitCode:0,
  ...archives,native_ui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN',installation:'NOT RUN'};
 fs.writeFileSync(path.join(destination,'native-app-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});return receipt;
}
// Native completion is read/verify/copy/package only. It never signs or opens
// a private key, and never treats a cross-machine pending receipt as readiness.
export function completeNativeMacPreview(config){
 assert(process.platform==='darwin','native_macos_completion_required');
 assert(config&&Object.keys(config).every(k=>['signedPendingSource','pendingReceiptSha256','destination','expectedPublisherSha256','createDmg'].includes(k)),'invalid_native_app_completion');
 const {signedPendingSource,pendingReceiptSha256,destination,expectedPublisherSha256,createDmg=true}=config;
 assert(typeof createDmg==='boolean','invalid_native_create_dmg');
 assert(ABS(signedPendingSource)&&ABS(destination)&&!fs.existsSync(destination)&&/^[a-f0-9]{64}$/.test(pendingReceiptSha256??'')&&expectedPublisherSha256==='ebb36f9dff7022d8921443bdc30c6236d18dd0535aa2cdce838d1c5b327bab67','native_app_completion_inputs_required');
 const relative=path.relative(signedPendingSource,destination),reverse=path.relative(destination,signedPendingSource),outside=p=>p==='..'||p.startsWith('..'+path.sep)||path.isAbsolute(p);
 assert(outside(relative)&&outside(reverse),'native_app_destination_overlap');
 const receiptPath=path.join(signedPendingSource,'signed-pending-app.json');requirePrivateFile(receiptPath);assert(sha(receiptPath)===pendingReceiptSha256,'signed_pending_receipt_changed');
 const metadata=JSON.parse(fs.readFileSync(receiptPath,'utf8')),originalApp=path.join(signedPendingSource,'image-root/Styx.app');
 assert(metadata.schema===1&&metadata.kind==='signed_native_rust_app_pending_native_verification'&&metadata.status==='SIGNED_PENDING_NATIVE_VERIFICATION'&&metadata.delivery==='NOT FINALIZED'&&metadata.arch===process.arch&&metadata.nativeReaderActualWait===false&&metadata.nativeReaderExitCode===null&&metadata.nativeRuntime.publisherSpkiSha256===expectedPublisherSha256&&JSON.stringify(preparedPreviewInventory(originalApp))===JSON.stringify(metadata.files),'signed_pending_app_changed');
 const local=metadata.local_signing;
 assert(local?.schema===1&&local.certificateSha1==='cb50cee601419f28b43756f4fc8aefdbf60abae2'&&local.certificateSha256==='90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e','original_native_app_identity_required');
 const inputFor=app=>({payloadDir:path.join(app,'Contents/Resources/native'),publisherFile:path.join(app,'Contents/Resources/native-publisher.pem'),expectedPublisher:expectedPublisherSha256});
 const requirement=`=identifier "${MAC_BUNDLE_ID}" and certificate leaf = H"${local.certificateSha1}"`;
 const observations=[];
 const run=(command,args,timeout=30000)=>{execFileSync(command,args,{stdio:'pipe',timeout});observations.push({command:[command,...args],actualWait:true,exitCode:0});};
 // Verify the original App before executing even its authenticated reader.
 run('/usr/bin/codesign',['--verify','--deep','--strict',originalApp]);
 run('/usr/bin/codesign',['--verify','--strict','-R',requirement,originalApp]);
 for(const file of machOFiles(originalApp))run('/usr/bin/codesign',['--verify','--strict','-R',`=certificate leaf = H"${local.certificateSha1}"`,file]);
 fs.mkdirSync(destination,{mode:0o700});
 const prefix=path.join(destination,'app-signing-certificate-');run('/usr/bin/codesign',['-d','--extract-certificates='+prefix,originalApp]);
 const certificate=prefix+'0',st=fs.lstatSync(certificate);
 assert(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=65536&&st.uid===process.getuid()&&!(st.mode&0o022)&&sha(certificate)===local.certificateSha256,'original_native_app_certificate_mismatch');
 const original=verifyNativeMacRuntime(inputFor(originalApp),metadata.arch);
 assert(original.manifestSha256===metadata.nativeRuntime.manifestSha256&&original.signatureSha256===metadata.nativeSignatureSha256&&original.cliSha256===metadata.nativeRuntime.cliSha256&&original.report.source_revision===metadata.runtimeSourceRevision&&original.report.source_revision===metadata.sourceRevision,'signed_pending_native_binding_changed');
 const app=path.join(destination,'image-root/Styx.app');tree(originalApp,app);fs.chmodSync(path.join(app,'Contents/Resources'),0o700);
 for(const row of metadata.files){const file=path.join(app,...row.path.split('/'));if(row.kind==='directory')fs.chmodSync(file,row.path.startsWith('Contents/Resources')?0o700:0o755);else fs.chmodSync(file,row.executable?0o700:0o600);}
 assert(JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'signed_native_copy_changed');
 run('/usr/bin/codesign',['--verify','--deep','--strict',app]);
 run('/usr/bin/codesign',['--verify','--strict','-R',requirement,app]);
 const copied=verifyNativeMacRuntime(inputFor(app),metadata.arch);
 assert(copied.manifestSha256===original.manifestSha256&&copied.signatureSha256===original.signatureSha256&&copied.cliSha256===original.cliSha256,'sealed_native_payload_changed');
 scanPrivateMaterial(app);
 const archives=nativeMacArtifacts({destination,app,metadata,expectedPublisherSha256,createDmg});
 assert(sha(receiptPath)===pendingReceiptSha256&&JSON.stringify(preparedPreviewInventory(originalApp))===JSON.stringify(metadata.files)&&JSON.stringify(preparedPreviewInventory(app))===JSON.stringify(metadata.files),'signed_native_inputs_changed');
 const receipt={schema:1,kind:'native_rust_local_certificate_preview',app,sourceRevision:metadata.sourceRevision,runtimeSourceRevision:metadata.runtimeSourceRevision,
  sourceFiles:metadata.sourceFiles,nativeRuntime:metadata.nativeRuntime,nativeSignatureSha256:copied.signatureSha256,
  signing:'local_certificate_preview',notarization:'NOT RUN',local_signing:local,private_key_in_artifact:false,compiler:metadata.compiler,
  completion:'native_architecture_verification_after_original_cross_signing',signedPendingReceiptSha256:pendingReceiptSha256,
  sealedRuntimeCodesign:'verified_only_never_resigned',coreManagementRuntime:'owned_rust_stdio_no_node_core',nativeReaderActualWait:true,nativeReaderExitCode:0,
  nativeVerification:observations,...archives,native_ui_acceptance:'NOT RUN',tcc_attribution:'NOT RUN',installation:'NOT RUN'};
 fs.writeFileSync(path.join(destination,'native-app-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o600});return receipt;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 try{assert(process.argv.length===3&&ABS(process.argv[2]),'usage_absolute_preview_config');const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));console.log(JSON.stringify(config.signedPendingSource?completeNativeMacPreview(config):config.nativePreparedSource?finalizeNativeMacPreview(config):config.preparedSource?finalizeMacPreview(config):buildMacPreview(config)));}
 catch{console.error('Styx developer preview build failed; preserve incomplete output for inspection.');process.exitCode=2;}
}
