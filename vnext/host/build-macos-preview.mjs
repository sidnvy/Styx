// Native self-contained precompiled developer preview. No Apple Developer account,
// notarization, existing application installation or private-key distribution.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,generateKeyPairSync,createPublicKey,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {buildMacApp,macAdhocSigningPlan} from './build-macos-app.mjs';
import {buildHostRelease} from './build-host-release.mjs';
import {verifySignedRelease} from './installer.mjs';
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
 const tops=new Set(['onboarding','gateway','host','shared','packages','licenses','plugin']);
 return files.filter(name=>{const parts=name.split('/');assert(parts.every(x=>x&&x!=='.'&&x!=='..')&&!name.includes('\\'),'invalid_source_snapshot_path');return (tops.has(parts[0])||['package.json','package-lock.json'].includes(name))&&!name.endsWith('.test.mjs')&&!parts.some(p=>p.startsWith('.')||SKIP.has(p));}).sort();
}
function scanPrivateMaterial(root){
 function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(file);else{assert(!['admin.token','model.token','device.token','identity.pem','publisher-private.pem'].includes(e.name),'private_material_filename_in_distribution');const bytes=fs.readFileSync(file);assert(!/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]/.test(bytes.toString('utf8')),'private_key_in_distribution');}}}walk(root);
}
export function copyOfflineDependencies({lockFile,dependenciesDir,destination}){
 const lock=JSON.parse(fs.readFileSync(lockFile,'utf8'));assert(lock.lockfileVersion===3&&lock.packages,'locked_npm_graph_required');
 const selected=Object.entries(lock.packages).filter(([name,p])=>name&&name.startsWith('node_modules/')&&!p.dev).sort(([a],[b])=>a.localeCompare(b));
 const records=[];
 for(const [name,pin]of selected){
  assert(name.split('/').every(x=>x&&x!=='.'&&x!=='..')&&!name.includes('\\'),'invalid_locked_package_path');
  const relative=name.slice('node_modules/'.length),source=path.join(dependenciesDir,...relative.split('/'));
  if(!fs.existsSync(source)){assert(pin.optional,'required_production_dependency_missing');continue;}
  assert(!pin.link&&typeof pin.integrity==='string'&&typeof pin.version==='string','registry_locked_dependency_required');
  const pkg=JSON.parse(fs.readFileSync(path.join(source,'package.json'),'utf8'));assert(pkg.version===pin.version,'installed_dependency_version_mismatch');
  tree(source,path.join(destination,...name.split('/')),{skip:n=>n==='node_modules'||n.startsWith('.')||['test','tests','__tests__','fixtures','examples','benchmarks'].includes(n)});
  records.push({path:name,version:pin.version,integrity:pin.integrity});
 }
 for(const name of ['@modelcontextprotocol/sdk','ws'])assert(records.some(r=>r.path==='node_modules/'+name),'onboarding_production_dependency_missing');
 return records;
}
export function machOFiles(root){
 const files=[];
 function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const file=path.join(dir,e.name);assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(file);else{assert(e.isFile(),'distribution_regular_files_required');const fd=fs.openSync(file,'r'),head=Buffer.alloc(8);let n;try{n=fs.readSync(fd,head,0,8,0)}finally{fs.closeSync(fd)}if(n>=4&&['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca'].includes(head.subarray(0,4).toString('hex')))files.push(file);}}}
 walk(root);return files.sort();
}
export function finalizePreviewHostBundle(root,privateKey){
 const m=JSON.parse(fs.readFileSync(path.join(root,'manifest.json'),'utf8'));
 const provenance=path.join(root,'provenance/node.json'),original=JSON.parse(fs.readFileSync(provenance,'utf8'));
 fs.writeFileSync(path.join(root,'provenance/node-upstream.json'),JSON.stringify(original,null,2)+'\n',{flag:'wx'});
 fs.writeFileSync(provenance,JSON.stringify({...original,upstream_binary_sha256:original.binary_sha256,binary_sha256:sha(path.join(root,'bin/node')),transformation:'macos_adhoc_codesign_after_verified_upstream_input',upstream_verification_record:'node-upstream.json'},null,2)+'\n');
 fs.writeFileSync(path.join(root,'provenance/macos-preview.json'),JSON.stringify({schema:1,signing:'adhoc',notarization:'NOT RUN',publisher_trust:'ephemeral_local_build_key_not_developer_id',native_binary_transformation:'codesign_before_final_release_manifest'},null,2)+'\n',{flag:'wx'});
 const names=[];function walk(dir,prefix=''){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const rel=prefix+e.name;assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory())walk(path.join(dir,e.name),rel+'/');else{assert(e.isFile(),'distribution_regular_files_required');if(!['manifest.json','manifest.sig'].includes(rel))names.push(rel);}}}walk(root);
 const prior=new Map(m.files.map(x=>[x.path,x]));
 m.files=names.sort().map(name=>({path:name,sha256:sha(path.join(root,...name.split('/'))),size:fs.statSync(path.join(root,...name.split('/'))).size,executable:prior.get(name)?.executable??false}));
 const raw=JSON.stringify(m,null,2)+'\n';fs.writeFileSync(path.join(root,'manifest.json'),raw);fs.writeFileSync(path.join(root,'manifest.sig'),sign(null,Buffer.from(raw),privateKey).toString('base64url')+'\n');
 return m;
}
// Verified from openai/tunnel-client v0.0.16 darwin-arm64 release archive.
export const TUNNEL_PREVIEW_PIN=Object.freeze({version:'0.0.16',platform:'darwin',arch:'arm64',archive_sha256:'a160820d45089b5253d8d671fe2a689bde0f73d78c135d1497a7b33f28a3ac62',binary_sha256:'6f1e8d5494d6c4d6c45cd4f6e07b5291459c0b23f4b8cd8266c7a64be3d9a2a0',source:'https://github.com/openai/tunnel-client/releases/tag/v0.0.16'});
const TUNNEL_NOTICES=Object.freeze({'LICENSE':'f4c1d7ba32ef5bcf5cf03e2eefec5825ebafedf50fa330a36700a49c605c1ef4','NOTICE':'1364c020d86ecf948b78b7c655175032068203d13aece70fb0bfe112d7802dc2','tunnel-client-v0.0.16-darwin-arm64-licenses.txt':'88cb2f313e4d12adc110cc5ebd9d626a5b4aae3874bb4abf386fdda59c215062','tunnel-client-v0.0.16-darwin-arm64.spdx.json':'2d116935e74f5571a0880e7d1ccda1ffe57332ab8b8b5f0a1fe447b58502457a'});
export function verifyPreviewTunnelInput(binary){
 assert(ABS(binary),'absolute_tunnel_binary_required');
 for(const [file,pin] of [[binary,TUNNEL_PREVIEW_PIN.binary_sha256],...Object.entries(TUNNEL_NOTICES).map(([name,pin])=>[path.join(path.dirname(binary),name),pin])]){
  const st=fs.lstatSync(file);assert(st.isFile()&&!st.isSymbolicLink()&&sha(file)===pin,'verified_original_tunnel_input_required');
 }
 return {...TUNNEL_PREVIEW_PIN};
}
function publicModes(root){for(const e of fs.readdirSync(root,{withFileTypes:true})){const f=path.join(root,e.name);assert(!e.isSymbolicLink(),'distribution_symlink_forbidden');if(e.isDirectory()){fs.chmodSync(f,0o755);publicModes(f)}else fs.chmodSync(f,fs.statSync(f).mode&0o111?0o755:0o644);}}
export function buildMacPreview(config){
 assert(process.platform==='darwin'&&process.arch==='arm64','native_arm64_macos_preview_build_required');
 assert(config&&typeof config==='object'&&!Object.keys(config).some(k=>!['destination','version','releaseVersion','sourceRevision','nodeBinary','codexBinary','cuaBinary','sourceRoot','dependenciesDir','createDmg','tunnelBinary'].includes(k)),'invalid_preview_configuration');
 const {destination,version,releaseVersion,sourceRevision,nodeBinary,codexBinary,cuaBinary,tunnelBinary,sourceRoot=ROOT,dependenciesDir=path.join(sourceRoot,'node_modules'),createDmg=true}=config;
 for(const p of [destination,nodeBinary,codexBinary,cuaBinary,sourceRoot,dependenciesDir])assert(ABS(p),'absolute_preview_paths_required');
 assert(/^[a-f0-9]{40}$/.test(sourceRevision??'')&&typeof createDmg==='boolean','preview_revision_and_archive_selection_required');
 assert(!fs.existsSync(destination),'fresh_preview_destination_required');
 const sourceFiles=previewSourceFiles(sourceRoot,{revision:sourceRevision});
 const tunnelRecord=tunnelBinary===undefined?null:verifyPreviewTunnelInput(tunnelBinary);
 const nodeRecord=JSON.parse(fs.readFileSync(path.join(path.dirname(nodeBinary),'node-provenance.json'),'utf8'));
 assert(nodeRecord.version==='22.23.3'&&nodeRecord.platform==='darwin'&&nodeRecord.arch==='arm64'&&nodeRecord.archive_sha256==='23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53'&&nodeRecord.binary_sha256===sha(nodeBinary),'verified_original_node_input_required');
 fs.mkdirSync(destination,{mode:0o700});const image=path.join(destination,'image-root');fs.mkdirSync(image);
 const app=path.join(image,'Styx.app'),resources=path.join(app,'Contents/Resources'),privateRoot=fs.mkdtempSync(path.join(os.tmpdir(),'styx-preview-publisher-'));fs.chmodSync(privateRoot,0o700);
 try{
  const {publicKey,privateKey}=generateKeyPairSync('ed25519'),privateFile=path.join(privateRoot,'publisher-private.pem');
  fs.writeFileSync(privateFile,privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
  buildMacApp({app,cuaBinary,version});
  const source=path.join(resources,'onboarding/vnext');fs.mkdirSync(source,{recursive:true});
  for(const name of sourceFiles)tree(path.join(sourceRoot,...name.split('/')),path.join(source,...name.split('/')));
  fs.writeFileSync(path.join(resources,'source-files.json'),JSON.stringify({schema:1,revision:sourceRevision,files:sourceFiles.map(name=>({path:name,sha256:sha(path.join(sourceRoot,...name.split('/')))}))},null,2)+'\n');
  const dependencies=copyOfflineDependencies({lockFile:path.join(sourceRoot,'package-lock.json'),dependenciesDir,destination:source});
  const runtime=path.join(resources,'runtime');fs.mkdirSync(runtime);fs.copyFileSync(nodeBinary,path.join(runtime,'node'));fs.chmodSync(path.join(runtime,'node'),0o755);
  fs.copyFileSync(path.join(path.dirname(nodeBinary),'LICENSE'),path.join(runtime,'LICENSE'));fs.copyFileSync(path.join(path.dirname(nodeBinary),'node-provenance.json'),path.join(runtime,'node-upstream.json'));
  const bundle=path.join(resources,'host-bundle');buildHostRelease({destination:bundle,version:releaseVersion,privateKeyFile:privateFile,codexBinary,cuaBinary,nodeBinary,sourceRoot});
  const publicPem=publicKey.export({type:'spki',format:'pem'}),fingerprint=createHash('sha256').update(createPublicKey(publicPem).export({type:'spki',format:'der'})).digest('hex');
  fs.writeFileSync(path.join(resources,'publisher.pem'),publicPem);fs.writeFileSync(path.join(resources,'artifact-defaults.json'),JSON.stringify({bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256:fingerprint},null,2)+'\n');
  for(const name of sourceFiles.filter(n=>n.startsWith('licenses/')))tree(path.join(sourceRoot,...name.split('/')),path.join(resources,...name.split('/')));
  fs.copyFileSync(path.join(runtime,'LICENSE'),path.join(resources,'licenses/node-LICENSE'));
  if(tunnelRecord){
   fs.copyFileSync(tunnelBinary,path.join(runtime,'tunnel-client'));fs.chmodSync(path.join(runtime,'tunnel-client'),0o755);
   const notices=path.join(resources,'licenses/tunnel-client');fs.mkdirSync(notices);
   for(const name of Object.keys(TUNNEL_NOTICES))fs.copyFileSync(path.join(path.dirname(tunnelBinary),name),path.join(notices,name));
  }
  fs.writeFileSync(path.join(resources,'production-dependencies.json'),JSON.stringify({schema:1,sourceRevision,graph:'npm-package-lock-production',packages:dependencies},null,2)+'\n');
  // Sign native payload bytes first; Ed25519 then covers their transformed bytes.
  const native=machOFiles(app);for(const [command,args]of macAdhocSigningPlan({app,files:native,sealApp:false}))execFileSync(command,args,{stdio:'pipe',timeout:30000});
  fs.writeFileSync(path.join(runtime,'node-provenance.json'),JSON.stringify({...nodeRecord,upstream_binary_sha256:nodeRecord.binary_sha256,binary_sha256:sha(path.join(runtime,'node')),transformation:'macos_adhoc_codesign',upstream_verification_record:'node-upstream.json'},null,2)+'\n');
  if(tunnelRecord)fs.writeFileSync(path.join(resources,'tunnel-client.json'),JSON.stringify({...tunnelRecord,path:'runtime/tunnel-client',upstream_binary_sha256:tunnelRecord.binary_sha256,binary_sha256:sha(path.join(runtime,'tunnel-client')),transformation:'macos_adhoc_codesign'},null,2)+'\n');
  finalizePreviewHostBundle(bundle,privateKey);verifySignedRelease(bundle,publicPem);
  scanPrivateMaterial(app);publicModes(app);for(const [command,args]of macAdhocSigningPlan({app,files:[],sealApp:true}))execFileSync(command,args,{stdio:'pipe',timeout:30000});
  execFileSync(path.join(runtime,'node'),['--version'],{stdio:'pipe',timeout:10000});
  fs.writeFileSync(path.join(image,'READ-ME.txt'),'Styx developer preview — ad-hoc signed, NOT notarized.\nMove Styx.app to /Applications before launching. macOS may require an explicit Open Anyway action.\nNo Apple Developer identity, automatic TCC grants, paid signing or public account connection is claimed.\nThe app includes runtime, offline dependencies and a local-build signed Host payload.\n');
  fs.symlinkSync('/Applications',path.join(image,'Applications'));
  const zip='Styx-'+releaseVersion+'-macos-arm64.zip';execFileSync('/usr/bin/ditto',['-c','-k','--keepParent',app,path.join(destination,zip)],{stdio:'pipe',timeout:180000});
  const artifacts=[zip];if(createDmg){const dmg='Styx-'+releaseVersion+'-macos-arm64.dmg';execFileSync('/usr/bin/hdiutil',['create','-volname','Styx Developer Preview','-srcfolder',image,'-format','UDZO',path.join(destination,dmg)],{stdio:'pipe',timeout:300000});artifacts.push(dmg);}
  const receipt={schema:1,kind:'precompiled_developer_preview',sourceRevision,version,releaseVersion,platform:'darwin',arch:'arm64',signing:'adhoc_preview',notarization:'NOT RUN',external_publisher_identity:'NOT ESTABLISHED',private_key_in_artifact:false,publisher_spki_sha256:fingerprint,production_packages:dependencies.length,tunnel_client:tunnelRecord?{version:tunnelRecord.version,archive_sha256:tunnelRecord.archive_sha256}:null,native_code_files:native.map(p=>path.relative(app,p).split(path.sep).join('/')),artifacts:artifacts.map(name=>({name,sha256:sha(path.join(destination,name)),bytes:fs.statSync(path.join(destination,name)).size})),native_ui_acceptance:'NOT RUN',cold_install:'NOT RUN'};
  fs.writeFileSync(path.join(destination,'preview-receipt.json'),JSON.stringify(receipt,null,2)+'\n');return receipt;
 }finally{fs.rmSync(privateRoot,{recursive:true,force:true});}
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 try{assert(process.argv.length===3&&ABS(process.argv[2]),'usage_absolute_preview_config');console.log(JSON.stringify(buildMacPreview(JSON.parse(fs.readFileSync(process.argv[2],'utf8')))));}
 catch{console.error('Styx developer preview build failed; preserve incomplete output for inspection.');process.exitCode=2;}
}
