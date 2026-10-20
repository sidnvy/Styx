// Bundled macOS preview only. URL is sent once over the owning app's private pipe.
// No global Node, shell command, remote installer or environment loader is used.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {readLocalCertificatePin,verifyLocalCertificate} from '../macos-local-signing.mjs';
const assert=(ok,code)=>{if(!ok)throw Error(code)};
function regular(file){const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink(),'bundled_setup_regular_file_required');return file}
function within(root,relative){
 assert(typeof relative==='string'&&relative.length>0&&!path.isAbsolute(relative)&&!relative.split(/[\\/]/).some(x=>x==='..'||x==='.'||x===''),'bundled_setup_relative_resource_required');
 const file=path.join(root,relative),resolved=fs.realpathSync(file);
 assert(resolved.startsWith(root+path.sep),'bundled_setup_resource_redirect');return file;
}
export function previewLayout(resourceRoot){
 assert(typeof resourceRoot==='string'&&path.isAbsolute(resourceRoot),'bundled_setup_absolute_resources_required');
 const resources=fs.realpathSync(resourceRoot),st=fs.lstatSync(resourceRoot);
 assert(st.isDirectory()&&!st.isSymbolicLink()&&path.basename(resources)==='Resources'&&path.basename(path.dirname(resources))==='Contents','bundled_setup_resources_required');
 const app=path.dirname(path.dirname(resources));assert(path.basename(app)==='Styx.app','bundled_setup_app_required');
 const defaults=JSON.parse(fs.readFileSync(regular(path.join(resources,'artifact-defaults.json')),'utf8'));
 assert(defaults&&Object.keys(defaults).length===3&&Object.keys(defaults).every(k=>['bundle','publisherKeyFile','publisherSha256'].includes(k))&&/^[a-f0-9]{64}$/.test(defaults.publisherSha256??''),'bundled_setup_artifact_defaults_invalid');
 assert(defaults.bundle==='host-bundle'&&defaults.publisherKeyFile==='publisher.pem','bundled_setup_artifact_locations_invalid');
 const bundle=within(resources,defaults.bundle);assert(fs.lstatSync(bundle).isDirectory(),'bundled_host_directory_required');
 return{resources,app,node:regular(within(resources,'runtime/node')),server:regular(within(resources,'onboarding/vnext/onboarding/server.mjs')),
  artifacts:{bundle,publisherKeyFile:regular(within(resources,defaults.publisherKeyFile)),publisherSha256:defaults.publisherSha256}};
}
export function previewTunnelClient(layout){
 const record=path.join(layout.resources,'tunnel-client.json');if(!fs.existsSync(record))return undefined;
 const pin=JSON.parse(fs.readFileSync(regular(record),'utf8'));
 assert(pin.version==='0.0.16'&&pin.platform==='darwin'&&pin.arch==='arm64'&&pin.path==='runtime/tunnel-client'&&/^[a-f0-9]{64}$/.test(pin.binary_sha256??''),'bundled_tunnel_record_invalid');
 const binary=regular(within(layout.resources,pin.path));
 assert(createHash('sha256').update(fs.readFileSync(binary)).digest('hex')===pin.binary_sha256,'bundled_tunnel_integrity_failed');
 return {binary,sha256:pin.binary_sha256};
}
export function previewSigningIdentity(layout,{run=spawnSync}={}){
 const opts={encoding:'utf8',timeout:10000,maxBuffer:65536,stdio:['ignore','pipe','pipe']};
 const verified=run('/usr/bin/codesign',['--verify','--deep','--strict',layout.app],opts);assert(verified.status===0,'bundled_preview_signature_invalid');
 const inspected=run('/usr/bin/codesign',['-d','--verbose=4',layout.app],opts);assert(inspected.status===0,'bundled_preview_signature_unavailable');
 const text=String(inspected.stderr??''),match=/^CDHash=([a-f0-9]{40})$/m.exec(text);
 if(!/^Signature=adhoc$/m.test(text)){
  assert(/^Identifier=app\.styx\.host$/m.test(text)&&match,'bundled_preview_ad_hoc_identity_required');
  const pin=readLocalCertificatePin(layout.app);assert(pin,'bundled_preview_ad_hoc_identity_required');
  verifyLocalCertificate(layout.app,pin,{run});
  return {path:layout.app,cdhash:match[1],certificateSha1:pin.certificateSha1,certificateSha256:pin.certificateSha256};
 }
 assert(!readLocalCertificatePin(layout.app),'bundled_preview_local_certificate_required');
 assert(/^Identifier=app\.styx\.host$/m.test(text)&&match,'bundled_preview_ad_hoc_identity_required');
 return{path:layout.app,cdhash:match[1]};
}
function privateDirectory(directory){
 if(!fs.existsSync(directory))fs.mkdirSync(directory,{mode:0o700});
 const s=fs.lstatSync(directory);assert(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&!(s.mode&0o077),'bundled_setup_private_state_required');
}
export function setupStorage(home){
 assert(typeof home==='string'&&path.isAbsolute(home),'bundled_setup_home_required');
 const support=path.join(home,'Library','Application Support');const s=fs.lstatSync(support);
 assert(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid(),'bundled_setup_support_directory_required');
 const parent=path.join(support,'Styx');privateDirectory(parent);
 const root=path.join(parent,'Setup');privateDirectory(root);
 return{root,stateDir:path.join(root,'deployment'),artifactDefaultsFile:path.join(root,'artifacts.json')};
}
function privateJson(file,value){
 if(fs.existsSync(file)){const s=fs.lstatSync(file);assert(s.isFile()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&!(s.mode&0o077),'bundled_setup_private_artifacts_required')}
 const tmp=file+'.'+process.pid+'.new';fs.writeFileSync(tmp,JSON.stringify(value)+'\n',{flag:'wx',mode:0o600});try{fs.renameSync(tmp,file)}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}
}
export async function startBundledSetup(resourceRoot,{setupRoot}={}){
 assert(process.platform==='darwin','bundled_setup_macos_required');
 const layout=previewLayout(resourceRoot);
 assert(fs.realpathSync(process.execPath)===fs.realpathSync(layout.node),'bundled_setup_runtime_required');
 const trustedMacPreviewApp=previewSigningIdentity(layout);
 let storage;
 if(setupRoot!==undefined){
  // Trusted native acceptance only: production CLI never accepts this option.
  assert(typeof setupRoot==='string'&&path.isAbsolute(setupRoot)&&!fs.existsSync(setupRoot),'fresh_explicit_preview_setup_root_required');
  const parent=fs.lstatSync(path.dirname(setupRoot));assert(parent.isDirectory()&&!parent.isSymbolicLink()&&parent.uid===process.getuid()&&!(parent.mode&0o077),'private_preview_test_parent_required');
  privateDirectory(setupRoot);storage={root:setupRoot,stateDir:path.join(setupRoot,'deployment'),artifactDefaultsFile:path.join(setupRoot,'artifacts.json')};
 }else storage=setupStorage(os.homedir());
 privateJson(storage.artifactDefaultsFile,layout.artifacts);
 const{createOnboardingServer}=await import(pathToFileURL(layout.server));
 const instance=await createOnboardingServer({stateDir:storage.stateDir,artifactDefaultsFile:storage.artifactDefaultsFile,trustedMacPreviewApp,trustedTunnelClient:previewTunnelClient(layout),trustedOpenSSL:'/usr/bin/openssl'});
 const url=new URL(instance.url);assert(url.protocol==='http:'&&url.hostname==='127.0.0.1'&&url.pathname==='/'&&!url.username&&!url.password&&!url.search&&/^#session=[A-Za-z0-9_-]{43}$/.test(url.hash),'bundled_setup_loopback_session_required');
 return instance;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(fileURLToPath(import.meta.url))){
 try{
  const instance=await startBundledSetup(process.argv[2]);
  process.stdout.write('STYX_SETUP_URL\t'+instance.url+'\n');
  let stopping=false;const stop=async()=>{if(stopping)return;stopping=true;await instance.close();process.exit(0)};
  for(const sig of['SIGINT','SIGTERM'])process.once(sig,()=>void stop().catch(()=>process.exit(2)));
  // The native app owns this pipe. Its crash/exit must not orphan an admin UI.
  process.stdin.resume();process.stdin.once('end',()=>void stop().catch(()=>process.exit(2)));
 }catch{process.stderr.write('Styx bundled setup unavailable. Inspect the private local installation.\n');process.exitCode=2}
}
