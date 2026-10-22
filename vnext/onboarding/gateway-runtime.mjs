// Gateway-owned signed Node runtime. This never prepares a Host, enrolls a
// device, installs Exec/Cua, or changes an OS service.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,createPrivateKey,randomBytes,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile,writePrivateFile} from '../host/private-storage.mjs';
import {verifySignedRelease,stageSignedRelease,activateRelease,activeRelease,verifiedServiceNode} from '../host/installer.mjs';
import {GATEWAY_SOURCE_FILES,GATEWAY_V2_SOURCE_FILES,GATEWAY_V3_SOURCE_FILES,LEGACY_GATEWAY_SOURCE_FILES,GATEWAY_SOURCE_CONTRACT,GATEWAY_ENTRYPOINT,gatewayApplicationFile} from './gateway-release-contract.mjs';

const fail=code=>{throw Error(code)};
const sum=bytes=>createHash('sha256').update(bytes).digest('hex');
const abs=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
const nodeName=()=>process.platform==='win32'?'node.exe':'node';
const write=(file,value)=>writePrivateFile(file,typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');
function trust(config,{installed=false}={}){
 if(!config||Object.keys(config).some(k=>!['bundle','publisherKeyFile','publisherSha256','baseDir'].includes(k)))fail('invalid_gateway_runtime_configuration');
 for(const k of ['bundle','publisherKeyFile','baseDir'])if(!abs(config[k]))fail('absolute_gateway_runtime_paths_required');
 if(!/^[a-f0-9]{64}$/.test(config.publisherSha256??''))fail('trusted_publisher_fingerprint_required');
 const file=installed?path.join(config.baseDir,'publisher.pem'):config.publisherKeyFile;
 if(installed)requirePrivateFile(file);
 const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink())fail('regular_publisher_key_required');
 const pem=fs.readFileSync(file,'utf8'),key=createPublicKey(pem);
 if(key.asymmetricKeyType!=='ed25519')fail('invalid_release_signing_key');
 if(sum(key.export({type:'spki',format:'der'}))!==config.publisherSha256)fail('publisher_fingerprint_mismatch');
 return {pem,file};
}
// Tokenize without executing signed application code. Comments and quoted
// examples cannot add imports; static import/export-from and literal dynamic
// imports retain their actual specifier. Escaped specifiers are unsupported
// rather than silently resolving a different path.
function literalImports(source){
 const tokens=[...source.matchAll(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|'(?:\\[\s\S]|[^'\\\r\n])*'|"(?:\\[\s\S]|[^"\\\r\n])*"|`(?:\\[\s\S]|[^`\\])*`|[A-Za-z_$][\w$]*|[^\s]/g)]
  .map(match=>match[0]).filter(token=>!token.startsWith('//')&&!token.startsWith('/*'));
 const result=[];
 const add=token=>{if(!token||!['"',"'"].includes(token[0]))return;if(token.includes('\\'))fail('unsupported_gateway_source_import');result.push(token.slice(1,-1));};
 for(let i=0;i<tokens.length;i++){
  const token=tokens[i];
  if(!['import','export'].includes(token)||tokens[i-1]==='.')continue;
  const next=tokens[i+1];
  if(token==='import'&&next==='('){if([')',','].includes(tokens[i+3]))add(tokens[i+2]);continue;}
  if(token==='import'&&['"',"'"].includes(next?.[0])){add(next);continue;}
  if(next==='.'||token==='export'&&!['{','*'].includes(next))continue;
  for(let j=i+1;j<tokens.length&&tokens[j]!==';';j++){
   if(tokens[j]==='from'){add(tokens[j+1]);break;}
  }
 }
 return result;
}
function verifySourceClosure(bundle,entries){
 const names=new Set(entries.map(entry=>entry.path));
 for(const entry of entries){
  if(!entry.path.startsWith('app/')||entry.path.startsWith('app/node_modules/')||!entry.path.endsWith('.mjs'))continue;
  for(const specifier of literalImports(fs.readFileSync(path.join(bundle,...entry.path.split('/')),'utf8'))){
   if(!specifier.startsWith('.'))continue;
   if(entry.path===GATEWAY_ENTRYPOINT&&['../../../../installer.mjs','../../../../private-storage.mjs'].includes(specifier))continue;
   const resolved=path.posix.normalize(path.posix.join(path.posix.dirname(entry.path),specifier));
   if(!resolved.startsWith('app/')||!names.has(resolved))fail('complete_signed_gateway_source_imports_required');
  }
 }
}
function runtimeOnly(verified,bundle){
 const name='bin/'+nodeName(),entries=verified.manifest.files;
 if(!entries.some(e=>e.path===name&&e.executable))fail('signed_gateway_node_required');
 if(Object.hasOwn(verified.manifest,'sourceContract')&&![2,3,GATEWAY_SOURCE_CONTRACT].includes(verified.manifest.sourceContract))fail('unsupported_gateway_source_contract');
 if(verified.manifest.component==='gateway-application'){
  const names=new Set(entries.map(e=>e.path));
  const required=verified.manifest.sourceContract===2?GATEWAY_V2_SOURCE_FILES:verified.manifest.sourceContract===3?GATEWAY_V3_SOURCE_FILES:Object.hasOwn(verified.manifest,'sourceContract')?GATEWAY_SOURCE_FILES:LEGACY_GATEWAY_SOURCE_FILES;
  if(verified.manifest.entrypoint!==GATEWAY_ENTRYPOINT||[...required.map(file=>'app/'+file),'app/package.json','app/package-lock.json','licenses/node-LICENSE','licenses/styx-LICENSE','provenance/gateway-build.json'].some(file=>!names.has(file)))fail('complete_signed_gateway_application_required');
  if(entries.some(e=>e.path!==name&&(!gatewayApplicationFile(e.path)||e.executable)))fail('gateway_runtime_contains_host_or_unknown_payload');
  verifySourceClosure(bundle,entries);
  return verified;
 }
 if(verified.manifest.component!==undefined)fail('unsupported_gateway_release_component');
 if(Object.hasOwn(verified.manifest,'sourceContract'))fail('unsupported_gateway_source_contract');
 // A Gateway runtime is a separate signed artifact, not a Host package whose
 // Exec/Cua files are silently copied into a Gateway-only installation.
 if(entries.some(e=>e.path!==name&&(!/^(licenses|provenance)\/[A-Za-z0-9._/-]+$/.test(e.path)||e.executable)))fail('gateway_runtime_contains_host_or_unknown_payload');
 return verified;
}
export function verifyGatewayRuntimeRelease(bundle,publicKeyPem){return runtimeOnly(verifySignedRelease(bundle,publicKeyPem),bundle);}
export function prepareGatewayRuntime(config){
 const {pem}=trust(config),verified=runtimeOnly(verifySignedRelease(config.bundle,pem),config.bundle);
 requirePrivateDirectory(path.dirname(config.baseDir));
 if(fs.existsSync(config.baseDir))fail('gateway_runtime_directory_already_exists');
 ensurePrivateDirectory(config.baseDir,{exclusive:true});
 // Interrupted setup remains inspectable and cannot be replayed as a new
 // install. Core owns the transaction journal and explicit reconciliation.
 write(path.join(config.baseDir,'runtime-state.json'),{schema:1,status:'preparing',version:verified.version});
 write(path.join(config.baseDir,'publisher.pem'),pem);
 const installRoot=path.join(config.baseDir,'install');
 stageSignedRelease({sourceDir:config.bundle,installRoot,publicKeyPem:pem});
 const source=path.join(installRoot,'releases',verified.version,'bin',nodeName());
 const destination=path.join(installRoot,nodeName());
 writePrivateFile(destination,fs.readFileSync(source),{mode:0o700});
 activateRelease(installRoot,verified.version,pem);
 const result=readGatewayRuntime(config);
 write(path.join(config.baseDir,'runtime-receipt.json'),{schema:1,...result,exec:'NOT INSTALLED',cua:'NOT INSTALLED',service:'NOT INSTALLED'});
 const next=path.join(config.baseDir,'runtime-state.'+randomBytes(8).toString('hex')+'.tmp');
 write(next,{schema:1,status:'prepared',version:result.version});fs.renameSync(next,path.join(config.baseDir,'runtime-state.json'));
 return {...result,status:'gateway_runtime_prepared'};
}
export function readGatewayRuntime(config){
 requirePrivateDirectory(config.baseDir);
 const {pem,file}=trust(config,{installed:true}),installRoot=path.join(config.baseDir,'install');
 const active=activeRelease(installRoot,pem);if(!active)fail('no_active_gateway_runtime');
 const verified=runtimeOnly(verifySignedRelease(active.release_root,pem),active.release_root);
 const nodeBinary=verifiedServiceNode({installRoot,publicKeyPem:pem});
 return {status:'gateway_runtime_verified',version:active.version,installRoot,nodeBinary,publisherKeyFile:file,publisherSha256:config.publisherSha256,manifestSha256:verified.sha256,
  application:verified.manifest.component==='gateway-application'?'signed_application':'source_checkout_preview',...(verified.manifest.component==='gateway-application'?{runnerBinary:path.join(active.release_root,GATEWAY_ENTRYPOINT)}:{})};
}

// Publisher-side artifact builder. The signer explicitly supplies the trusted
// Node binary and its license; this is never a downloader or unsigned updater.
export function buildGatewayRuntimeRelease({destination,version,privateKeyFile,nodeBinary,nodeLicenseFile}={}){
 for(const value of [destination,privateKeyFile,nodeBinary,nodeLicenseFile])if(!abs(value))fail('absolute_gateway_runtime_paths_required');
 if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(version??''))fail('invalid_release_version');
 if(fs.existsSync(destination))fail('release_destination_must_be_empty');
 requirePrivateFile(privateKeyFile);
 const key=createPrivateKey(fs.readFileSync(privateKeyFile,'utf8'));if(key.asymmetricKeyType!=='ed25519')fail('ed25519_signing_key_required');
 for(const file of [nodeBinary,nodeLicenseFile]){const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink())fail('nonregular_release_source');}
 ensurePrivateDirectory(destination,{exclusive:true});
 try{
  const payloads=[['bin/'+nodeName(),nodeBinary,true],['licenses/node-LICENSE',nodeLicenseFile,false]];
  const files=payloads.map(([name,source,executable])=>{
   const dest=path.join(destination,name);let parent=destination;for(const part of path.dirname(name).split(path.sep)){if(part==='.')continue;parent=path.join(parent,part);ensurePrivateDirectory(parent);}writePrivateFile(dest,fs.readFileSync(source),{mode:executable?0o700:0o600});
   const bytes=fs.readFileSync(dest);return {path:name,sha256:sum(bytes),size:bytes.length,executable};
  });
  const manifest={schema:1,version,platform:process.platform,arch:process.arch,files};
  const raw=JSON.stringify(manifest,null,2)+'\n';write(path.join(destination,'manifest.json'),raw);write(path.join(destination,'manifest.sig'),sign(null,Buffer.from(raw),key).toString('base64url')+'\n');
  return {version,platform:process.platform,arch:process.arch,files:files.length,publisherSha256:sum(createPublicKey(key).export({type:'spki',format:'der'})),manifestSha256:sum(raw)};
 }catch(e){fs.rmSync(destination,{recursive:true,force:true});throw e;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const [action,configFile]=process.argv.slice(2);if(!['build','prepare','status'].includes(action)||!abs(configFile))fail('usage_build_prepare_or_status_absolute_config');
  requirePrivateFile(configFile);const config=JSON.parse(fs.readFileSync(configFile,'utf8'));
  const result=action==='build'?buildGatewayRuntimeRelease(config):action==='prepare'?prepareGatewayRuntime(config):readGatewayRuntime(config);
  process.stdout.write(JSON.stringify(result)+'\n');
 }catch(e){process.stderr.write('Styx Gateway runtime: '+e.message+'\n');process.exitCode=2;}
}
