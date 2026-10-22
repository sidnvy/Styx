// Trusted publisher build, using tracked product sources and the installed,
// locked production dependency tree. No npm lifecycle scripts or downloads.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {requirePrivateFile} from '../host/private-storage.mjs';
import {verifySignedRelease} from '../host/installer.mjs';
import {GATEWAY_SOURCE_FILES,GATEWAY_ENTRYPOINT,productionDependencyFile,productionDependencyPath} from './gateway-release-contract.mjs';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
const fail=code=>{throw Error(code)};
const abs=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function regular(file){const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink())fail('nonregular_gateway_release_source');return st;}
function json(file){regular(file);return JSON.parse(fs.readFileSync(file,'utf8'));}
function trackedSources(sourceRoot,names){
 let repo,files;try{repo=execFileSync('git',['-C',sourceRoot,'rev-parse','--show-toplevel'],{encoding:'utf8',timeout:10000}).trim();files=execFileSync('git',['-C',sourceRoot,'ls-files','--full-name','-z'],{encoding:'utf8',timeout:10000,maxBuffer:4*1024*1024});}catch{fail('tracked_gateway_source_checkout_required');}
 const tracked=new Set(files.split('\0').filter(Boolean).map(file=>path.join(repo,file)));
 for(const name of names)if(!tracked.has(path.join(sourceRoot,name)))fail('untracked_gateway_release_source');
}
function dependencyClosure(sourceRoot,dependenciesRoot,lock,roots){
 const packages=new Map(),rootNode=path.resolve(dependenciesRoot);
 function resolve(name,from){
  if(!/^(?:@[a-zA-Z0-9._-]+\/)?[a-zA-Z0-9._-]+$/.test(name))fail('invalid_gateway_dependency_name');
  let current=from;
  while(current.startsWith(rootNode+path.sep)){
   if(path.basename(current)!=='node_modules'){
    const dir=path.join(current,'node_modules',name);if(fs.existsSync(path.join(dir,'package.json')))return dir;
   }
   current=path.dirname(current);
  }
  const dir=path.join(rootNode,name);if(fs.existsSync(path.join(dir,'package.json')))return dir;
  fail('locked_gateway_dependency_missing');
 }
 function add(name,from=rootNode){
  const dir=resolve(name,from),relative=path.relative(rootNode,dir).split(path.sep).join('/'),locator='node_modules/'+relative;
  if(packages.has(locator))return;
  const info=fs.lstatSync(dir);if(!info.isDirectory()||info.isSymbolicLink())fail('gateway_dependency_symlink_forbidden');
  const pkg=json(path.join(dir,'package.json')),locked=lock.packages?.[locator];
  if(pkg.name!==name||!locked||pkg.version!==locked.version||typeof locked.integrity!=='string'||!/^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(locked.integrity))fail('gateway_dependency_lock_mismatch');
  packages.set(locator,{locator,dir,version:pkg.version,integrity:locked.integrity});
  const required={...(pkg.dependencies??{})};
  for(const peer of Object.keys(pkg.peerDependencies??{}))if(!pkg.peerDependenciesMeta?.[peer]?.optional)required[peer]=pkg.peerDependencies[peer];
  for(const dependency of Object.keys(required).sort())add(dependency,dir);
 }
 for(const name of roots)add(name);
 return [...packages.values()].sort((a,b)=>a.locator.localeCompare(b.locator));
}
function walkDependency(root,relative=''){
 const files=[];
 for(const entry of fs.readdirSync(path.join(root,relative),{withFileTypes:true})){
  const name=relative?relative+'/'+entry.name:entry.name;
  if(entry.isSymbolicLink())fail('gateway_dependency_symlink_forbidden');
  if(entry.isDirectory()){
   if(productionDependencyPath(name))files.push(...walkDependency(root,name));
  }else if(entry.isFile()&&productionDependencyFile(name))files.push(name);
  else if(!entry.isFile())fail('gateway_dependency_nonregular_member');
 }
 return files.sort();
}
export function buildGatewayRelease({destination,version,privateKeyFile,nodeBinary,nodeLicenseFile,sourceRoot=ROOT,dependenciesRoot=path.join(sourceRoot,'node_modules')}={}){
 for(const value of [destination,privateKeyFile,nodeBinary,nodeLicenseFile,sourceRoot,dependenciesRoot])if(!abs(value))fail('absolute_gateway_release_paths_required');
 if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(version??''))fail('invalid_release_version');
 if(fs.existsSync(destination))fail('release_destination_must_be_empty');
 requirePrivateFile(privateKeyFile);regular(nodeBinary);regular(nodeLicenseFile);
 const key=createPrivateKey(fs.readFileSync(privateKeyFile,'utf8'));if(key.asymmetricKeyType!=='ed25519')fail('ed25519_signing_key_required');
 const sourceNames=[...GATEWAY_SOURCE_FILES,'package.json','package-lock.json','licenses/styx-LICENSE'];trackedSources(sourceRoot,sourceNames);
 for(const name of sourceNames)regular(path.join(sourceRoot,name));
 const pkg=json(path.join(sourceRoot,'package.json')),lock=json(path.join(sourceRoot,'package-lock.json'));
 if(lock.lockfileVersion!==3||pkg.dependencies?.['@modelcontextprotocol/sdk']!==lock.packages?.['']?.dependencies?.['@modelcontextprotocol/sdk']||pkg.dependencies?.ws!==lock.packages?.['']?.dependencies?.ws)fail('gateway_root_dependency_lock_mismatch');
 const dependencies=dependencyClosure(sourceRoot,dependenciesRoot,lock,['@modelcontextprotocol/sdk','ws']);
 const payload=[];
 for(const name of [...GATEWAY_SOURCE_FILES,'package.json','package-lock.json'])payload.push({name:'app/'+name,source:path.join(sourceRoot,name)});
 payload.push({name:'licenses/styx-LICENSE',source:path.join(sourceRoot,'licenses/styx-LICENSE')},{name:'licenses/node-LICENSE',source:nodeLicenseFile},{name:'bin/'+(process.platform==='win32'?'node.exe':'node'),source:nodeBinary,executable:true});
 for(const dependency of dependencies)for(const name of walkDependency(dependency.dir))payload.push({name:'app/'+dependency.locator+'/'+name,source:path.join(dependency.dir,name)});
 if(payload.length+1>4096)fail('gateway_release_member_limit');
 fs.mkdirSync(destination,{mode:0o700});
 try{
  const files=[];
  for(const entry of payload){
   regular(entry.source);const dest=path.join(destination,entry.name);fs.mkdirSync(path.dirname(dest),{mode:0o700,recursive:true});fs.copyFileSync(entry.source,dest,fs.constants.COPYFILE_EXCL);fs.chmodSync(dest,entry.executable?0o700:0o600);
   const bytes=fs.readFileSync(dest);files.push({path:entry.name,sha256:digest(bytes),size:bytes.length,executable:entry.executable===true});
  }
  const provenance={schema:1,source:'explicit_tracked_source_allowlist',lockSha256:digest(fs.readFileSync(path.join(sourceRoot,'package-lock.json'))),dependencies:dependencies.map(({locator,version,integrity})=>({locator,version,integrity})),installedDependencyBytes:'trusted_publisher_tree_hashed_in_signed_manifest',nativePlatformAcceptance:'NOT RUN'};
  const provenanceRaw=JSON.stringify(provenance,null,2)+'\n';fs.mkdirSync(path.join(destination,'provenance'),{mode:0o700});fs.writeFileSync(path.join(destination,'provenance/gateway-build.json'),provenanceRaw,{mode:0o600,flag:'wx'});files.push({path:'provenance/gateway-build.json',sha256:digest(provenanceRaw),size:Buffer.byteLength(provenanceRaw),executable:false});
  files.sort((a,b)=>a.path.localeCompare(b.path));
  const manifest={schema:1,component:'gateway-application',entrypoint:GATEWAY_ENTRYPOINT,version,platform:process.platform,arch:process.arch,files};
  const raw=JSON.stringify(manifest,null,2)+'\n';fs.writeFileSync(path.join(destination,'manifest.json'),raw,{mode:0o600,flag:'wx'});fs.writeFileSync(path.join(destination,'manifest.sig'),sign(null,Buffer.from(raw),key).toString('base64url')+'\n',{mode:0o600,flag:'wx'});
  const publicKey=createPublicKey(key),pem=publicKey.export({format:'pem',type:'spki'});verifySignedRelease(destination,pem);
  return {component:manifest.component,version,platform:process.platform,arch:process.arch,files:files.length,dependencies:dependencies.length,manifestSha256:digest(raw),publisherSha256:digest(publicKey.export({type:'spki',format:'der'})),entrypoint:GATEWAY_ENTRYPOINT};
 }catch(e){fs.rmSync(destination,{recursive:true,force:true});throw e;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{if(process.argv.length!==3||!abs(process.argv[2]))fail('usage_absolute_build_configuration');requirePrivateFile(process.argv[2]);process.stdout.write(JSON.stringify(buildGatewayRelease(json(process.argv[2])))+'\n');}
 catch(e){process.stderr.write('Styx Gateway release: '+e.message+'\n');process.exitCode=2;}
}
