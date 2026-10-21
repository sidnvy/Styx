// Cross-platform signed Styx Host release builder. Executed locally by
// a trusted publisher on the target OS; it does not install or start services.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {requirePrivateFile} from './private-storage.mjs';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const STATIC=Object.freeze([
  'host/connect.mjs','host/computer.mjs','host/linux-desktop.mjs',
  'host/launch.mjs','host/installer.mjs','host/health-update.mjs','host/service-update.mjs',
  'host/enroll.mjs','host/setup-native.mjs','host/macos-preview-trust.mjs','host/macos-local-signing.mjs','host/doctor.mjs','host/linux-service.mjs',
  'host/macos-launchagent.mjs','host/macos-native-launcher.mjs','host/windows-task.ps1',
  'shared/enrollment-protocol.mjs',
  'host/private-storage.mjs','shared/private-file.mjs',
  'licenses/styx-LICENSE','licenses/cua-LICENSE',
  'licenses/codex-LICENSE','licenses/codex-NOTICE','licenses/provenance.json',
  'packages/styx-exec-adapter/rpc.mjs',
  'packages/styx-exec-adapter/errors.mjs'
]);
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const assert=(ok,why)=>{if(!ok)throw Error(why)};
function regular(p) {
  const stat=fs.lstatSync(p);
  assert(stat.isFile()&&!stat.isSymbolicLink(),'nonregular_release_source');
  return p;
}
function sha256(p) {
  const fd=fs.openSync(p,'r');
  try {
    const digest=createHash('sha256'),buf=Buffer.allocUnsafe(1024*1024);
    let n;
    while((n=fs.readSync(fd,buf,0,buf.length,null))>0)digest.update(buf.subarray(0,n));
    return digest.digest('hex');
  }finally{fs.closeSync(fd)}
}
function walk(root,prefix=''){
  const entries=fs.readdirSync(root,{withFileTypes:true}), files=[];
  for(const entry of entries){
    const rel=prefix?prefix+'/'+entry.name:entry.name;
    if(entry.isDirectory())files.push(...walk(path.join(root,entry.name),rel));
    else if(entry.isFile())files.push(rel);
    else throw Error('unsupported_bundled_dependency');
  }
  return files.sort();
}
function copy(from,to){
  regular(from);
  fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});
  fs.copyFileSync(from,to,fs.constants.COPYFILE_EXCL);
  if(process.platform!=='win32')fs.chmodSync(to,0o600);
}
function version(binary,prefix) {
  const observed=execFileSync(binary,['--version'],{
    encoding:'utf8',timeout:7000,windowsHide:true
  }).trim();
  assert(observed.startsWith(prefix),'unsupported_pinned_binary_version');
  return observed.slice(0,120);
}
export function buildHostRelease({destination,version,privateKeyFile,
  codexBinary,cuaBinary,nodeBinary,sourceRoot=ROOT,platform=process.platform,
  arch=process.arch,browserRuntime=false}={}){
  assert(typeof browserRuntime==='boolean','invalid_browser_runtime_selection');
  assert(['linux','darwin','win32'].includes(platform) &&
    platform===process.platform && arch===process.arch,'native_build_platform_required');
  assert(ID.test(version??''),'invalid_release_version');
  for(const p of [destination,privateKeyFile,codexBinary,cuaBinary,sourceRoot])
    assert(typeof p==='string'&&path.isAbsolute(p),'absolute_release_path_required');
  assert(!fs.existsSync(destination),'release_destination_must_be_empty');
  try{requirePrivateFile(privateKeyFile)}
  catch{throw Error('release_signing_key_permissions')}
  const privateKey=createPrivateKey(fs.readFileSync(privateKeyFile,'utf8'));
  assert(privateKey.asymmetricKeyType==='ed25519','ed25519_signing_key_required');
  const codexVer=versionBinary(codexBinary,'codex-cli 0.163.0');
  const cuaVer=versionBinary(cuaBinary,'cua-driver 0.36.0');
  if(platform==='win32')assert(nodeBinary,'windows_node_runtime_required');
  let nodeProvenance=null;
  if(nodeBinary){
    assert(path.isAbsolute(nodeBinary),'absolute_node_path_required');
    regular(nodeBinary);
    nodeProvenance=JSON.parse(fs.readFileSync(regular(path.join(path.dirname(nodeBinary),'node-provenance.json')),'utf8'));
    assert(nodeProvenance.schema===1 && nodeProvenance.component==='node' &&
      nodeProvenance.version==='22.23.3' && nodeProvenance.platform===platform &&
      nodeProvenance.arch===arch && nodeProvenance.binary_sha256===sha256(nodeBinary) &&
      nodeProvenance.license_sha256===sha256(regular(path.join(path.dirname(nodeBinary),'LICENSE'))),
      'invalid_node_provenance');
    assert(versionBinary(nodeBinary,'v22.23.3')==='v22.23.3','unsupported_node_version');
  }
  const names={
    codex:platform==='win32'?'codex.exe':'codex',
    cua:platform==='win32'?'cua-driver.exe':'cua-driver'
  };
  fs.mkdirSync(destination,{recursive:false,mode:0o700});
  try{
    for(const name of STATIC)
      copy(path.join(sourceRoot,name),path.join(destination,name));
    if(browserRuntime){
      const browserRoot=path.join(sourceRoot,'packages/styx-browser-provider'),browserLock=JSON.parse(fs.readFileSync(path.join(browserRoot,'package-lock.json'),'utf8'));
      for(const [locator,locked]of Object.entries(browserLock.packages??{})){if(!locator)continue;const folder=path.join(browserRoot,...locator.split('/'));if(!fs.existsSync(folder)){if(locked.optional)continue;throw Error('browser_locked_dependency_missing');}const pkg=JSON.parse(fs.readFileSync(path.join(folder,'package.json'),'utf8'));assert(pkg.version===locked.version&&typeof locked.integrity==='string','browser_dependency_lock_mismatch');}
      for(const name of ['host/browser.mjs',...['host.mjs','config.mjs','contract.mjs','prepare.mjs','installed.mjs','login-state.mjs','package.json','package-lock.json','playwright-contract-0.0.83.json'].map(name=>'packages/styx-browser-provider/'+name)])copy(path.join(sourceRoot,name),path.join(destination,name));
      const dependencyRoot=path.join(browserRoot,'node_modules');
      const members=(root,prefix='')=>fs.readdirSync(root,{withFileTypes:true}).flatMap(entry=>{if(entry.name==='.bin'||entry.name==='.package-lock.json')return [];const rel=prefix?prefix+'/'+entry.name:entry.name;if(entry.isDirectory())return members(path.join(root,entry.name),rel);if(!entry.isFile())throw Error('unsupported_browser_dependency');return /\.(map|ts)$/.test(entry.name)?[]:[rel];});
      for(const name of members(dependencyRoot))copy(path.join(dependencyRoot,name),path.join(destination,'packages/styx-browser-provider/node_modules',name));
    }
    const dependencies=path.join(sourceRoot,'node_modules/ws');
    for(const name of walk(dependencies))
      copy(path.join(dependencies,name),path.join(destination,'node_modules/ws',name));
    copy(codexBinary,path.join(destination,'bin',names.codex));
    copy(cuaBinary,path.join(destination,'bin',names.cua));
    if(nodeBinary){
      copy(nodeBinary,path.join(destination,'bin',platform==='win32'?'node.exe':'node'));
      copy(path.join(path.dirname(nodeBinary),'LICENSE'),path.join(destination,'licenses/node-LICENSE'));
      copy(path.join(path.dirname(nodeBinary),'node-provenance.json'),path.join(destination,'provenance/node.json'));
    }
    const files=walk(destination).map(name=>{
      const abs=path.join(destination,...name.split('/'));
      const executable=name.startsWith('bin/');
      if(executable&&process.platform!=='win32')fs.chmodSync(abs,0o700);
      return {path:name,sha256:sha256(abs),size:fs.statSync(abs).size,executable};
    });
    const manifest={schema:1,version,platform,arch,
      upstream:{codex:codexVer,cua:cuaVer,...(browserRuntime?{browserMcp:'0.0.83',playwright:'1.64.0-alpha-1790635538000'}:{}),...(nodeProvenance?{node:nodeProvenance.version}:{}),
        ws:JSON.parse(fs.readFileSync(path.join(dependencies,'package.json'),'utf8')).version},
      files
    };
    const raw=JSON.stringify(manifest,null,2)+'\n';
    const sig=sign(null,Buffer.from(raw),privateKey).toString('base64url')+'\n';
    fs.writeFileSync(path.join(destination,'manifest.json'),raw,{flag:'wx',mode:0o600});
    fs.writeFileSync(path.join(destination,'manifest.sig'),sig,{flag:'wx',mode:0o600});
    const fingerprint=createHash('sha256').update(
      createPublicKey(privateKey).export({type:'spki',format:'der'})).digest('hex');
    return {version,platform,arch,files:files.length,upstream:manifest.upstream,
      publisher_spki_sha256:fingerprint};
  }catch(e){fs.rmSync(destination,{recursive:true,force:true});throw e}
}
const versionBinary=version;
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2),browserRuntime=args.at(-1)==='--browser-runtime';if(browserRuntime)args.pop();
  const [destination,version,privateKeyFile,codexBinary,cuaBinary,nodeBinary]=args;
  try{
    assert(args.length===5||args.length===6,'usage_host_release_requires_paths_and_optional_browser_runtime');
    const result=buildHostRelease({destination,version,privateKeyFile,codexBinary,cuaBinary,nodeBinary,browserRuntime});
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch(e){
    process.stderr.write('Styx Host bundle: '+e.message+'\n');process.exitCode=2;
  }
}
