// Cross-platform signed Styx Host release builder. Executed locally by
// a trusted publisher on the target OS; it does not install or start services.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const STATIC=Object.freeze([
  'host/connect.mjs','host/computer.mjs',
  'host/launch.mjs','host/installer.mjs',
  'shared/private-file.mjs',
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
  codexBinary,cuaBinary,sourceRoot=ROOT,platform=process.platform,
  arch=process.arch}={}){
  assert(['linux','darwin','win32'].includes(platform) &&
    platform===process.platform && arch===process.arch,'native_build_platform_required');
  assert(ID.test(version??''),'invalid_release_version');
  for(const p of [destination,privateKeyFile,codexBinary,cuaBinary,sourceRoot])
    assert(typeof p==='string'&&path.isAbsolute(p),'absolute_release_path_required');
  assert(!fs.existsSync(destination),'release_destination_must_be_empty');
  const k=fs.lstatSync(privateKeyFile);
  assert(k.isFile()&&!k.isSymbolicLink() &&
    (process.platform==='win32'||(k.mode&0o077)===0),
    'release_signing_key_permissions');
  const privateKey=createPrivateKey(fs.readFileSync(privateKeyFile,'utf8'));
  assert(privateKey.asymmetricKeyType==='ed25519','ed25519_signing_key_required');
  const codexVer=versionBinary(codexBinary,'codex-cli 0.163.0');
  const cuaVer=versionBinary(cuaBinary,'cua-driver 0.36.0');
  const names={
    codex:platform==='win32'?'codex.exe':'codex',
    cua:platform==='win32'?'cua-driver.exe':'cua-driver'
  };
  fs.mkdirSync(destination,{recursive:false,mode:0o700});
  try{
    for(const name of STATIC)
      copy(path.join(sourceRoot,name),path.join(destination,name));
    const dependencies=path.join(sourceRoot,'node_modules/ws');
    for(const name of walk(dependencies))
      copy(path.join(dependencies,name),path.join(destination,'node_modules/ws',name));
    copy(codexBinary,path.join(destination,'bin',names.codex));
    copy(cuaBinary,path.join(destination,'bin',names.cua));
    const files=walk(destination).map(name=>{
      const abs=path.join(destination,...name.split('/'));
      const executable=name.startsWith('bin/');
      if(executable&&process.platform!=='win32')fs.chmodSync(abs,0o700);
      return {path:name,sha256:sha256(abs),size:fs.statSync(abs).size,executable};
    });
    const manifest={schema:1,version,platform,arch,
      upstream:{codex:codexVer,cua:cuaVer,
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
  const [destination,version,privateKeyFile,codexBinary,cuaBinary]=process.argv.slice(2);
  try{
    const result=buildHostRelease({destination,version,privateKeyFile,codexBinary,cuaBinary});
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch(e){
    process.stderr.write('Styx Host bundle: '+e.message+'\n');process.exitCode=2;
  }
}
