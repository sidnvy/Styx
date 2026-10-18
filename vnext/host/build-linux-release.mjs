// Isolated, reviewable Linux Host build. Produces an offline Ed25519-signed
// bundle; never starts daemons, copies private keys, or changes system services.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const ROOT=fileURLToPath(new URL('../',import.meta.url));
const STATIC=[
  'host/connect.mjs',
  'host/computer.mjs',
  // Stable Bootstrap updates are only allowed from an already verified
  // versioned signed bundle. They never use mutable development source.
  'host/launch.mjs',
  'host/installer.mjs',
  'packages/styx-exec-adapter/rpc.mjs',
  'packages/styx-exec-adapter/errors.mjs'
];
const ID=/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
function assert(ok,why){if(!ok)throw Error(why)}
function sourceFile(p) {
  const st=fs.lstatSync(p);
  assert(st.isFile()&&!st.isSymbolicLink(),'nonregular_release_source');
  return p;
}
function sha(p){return createHash('sha256').update(fs.readFileSync(p)).digest('hex')}
function walk(root,prefix=''){
  const files=[];
  for(const entry of fs.readdirSync(root,{withFileTypes:true})){
    const rel=prefix?prefix+'/'+entry.name:entry.name;
    if(entry.isDirectory())files.push(...walk(path.join(root,entry.name),rel));
    else if(entry.isFile())files.push(rel);
    else throw Error('unsupported_bundled_dependency');
  }
  return files.sort();
}
function copyInto(from,destination) {
  sourceFile(from);
  fs.mkdirSync(path.dirname(destination),{recursive:true,mode:0o700});
  fs.copyFileSync(from,destination,fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination,0o600);
}
function binaryVersion(binary,prefix){
  const text=execFileSync(binary,['--version'],{encoding:'utf8',timeout:5000}).trim();
  assert(text.startsWith(prefix),'unsupported_pinned_binary_version');
  return text;
}
export function buildLinuxRelease({destination,version,privateKeyFile,
  codexBinary,cuaBinary,sourceRoot=ROOT}={}){
  assert(process.platform==='linux'&&process.arch==='x64','linux_x64_only');
  assert(ID.test(version??''),'invalid_release_version');
  for(const val of [destination,privateKeyFile,codexBinary,cuaBinary,sourceRoot])
    assert(typeof val==='string'&&path.isAbsolute(val),'absolute_release_path_required');
  assert(!fs.existsSync(destination),'release_destination_must_be_empty');
  const signingStat=fs.lstatSync(privateKeyFile);
  assert(signingStat.isFile()&&!signingStat.isSymbolicLink() &&
    (signingStat.mode&0o077)===0,'release_signing_key_permissions');
  const signingKey=createPrivateKey(fs.readFileSync(privateKeyFile,'utf8'));
  assert(signingKey.asymmetricKeyType==='ed25519','ed25519_signing_key_required');
  const codexVersion=binaryVersion(codexBinary,'codex-cli 0.163.0');
  const cuaVersion=binaryVersion(cuaBinary,'cua-driver 0.36.0');
  fs.mkdirSync(destination,{recursive:false,mode:0o700});
  try {
    for(const f of STATIC)
      copyInto(path.join(sourceRoot,f),path.join(destination,f));
    const wsPath=path.join(sourceRoot,'node_modules/ws');
    for(const f of walk(wsPath))
      copyInto(path.join(wsPath,f),path.join(destination,'node_modules/ws',f));
    copyInto(codexBinary,path.join(destination,'bin/codex'));
    copyInto(cuaBinary,path.join(destination,'bin/cua-driver'));
    const manifestFiles=walk(destination).map(f=>{
      const full=path.join(destination,f);
      const executable=f.startsWith('bin/');
      if(executable)fs.chmodSync(full,0o700);
      return {path:f,sha256:sha(full),size:fs.statSync(full).size,executable};
    });
    const manifest={
      schema:1,version,platform:'linux',arch:'x64',
      upstream:{codex:codexVersion,cua:cuaVersion,
        ws:JSON.parse(fs.readFileSync(path.join(wsPath,'package.json'),'utf8')).version},
      files:manifestFiles
    };
    const raw=JSON.stringify(manifest,null,2)+'\n';
    const sig=sign(null,Buffer.from(raw),signingKey).toString('base64url')+'\n';
    fs.writeFileSync(path.join(destination,'manifest.json'),raw,{flag:'wx',mode:0o600});
    fs.writeFileSync(path.join(destination,'manifest.sig'),sig,{flag:'wx',mode:0o600});
    return {version,files:manifestFiles.length,upstream:manifest.upstream,
      publisher_spki_sha256:createHash('sha256').update(
        createPublicKey(signingKey).export({type:'spki',format:'der'})).digest('hex')};
  }catch(e){fs.rmSync(destination,{recursive:true,force:true});throw e}
}
if (process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [destination,version,privateKeyFile,codexBinary,cuaBinary]=process.argv.slice(2);
  try{
    const r=buildLinuxRelease({destination,version,privateKeyFile,codexBinary,cuaBinary});
    process.stdout.write(JSON.stringify(r)+'\n');
  }catch(e){
    process.stderr.write('Styx Linux bundle: '+e.message+'\n');
    process.exitCode=2;
  }
}
