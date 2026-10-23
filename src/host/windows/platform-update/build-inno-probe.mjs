import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
// A thin adapter around the upstream compiler: no file replacement, rollback,
// process killing, service manipulation, or new state/identity implementation.
export function buildInnoProbe(config){
  if(process.platform!=='win32')throw Error('native_windows_required');
  const {packageDirectory,compiler,stateDirectory,outputDirectory,version,expectedPackageSha256}=config;
  for(const value of [packageDirectory,compiler,stateDirectory,outputDirectory]){
    if(typeof value!=='string'||!path.isAbsolute(value)||/["\r\n]/.test(value))throw Error('absolute_safe_build_path_required');
  }
  if(!/^\d+\.\d+\.\d+\.\d+$/.test(version)||!/^[a-f0-9]{64}$/.test(expectedPackageSha256))throw Error('reviewed_build_identity_required');
  if(fs.existsSync(outputDirectory))throw Error('fresh_output_required');
  const manifest=path.join(packageDirectory,'windows-package.json');
  if(hash(manifest)!==expectedPackageSha256)throw Error('reviewed_package_changed');
  const node=path.join(packageDirectory,'runtime/node.exe'),verify=path.join(packageDirectory,'install-windows-preview.mjs');
  const verifyPackage=()=>execFileSync(node,[verify,'verify'],{cwd:packageDirectory,encoding:'utf8',windowsHide:true,maxBuffer:4*1024*1024});
  verifyPackage();
  fs.mkdirSync(outputDirectory);
  const generationFile=path.join(outputDirectory,'platform-generation.json');
  fs.writeFileSync(generationFile,JSON.stringify({version,packageSha256:expectedPackageSha256})+'\n');
  const script=path.join(path.dirname(fileURLToPath(import.meta.url)),'probe.iss');
  const output=execFileSync(compiler,[`/DSourceDir=${packageDirectory}`,`/DProbeState=${stateDirectory}`,`/DOutputDir=${outputDirectory}`,`/DProbeVersion=${version}`,`/DGenerationFile=${generationFile}`,script],{encoding:'utf8',windowsHide:true,maxBuffer:8*1024*1024});
  fs.writeFileSync(path.join(outputDirectory,'compiler.log'),output);
  verifyPackage();if(hash(manifest)!==expectedPackageSha256)throw Error('reviewed_package_changed_during_compile');
  const installer=path.join(outputDirectory,`StyxPlatformProbe-${version}.exe`);
  const receipt={schema:1,status:'BUILT_NOT_INSTALLED',engine:'Inno Setup',version,packageSha256:expectedPackageSha256,compilerSha256:hash(compiler),scriptSha256:hash(script),installerSha256:hash(installer),installer,scope:'current-user Styx.PlatformProbe.9c71 only',stateDirectory,hostRuntimeUpgrade:'NOT PERFORMED',signature:'Preview installer unsigned; compiler trust verified separately'};
  fs.writeFileSync(path.join(outputDirectory,'build-receipt.json'),JSON.stringify(receipt,null,2)+'\n');return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{console.log(JSON.stringify(buildInnoProbe(JSON.parse(fs.readFileSync(process.argv[2],'utf8'))),null,2));}catch(error){console.error(error.message);process.exitCode=1;}
}
