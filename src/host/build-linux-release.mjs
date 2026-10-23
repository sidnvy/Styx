// Legacy Linux entrypoint retained for existing installation scripts.
// The signed payload builder itself is now one cross-platform Styx module.
import {buildHostRelease} from './build-host-release.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export function buildLinuxRelease(options={}){
  if(process.platform!=='linux'||process.arch!=='x64')
    throw Error('linux_x64_only');
  return buildHostRelease({...options,platform:'linux',arch:'x64'});
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [destination,version,privateKeyFile,codexBinary,cuaBinary]=process.argv.slice(2);
  try{
    const result=buildLinuxRelease({destination,version,privateKeyFile,codexBinary,cuaBinary});
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch(e){
    process.stderr.write('Styx Linux bundle: '+e.message+'\n');process.exitCode=2;
  }
}
