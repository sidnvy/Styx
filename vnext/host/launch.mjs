import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {activeRelease} from './installer.mjs';

// Stable, tiny launch shim: service manager restarts this entrypoint after
// login, reboot, or an approved version switch. It verifies signed active
// generation before loading any executable code from that generation.
export async function launchActive({installRoot,hostConfigFile,trustPublicKeyFile,
  signal}={}) {
  if(![installRoot,hostConfigFile,trustPublicKeyFile].every(
      p=>typeof p==='string'&&path.isAbsolute(p)))
    throw Error('absolute_launcher_paths_required');
  if(!fs.statSync(hostConfigFile).isFile())throw Error('host_config_missing');
  const key=fs.readFileSync(trustPublicKeyFile,'utf8');
  const active=activeRelease(installRoot,key);
  if(!active)throw Error('no_active_release');
  const hostScript=path.join(active.release_root,'host','connect.mjs');
  if(!fs.statSync(hostScript).isFile())throw Error('host_connector_not_packaged');
  return new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,[hostScript,hostConfigFile],{
      cwd:active.release_root,stdio:'inherit',windowsHide:true
    });
    let settled=false;
    const finish=(status)=>{
      if(settled)return;
      settled=true;
      signal?.removeEventListener('abort',abort);
      process.off('SIGINT',onInt);
      process.off('SIGTERM',onTerm);
      resolve(status);
    };
    const abort=()=>child.kill('SIGTERM');
    const onInt=()=>child.kill('SIGINT');
    const onTerm=()=>child.kill('SIGTERM');
    process.once('SIGINT',onInt);
    process.once('SIGTERM',onTerm);
    signal?.addEventListener('abort',abort,{once:true});
    child.once('error',e=>{if(!settled){settled=true;reject(e)}});
    child.once('close',(code,terminationSignal)=>finish({
      exit_code:code,signal:terminationSignal,
      version:active.version
    }));
  });
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [installRoot,hostConfigFile,trustPublicKeyFile]=process.argv.slice(2);
  try{
    const outcome=await launchActive({installRoot,hostConfigFile,trustPublicKeyFile});
    if(outcome.signal)process.exitCode=1;
    else process.exitCode=outcome.exit_code??1;
  }catch(e){
    process.stderr.write('Styx launch: '+e.message+'\n');
    process.exitCode=2;
  }
}
