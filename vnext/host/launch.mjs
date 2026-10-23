import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {activeRelease} from './installer.mjs';
import {requirePrivateFile} from './private-storage.mjs';

// Stable, tiny launch shim: service manager restarts this entrypoint after
// login, reboot, or an approved version switch. It verifies signed active
// generation before loading any executable code from that generation.
export function activeHostConfig(raw,releaseRoot) {
  if(!raw || typeof raw!=='object' || Array.isArray(raw) ||
    !raw.exec || typeof raw.exec!=='object')throw Error('host_config_invalid');
  const codex=path.join(releaseRoot,'bin',
    process.platform==='win32'?'codex.exe':'codex');
  const cua=path.join(releaseRoot,'bin',
    process.platform==='win32'?'cua-driver.exe':'cua-driver');
  if(!fs.statSync(codex).isFile())throw Error('signed_codex_binary_missing');
  const updated={...raw,exec:{...raw.exec,binary:codex}};
  if(raw.computer?.enabled){
    if(!fs.statSync(cua).isFile())throw Error('signed_cua_binary_missing');
    updated.computer={...raw.computer,binary:cua};
    if(process.platform==='win32'){
      // Pin comes from the already verified signed generation, never from Host
      // preferences. Legacy generations remain explicitly unavailable for Cua.
      const manifest=JSON.parse(fs.readFileSync(path.join(releaseRoot,'manifest.json'),'utf8'));
      const probe=manifest.files?.find(entry=>entry.path==='bin/StyxSessionProbe.exe'&&entry.executable===true);
      updated.computer.sessionProbe=probe?{binary:path.join(releaseRoot,'bin','StyxSessionProbe.exe'),sha256:probe.sha256}:null;
    }
  }
  if(raw.browser?.enabled){for(const name of ['host/browser.mjs','packages/styx-browser-provider/host.mjs','packages/styx-browser-provider/config.mjs','packages/styx-browser-provider/prepare.mjs','packages/styx-browser-provider/contract.mjs','packages/styx-browser-provider/playwright-contract-0.0.83.json','packages/styx-browser-provider/node_modules/@playwright/mcp/package.json']){if(!fs.existsSync(path.join(releaseRoot,...name.split('/'))))throw Error('signed_browser_runtime_missing');}}
  if(raw.browser?.enabled&&(raw.browser.channel||raw.browser.persistLogin)){
    for(const name of ['installed.mjs','login-state.mjs'])if(!fs.existsSync(path.join(releaseRoot,'packages/styx-browser-provider',name)))throw Error('signed_browser_runtime_missing');
  }
  // The Host binary paths are intentionally derived from the signed active
  // release, never from mutable onboarding/Host config fields.
  return updated;
}
export async function launchActive({installRoot,hostConfigFile,trustPublicKeyFile,
  signal}={}) {
  if(![installRoot,hostConfigFile,trustPublicKeyFile].every(
      p=>typeof p==='string'&&path.isAbsolute(p)))
    throw Error('absolute_launcher_paths_required');
  try{requirePrivateFile(hostConfigFile)}
  catch{throw Error('host_config_not_private')}
  const key=fs.readFileSync(trustPublicKeyFile,'utf8');
  const active=activeRelease(installRoot,key);
  if(!active)throw Error('no_active_release');
  const hostScript=path.join(active.release_root,'host','connect.mjs');
  if(!fs.statSync(hostScript).isFile())throw Error('host_connector_not_packaged');
  const nativeConfig=activeHostConfig(
    JSON.parse(fs.readFileSync(hostConfigFile,'utf8')),active.release_root);
  return new Promise((resolve,reject)=>{
    const bundledRuntime=path.join(active.release_root,'bin',process.platform==='win32'?'node.exe':'node');
    // activeRelease verifies every signed member before executable selection.
    const runtime=fs.existsSync(bundledRuntime)?bundledRuntime:process.execPath;
    if(process.platform==='win32' && runtime===process.execPath && !fs.existsSync(bundledRuntime))
      throw Error('signed_windows_node_missing');
    const child=spawn(runtime,[hostScript,'--stdin-config'],{
      cwd:active.release_root,stdio:['pipe','inherit','inherit'],windowsHide:true
    });
    child.stdin.on('error',()=>{});
    child.stdin.end(JSON.stringify(nativeConfig));
    let settled=false,requestedStop=false;
    const finish=(status)=>{
      if(settled)return;
      settled=true;
      signal?.removeEventListener('abort',abort);
      process.off('SIGINT',onInt);
      process.off('SIGTERM',onTerm);
      resolve(status);
    };
    const abort=()=>{requestedStop=true;child.kill('SIGTERM')};
    const onInt=()=>{requestedStop=true;child.kill('SIGINT')};
    const onTerm=()=>{requestedStop=true;child.kill('SIGTERM')};
    process.once('SIGINT',onInt);
    process.once('SIGTERM',onTerm);
    signal?.addEventListener('abort',abort,{once:true});
    child.once('error',e=>{if(!settled){settled=true;reject(e)}});
    child.once('close',(code,terminationSignal)=>finish({
      exit_code:code,signal:terminationSignal,expected_stop:requestedStop,
      version:active.version
    }));
  });
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [installRoot,hostConfigFile,trustPublicKeyFile]=process.argv.slice(2);
  try{
    const outcome=await launchActive({installRoot,hostConfigFile,trustPublicKeyFile});
    if(outcome.expected_stop)process.exitCode=0;
    else if(outcome.signal)process.exitCode=1;
    else process.exitCode=outcome.exit_code??1;
  }catch(e){
    process.stderr.write('Styx launch: '+e.message+'\n');
    process.exitCode=2;
  }
}
