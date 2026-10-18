import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {normalizeConnector} from './connect.mjs';
import {activeRelease} from './installer.mjs';
import {requirePrivateFile} from './private-storage.mjs';

// A local preflight only; no automatic service or OS permission changes.
async function version(binary) {
  const info=fs.lstatSync(binary);
  if(!info.isFile()||info.isSymbolicLink())throw Error('nonregular_runtime_binary');
  return await new Promise(resolve=>{
    let completed=false,stdout='';
    let child;
    const finish=value=>{
      if(completed)return;
      completed=true;clearTimeout(timer);resolve(value);
    };
    try{
      child=spawn(binary,['--version'],{
        stdio:['ignore','pipe','ignore'],windowsHide:true
      });
    }catch{return resolve(null)}
    const timer=setTimeout(()=>{child.kill();finish(null)},4000);
    timer.unref?.();
    child.stdout.on('data',bytes=>{
      stdout+=String(bytes);
      if(stdout.length>2048){child.kill();finish(null)}
    });
    child.once('error',()=>finish(null));
    child.once('close',code=>finish(code===0?stdout.trim().slice(0,120):null));
  });
}
function installedConfig(raw,{installRoot,trustPublicKeyFile,platform}){
  if(!installRoot && !trustPublicKeyFile)return {config:raw,release:null};
  if(!installRoot || !trustPublicKeyFile ||
     !path.isAbsolute(installRoot) || !path.isAbsolute(trustPublicKeyFile))
    throw Error('trusted_install_paths_required');
  const keyStat=fs.lstatSync(trustPublicKeyFile);
  if(!keyStat.isFile()||keyStat.isSymbolicLink())throw Error('invalid_publisher_key_file');
  const key=fs.readFileSync(trustPublicKeyFile,'utf8');
  // Recheck all signed payload bytes before reporting a release as ready.
  const active=activeRelease(installRoot,key,{platform,arch:os.arch()});
  if(!active)throw Error('no_active_signed_release');
  const codex=path.join(active.release_root,'bin',
    platform==='win32'?'codex.exe':'codex');
  const cua=path.join(active.release_root,'bin',
    platform==='win32'?'cua-driver.exe':'cua-driver');
  return {
    release: {version:active.version,previous:active.previous,
      publisher_verified:true},
    config: {
      ...raw,
      exec:{...raw.exec,binary:codex},
      ...(raw.computer?.enabled?{
        computer:{...raw.computer,binary:cua}
      }:{})
    }
  };
}
export async function doctor(config,{platform=process.platform,
  installRoot,trustPublicKeyFile}={}){
  const checks={},blockers=[],warnings=[];
  let selected={config,release:null};
  try {
    selected=installedConfig(config,{installRoot,trustPublicKeyFile,platform});
    checks.signed_install=selected.release??'not_selected';
  }catch {
    checks.signed_install='invalid';
    blockers.push('signed_install_unavailable');
  }
  let normalized;
  try {
    normalized=normalizeConnector(selected.config);
    checks.configuration='ok';
  }catch {
    checks.configuration='invalid';
    blockers.push('invalid_host_configuration');
  }
  if(normalized){
    checks.host_id=normalized.host_id;
    try {
      if(normalized.token_file){
        requirePrivateFile(normalized.token_file);
        const token=fs.readFileSync(normalized.token_file,'utf8').trim();
        if(!/^[A-Za-z0-9_-]{32,}$/.test(token))throw Error();
      }else{
        const cert=fs.readFileSync(normalized.client_cert_file,'utf8');
        requirePrivateFile(normalized.client_key_file);
        if(!cert.includes('BEGIN CERTIFICATE')||
          !fs.readFileSync(normalized.client_key_file,'utf8').includes('BEGIN PRIVATE KEY'))
          throw Error();
      }
      if(normalized.gateway_ca_file)fs.readFileSync(normalized.gateway_ca_file);
      checks.host_credential='ok';
    }catch{
      checks.host_credential='blocked';
      blockers.push('host_credential_unavailable');
    }
    // A requested signed installation must fail closed: never fall back to
    // enrollment paths after signature/payload verification failed.
    if(checks.signed_install!=='invalid' && checks.host_credential==='ok'){
      try {
        const ver=await version(normalized.exec.binary);
        checks.executor_version=ver;
        if(!ver?.startsWith('codex-cli '))throw Error();
        if(selected.release && !/^codex-cli 0\.163\.0(?:$|\s)/.test(ver))
          throw Error();
      }catch{
        checks.executor_version=null;
        blockers.push('codex_executor_unavailable');
      }
      if(normalized.computer?.enabled){
        try {
          const ver=await version(normalized.computer.binary);
          checks.computer_version=ver;
          if(selected.release && !/^cua-driver 0\.36\.0(?:$|\s)/.test(ver??''))
            throw Error();
        }catch{
          checks.computer_version=null;
          if(selected.release)blockers.push('signed_computer_runtime_unavailable');
        }
      }
    }else{
      checks.executor_version=null;
      if(normalized.computer?.enabled)checks.computer_version=null;
      checks.runtime_probe='not_run_preflight_blocked';
    }
    checks.gateway_transport=normalized.endpoint.startsWith('wss:')?'wss':'loopback_ws';
  }
  const graphical=platform==='darwin'
    ? 'requires_interactive_tcc_authorized_styx_app'
    : platform==='win32'
      ? 'requires_interactive_logon_session'
      : (process.env.WAYLAND_DISPLAY?'wayland':
        process.env.DISPLAY?'x11':'headless');
  checks.native_gui=graphical;
  if(platform==='linux' && graphical==='headless') {
    warnings.push('desktop_session_not_attached');
  }
  if(normalized?.computer?.enabled && platform==='linux' && graphical==='wayland'){
    const optin=normalized.computer.env?.CUA_DRIVER_RS_ENABLE_WAYLAND ??
      process.env.CUA_DRIVER_RS_ENABLE_WAYLAND;
    checks.cua_wayland=optin==='1'?'native_opted_in':'xwayland_fallback';
    if(optin!=='1')warnings.push('native_wayland_requires_explicit_opt_in');
  }
  if(normalized?.computer?.enabled && platform==='darwin' && !normalized.computer.socket){
    checks.cua_embedded='blocked';
    blockers.push('macos_requires_embedded_cua_socket');
  }
  return {
    product:'styx-vnext',platform,architecture:os.arch(),
    status:blockers.length?'blocked':'ready_for_exec',
    checks,blockers,warnings
  };
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [configFile,installRoot,trustPublicKeyFile]=process.argv.slice(2);
  if(!configFile){
    process.stderr.write('Usage: node host/doctor.mjs /private/host.json [install-root trusted-publisher-key]\n');
    process.exit(2);
  }
  let result;
  try {
    requirePrivateFile(configFile);
    result=await doctor(JSON.parse(fs.readFileSync(configFile,'utf8')),
      {installRoot,trustPublicKeyFile});
  }catch{
    result={status:'blocked',blockers:['host_doctor_failed']};
  }
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
  process.exitCode=result.status==='ready_for_exec'?0:2;
}
