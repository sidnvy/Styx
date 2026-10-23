import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {normalizeConnector} from './connect.mjs';
import {activeRelease} from './installer.mjs';
import {requirePrivateFile} from './private-storage.mjs';

// A local preflight only; no automatic service or OS permission changes.
const VERSION_TIMEOUT_MS=30000;
const SPAWN_ERRORS=new Set(['ENOENT','EACCES','EPERM','ENOEXEC','ENOMEM','EAGAIN','EMFILE','ENFILE','ETXTBSY','EIO']);
const safeError=error=>SPAWN_ERRORS.has(error?.code)?error.code:'UNKNOWN';
// timeoutMs is a bounded test seam; Doctor always uses the fixed product limit.
// A deadline ends only after this owned --version child has actually closed.
export async function probeRuntimeVersion(binary,{timeoutMs=VERSION_TIMEOUT_MS}={}) {
  if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>VERSION_TIMEOUT_MS)throw Error('invalid_version_probe_timeout');
  const started=performance.now(),probe={status:'pending',elapsedMs:0,timeoutMs,exitCode:null,signal:null};
  const result=(status,version=null)=>({version,probe:{...probe,status,elapsedMs:Math.round(performance.now()-started)}});
  try{const info=fs.lstatSync(binary);if(!info.isFile()||info.isSymbolicLink())return result('invalid_binary');}
  catch(error){probe.errorCode=safeError(error);return result('binary_unavailable');}
  return await new Promise(resolve=>{
    let completed=false,stdout='',size=0,child,timer,stopped;
    const finish=(status,version=null)=>{if(completed)return;completed=true;clearTimeout(timer);resolve(result(status,version));};
    const stop=status=>{
      if(completed||stopped)return;stopped=status;
      // This is a fixed, side-effect-free version probe, not an Exec command.
      // Kill only its owned process and wait for close before returning evidence.
      child.kill('SIGKILL');
    };
    try{child=spawn(binary,['--version'],{stdio:['ignore','pipe','ignore'],windowsHide:true});}
    catch(error){probe.errorCode=safeError(error);finish('spawn_error');return;}
    timer=setTimeout(()=>stop('timeout'),timeoutMs);
    child.stdout.on('data',bytes=>{size+=bytes.length;if(size>2048)stop('output_limit');else stdout+=String(bytes);});
    child.once('error',error=>{probe.errorCode=safeError(error);if(!child.pid)finish('spawn_error');else stopped='spawn_error';});
    child.once('close',(code,signal)=>{
      probe.exitCode=Number.isInteger(code)?code:null;
      probe.signal=typeof signal==='string'&&/^SIG[A-Z0-9]{1,12}$/.test(signal)?signal:null;
      if(stopped)finish(stopped);
      else if(signal)finish('terminated');
      else if(code!==0)finish('exit_nonzero');
      else finish('ok',stdout.trim().slice(0,120));
    });
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
        const observed=await probeRuntimeVersion(normalized.exec.binary);
        const ver=observed.version;checks.executor_probe=observed.probe;
        checks.executor_version=ver;
        if(!ver?.startsWith('codex-cli '))throw Error();
        if(selected.release && !/^codex-cli 0\.163\.0(?:$|\s)/.test(ver))
          throw Error();
      }catch{
        checks.executor_version=null;
        if(checks.executor_probe?.status==='ok')checks.executor_probe.status='version_mismatch';
        blockers.push('codex_executor_unavailable');
      }
      if(normalized.computer?.enabled){
        try {
          const observed=await probeRuntimeVersion(normalized.computer.binary);
          const ver=observed.version;checks.computer_probe=observed.probe;
          checks.computer_version=ver;
          if(selected.release && !/^cua-driver 0\.36\.0(?:$|\s)/.test(ver??''))
            throw Error();
        }catch{
          checks.computer_version=null;
          if(checks.computer_probe?.status==='ok')checks.computer_probe.status='version_mismatch';
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
