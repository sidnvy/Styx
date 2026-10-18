import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {normalizeConnector} from './connect.mjs';

async function version(binary) {
  if (!fs.statSync(binary).isFile()) throw Error('missing_binary');
  const child=spawn(binary,['--version'],{stdio:['ignore','pipe','ignore'],
    windowsHide:true});
  let stdout='';
  child.stdout.on('data',bytes=>{
    stdout+=String(bytes);
    if (stdout.length>2048) child.kill();
  });
  const result=await Promise.race([
    new Promise(resolve=>child.once('close',code=>resolve(code===0))),
    new Promise(resolve=>setTimeout(()=>{child.kill();resolve(false)},4000))
  ]);
  return result?stdout.trim().slice(0,120):null;
}
export async function doctor(config,{platform=process.platform}={}) {
  const checks={}, blockers=[],warnings=[];
  let normalized;
  try {normalized=normalizeConnector(config);checks.configuration='ok'}
  catch {checks.configuration='invalid';blockers.push('invalid_host_configuration')}
  if (normalized) {
    checks.host_id=normalized.host_id;
    try {
      if(normalized.token_file) {
        const stat=fs.statSync(normalized.token_file);
        const token=fs.readFileSync(normalized.token_file,'utf8').trim();
        if (!stat.isFile() || (platform!=='win32' && (stat.mode & 0o077)) ||
          !/^[A-Za-z0-9_-]{32,}$/.test(token)) throw Error();
      } else {
        const cert=fs.readFileSync(normalized.client_cert_file,'utf8');
        const stat=fs.statSync(normalized.client_key_file);
        if (!stat.isFile() || (platform!=='win32' && (stat.mode & 0o077)) ||
          !cert.includes('BEGIN CERTIFICATE') ||
          !fs.readFileSync(normalized.client_key_file,'utf8').includes('BEGIN PRIVATE KEY'))
          throw Error();
      }
      if(normalized.gateway_ca_file) fs.readFileSync(normalized.gateway_ca_file);
      checks.host_credential='ok';
    } catch {checks.host_credential='blocked';blockers.push('host_credential_unavailable')}
    try {
      checks.executor_version=await version(normalized.exec.binary);
      if (!checks.executor_version?.startsWith('codex-cli '))
        throw Error();
    } catch {checks.executor_version=null;blockers.push('codex_executor_unavailable')}
    checks.gateway_transport=normalized.endpoint.startsWith('wss:')?'wss':'loopback_ws';
  }
  const graphical=platform==='darwin'
    ? 'requires_interactive_tcc_authorized_styx_app'
    : platform==='win32'
      ? 'requires_interactive_logon_session'
      : (process.env.WAYLAND_DISPLAY ? 'wayland' :
        process.env.DISPLAY ? 'x11' : 'headless');
  checks.native_gui=graphical;
  if(platform==='linux' && graphical==='headless')blockers.push('desktop_session_unavailable');
  if(normalized?.computer?.enabled && platform==='linux' && graphical==='wayland'){
    const nativeFlag=normalized.computer.env?.CUA_DRIVER_RS_ENABLE_WAYLAND ??
      process.env.CUA_DRIVER_RS_ENABLE_WAYLAND;
    checks.cua_wayland=nativeFlag==='1'?'native_opted_in':'xwayland_fallback';
    if(nativeFlag!=='1') warnings.push('native_wayland_requires_explicit_opt_in');
  }
  if(normalized?.computer?.enabled && platform==='darwin' && !normalized.computer.socket){
    checks.cua_embedded='blocked';
    blockers.push('macos_requires_embedded_cua_socket');
  }
  return {product:'styx-vnext',platform,architecture:os.arch(),
    status:blockers.length?'blocked':'ready_for_exec',
    checks,blockers,warnings};
}
if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const cfgFile=process.argv[2];
  if(!cfgFile){process.stderr.write('Usage: node host/doctor.mjs /private/host.json\n');process.exit(2)}
  let result;
  try{result=await doctor(JSON.parse(fs.readFileSync(cfgFile,'utf8')))}
  catch{result={status:'blocked',blockers:['host_doctor_failed']}}
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
  process.exitCode=result.status==='ready_for_exec'?0:2;
}
