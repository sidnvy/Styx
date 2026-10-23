// Read-only package/runtime identity. Availability here is never Cua evidence.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const unavailable=()=>({source:'not_observed'});
const epochTicks=621355968000000000n;
// Capture once. Millisecond rounding is widened by 1 ms so a real parent that
// immediately spawned Node is retained; later process starts fail closed.
const coreStartedBeforeTicks=epochTicks+BigInt(Math.ceil(Date.now()-process.uptime()*1000)+1)*10000n;
const pathKey=file=>path.resolve(file).toLowerCase();
const validTicks=value=>typeof value==='string'&&/^[1-9][0-9]{0,18}$/.test(value)&&BigInt(value)<=3155378975999999999n;
function member(root,pin,name){
 if(pin?.path!==name||!/^[a-f0-9]{64}$/.test(pin?.sha256??''))throw Error('invalid_native_app_pin');
 const file=path.join(root,name),stat=fs.lstatSync(file),canonical=fs.realpathSync(file);
 if(!stat.isFile()||stat.isSymbolicLink()||!pathKey(canonical).startsWith(pathKey(fs.realpathSync(root))+path.sep)||createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==pin.sha256)throw Error('native_app_pin_mismatch');
 return {file,canonical};
}
// The production caller supplies only the package root/manifest. parentPid and
// run are internal test seams, never HTTP, pipe, CLI, descriptor or env values.
export function observeWindowsNativeAppAuthority(resourceRoot,manifest,{platform=process.platform,parentPid=process.ppid,run=execFileSync}={}){
 try{
  if(platform!=='win32'||typeof resourceRoot!=='string'||!path.isAbsolute(resourceRoot)||!Number.isSafeInteger(parentPid)||parentPid<1||parentPid>2147483647)return unavailable();
  const app=member(resourceRoot,manifest?.desktopApp,'StyxPreview.exe'),probe=member(resourceRoot,manifest?.desktopProbe,'StyxSessionProbe.exe');
  const env=Object.fromEntries(['SystemRoot','WINDIR','TEMP','TMP'].filter(k=>process.env[k]!==undefined).map(k=>[k,process.env[k]]));
  const output=run(probe.file,['--app-pid',String(parentPid)],{encoding:'utf8',timeout:5000,maxBuffer:8192,windowsHide:true,stdio:['ignore','pipe','ignore'],env});
  if(typeof output!=='string'||Buffer.byteLength(output)>8192)return unavailable();
  const value=JSON.parse(output),processInfo=value?.app;
  if(value?.schema!==1||value.status!=='available'||!Number.isSafeInteger(value.sessionId)||value.sessionId<1||value.interactive!==true||value.windowStation!=='WinSta0'||value.inputDesktop!=='Default'||processInfo?.pid!==parentPid||processInfo.sessionId!==value.sessionId||!validTicks(processInfo.startTimeUtcTicks)||BigInt(processInfo.startTimeUtcTicks)>coreStartedBeforeTicks||typeof processInfo.executablePath!=='string'||processInfo.executablePath.length>32768||!path.isAbsolute(processInfo.executablePath))return unavailable();
  // Match the actual kernel-reported image path, including its canonical file.
  // Another copy, hard link, arbitrary descriptor, or relative path cannot bind.
  if(pathKey(processInfo.executablePath)!==pathKey(app.file)||pathKey(fs.realpathSync(processInfo.executablePath))!==pathKey(app.canonical))return unavailable();
  if(pathKey(member(resourceRoot,manifest.desktopApp,'StyxPreview.exe').canonical)!==pathKey(app.canonical)||pathKey(member(resourceRoot,manifest.desktopProbe,'StyxSessionProbe.exe').canonical)!==pathKey(probe.canonical))return unavailable();
  return {source:'current_windows_native_app',nativeAppPid:parentPid,nativeAppGeneration:processInfo.startTimeUtcTicks};
 }catch{return unavailable()}
}
