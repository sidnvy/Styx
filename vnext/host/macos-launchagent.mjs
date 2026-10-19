// macOS user LaunchAgent adapter for a signed Styx Host release.
// Only affects the caller's login domain and Styx-owned plist. Never
// registers system LaunchDaemons or grants native Accessibility/TCC.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {verifiedServiceNode} from './installer.mjs';
import {requirePrivateFile} from './private-storage.mjs';

const LABEL=/^app\.styx\.(?:connector|host(?:-pilot)?(?:\.[a-z0-9][a-z0-9-]{0,32})?)$/;
// Paths become XML strings and argv entries, never shell source. Accept normal
// macOS names (including Application Support and Unicode), but reject controls
// and characters XML 1.0 cannot represent losslessly.
const INVALID_PATH_CHARACTERS=/[\u0000-\u001f\u007f-\u009f\ud800-\udfff\ufffe\uffff]/u;
const MARKER='Managed-by: Styx-VNext-user-launchagent-v1';
const esc=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;')
  .replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
const assert=(ok,msg)=>{if(!ok)throw Error(msg)};
const isDarwin=()=>assert(process.platform==='darwin','macos_only');
const safePath=(str,label)=>{assert(typeof str==='string' && path.isAbsolute(str) &&
  path.normalize(str)===str&&!INVALID_PATH_CHARACTERS.test(str),label+'_unsafe_path');return str};
const safeLabel=label=>{assert(LABEL.test(label??''),'invalid_styx_launchagent_label');return label};
function verifyPrivate(p){
  safePath(p,'host_config');
  try{requirePrivateFile(p)}
  catch{throw Error('host_config_not_private')}
}
function unitFile(label,home){
  safeLabel(label);
  safePath(home,'home');
  return path.join(home,'Library','LaunchAgents',label+'.plist');
}
function owned(p){
  const st=fs.lstatSync(p);
  assert(st.isFile()&&!st.isSymbolicLink()&&
    fs.readFileSync(p,'utf8').includes('<!-- '+MARKER+' -->'),
    'launchagent_not_owned');
}
export function macLaunchAgent({label='app.styx.host-pilot',
  installRoot,hostConfigFile,trustPublicKeyFile,nodeBinary,
  logDir}={}){
  isDarwin();safeLabel(label);
  for(const [name,p] of [['install_root',installRoot],
    ['config',hostConfigFile],['publisher',trustPublicKeyFile],
    ['logs',logDir]])safePath(p,name);
  verifyPrivate(hostConfigFile);
  const keyInfo=fs.lstatSync(trustPublicKeyFile);
  assert(keyInfo.isFile()&&!keyInfo.isSymbolicLink(),'invalid_publisher_file');
  nodeBinary=verifiedServiceNode({installRoot,publicKeyPem:fs.readFileSync(trustPublicKeyFile,'utf8'),nodeBinary});
  safePath(nodeBinary,'node');
  const args=[nodeBinary,path.join(installRoot,'launch.mjs'),
    installRoot,hostConfigFile,trustPublicKeyFile];
  const body=[
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<!-- '+MARKER+' -->',
    '<dict>',
    '<key>Label</key><string>'+esc(label)+'</string>',
    '<key>ProgramArguments</key><array>',
    ...args.map(a=>'<string>'+esc(a)+'</string>'),
    '</array>',
    '<key>RunAtLoad</key><true/>',
    '<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>',
    '<key>ProcessType</key><string>Background</string>',
    '<key>WorkingDirectory</key><string>'+esc(installRoot)+'</string>',
    '<key>StandardOutPath</key><string>'+esc(path.join(logDir,'host.stdout.log'))+'</string>',
    '<key>StandardErrorPath</key><string>'+esc(path.join(logDir,'host.stderr.log'))+'</string>',
    '</dict>',
    '</plist>',
    ''
  ];
  return body.join('\n');
}
export function writeMacLaunchAgent(options,{home=os.homedir()}={}){
  isDarwin();
  const label=options.label??'app.styx.host-pilot';
  const xml=macLaunchAgent(options);
  const dest=unitFile(label,home);
  fs.mkdirSync(path.dirname(dest),{recursive:true,mode:0o700});
  fs.mkdirSync(options.logDir,{recursive:true,mode:0o700});
  for(const dir of [path.dirname(dest),options.logDir]){
    const st=fs.lstatSync(dir);
    assert(st.isDirectory()&&!st.isSymbolicLink(),'unsafe_launchagent_directory');
  }
  assert(!fs.existsSync(dest),'launchagent_already_installed');
  fs.writeFileSync(dest,xml,{mode:0o600,flag:'wx'});
  return {status:'installed_not_loaded',label,plist:dest};
}
function launchctl(verb,args,{run=execFileSync}={}){
  const res=run('/bin/launchctl',[verb,...args],
    {encoding:'utf8',timeout:20000,stdio:['ignore','pipe','pipe']});
  return String(res||'');
}
export function statusMacLaunchAgent(label,{uid=process.getuid?.(),
  run=execFileSync}={}){
  isDarwin();safeLabel(label);
  assert(Number.isInteger(uid)&&uid>=1,'invalid_native_uid');
  try{
    const data=launchctl('print',['gui/'+uid+'/'+label],{run});
    const pid=/^\s*pid = (\d+)/m.exec(data);
    const state=/^\s*state = ([^\n]+)/m.exec(data);
    return {label,status:'reported',loaded:true,pid:pid?Number(pid[1]):null,
      state:state?.[1]?.trim()??null};
  }catch(error){
    if(/Could not find (?:specified )?service/i.test(String(error.stderr??'')))return {label,status:'not_loaded',loaded:false};
    return {label,status:'unavailable',loaded:null};
  }
}
export function controlMacLaunchAgent(action,label,{home=os.homedir(),
  uid=process.getuid?.(),run=execFileSync}={}){
  isDarwin();safeLabel(label);
  assert(Number.isInteger(uid)&&uid>=1,'invalid_native_uid');
  const plist=unitFile(label,home);
  owned(plist);
  const domain='gui/'+uid;
  const target=domain+'/'+label;
  if(action==='start'){
    // launchctl disable persists across bootout/uninstall even after a new
    // user-owned plist is installed. Explicit start is user authorization
    // to re-enable exactly this verified Styx label before bootstrap.
    launchctl('enable',[target],{run});
    launchctl('bootstrap',[domain,plist],{run});
    return statusMacLaunchAgent(label,{uid,run});
  }
  if(action==='stop'){
    launchctl('bootout',[domain,plist],{run});
    return {label,status:'unloaded'};
  }
  if(action==='restart'){
    launchctl('bootout',[domain,plist],{run});
    launchctl('bootstrap',[domain,plist],{run});
    return statusMacLaunchAgent(label,{uid,run});
  }
  if(action==='enable'){
    launchctl('enable',[target],{run});
    return {label,status:'enabled'};
  }
  if(action==='disable'){
    launchctl('disable',[target],{run});
    return {label,status:'disabled'};
  }
  throw Error('unsupported_launchagent_action');
}
export function removeMacLaunchAgent(label,{home=os.homedir(),
  uid=process.getuid?.(),run=execFileSync}={}){
  isDarwin();safeLabel(label);
  const plist=unitFile(label,home);
  owned(plist);
  const domain='gui/'+uid;
  // Unload before unlinking; unknown launchd errors must not be interpreted
  // as successful removal of a potentially running service.
  const status=statusMacLaunchAgent(label,{uid,run});
  assert(status.status!=='unavailable','launchagent_status_unavailable');
  if(status.loaded)launchctl('bootout',[domain,plist],{run});
  launchctl('disable',[domain+'/'+label],{run});
  fs.unlinkSync(plist);
  return {status:'removed',label,preservedInstallRoot:true};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [action,label,configFile]=process.argv.slice(2);
  try{
    if(!action||!label)throw Error('mac_launchagent_usage');
    const result=action==='install'
      ?writeMacLaunchAgent(JSON.parse(fs.readFileSync(safePath(configFile,'config'),'utf8')))
      :action==='status'?statusMacLaunchAgent(label)
      :action==='uninstall'?removeMacLaunchAgent(label)
      :controlMacLaunchAgent(action,label);
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch(e){process.stderr.write('Styx macOS LaunchAgent: '+e.message+'\n');process.exitCode=2}
}
