// Companion lifecycles for an existing macOS installation. No pairing, secrets,
// bundle edits or system boot daemon. LaunchServices retains the App identity.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {requirePrivateFile,ensurePrivateDirectory} from '../host/private-storage.mjs';
const check=(ok,code)=>{if(!ok)throw Error(code)};
const xml=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
function absolute(s){check(typeof s==='string'&&path.posix.isAbsolute(s)&&path.posix.normalize(s)===s&&!/[\x00-\x1f\x7f]/.test(s),'login_recovery_invalid_path');return s}
export function macLoginRecoveryPlan({appPath='/Applications/Styx.app',tunnelRoot,logDir}={}){
 absolute(appPath);absolute(logDir);check(path.basename(appPath)==='Styx.app','login_recovery_styx_app_required');
 const entries=[{label:'app.styx.desktop-login',args:['/usr/bin/open','-W','-g',appPath]}];
 if(tunnelRoot!==undefined){absolute(tunnelRoot);entries.push({label:'app.styx.bieber-tunnel',args:[path.join(tunnelRoot,'bin/tunnel-client'),'run','--profile-file',path.join(tunnelRoot,'profiles/bieber.yaml'),'--log.level','warn'],cwd:tunnelRoot});}
 return entries.map(e=>({...e,plist:[
 '<?xml version="1.0" encoding="UTF-8"?>','<plist version="1.0"><dict>',
 '<key>Label</key><string>'+e.label+'</string>',
 '<key>ProgramArguments</key><array>'+e.args.map(x=>'<string>'+xml(x)+'</string>').join('')+'</array>',
 ...(e.cwd?['<key>WorkingDirectory</key><string>'+xml(e.cwd)+'</string>']:[]),
 '<key>RunAtLoad</key><true/>','<key>KeepAlive</key><true/>',
 '<key>ThrottleInterval</key><integer>15</integer>',
 '<key>LimitLoadToSessionType</key><string>Aqua</string>',
 '<key>StandardOutPath</key><string>'+xml(path.join(logDir,e.label+'.stdout.log'))+'</string>',
 '<key>StandardErrorPath</key><string>'+xml(path.join(logDir,e.label+'.stderr.log'))+'</string>',
 '</dict></plist>',''].join('\n')}));
}
export function controlMacLoginRecovery(config,{action='status',authorize=false,platform=process.platform,home=os.homedir(),uid=process.getuid?.(),run=execFileSync}={}){
 check(platform==='darwin'&&uid>0,'login_recovery_graphical_user_required');
 check(['install','start','stop','status','uninstall'].includes(action),'login_recovery_action_invalid');
 check(action==='status'||authorize===true,'login_recovery_authorization_required');
 const plan=macLoginRecoveryPlan(config),domain='gui/'+uid;
 const ctl=(...args)=>String(run('/bin/launchctl',args,{encoding:'utf8',timeout:20000,stdio:['ignore','pipe','pipe']}));
 // A user boot domain is not a logged-in Aqua domain.
 ctl('print',domain);
 const dir=path.join(home,'Library','LaunchAgents');
 const observe=label=>{try{const text=ctl('print',domain+'/'+label);return {loaded:true,running:/^\s*state = running$/m.test(text),pid:Number(/^\s*pid = (\d+)$/m.exec(text)?.[1])||null};}catch(e){if(!/Could not find (?:specified )?service/.test(String(e.stderr??'')))throw Error('login_recovery_observation_unknown');return {loaded:false,running:false,pid:null}}};
 // Validate the entire plan before any mutation, including existing definitions.
 for(const e of plan){
  e.file=path.join(dir,e.label+'.plist');
  if(fs.existsSync(e.file)){requirePrivateFile(e.file);check(fs.readFileSync(e.file,'utf8')===e.plist,'login_recovery_existing_definition_mismatch');}
  else check(!observe(e.label).loaded,'login_recovery_unowned_loaded_job');
 }
 if(action==='install'){
  const app=fs.lstatSync(config.appPath??'/Applications/Styx.app');check(app.isDirectory()&&!app.isSymbolicLink(),'login_recovery_app_missing');
  run('/usr/bin/codesign',['--verify','--deep','--strict',config.appPath??'/Applications/Styx.app'],{stdio:'pipe',timeout:20000});
  if(config.tunnelRoot){requirePrivateFile(path.join(config.tunnelRoot,'profiles/bieber.yaml'));fs.accessSync(path.join(config.tunnelRoot,'bin/tunnel-client'),fs.constants.X_OK);}
  for(const parent of [path.dirname(dir),dir]){const s=fs.lstatSync(parent);check(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===uid&&!(s.mode&0o022),'login_recovery_untrusted_launch_directory');}
  ensurePrivateDirectory(config.logDir);
 }
 const results=[];
 for(const e of plan){
  const target=domain+'/'+e.label;
  if(action==='install'&&!fs.existsSync(e.file)){
   // Persist the disabled definition before enabling; a failed install is safe
   // to inspect and retry, and does not silently claim successful recovery.
   ctl('disable',target);fs.writeFileSync(e.file,e.plist,{mode:0o600,flag:'wx'});
  }
  if(['start','install'].includes(action)){
   check(fs.existsSync(e.file),'login_recovery_install_required');ctl('enable',target);
   if(!observe(e.label).loaded)ctl('bootstrap',domain,e.file);
  }
  if(['stop','uninstall'].includes(action)){
   ctl('disable',target);if(observe(e.label).loaded)ctl('bootout',target);
   check(!observe(e.label).loaded,'login_recovery_unload_unconfirmed');
   if(action==='uninstall'&&fs.existsSync(e.file))fs.unlinkSync(e.file);
  }
  results.push({label:e.label,installed:fs.existsSync(e.file),...observe(e.label)});
 }
 return {startup:'current_user_aqua_login',systemBootWithoutLogin:'NOT CONFIGURED',accountAcceptance:'NOT RUN',services:results};
}
