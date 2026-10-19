// Fixed owner-local Gateway service adapters. Never a shell/MCP command API.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {requirePrivateDirectory,requirePrivateFile,ensurePrivateDirectory} from '../host/private-storage.mjs';
const assert=(v,c)=>{if(!v)throw Error(c)};
const hash=s=>createHash('sha256').update(s).digest('hex');
const actions=['install','status','start','stop','enable','disable','uninstall'];
const xml=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
export function platformGatewayPlan(descriptor,{platform=process.platform}={}){
 assert(['darwin','win32'].includes(platform),'gateway_platform_not_supported');
 assert(descriptor&&typeof descriptor==='object'&&!Array.isArray(descriptor)&&!Object.keys(descriptor).some(k=>!['stateDir','nodeBinary','runner','identityHash'].includes(k)),'gateway_descriptor_invalid');
 const parser=platform==='win32'?path.win32:path.posix;
 for(const k of ['stateDir','nodeBinary','runner'])assert(typeof descriptor[k]==='string'&&parser.isAbsolute(descriptor[k])&&parser.normalize(descriptor[k])===descriptor[k]&&!/[\x00-\x1f\x7f]/.test(descriptor[k]),'gateway_path_invalid');
 assert(/^[a-f0-9]{64}$/.test(descriptor.identityHash??'')&&hash(descriptor.stateDir)===descriptor.identityHash,'gateway_identity_mismatch');
 const suffix=descriptor.identityHash.slice(0,12),name=platform==='darwin'?'app.styx.gateway.'+suffix:'StyxGateway-'+suffix;
 return {name,marker:'Styx-VNext-Gateway-v1:'+descriptor.identityHash,platform,startup:'interactive_user_login',systemBootWithoutLogin:'NOT CONFIGURED',startEnablesStartup:true};
}
function macPlist(d,p){const logs=path.join(d.stateDir,'gateway-service-logs');return [
 '<?xml version="1.0" encoding="UTF-8"?>','<plist version="1.0">','<!-- '+p.marker+' -->','<dict>',
 '<key>Label</key><string>'+p.name+'</string>','<key>ProgramArguments</key><array>',
 ...[d.nodeBinary,d.runner,d.stateDir].map(s=>'<string>'+xml(s)+'</string>'),'</array>',
 '<key>WorkingDirectory</key><string>'+xml(d.stateDir)+'</string>',
 '<key>RunAtLoad</key><true/>','<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>',
 '<key>ProcessType</key><string>Background</string>',
 '<key>StandardOutPath</key><string>'+xml(path.join(logs,'gateway.stdout.log'))+'</string>',
 '<key>StandardErrorPath</key><string>'+xml(path.join(logs,'gateway.stderr.log'))+'</string>',
 '</dict>','</plist>',''].join('\n')}
function userLaunchDir(home){
 for(const dir of [path.join(home,'Library'),path.join(home,'Library','LaunchAgents')]){
  if(fs.existsSync(dir)){const s=fs.lstatSync(dir);assert(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&!(s.mode&0o022),'gateway_launch_directory_untrusted')}
  else fs.mkdirSync(dir,{mode:0o700});
 }
 return path.join(home,'Library','LaunchAgents');
}
const escapeRegex=s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
function macService(action,d,p,{run,home}){
 const uid=process.getuid();assert(uid>0,'gateway_user_domain_required');
 const domain='gui/'+uid,target=domain+'/'+p.name,file=path.join(home,'Library','LaunchAgents',p.name+'.plist'),expected=macPlist(d,p);
 const ctl=(verb,args)=>run('/bin/launchctl',[verb,...args],{encoding:'utf8',timeout:20000,maxBuffer:65536,env:{...process.env,LC_ALL:'C'},stdio:['ignore','pipe','pipe']});
 const observe=()=>{
  let text;try{text=String(ctl('print',[target]))}catch(e){if(!/Could not find (?:specified )?service/i.test(String(e.stderr??'')))throw Error('gateway_launchd_status_unknown');return {loaded:false,pid:null,state:'inactive'}}
  const program=/^\s*program = (.+)$/m.exec(text)?.[1];
  const block=/^\s*arguments = \{\n([\s\S]*?)^\s*\}/m.exec(text)?.[1];
  const argv=block?.split('\n').map(x=>x.trim()).filter(Boolean).map(x=>x.replace(/^\d+ = /,''));
  assert(program===d.nodeBinary&&JSON.stringify(argv)===JSON.stringify([d.nodeBinary,d.runner,d.stateDir]),'gateway_loaded_definition_mismatch');
  return {loaded:true,pid:Number(/^\s*pid = (\d+)$/m.exec(text)?.[1])||null,state:/^\s*state = (.+)$/m.exec(text)?.[1]?.trim()??'unknown'};
 };
 const preference=()=>{const text=String(ctl('print-disabled',[domain]));const match=new RegExp('"'+escapeRegex(p.name)+'"\\s*=>\\s*(true|false)').exec(text);return match?.[1]==='true'?'disabled':match?.[1]==='false'?'enabled':'default'};
 const bind=()=>{requirePrivateFile(file);assert(fs.readFileSync(file,'utf8')===expected,'gateway_plist_definition_mismatch')};
 if(action==='install'){
  if(fs.existsSync(file)){bind();return {...result(observe(),preference()),status:'already_installed'}}
  assert(!observe().loaded,'gateway_foreign_job_registered');
  userLaunchDir(home);ensurePrivateDirectory(path.join(d.stateDir,'gateway-service-logs'));
  // Disable this new, proven-absent label before exposing a RunAtLoad plist.
  ctl('disable',[target]);fs.writeFileSync(file,expected,{mode:0o600,flag:'wx'});requirePrivateFile(file);
  return {...result(observe(),preference()),status:'installed_not_started'};
 }
 if(!fs.existsSync(file)){assert(!observe().loaded,'gateway_foreign_job_registered');return {status:'not_installed',name:p.name,active:'inactive',substate:'not_installed',enabled:'none',pid:null}}
 bind();let current=observe();
 if(action==='uninstall'){if(current.loaded)ctl('bootout',[domain,file]);ctl('disable',[target]);assert(!observe().loaded,'gateway_unload_unconfirmed');fs.unlinkSync(file);return {status:'uninstalled_state_preserved',name:p.name,active:'inactive',substate:'not_installed',enabled:'disabled',pid:null}}
 if(action==='start'){ctl('enable',[target]);if(!current.loaded)ctl('bootstrap',[domain,file])}
 if(action==='stop'){ctl('disable',[target]);if(current.loaded)ctl('bootout',[domain,file])}
 if(action==='enable'||action==='disable')ctl(action,[target]);
 return result(observe(),preference());
 function result(s,enabled){return {name:p.name,active:s.loaded?(s.state==='running'&&s.pid?'active':'unknown'):'inactive',substate:s.state,enabled,pid:s.pid}}
}
const WINDOWS=`$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
try{
$d=$env:STYX_GATEWAY_SERVICE_JSON|ConvertFrom-Json;$action=$env:STYX_GATEWAY_SERVICE_ACTION
if($action -notin @('install','status','start','stop','enable','disable','uninstall')){throw 'action'}
$name='StyxGateway-'+$d.identityHash.Substring(0,12);$marker='Styx-VNext-Gateway-v1:'+$d.identityHash
$current=[Security.Principal.WindowsIdentity]::GetCurrent();$sid=$current.User.Value;$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
if($session -eq 0 -or -not [Environment]::UserInteractive -or $sid -eq 'S-1-5-18'){throw 'interactive_owner_required'}
$arguments='"'+$d.runner+'" "'+$d.stateDir+'"'
function Owned {
 $t=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
 if($null -eq $t){return $null}
 $who=[string]$t.Principal.UserId;if($who -notmatch '^S-1-'){$who=(New-Object Security.Principal.NTAccount($who)).Translate([Security.Principal.SecurityIdentifier]).Value}
 if($t.Description -ne $marker -or $who -ne $sid -or $t.Principal.LogonType -notin @('Interactive','InteractiveToken') -or $t.Principal.RunLevel -ne 'Limited'){throw 'foreign_task'}
 if(@($t.Actions).Count -ne 1 -or $t.Actions.Execute -cne $d.nodeBinary -or $t.Actions.Arguments -cne $arguments -or $t.Actions.WorkingDirectory -cne $d.stateDir){throw 'changed_action'}
 return $t
}
function State {
 $t=Owned;if($null -eq $t){return @{name=$name;active='inactive';substate='not_installed';enabled='none';pid=$null;status='not_installed'}}
 $expected='"'+$d.nodeBinary+'" '+$arguments;$other=$d.nodeBinary+' '+$arguments
 $pids=@(Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object {$_.ExecutablePath -eq $d.nodeBinary -and ($_.CommandLine -ceq $expected -or $_.CommandLine -ceq $other)} | Select-Object -ExpandProperty ProcessId)
 $active='inactive';$pidValue=$null
 if($t.State -eq 'Running'){$active='unknown';if($pids.Count -eq 1){$active='active';$pidValue=$pids[0]}}elseif($pids.Count -gt 0){$active='unknown'}
 $enabled='enabled';if(-not $t.Settings.Enabled){$enabled='disabled'}
 return @{name=$name;active=$active;substate=[string]$t.State;enabled=$enabled;pid=$pidValue}
}
$t=Owned
if($action -eq 'install'){
 if($null -ne $t){$s=State;$s.status='already_installed';$s|ConvertTo-Json -Compress;exit 0}
 $native=New-ScheduledTaskAction -Execute $d.nodeBinary -Argument $arguments -WorkingDirectory $d.stateDir
 $principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
 $triggers=@((New-ScheduledTaskTrigger -AtLogOn -User $sid),(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)))
 $settings=New-ScheduledTaskSettingsSet -Disable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
 Register-ScheduledTask -TaskName $name -Action $native -Principal $principal -Trigger $triggers -Settings $settings -Description $marker -ErrorAction Stop|Out-Null
 $s=State;$s.status='installed_not_started';$s|ConvertTo-Json -Compress;exit 0
}
if($null -eq $t){if($action -eq 'status'){State|ConvertTo-Json -Compress;exit 0};throw 'not_installed'}
if($action -eq 'start'){Enable-ScheduledTask -TaskName $name -ErrorAction Stop|Out-Null;Start-ScheduledTask -TaskName $name -ErrorAction Stop}
if($action -eq 'stop' -or $action -eq 'uninstall'){Disable-ScheduledTask -TaskName $name -ErrorAction Stop|Out-Null;if($t.State -eq 'Running'){Stop-ScheduledTask -TaskName $name -ErrorAction Stop}}
if($action -eq 'enable'){Enable-ScheduledTask -TaskName $name -ErrorAction Stop|Out-Null}
if($action -eq 'disable'){Disable-ScheduledTask -TaskName $name -ErrorAction Stop|Out-Null}
if($action -eq 'uninstall'){if((State).active -ne 'inactive'){throw 'stop_unconfirmed'};Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop;@{status='uninstalled_state_preserved';name=$name;active='inactive';substate='not_installed';enabled='disabled';pid=$null}|ConvertTo-Json -Compress;exit 0}
State|ConvertTo-Json -Compress
}catch{[Console]::Error.Write('styx_gateway_task_refused');exit 2}`;
function windowsService(action,d,p,{run}){
 const raw=run('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(WINDOWS,'utf16le').toString('base64')],{env:{...process.env,STYX_GATEWAY_SERVICE_JSON:JSON.stringify(d),STYX_GATEWAY_SERVICE_ACTION:action},encoding:'utf8',timeout:45000,maxBuffer:16384,windowsHide:true,stdio:['ignore','pipe','pipe']});
 const data=JSON.parse(String(raw));assert(data.name===p.name&&['active','inactive','unknown'].includes(data.active)&&['enabled','disabled','none'].includes(data.enabled)&&(!data.pid||Number.isSafeInteger(data.pid)),'gateway_task_reply_invalid');
 return {name:p.name,active:data.active,substate:String(data.substate).slice(0,64),enabled:data.enabled,pid:data.pid??null,...(data.status?{status:data.status}:{})};
}
export function platformGatewayDefinition(descriptor,{platform=process.platform}={}){
 const plan=platformGatewayPlan(descriptor,{platform});
 return {...plan,...(platform==='darwin'?{plist:macPlist(descriptor,plan)}:{powershell:WINDOWS})};
}
export function platformGatewayService({action,authorize=false,descriptor}={}, {run=execFileSync,home=os.homedir()}={}){
 assert(actions.includes(action),'gateway_service_action_invalid');assert(action==='status'||authorize===true,'gateway_service_authorization_required');
 const p=platformGatewayPlan(descriptor);
 requirePrivateDirectory(descriptor.stateDir);
 const runnerInfo=fs.lstatSync(descriptor.runner);assert(runnerInfo.isFile()&&!runnerInfo.isSymbolicLink(),'gateway_runner_not_regular');
 if(process.platform==='win32')requirePrivateFile(descriptor.runner);else assert(runnerInfo.uid===process.getuid()&&!(runnerInfo.mode&0o022),'gateway_runner_not_owner_controlled');
 const info=fs.lstatSync(descriptor.nodeBinary);assert(info.isFile()&&!info.isSymbolicLink(),'gateway_runtime_not_regular');
 // Signature/source provenance is the verified facade's responsibility. Never
 // put credentials in descriptor/arguments: runner reads private state itself.
 try{return {...(process.platform==='darwin'?macService(action,descriptor,p,{run,home}):windowsService(action,descriptor,p,{run})),startup:p.startup,startEnablesStartup:true}}
 catch{throw Error(action==='status'?'gateway_service_status_unavailable':'gateway_service_operation_uncertain_inspect_owned_state')}
}
