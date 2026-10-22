// Native, read-only offline boundary. Never disables tasks, stops services or
// terminates processes; the upgrade coordinator owns those separate decisions.
import path from 'node:path';
import {execFileSync} from 'node:child_process';

const absolute=value=>typeof value==='string'&&/^[A-Za-z]:\\/.test(value)&&path.win32.normalize(value)===value&&value.length>3&&!/[\x00-\x1f\x7f]/.test(value);
const taskName=value=>typeof value==='string'&&/^(?:Styx-Host|StyxPilot-[A-Za-z0-9-]{1,30})$/.test(value);
const reasons=new Set(['native_service_definition_present','native_owned_process_present','independent_updater_runtime_required','native_updater_identity_unverified','native_process_observation_unknown','native_observation_unavailable']);
const result=(status,reason,extra={})=>({schema:1,status,observation:'native_offline_boundary',mutation:'NONE',...(reason?{reason}:{}),...extra});
export function observeWindowsHostPayloadAbsence({installRoot,hostConfigFile,stateDir,hostServiceTaskName,appPath}={}, {platform=process.platform,pid=process.pid,execPath=process.execPath,run=execFileSync}={}){
 if(platform!=='win32')return result('blocked','windows_native_observation_required');
 if(![installRoot,hostConfigFile,stateDir,execPath].every(absolute)||appPath!==undefined&&!absolute(appPath)||!taskName(hostServiceTaskName)||!Number.isSafeInteger(pid)||pid<1)return result('blocked','native_scope_invalid');
 // UTF16 EncodedCommand carries JSON data, never executable path interpolation.
 const scope=Buffer.from(JSON.stringify({installRoot,hostConfigFile,stateDir,hostServiceTaskName,appPath,pid,execPath}),'utf8').toString('base64');
 const script=String.raw`$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Finish([string]$status,[string]$reason){@{schema=1;status=$status;reason=$reason}|ConvertTo-Json -Compress;exit 0}
try {
 $s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${scope}'))|ConvertFrom-Json
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $needles=@($s.installRoot,[IO.Path]::GetDirectoryName($s.installRoot),$s.hostConfigFile,$s.stateDir)
 if($s.PSObject.Properties.Name -contains 'appPath'){$needles+=@($s.appPath)}
 function Matches([string]$value){foreach($n in $needles){if($value.IndexOf($n,[StringComparison]::OrdinalIgnoreCase) -ge 0){return $true}};return $false}
 # A task may restart a stopped process. Any relevant definition blocks,
 # regardless of Enabled or current State; never infer absence from stopped.
 foreach($t in @(Get-ScheduledTask -ErrorAction Stop)){
  if($t.TaskName -eq $s.hostServiceTaskName){Finish 'blocked' 'native_service_definition_present'}
  foreach($a in @($t.Actions)){
   foreach($property in @('Execute','Arguments','WorkingDirectory')){
    if($a.PSObject.Properties.Name -contains $property -and (Matches ([string]$a.$property))){Finish 'blocked' 'native_service_definition_present'}
   }
  }
 }
 foreach($service in @(Get-CimInstance Win32_Service -ErrorAction Stop)){if(Matches ([string]$service.PathName)){Finish 'blocked' 'native_service_definition_present'}}
 $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop)
 if($processes.Count -eq 0){Finish 'blocked' 'native_process_observation_unknown'}
 $self=@($processes|Where-Object {$_.ProcessId -eq $s.pid})
 if($self.Count -ne 1 -or [string]::IsNullOrWhiteSpace($self[0].ExecutablePath) -or $self[0].ExecutablePath -ine $s.execPath){Finish 'blocked' 'native_updater_identity_unverified'}
 $owner=Invoke-CimMethod -InputObject $self[0] -MethodName GetOwnerSid -ErrorAction Stop
 if($owner.ReturnValue -ne 0 -or $owner.Sid -ne $sid){Finish 'blocked' 'native_updater_identity_unverified'}
 $exe=[IO.Path]::GetFullPath($self[0].ExecutablePath)
 $root=[IO.Path]::GetFullPath($s.installRoot).TrimEnd('\')
 if($exe.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or $exe.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){Finish 'blocked' 'independent_updater_runtime_required'}
 foreach($p in $processes){
  if($p.ProcessId -eq $s.pid){continue}
  if((Matches ([string]$p.ExecutablePath)) -or (Matches ([string]$p.CommandLine))){
   $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
   if($owner.ReturnValue -ne 0){Finish 'blocked' 'native_process_observation_unknown'}
   if($owner.Sid -eq $sid){Finish 'blocked' 'native_owned_process_present'}
  }
 }
 Finish 'absent' ''
} catch {Finish 'blocked' 'native_observation_unavailable'}`;
 try{
  const observed=JSON.parse(String(run('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:30000,maxBuffer:1024*1024,windowsHide:true,stdio:['ignore','pipe','pipe']})).trim());
  if(observed.schema!==1)return result('blocked','native_observation_unavailable');
  if(observed.status==='absent'&&observed.reason==='')return result('absent',null,{services:'no_matching_task_or_service_definition',processes:'no_matching_current_user_process',pointInTime:true});
  return result('blocked',reasons.has(observed.reason)?observed.reason:'native_observation_unavailable');
 }catch{return result('blocked','native_observation_unavailable')}
}
