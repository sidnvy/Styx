import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {runVerifiedWindowsTask} from '../service-lifecycle.mjs';
const helper=fileURLToPath(new URL('../../host/windows-task.ps1',import.meta.url));
const digest=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const invocation=()=>({helper,expectedSha256:digest(helper),action:'status',taskName:'StyxPilot-Status-'+randomBytes(5).toString('hex')});
test('fixed Windows task command executes only the expected helper bytes with parameters as data',()=>{
 const request={...invocation(),configFile:path.join(os.tmpdir(),"config ' $value.json")};let calls=0;
 const result=runVerifiedWindowsTask(request,(program,args,options)=>{
  calls++;assert.equal(program,'powershell.exe');assert(args.includes('-EncodedCommand'));assert(!args.includes('-File'));assert(!args.includes('-ExecutionPolicy'));
  assert.deepEqual(Buffer.from(options.env.STYX_FIXED_TASK_SOURCE,'base64'),fs.readFileSync(helper));
  const command=Buffer.from(args.at(-1),'base64').toString('utf16le');assert(!command.includes(request.configFile));assert(!command.includes(request.taskName));
  assert.equal(options.env.STYX_FIXED_TASK_CONFIG,request.configFile);assert.equal(options.env.STYX_FIXED_TASK_ACTION,'status');assert.equal(options.env.STYX_FIXED_TASK_NAME,request.taskName);
  return JSON.stringify({status:'not_installed',session:0});
 });assert.equal(calls,1);assert.equal(result.status,'not_installed');
});
test('changed helper bytes and unsupported action or task cannot reach PowerShell',t=>{
 const folder=fs.mkdtempSync(path.join(os.tmpdir(),'styx-task-command-'));t.after(()=>fs.rmSync(folder,{recursive:true,force:true}));const copy=path.join(folder,'helper.ps1');fs.copyFileSync(helper,copy);const request={...invocation(),helper:copy};fs.appendFileSync(copy,'\n# changed');
 const run=()=>assert.fail('unverified helper reached native execution');
 assert.throws(()=>runVerifiedWindowsTask(request,run),/signed_windows_task_helper_changed/);
 assert.throws(()=>runVerifiedWindowsTask({...invocation(),action:'uninstall'},run),/unsupported_service_action/);
 assert.throws(()=>runVerifiedWindowsTask({...invocation(),taskName:'foreign-task'},run),/invalid_service_identity/);
});
test('native read-only task status works under current policy without a GUI session or policy changes',{skip:process.platform!=='win32'},()=>{
 const policy=()=>execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from('Get-ExecutionPolicy -List | ConvertTo-Json -Compress','utf16le').toString('base64')],{encoding:'utf8',windowsHide:true,timeout:30000});
 const before=policy(),request=invocation(),state=runVerifiedWindowsTask(request);
 assert.equal(state.status,'not_installed');assert(Number.isInteger(state.session));
 if(state.session===0)assert.throws(()=>runVerifiedWindowsTask({...request,action:'start'}),/interactive_user_session_required/);
 assert.equal(policy(),before);
});

test('native task-query failures stay unknown; only exact missing-name errors establish absence',{skip:process.platform!=='win32'},()=>{
 const script=`$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:STYX_QUERY_TEST_HELPER,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'invalid_helper_syntax'}
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-OwnedTask'},$true)
if($null -eq $fn){throw 'missing_task_query'}
. ([ScriptBlock]::Create($fn.Extent.Text))
$TaskName='StyxPilot-QueryFault';$marker='unused';$sid='unused'
function Get-ScheduledTask { [CmdletBinding()]param([string]$TaskName)
 if($env:STYX_QUERY_TEST_CASE -eq 'empty'){return}
 $category=if($env:STYX_QUERY_TEST_CASE -eq 'denied'){[Management.Automation.ErrorCategory]::PermissionDenied}else{[Management.Automation.ErrorCategory]::ObjectNotFound}
 $id=if($env:STYX_QUERY_TEST_CASE -eq 'missing'){'CmdletizationQuery_NotFound_TaskName,Get-ScheduledTask'}else{'unexpected_scheduler_failure'}
 throw [Management.Automation.ErrorRecord]::new([Exception]::new('controlled_query_failure'),$id,$category,$TaskName)
}
$absent=$false;$refused=$false
try{$value=Get-OwnedTask;$absent=$null -eq $value}catch{$refused=$true}
if($env:STYX_QUERY_TEST_CASE -eq 'missing'){if(-not $absent -or $refused){throw 'missing_task_not_recognized'}}else{if(-not $refused -or $absent){throw 'query_failure_misreported_as_absent'}}
`;
 for(const kind of ['missing','denied','foreign-missing','empty'])execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{env:{...process.env,STYX_QUERY_TEST_HELPER:helper,STYX_QUERY_TEST_CASE:kind},windowsHide:true,stdio:'pipe',timeout:30000});
});
