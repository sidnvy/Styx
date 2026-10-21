# Bounded controller for this test's single manual InteractiveToken task.
# Inputs are public paths. This never changes execution policy or startup triggers.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Set-StrictMode -Version Latest
$action=$env:STYX_DESKTOP_ACCEPTANCE_ACTION
if($action -notin @('install','start','status','cleanup')){throw 'fixed_owned_desktop_action_required'}
$cfg=Get-Content -LiteralPath $env:STYX_DESKTOP_ACCEPTANCE_CONFIG -Raw | ConvertFrom-Json
if($cfg.taskName -notmatch '^StyxPilot-Desktop-[a-f0-9]{12}$'){throw 'fresh_owned_task_name_required'}
$root=[IO.Path]::GetFullPath($cfg.taskRoot)
$prefix=Join-Path $env:USERPROFILE 'Documents\WindowsSecond-20261021\desktop-owned-'
if(-not $root.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){throw 'owned_test_root_required'}
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$marker='Styx-Owned-Desktop-Acceptance-v1 '+$cfg.taskName
$node=Join-Path $root 'public-native\node.exe'
$inputFile=Join-Path $root 'input.json'
$script=Join-Path $env:USERPROFILE 'Documents\WindowsSecond-20261021\vnext\host\windows\desktop-acceptance.mjs'
foreach($file in @($node,$inputFile,$script)){if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw 'owned_public_input_missing'}}
if((Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash.ToLowerInvariant() -ne $cfg.scriptSha256){throw 'owned_test_source_changed'}
if((Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash.ToLowerInvariant() -ne '9c9245166b4a8e182e0b797da9c20136117ff24368eaff1fec8343a123c8db0e'){throw 'owned_node_pin_mismatch'}
$arguments='"'+$script+'" "'+$inputFile+'" --authorize-owned-desktop'
function OwnedTask {
 $task=Get-ScheduledTask -TaskName $cfg.taskName -ErrorAction SilentlyContinue
 if($null -eq $task){return $null}
 if($task.Description -ne $marker){throw 'foreign_task_marker'}
 $principal=[string]$task.Principal.UserId
 if($principal -notmatch '^S-1-'){$principal=(New-Object Security.Principal.NTAccount($principal)).Translate([Security.Principal.SecurityIdentifier]).Value}
 if($principal -ne $current -or $task.Principal.LogonType -notin @('Interactive','InteractiveToken') -or $task.Principal.RunLevel -notin @('Limited','LeastPrivilege')){throw 'foreign_task_identity'}
 if(@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $node -or $task.Actions[0].Arguments -ne $arguments -or $task.Actions[0].WorkingDirectory -ne $root){throw 'foreign_task_action'}
 if($null -ne $task.Triggers -and @($task.Triggers).Count -gt 0){throw 'manual_test_must_not_have_startup_trigger'}
 return $task
}
if($action -eq 'install'){
 if($null -ne (Get-ScheduledTask -TaskName $cfg.taskName -ErrorAction SilentlyContinue)){throw 'task_already_exists_no_overwrite'}
 $principal=New-ScheduledTaskPrincipal -UserId $current -LogonType Interactive -RunLevel Limited
 $taskAction=New-ScheduledTaskAction -Execute $node -Argument $arguments -WorkingDirectory $root
 $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $cfg.taskName -Action $taskAction -Principal $principal -Settings $settings -Description $marker -ErrorAction Stop | Out-Null
 $null=OwnedTask
 @{task=$cfg.taskName;status='installed_manual_not_started';ownerMatched=$true;runLevel='Limited';logonType='InteractiveToken';startupTriggers=0} | ConvertTo-Json -Compress
 exit 0
}
$task=OwnedTask
if($null -eq $task){if($action -in @('status','cleanup')){@{task=$cfg.taskName;status='not_installed'} | ConvertTo-Json -Compress;exit 0};throw 'owned_task_missing'}
if($action -eq 'start'){if($task.State -eq 'Running'){throw 'owned_test_already_running'};Enable-ScheduledTask -TaskName $cfg.taskName | Out-Null;Start-ScheduledTask -TaskName $cfg.taskName}
if($action -eq 'cleanup'){
 Disable-ScheduledTask -TaskName $cfg.taskName | Out-Null
 if((OwnedTask).State -eq 'Running'){Stop-ScheduledTask -TaskName $cfg.taskName}
 Unregister-ScheduledTask -TaskName $cfg.taskName -Confirm:$false
 if($null -ne (Get-ScheduledTask -TaskName $cfg.taskName -ErrorAction SilentlyContinue)){throw 'owned_task_cleanup_unconfirmed'}
 @{task=$cfg.taskName;status='unregistered'} | ConvertTo-Json -Compress;exit 0
}
$task=OwnedTask
$info=Get-ScheduledTaskInfo -TaskName $cfg.taskName
@{task=$cfg.taskName;status=[string]$task.State;lastTaskResult=$info.LastTaskResult;ownerMatched=$true;startupTriggers=0} | ConvertTo-Json -Compress
