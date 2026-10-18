# Styx VNext Windows user-scoped Scheduled Task pilot.
# Run with native interactive user. No SYSTEM, Session 0 or elevated task.
# Only StyxPilot- prefixed tasks are accepted and owner verified.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('install','start','stop','restart','status','uninstall')]
    [string]$Action,
    [string]$TaskName = 'StyxPilot-Host',
    [string]$ConfigPath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$marker='Styx-VNext-Windows-Interactive-User-v1'
if ($TaskName -notmatch '^StyxPilot-[A-Za-z0-9-]{1,30}$') {
    throw 'invalid_styx_task_name'
}
$current=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$current.User.Value
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
if ($session -eq 0 -or -not [Environment]::UserInteractive) {
    throw 'interactive_user_session_required'
}
function Get-OwnedTask {
    $existing=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $existing) { return $null }
    if ($existing.Description -ne $marker) { throw 'task_not_owned_by_styx' }
    $principalId=[string]$existing.Principal.UserId
    if ($principalId -match '^S-1-') { $actualSid=$principalId }
    else {
      try {
        $actualSid=(New-Object Security.Principal.NTAccount($principalId)).Translate(
          [Security.Principal.SecurityIdentifier]).Value
      } catch { throw 'unresolvable_task_owner' }
    }
    if ($actualSid -ne $sid) { throw 'task_owner_mismatch' }
    if ($existing.Principal.LogonType -notin @('Interactive','InteractiveToken')) {
        throw 'interactive_token_required'
    }
    if ($existing.Principal.RunLevel -ne 'Limited') {
        throw 'least_privilege_required'
    }
    return $existing
}
function Get-State {
    $task=Get-OwnedTask
    if ($null -eq $task) {
        return @{task=$TaskName;status='not_installed';session=$session}
    }
    $info=Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
    return @{
      task=$TaskName;status=[string]$task.State;session=$session;
      taskOwnerSidMatches=$true;
      interactiveLogon=$true;
      lastTaskResult=$info.LastTaskResult;
      numberOfMissedRuns=$info.NumberOfMissedRuns
    }
}
function Require-SafePath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p) -or
        $p -notmatch '^[A-Za-z]:\\[A-Za-z0-9_. +@\\-]+$' -or
        $p -match '\.\.[\\/]') { throw 'unsafe_native_path' }
    return $p
}
if ($Action -eq 'install') {
    if (-not $ConfigPath) { throw 'task_install_config_required' }
    $ConfigPath=Require-SafePath $ConfigPath
    $file=Get-Item -LiteralPath $ConfigPath -ErrorAction Stop
    if (-not $file -or $file.PSIsContainer) { throw 'invalid_task_config_file' }
    $cfg=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ([string]$cfg.task_name -ne $TaskName) { throw 'task_identity_mismatch' }
    if ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        throw 'task_already_exists'
    }
    $root=Require-SafePath ([string]$cfg.install_root)
    $hostFile=Require-SafePath ([string]$cfg.host_config_file)
    $keyFile=Require-SafePath ([string]$cfg.publisher_key_file)
    $node=Require-SafePath ([string]$cfg.node_binary)
    foreach($p in @($hostFile,$keyFile,$node,("$root\installer.mjs"),
            ("$root\launch.mjs"))) {
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            throw 'missing_verified_install_dependency'
        }
    }
    # A failed signed release cannot create an executable scheduled task.
    & $node "$root\installer.mjs" 'active' $root 'unused' $keyFile 1>$null
    if ($LASTEXITCODE -ne 0) { throw 'signed_release_unverified' }
    function Q([string]$str) { return '"' + $str + '"' }
    $argstring=(Q "$root\launch.mjs")+' '+(Q $root)+' '+
        (Q $hostFile)+' '+(Q $keyFile)
    $taskAction=New-ScheduledTaskAction -Execute $node -Argument $argstring -WorkingDirectory $root
    $taskTrigger=New-ScheduledTaskTrigger -AtLogOn -User $sid
    $taskPrincipal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
    $taskSettings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Description $marker -ErrorAction Stop | Out-Null
    @{task=$TaskName;status='installed_not_started';logonType='InteractiveToken';session=$session} | ConvertTo-Json -Compress
    exit 0
}
$task=Get-OwnedTask
if ($null -eq $task -and $Action -eq 'status') {
    Get-State | ConvertTo-Json -Compress
    exit 0
}
if ($null -eq $task) { throw 'task_not_installed' }
switch ($Action) {
 'start' { Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
 'stop' { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
 'restart' {
   Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
   Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
 }
 'uninstall' {
   if ($task.State -eq 'Running') {
     Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
   }
   Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
   @{task=$TaskName;status='uninstalled';preservedSignedRelease=$true} | ConvertTo-Json -Compress
   exit 0
 }
 'status' {}
}
Get-State | ConvertTo-Json -Compress
