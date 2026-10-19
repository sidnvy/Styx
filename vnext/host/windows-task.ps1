# Styx VNext Windows user-scoped Scheduled Task pilot.
# Run with native interactive user. No SYSTEM, Session 0 or elevated task.
# Only the canonical Styx-Host or scoped StyxPilot- tasks are accepted and owner verified.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('install','enable','disable','start','stop','restart','status','uninstall')]
    [string]$Action,
    [string]$TaskName = 'StyxPilot-Host',
    [string]$ConfigPath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$marker='Styx-VNext-Windows-Interactive-User-v1'
if ($TaskName -ne 'Styx-Host' -and $TaskName -notmatch '^StyxPilot-[A-Za-z0-9-]{1,30}$') {
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
# Setup configuration controls executable paths. Reject foreign owners, null
# DACLs, reparse points and broad access before reading it or creating a task.
function Require-PrivateFile([string]$p) {
    $item=Get-Item -LiteralPath $p -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'task_config_not_private'
    }
    $acl=Get-Acl -LiteralPath $p
    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $acl.Sddl
    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'task_config_not_private' }
    $userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $ownerSid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($ownerSid -ne $userSid) { throw 'task_config_not_private' }
    $allowed=@($userSid,'S-1-5-18','S-1-5-32-544')
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $allowed -notcontains $rule.IdentityReference.Value) {
            throw 'task_config_not_private'
        }
    }
}
if ($Action -eq 'install') {
    if (-not $ConfigPath) { throw 'task_install_config_required' }
    $ConfigPath=Require-SafePath $ConfigPath
    Require-PrivateFile $ConfigPath
    $cfg=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ([string]$cfg.task_name -ne $TaskName) { throw 'task_identity_mismatch' }
    if ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) {
        throw 'task_already_exists'
    }
    $root=Require-SafePath ([string]$cfg.install_root)
    $hostFile=Require-SafePath ([string]$cfg.host_config_file)
    Require-PrivateFile $hostFile
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
    # This host's Task Scheduler has been observed NOT to resume a killed
    # process on RestartOnFailure alone. A native once+repetition trigger
    # probes the service every minute. IgnoreNew never launches duplicates.
    # The task remains bound to THIS interactive user SID.
    $taskTrigger=@(
      (New-ScheduledTaskTrigger -AtLogOn -User $sid)
      (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1))
    )
    $taskPrincipal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
    # Native Task Scheduler restarts an unexpectedly terminated Host process.
    # The signed launcher exits normally on a deliberate stop/restart.
    $taskSettings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
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
 'enable' { Enable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null }
 'disable' { Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null }
 'start' {
   Enable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
   Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
 }
 'stop' {
   # Disable BEFORE stopping, otherwise the native recovery timer could
   # restart a service the user explicitly asked to stop.
   Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
   if ($task.State -eq 'Running') {
     Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
   }
 }
 'restart' {
   Enable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
   if ($task.State -eq 'Running') {
     Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop
   }
   Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
 }
 'uninstall' {
   Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
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
