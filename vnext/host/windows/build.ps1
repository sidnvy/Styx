[CmdletBinding()]
param([string]$OutputDirectory=$PSScriptRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$csc=Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path -LiteralPath $csc)){throw 'framework_compiler_required'}
if(-not(Test-Path -LiteralPath $OutputDirectory)){New-Item -ItemType Directory -Path $OutputDirectory | Out-Null}
& $csc /nologo /warn:4 /warnaserror+ /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /out:"$OutputDirectory\StyxPreview.exe" "$PSScriptRoot\Styx.cs"
if($LASTEXITCODE -ne 0){throw 'native_build_failed'}

& $csc /nologo /warn:4 /warnaserror+ /target:exe /platform:anycpu /optimize+ /out:"$OutputDirectory\StyxSessionProbe.exe" "$PSScriptRoot\SessionProbe.cs"
if($LASTEXITCODE -ne 0){throw 'native_probe_build_failed'}

& $csc /nologo /warn:4 /warnaserror+ /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /out:"$OutputDirectory\StyxUpdater.exe" "$PSScriptRoot\HostUpdater.cs"
if($LASTEXITCODE -ne 0){throw 'native_updater_build_failed'}

$manifestFile=Join-Path $OutputDirectory 'windows-runtime.json'
if(Test-Path -LiteralPath $manifestFile){
    $manifest=Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
    $pin=@{path='StyxSessionProbe.exe';sha256=(Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'StyxSessionProbe.exe') -Algorithm SHA256).Hash.ToLowerInvariant()}
    $manifest | Add-Member -NotePropertyName desktopProbe -NotePropertyValue $pin -Force
    $manifest | Add-Member -NotePropertyName hostUpdater -NotePropertyValue @{path='StyxUpdater.exe';sha256=(Get-FileHash -LiteralPath (Join-Path $OutputDirectory 'StyxUpdater.exe') -Algorithm SHA256).Hash.ToLowerInvariant()} -Force
    [IO.File]::WriteAllText($manifestFile,($manifest | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
}
