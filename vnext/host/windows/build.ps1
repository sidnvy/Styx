[CmdletBinding()]
param([string]$OutputDirectory=$PSScriptRoot)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$csc=Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path -LiteralPath $csc)){throw 'framework_compiler_required'}
if(-not(Test-Path -LiteralPath $OutputDirectory)){New-Item -ItemType Directory -Path $OutputDirectory | Out-Null}
& $csc /nologo /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /out:"$OutputDirectory\StyxPreview.exe" "$PSScriptRoot\Styx.cs"
if($LASTEXITCODE -ne 0){throw 'native_build_failed'}

& $csc /nologo /target:exe /platform:anycpu /optimize+ /out:"$OutputDirectory\StyxSessionProbe.exe" "$PSScriptRoot\SessionProbe.cs"
if($LASTEXITCODE -ne 0){throw 'native_probe_build_failed'}
