[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$PackageDirectory,
 [Parameter(Mandatory=$true)][string]$OutputFile,
 [Parameter(Mandatory=$true)][string]$Compiler,
 [Parameter(Mandatory=$true)][string]$Version
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$PackageDirectory=[IO.Path]::GetFullPath($PackageDirectory)
$OutputFile=[IO.Path]::GetFullPath($OutputFile)
if(Test-Path -LiteralPath $OutputFile){throw 'fresh_setup_output_required'}
$stage=Join-Path ([IO.Path]::GetDirectoryName($OutputFile)) ('inno-build-'+[Guid]::NewGuid().ToString('N'))
$configFile=$stage+'.json'
try {
 [ordered]@{packageDirectory=$PackageDirectory;compiler=[IO.Path]::GetFullPath($Compiler);outputDirectory=$stage;version=$Version;expectedPackageSha256=(Get-FileHash -LiteralPath (Join-Path $PackageDirectory 'windows-package.json') -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json | Set-Content -LiteralPath $configFile -Encoding UTF8
 $node=Join-Path $PackageDirectory 'runtime\node.exe'
 & $node (Join-Path $PSScriptRoot 'platform-update\build-inno.mjs') $configFile
 if($LASTEXITCODE -ne 0){throw 'inno_setup_build_failed'}
 $receipt=Get-Content -LiteralPath (Join-Path $stage 'build-receipt.json') -Raw | ConvertFrom-Json
 Move-Item -LiteralPath $receipt.installer -Destination $OutputFile
 $receipt.installer=$OutputFile
 $receipt | ConvertTo-Json | Set-Content -LiteralPath ($OutputFile+'.receipt.json') -Encoding UTF8
 Copy-Item -LiteralPath (Join-Path $stage 'compiler.log') -Destination ($OutputFile+'.build.log')
 $receipt | ConvertTo-Json
} finally {
 if(Test-Path -LiteralPath $configFile){Remove-Item -LiteralPath $configFile}
 if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}
}
