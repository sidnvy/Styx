[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PackageDirectory,[Parameter(Mandatory=$true)][string]$OutputFile)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$PackageDirectory=[IO.Path]::GetFullPath($PackageDirectory)
$OutputFile=[IO.Path]::GetFullPath($OutputFile)
if(Test-Path -LiteralPath $OutputFile){throw 'fresh_setup_output_required'}
$compiler=Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path -LiteralPath $compiler)){throw 'framework_compiler_required'}
$node=Join-Path $PackageDirectory 'runtime\node.exe'
& $node (Join-Path $PackageDirectory 'install-windows-preview.mjs') verify
if($LASTEXITCODE -ne 0){throw 'package_verification_failed'}
$manifest=Get-Content -LiteralPath (Join-Path $PackageDirectory 'windows-package.json') -Raw | ConvertFrom-Json
if(-not $manifest.compiled){throw 'compiled_package_required'}
if(-not(Test-Path -LiteralPath (Join-Path $PackageDirectory 'vnext\host\windows\setup-install.mjs'))){throw 'setup_lifecycle_source_required'}
$stage=Join-Path ([IO.Path]::GetTempPath()) ('StyxSetupBuild-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
 Add-Type -AssemblyName System.IO.Compression
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 Add-Type -AssemblyName System.Drawing
 $iconFile=Join-Path $stage 'Styx.ico'
 $image=[Drawing.Bitmap]::new((Join-Path $PackageDirectory 'styx-logo.png'))
 $scaled=[Drawing.Bitmap]::new($image,256,256)
 $icon=[Drawing.Icon]::FromHandle($scaled.GetHicon())
 $stream=[IO.File]::Create($iconFile)
 try{$icon.Save($stream)}finally{$stream.Dispose();$icon.Dispose();$scaled.Dispose();$image.Dispose()}
 $launcher=Join-Path $stage 'StyxLauncher.exe'
 & $compiler /nologo /warn:4 /warnaserror+ /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /win32icon:"$iconFile" /win32manifest:"$PSScriptRoot\setup.manifest" /out:"$launcher" "$PSScriptRoot\Launcher.cs"
 if($LASTEXITCODE -ne 0){throw 'launcher_compile_failed'}
 $zipFile=Join-Path $stage 'payload.zip'
 $archive=[IO.Compression.ZipFile]::Open($zipFile,[IO.Compression.ZipArchiveMode]::Create)
 try {
  foreach($file in Get-ChildItem -LiteralPath $PackageDirectory -File -Recurse){
   $relative=$file.FullName.Substring($PackageDirectory.Length+1).Replace('\','/')
   [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$file.FullName,('package/'+$relative),[IO.Compression.CompressionLevel]::Optimal) | Out-Null
  }
  [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$launcher,'StyxLauncher.exe',[IO.Compression.CompressionLevel]::Optimal) | Out-Null
 }finally{$archive.Dispose()}
 & $compiler /nologo /warn:4 /warnaserror+ /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll /win32icon:"$iconFile" /win32manifest:"$PSScriptRoot\setup.manifest" /resource:"$zipFile,StyxPayload.zip" /out:"$OutputFile" "$PSScriptRoot\Setup.cs"
 if($LASTEXITCODE -ne 0){throw 'setup_compile_failed'}
 [ordered]@{status='built_unsigned_setup';artifact=$OutputFile;sha256=(Get-FileHash -LiteralPath $OutputFile -Algorithm SHA256).Hash.ToLowerInvariant();packageSha256=(Get-FileHash -LiteralPath (Join-Path $PackageDirectory 'windows-package.json') -Algorithm SHA256).Hash.ToLowerInvariant();scope='current_user';desktopAcceptance='NOT RUN';authenticode='NOT SIGNED'} | ConvertTo-Json
} finally {Remove-Item -LiteralPath $stage -Recurse -Force}
