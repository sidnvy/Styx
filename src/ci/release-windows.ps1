[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Build','Package')][string]$Stage,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceRevision,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$GateReceipt,
    [string]$TargetDirectory,
    [string]$RuntimeDirectory,
    [string]$SourceArchiveDirectory,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z.+-]*$')][string]$RuntimeVersion,
    [ValidateRange(1,65535)][int]$BuildNumber=1,
    [ValidateRange(0,256)][int]$Jobs=0
)
# CI adapter only: no install, service registration, profiles or private keys.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'Windows runner required' }
$Root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Fresh output directory required' }
if ($OutputDirectory.StartsWith($Root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release outputs must stay outside the source checkout'
}
$Python=(Get-Command python -ErrorAction Stop).Source
$Node=(Get-Command node -ErrorAction Stop).Source

function Invoke-Checked([string]$Program,[string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw ('Release producer failed: '+[IO.Path]::GetFileName($Program)) }
}
function Require-Input([string]$Path,[string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        throw ('Missing '+$Name)
    }
    return [IO.Path]::GetFullPath($Path)
}
function Write-Json([string]$Path,$Value) {
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding utf8NoBOM
}
function Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

Push-Location $Root
try {
    if ($Stage -eq 'Build') {
        $GateReceipt=Require-Input $GateReceipt 'quality receipt'
        $TargetDirectory=Require-Input $TargetDirectory 'Cargo target directory'
        if ($Jobs -eq 0) {
            if ($env:CARGO_BUILD_JOBS) { $Jobs=[int]$env:CARGO_BUILD_JOBS }
            else { $Jobs=[Environment]::ProcessorCount }
        }
        if ($Jobs -lt 1 -or $Jobs -gt 256) { throw 'Cargo jobs must be in 1..256' }
        $memory=Get-CimInstance Win32_OperatingSystem
        Write-Host ('Windows build: jobs={0}, logicalCPUs={1}, freeMemoryMiB={2}, target=x86_64-pc-windows-msvc, profile=release, cache={3}' -f $Jobs,[Environment]::ProcessorCount,[math]::Floor($memory.FreePhysicalMemory/1024),$TargetDirectory)
        Invoke-Checked $Python @('-I','-B',(Join-Path $Root 'src/tools/release/build-native-binary.py'),
            '--source-revision',$SourceRevision,'--gate-receipt',$GateReceipt,
            '--target-dir',$TargetDirectory,'--output',$OutputDirectory,'--jobs',"$Jobs",'--reuse-workspace-cache')
        return
    }

    $RuntimeDirectory=Require-Input $RuntimeDirectory 'signed Runtime directory'
    $SourceArchiveDirectory=Require-Input $SourceArchiveDirectory 'source archive directory'
    if (-not $Version -or -not $RuntimeVersion) { throw 'Package requires Version and RuntimeVersion' }
    foreach ($part in $Version.Split('.')) {
        if ([int]$part -gt 65535) { throw 'Windows version component exceeds 65535' }
    }
    $runtimeManifest=Get-Content -LiteralPath (Join-Path $RuntimeDirectory 'payload/manifest.json') -Raw | ConvertFrom-Json
    if ($runtimeManifest.source.revision -ne $SourceRevision -or $runtimeManifest.version -ne $RuntimeVersion -or $runtimeManifest.target -ne 'x86_64-pc-windows-msvc') {
        throw 'Signed Runtime version/source/target mismatch'
    }
    $archiveManifest=Join-Path $SourceArchiveDirectory 'source-inputs.json'
    $archive=Join-Path $SourceArchiveDirectory 'source.tar'
    $publisher=Get-Content -LiteralPath (Join-Path $Root 'src/release-publisher.json') -Raw | ConvertFrom-Json
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
    $packageDirectory=Join-Path $OutputDirectory 'app'
    $appConfig=Join-Path $OutputDirectory 'app-inputs.json'
    Write-Json $appConfig ([ordered]@{
        sourceRoot=(Join-Path $Root 'src');sourceRevision=$SourceRevision;
        sourceArchiveManifest=$archiveManifest;expectedSourceArchiveSha256=(Sha256 $archive);
        expectedSourceManifestSha256=(Sha256 $archiveManifest);output=$packageDirectory;arch='x64';compile=$true;
        nativeRuntime=@{payloadDir=(Join-Path $RuntimeDirectory 'payload');publisherFile=(Join-Path $RuntimeDirectory 'publisher.pem');expectedPublisher=$publisher.publisherSpkiSha256}
    })
    Invoke-Checked $Node @((Join-Path $Root 'src/host/build-windows-app.mjs'),$appConfig)

    # Reuse the fixed compiler cache; validate its digest even on a cache hit.
    $pin=Get-Content -LiteralPath (Join-Path $Root 'src/host/windows/platform-update/toolchain.json') -Raw | ConvertFrom-Json
    $tools=Join-Path $env:USERPROFILE '.cache/styx-release-inputs/inno-7.1.0'
    $compiler=Join-Path $tools 'ISCC.exe'
    if (-not (Test-Path -LiteralPath $compiler)) {
        New-Item -ItemType Directory -Path $tools -Force | Out-Null
        $download=Join-Path $tools 'innosetup-download.exe'
        Invoke-WebRequest -Uri $pin.source -OutFile $download
        if ((Sha256 $download) -ne $pin.downloadSha256) { throw 'Inno Setup download digest mismatch' }
        $signature=Get-AuthenticodeSignature -LiteralPath $download
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch ('(?:^|,\s*)CN='+[regex]::Escape($pin.authenticodePublisher)+'(?:,|$)')) {
            throw 'Inno Setup Authenticode publisher mismatch'
        }
        $arguments=@('/PORTABLE=1','/CURRENTUSER','/NOICONS','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/DIR="'+$tools+'"'))
        $install=Start-Process -FilePath $download -ArgumentList $arguments -Wait -PassThru
        if ($install.ExitCode -ne 0) { throw 'Portable Inno compiler preparation failed' }
        Remove-Item -LiteralPath $download
    }
    if ((Sha256 $compiler) -ne $pin.compilerSha256) { throw 'Cached Inno compiler digest mismatch' }
    $innoDirectory=Join-Path $OutputDirectory 'inno'
    $innoConfig=Join-Path $OutputDirectory 'inno-inputs.json'
    Write-Json $innoConfig ([ordered]@{
        packageDirectory=$packageDirectory;compiler=$compiler;outputDirectory=$innoDirectory;
        version=($Version+'.'+$BuildNumber);expectedPackageSha256=(Sha256 (Join-Path $packageDirectory 'windows-package.json'));
        productId='Styx.Desktop';productName='Styx';installFolder='Styx'
    })
    Invoke-Checked $Node @((Join-Path $Root 'src/host/windows/platform-update/build-inno.mjs'),$innoConfig)
    $receipt=Get-Content -LiteralPath (Join-Path $innoDirectory 'build-receipt.json') -Raw | ConvertFrom-Json
    $assets=Join-Path $OutputDirectory 'assets'
    New-Item -ItemType Directory -Path $assets | Out-Null
    $asset=Join-Path $assets ('Styx-'+$RuntimeVersion+'-windows-x64.exe')
    Copy-Item -LiteralPath $receipt.installer -Destination $asset
    if ((Sha256 $asset) -ne $receipt.installerSha256) { throw 'Release asset digest mismatch' }
    Write-Json (Join-Path $OutputDirectory 'receipt.json') ([ordered]@{
        schema=1;status='PACKAGED_NOT_INSTALLED';sourceRevision=$SourceRevision;version=$RuntimeVersion;
        target='x86_64-pc-windows-msvc';asset=$asset;sha256=$receipt.installerSha256;
        nativeManifestSha256=(Sha256 (Join-Path $RuntimeDirectory 'payload/manifest.json'));
        publisherSpkiSha256=$publisher.publisherSpkiSha256;productId=$receipt.productId;
        authenticode=$receipt.authenticode;installation='NOT_RUN';desktopAcceptance='NOT_RUN'
    })
} finally {
    Pop-Location
}
