; Isolated compatibility probe, not the product release installer.
; Compile only with reviewed SourceDir, ProbeState and OutputDir defines.
#ifndef SourceDir
  #error SourceDir is required
#endif
#ifndef ProbeState
  #error ProbeState is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef ProbeVersion
  #error ProbeVersion is required
#endif
#ifndef GenerationFile
  #error GenerationFile is required
#endif
[Setup]
AppId=Styx.PlatformProbe.9c71
AppName=Styx Platform Probe 9c71
AppVersion={#ProbeVersion}
AppPublisher=Styx development preview
DefaultDirName={localappdata}\Programs\StyxPlatformProbe9c71
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
SetupArchitecture=x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=StyxPlatformProbe-{#ProbeVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
RestartApplications=no
Uninstallable=yes
UninstallFilesDir={app}\.uninstall
UninstallDisplayIcon={app}\app\StyxPreview.exe

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#GenerationFile}"; DestDir: "{app}"; DestName: "platform-generation.json"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\Styx Platform Probe 9c71"; Filename: "{app}\app\StyxPreview.exe"; Parameters: "--state-dir ""{#ProbeState}"""; WorkingDir: "{app}\app"
