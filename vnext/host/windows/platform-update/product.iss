#ifndef SourceDir
  #error SourceDir is required
#endif
[Setup]
AppId={#ProductId}
AppName={#ProductName}
AppVersion={#ProductVersion}
AppPublisher=Styx
DefaultDirName={localappdata}\Programs\{#InstallFolder}
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
SetupArchitecture=x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=StyxSetup-{#ProductVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
RestartApplications=no
AppMutex={code:AppMutexName}
SetupMutex={code:SetupMutexName}
Uninstallable=yes
UninstallFilesDir={app}\.installer
UninstallDisplayIcon={app}\versions\{#PackageHash}\StyxPreview.exe

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}\versions\{#PackageHash}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#GateFile}"; DestDir: "{app}\.installer"; Flags: ignoreversion
Source: "{#GateFile}"; Flags: dontcopy

[Icons]
Name: "{userprograms}\{#ProductName}"; Filename: "{app}\versions\{#PackageHash}\StyxPreview.exe"; WorkingDir: "{app}\versions\{#PackageHash}"; Parameters: "{#AppParameters}"

[Code]
function InstallRoot: String;
begin
  Result := ExpandConstant('{localappdata}\Programs\{#InstallFolder}');
end;
function MutexScope: String;
begin
  Result := Lowercase(GetSHA256OfUnicodeString(Lowercase(InstallRoot)));
end;
function AppMutexName(Param: String): String;
begin
  Result := 'Global\Styx.App.' + MutexScope;
end;
function SetupMutexName(Param: String): String;
begin
  Result := 'Global\Styx.Install.' + MutexScope;
end;
function CheckIdle(Gate: String): String;
var Code: Integer;
begin
  Result := '';
  if CheckForMutexes(AppMutexName('')) then begin
    Result := 'Styx is still running. Finish any tasks, then choose Quit Styx and retry.';
    exit;
  end;
  if not Exec(Gate, 'check "' + InstallRoot + '"', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
  if Code = 1 then Result := 'Styx files are still in use. Finish any tasks and quit Styx before retrying.'
  else if Code <> 0 then Result := 'Setup could not confirm that Styx has stopped. No program files have been changed. Close Styx and retry.';
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  if CompareText(ExpandConstant('{app}'), InstallRoot) <> 0 then begin
    Result := 'Use the standard per-user Styx installation folder.';
    exit;
  end;
  ExtractTemporaryFile('StyxInstallGate.exe');
  // SetupMutex is held here. Recheck AppMutex to close the startup race.
  Result := CheckIdle(ExpandConstant('{tmp}\StyxInstallGate.exe'));
end;
function InitializeUninstall: Boolean;
var Problem: String;
begin
  Result := False;
  if CheckForMutexes(SetupMutexName('')) then exit;
  CreateMutex(SetupMutexName(''));
  Problem := CheckIdle(ExpandConstant('{app}\.installer\StyxInstallGate.exe'));
  if Problem <> '' then begin
    if not UninstallSilent then MsgBox(Problem, mbInformation, MB_OK);
    exit;
  end;
  Result := True;
end;
