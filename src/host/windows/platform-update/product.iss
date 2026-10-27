#ifndef SourceDir
  #error SourceDir is required
#endif
#ifndef NativePackage
  #define NativePackage 0
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
#if NativePackage == 0
AppMutex={code:AppMutexName}
#endif
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

; The App creates this optional entry through Core. Setup only retargets an
; existing owned entry; a deleted entry is never recreated by an upgrade.
Name: "{userstartup}\Styx"; Filename: "{app}\versions\{#PackageHash}\StyxPreview.exe"; WorkingDir: "{app}\versions\{#PackageHash}"; Parameters: "{code:StartupArguments}"; Comment: "Styx"; Flags: uninsneveruninstall; Check: OwnedStartupUnchanged

[UninstallDelete]
Type: files; Name: "{userstartup}\Styx.lnk"; Check: OwnedStartupUnchanged

[Code]
var StartupOwned, NativeMaintenanceAttempted: Boolean; StartupHash, StartupArgs: String;
function NativeAttributes(Name: String): Cardinal;
  external 'GetFileAttributesW@kernel32.dll stdcall';
function StartupPath: String;
begin Result := ExpandConstant('{userstartup}\Styx.lnk'); end;
function StartupArguments(Param: String): String;
begin Result := StartupArgs; end;
function OwnedStartupUnchanged: Boolean;
begin
  Result := StartupOwned and FileExists(StartupPath);
  if Result then Result := ((NativeAttributes(StartupPath) and $400) = 0) and (GetSHA256OfFile(StartupPath) = StartupHash);
end;
function InstallRoot: String;
begin
  Result := ExpandConstant('{localappdata}\Programs\{#InstallFolder}');
end;
procedure CaptureOwnedStartup(Gate: String);
var Shell, Link: Variant; Target, Folder, VersionName, StateRoot: String; I, Code: Integer;
begin
  StartupOwned := False;
  // Native App startup remains owned by its original Rust coordinator. Never
  // reinterpret a legacy registration or retarget it during a blocked upgrade.
  if '{#NativePackage}' = '1' then exit;
  if not FileExists(StartupPath) then exit;
  if (NativeAttributes(StartupPath) and $400) <> 0 then exit;
  try
    Shell := CreateOleObject('WScript.Shell'); Link := Shell.CreateShortcut(StartupPath);
    Target := Link.TargetPath; Folder := RemoveBackslashUnlessRoot(ExtractFileDir(Target));
    VersionName := ExtractFileName(Folder);
    if (CompareText(Target, Folder + '\StyxPreview.exe') <> 0) or (Length(VersionName) <> 64) then exit;
    for I := 1 to Length(VersionName) do if Pos(VersionName[I], '0123456789abcdef') = 0 then exit;
    if CompareText(Folder, InstallRoot + '\versions\' + VersionName) <> 0 then exit;
    if CompareText(RemoveBackslashUnlessRoot(String(Link.WorkingDirectory)), Folder) <> 0 then exit;
    if not FileExists(Folder + '\windows-package.json') then exit;
    if GetSHA256OfFile(Folder + '\windows-package.json') <> VersionName then exit;
    if not FileExists(Target) then exit;
    StartupArgs := Link.Arguments;
    if Copy(StartupArgs, 1, 23) <> '--startup --state-dir "' then exit;
    if Copy(StartupArgs, Length(StartupArgs), 1) <> '"' then exit;
    StateRoot := Copy(StartupArgs, 24, Length(StartupArgs) - 24);
    if (Length(StateRoot) < 3) or (Copy(StateRoot, 2, 2) <> ':\') or (Pos('"', StateRoot) <> 0) or (Pos(#13, StateRoot) <> 0) or (Pos(#10, StateRoot) <> 0) then exit;
    if not Exec(Gate, 'check-login "' + InstallRoot + '" "' + StateRoot + '" "' + Folder + '" "' + StartupPath + '"', '', SW_HIDE, ewWaitUntilTerminated, Code) then exit;
    if Code <> 0 then exit;
    StartupHash := GetSHA256OfFile(StartupPath); StartupOwned := True;
  except
    Log('The startup shortcut is not an owned Styx entry; leaving it unchanged.');
  end;
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
function CheckIdle(Gate, Operation: String): String;
var Code: Integer;
begin
  Result := '';
  if '{#NativePackage}' = '1' then begin
    // The original App must consent and settle through its original Core.
    // Never automatically repeat a possibly dispatched maintenance mutation.
    if NativeMaintenanceAttempted then begin
      Result := 'This Setup attempt already requested an App handoff. Review its result before starting a new Setup attempt.';
      exit;
    end;
    NativeMaintenanceAttempted := True;
    if Operation = 'upgrade' then begin
      if not Exec(Gate, 'maintain-native-install "' + InstallRoot + '" upgrade "{#PackageHash}"', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
    end else if not Exec(Gate, 'maintain-native-install "' + InstallRoot + '" uninstall -', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
  end else begin
    if CheckForMutexes(AppMutexName('')) then begin
      Result := 'Styx is still running. Finish any tasks, then choose Quit Styx and retry.';
      exit;
    end;
    if not Exec(Gate, 'check "' + InstallRoot + '"', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
  end;
  if Code = 3 then Result := 'Setup could not confirm the original App/Core handoff. Open the installed Styx fully and review its request. An older or closed App requires a supported migration; no program files were changed.'
  else if Code = 1 then Result := 'Styx files are still in use. Finish any tasks and quit Styx before retrying.'
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
  Result := CheckIdle(ExpandConstant('{tmp}\StyxInstallGate.exe'), 'upgrade');
  if Result = '' then CaptureOwnedStartup(ExpandConstant('{tmp}\StyxInstallGate.exe'));
end;
function InitializeUninstall: Boolean;
var Problem: String;
begin
  Result := False;
  if CheckForMutexes(SetupMutexName('')) then exit;
  CreateMutex(SetupMutexName(''));
  Problem := CheckIdle(ExpandConstant('{app}\.installer\StyxInstallGate.exe'), 'uninstall');
  if Problem <> '' then begin
    if not UninstallSilent then MsgBox(Problem, mbInformation, MB_OK);
    exit;
  end;
  CaptureOwnedStartup(ExpandConstant('{app}\.installer\StyxInstallGate.exe'));
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer; Candidate: String;
begin
  if (CurStep = ssPostInstall) and ('{#NativePackage}' = '1') then begin
    Candidate := InstallRoot + '\versions\{#PackageHash}';
    if not Exec(ExpandConstant('{app}\.installer\StyxInstallGate.exe'), 'verify-native "' + Candidate + '" "{#PackageHash}"', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
    if Code <> 0 then RaiseException('Native package verification did not complete. Do not open this candidate; original device settings have not been changed.');
  end;
end;
