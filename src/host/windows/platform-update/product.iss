#ifndef SourceDir
  #error SourceDir is required
#endif
[Setup]
AppId={#ProductId}
AppName={#ProductName}
AppVersion={#ProductVersion}
AppPublisher=Styx
DefaultDirName={localappdata}\Programs\{#InstallFolder}
DisableDirPage=no
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
SetupIconFile={#SourceDir}\styx.ico
CloseApplications=no
RestartApplications=no
; Serialize this product's setup UI independently of its not-yet-selected path.
; The App's root-scoped fence is acquired in PrepareToInstall, after selection.
SetupMutex=Global\Styx.Setup.{#ProductId}
Uninstallable=yes
UninstallFilesDir={app}\.installer
UninstallDisplayIcon={app}\versions\{#PackageHash}\StyxPreview.exe

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}\versions\{#PackageHash}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#GateFile}"; DestDir: "{app}\.installer"; Flags: ignoreversion
Source: "{#GateFile}"; Flags: dontcopy

#define StateDirectory Copy(StateDirectoryArgument, 1, Len(StateDirectoryArgument) - 1)
[Icons]
#if StateDirectory != ""
Name: "{userprograms}\{#ProductName}"; Filename: "{app}\versions\{#PackageHash}\StyxPreview.exe"; WorkingDir: "{app}\versions\{#PackageHash}"; Parameters: "--state-dir ""{#StateDirectory}"""
#else
Name: "{userprograms}\{#ProductName}"; Filename: "{app}\versions\{#PackageHash}\StyxPreview.exe"; WorkingDir: "{app}\versions\{#PackageHash}"; Parameters: ""
#endif

[Code]
var NativeVerificationFailed: Boolean;
var HeldInstallRoot: String; HeldInstallMutex: THandle;
function NativeCreateMutex(Attributes: NativeUInt; InitialOwner: BOOL; Name: String): THandle;
  external 'CreateMutexW@kernel32.dll stdcall';
function NativeCloseHandle(Handle: THandle): BOOL;
  external 'CloseHandle@kernel32.dll stdcall';
function InstallRoot: String;
begin
  Result := RemoveBackslashUnlessRoot(ExpandConstant('{app}'));
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
function HoldInstallFence: Boolean;
var Handle: THandle; Error: LongInt; Root: String;
begin
  Root := InstallRoot;
  if (HeldInstallMutex <> 0) and (CompareText(HeldInstallRoot, Root) = 0) then begin
    Result := True;
    exit;
  end;
  // Atomically create the same root-scoped fence that the App checks. A
  // pre-existing fence belongs to another installer/uninstaller, not this one.
  Handle := NativeCreateMutex(0, False, SetupMutexName(''));
  Error := DLLGetLastError;
  Result := (Handle <> 0) and (Error <> 183); // ERROR_ALREADY_EXISTS
  if not Result then begin
    if Handle <> 0 then NativeCloseHandle(Handle);
    exit;
  end;
  // Back navigation may select another root after a known admission refusal.
  if HeldInstallMutex <> 0 then NativeCloseHandle(HeldInstallMutex);
  HeldInstallMutex := Handle;
  HeldInstallRoot := Root;
  // Keep the handle until process exit, including final file/shortcut writes.
end;
function CheckIdle(Gate: String): String;
var Code: Integer;
begin
  Result := '';
  // The selected root's install fence is held during setup and uninstall. The App checks it
  // after creating AppMutex, so this check also fences concurrent startup.
  if CheckForMutexes(AppMutexName('')) then begin
    Result := 'Styx is still running. Finish any tasks, then choose Quit Styx and retry.';
    exit;
  end;
  if not Exec(Gate, 'check "' + InstallRoot + '"', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
  if Code = 1 then Result := 'Styx files are still in use. Finish any tasks and quit Styx before retrying.'
  else if Code <> 0 then Result := 'Setup could not confirm that Styx has stopped. No program files have been changed. Close Styx and retry.';
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer;
begin
  if not HoldInstallFence then begin
    Result := 'Another Styx installer or uninstaller is using this installation folder.';
    exit;
  end;
  ExtractTemporaryFile('StyxInstallGate.exe');
  if not Exec(ExpandConstant('{tmp}\StyxInstallGate.exe'), 'check-native-user', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
  if Code <> 0 then begin
    Result := 'Run Styx Setup from your normal logged-in desktop without administrator privileges. No program files were changed.';
    exit;
  end;
  // The selected root is fenced here. Recheck AppMutex to close the startup race.
  Result := CheckIdle(ExpandConstant('{tmp}\StyxInstallGate.exe'));
  if Result = '' then begin
    if not Exec(ExpandConstant('{tmp}\StyxInstallGate.exe'), 'create-native-root "' + InstallRoot + '"', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
    if Code <> 0 then Result := 'Setup could not create the selected program folder with private permissions. Existing folder permissions have not been changed.';
  end;
end;
function InitializeUninstall: Boolean;
var Problem: String;
begin
  Result := False;
  if not HoldInstallFence then exit;
  Problem := CheckIdle(ExpandConstant('{app}\.installer\StyxInstallGate.exe'));
  if Problem <> '' then begin
    if not UninstallSilent then MsgBox(Problem, mbInformation, MB_OK);
    exit;
  end;
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Code: Integer; Candidate: String;
begin
  if CurStep = ssPostInstall then begin
    NativeVerificationFailed := True;
    Candidate := InstallRoot + '\versions\{#PackageHash}';
    if not Exec(ExpandConstant('{app}\.installer\StyxInstallGate.exe'), 'verify-native "' + Candidate + '" "{#PackageHash}"', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := 2;
    if Code <> 0 then RaiseException('Native package verification did not complete. Do not open this candidate; original device settings have not been changed.');
    NativeVerificationFailed := False;
  end;
end;

// Silent post-install verification failures must not appear successful.
function GetCustomSetupExitCode: Integer;
begin
  if NativeVerificationFailed then Result := 2 else Result := 0;
end;
