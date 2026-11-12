import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const temporary=prefix=>fs.mkdtempSync(path.join(process.env.STYX_INSTALL_TEST_PARENT??os.tmpdir(),prefix));
test('Windows native installer admission holds package mutex and observes running resources',{skip:process.platform!=='win32'},t=>{
  const temp=temporary('styx-install-admission-');t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
  const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),gate=path.join(temp,'gate.exe'),harness=path.join(temp,'test.exe');
  const compile=args=>execFileSync(csc,['/nologo','/warn:4','/warnaserror+','/target:exe','/reference:System.Web.Extensions.dll',...args],{windowsHide:true,stdio:'pipe'});
  compile(['/out:'+gate,path.join(here,'InstallGate.cs')]);
  compile(['/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/main:InstallCoordinationTest','/out:'+harness,path.join(here,'../Styx.cs'),path.join(here,'InstallCoordinationTest.cs')]);
  execFileSync(harness,[path.join(temp,'Programs Styx 中文'),gate],{windowsHide:true,timeout:30000,stdio:'pipe'});
});

test('Windows installer requires the existing Core registration before touching a startup entry',{skip:process.platform!=='win32'},t=>{
 const temp=temporary('styx-login-ownership-');t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),gate=path.join(temp,'gate.exe'),harness=path.join(temp,'test.exe');
 const compile=(out,file)=>execFileSync(csc,['/nologo','/warn:4','/warnaserror+','/target:exe','/reference:System.Web.Extensions.dll','/out:'+out,path.join(here,file)],{windowsHide:true,stdio:'pipe'});
 compile(gate,'InstallGate.cs');compile(harness,'LoginOwnershipTest.cs');execFileSync(harness,[temp,gate],{windowsHide:true,timeout:30000,stdio:'pipe'});
});

test('Windows native setup creates only missing private program directories',{skip:process.platform!=='win32'},t=>{
 const temp=temporary('styx-root-creation-');t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),gate=path.join(temp,'gate.exe'),harness=path.join(temp,'test.exe');
 for(const [output,input] of [[gate,'InstallGate.cs'],[harness,'InstallRootCreationTest.cs']])
  execFileSync(csc,['/nologo','/warn:4','/warnaserror+','/target:exe','/reference:System.Web.Extensions.dll','/out:'+output,path.join(here,input)],{windowsHide:true,stdio:'pipe'});
 execFileSync(harness,[temp,gate],{windowsHide:true,timeout:30000,stdio:'pipe'});
});

test('Inno selected directory scopes admission and atomic App fencing before any install',{
 skip:process.platform!=='win32'||!process.env.STYX_INNO_COMPILER,
},t=>{
 const temp=temporary('styx-selected-root-');t.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
 const payload=path.join(temp,'payload'),output=path.join(temp,'output');fs.mkdirSync(payload);fs.mkdirSync(output);
 fs.writeFileSync(path.join(payload,'inert.txt'),'installer admission test only\n');
 const gate=path.join(temp,'StyxInstallGate.exe');
 execFileSync(path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe'),[
  '/nologo','/warn:4','/warnaserror+','/target:exe','/reference:System.Web.Extensions.dll','/out:'+gate,path.join(here,'InstallGate.cs'),
 ],{windowsHide:true,stdio:'pipe'});
 // Include the real template unchanged. At Ready, exercise its actual admission
 // then stop before file copy, registry or shortcut writes.
 const harness=path.join(temp,'selected-root.iss');
 fs.writeFileSync(harness,`#include "${path.join(here,'product.iss')}"
[Code]
function NextButtonClick(CurPageID: Integer): Boolean;
var Root, Mode, Message, Report: String; Duplicate: THandle; Error: LongInt; Restart: Boolean;
begin
  Result := True;
  if CurPageID <> wpReady then exit;
  Root := ExpandConstant('{param:TESTROOT}');
  Mode := ExpandConstant('{param:TESTMODE}');
  Report := ExpandConstant('{param:TESTREPORT}');
  if CompareText(InstallRoot, Root) <> 0 then RaiseException('selected_root_mismatch');
  // A running App at a different root must not block this selected root.
  CreateMutex('Global\\Styx.App.' + Lowercase(GetSHA256OfUnicodeString(Lowercase(Root + '-other'))));
  if Mode = 'setup-busy' then CreateMutex(SetupMutexName(''));
  if Mode = 'app-busy' then CreateMutex(AppMutexName(''));
  Restart := False;
  Message := PrepareToInstall(Restart);
  if Mode = 'setup-busy' then begin
    if Message <> 'Another Styx installer or uninstaller is using this installation folder.' then RaiseException('occupied_fence_accepted');
  end else if Mode = 'app-busy' then begin
    if Message <> 'Styx is still running. Finish any tasks, then choose Quit Styx and retry.' then RaiseException('running_app_accepted');
  end else begin
    if Message <> '' then RaiseException(Message);
    if not HoldInstallFence then RaiseException('own_fence_not_reused');
    Duplicate := NativeCreateMutex(0, False, SetupMutexName(''));
    Error := DLLGetLastError;
    if Duplicate <> 0 then NativeCloseHandle(Duplicate);
    if (Duplicate = 0) or (Error <> 183) then RaiseException('selected_fence_missing');
  end;
  if not SaveStringToFile(Report, 'PASS ' + Mode, False) then RaiseException('report_write_failed');
  Result := False;
end;
`);
 const defines={NativePackage:'0',SourceDir:payload,OutputDir:output,ProductVersion:'0.0.0.1',PackageHash:'a'.repeat(64),GateFile:gate,
  ProductId:'Styx.SelectedRoot.Test',ProductName:'Styx Selected Root Test',InstallFolder:'StyxSelectedRootTest',StateDirectoryArgument:'X'};
 execFileSync(process.env.STYX_INNO_COMPILER,[...Object.entries(defines).map(([key,value])=>`/D${key}=${value}`),harness],{windowsHide:true,stdio:'pipe'});
 for(const mode of ['idle','app-busy','setup-busy']){
  const root=path.join(temp,`Chosen D drive 中文 ${mode}`),report=path.join(temp,`${mode}.txt`),log=path.join(temp,`${mode}.log`);
  let exitCode=0;try{execFileSync(path.join(output,'StyxSetup-0.0.0.1.exe'),[
   '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',`/LOG=${log}`,`/DIR=${root}`,`/TESTROOT=${root}`,`/TESTMODE=${mode}`,`/TESTREPORT=${report}`,
  ],{windowsHide:true,stdio:'pipe',timeout:30000});}catch(error){exitCode=error.status;}
  if(!fs.existsSync(report))throw Error(fs.existsSync(log)?fs.readFileSync(log,'utf8'):`selected_root_report_missing_${mode}`);
  if(fs.readFileSync(report,'utf8')!==`PASS ${mode}`)throw Error(`selected_root_check_failed_${mode}`);
  // Silent pre-install navigation refusal exits 1; the report distinguishes our
  // intentional stop from an initialization failure, without installing anything.
  if(exitCode!==1)throw Error(`expected_preinstall_abort_${mode}: ${exitCode}`);
  if(fs.existsSync(root))throw Error(`unexpected_install_write_${mode}`);
 }
});
