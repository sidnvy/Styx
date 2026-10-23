// Current-user Shell startup entry. Core owns preference/journal persistence.
// Never reads or writes Windows' private StartupApproved representation.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {observeWindowsNativeAppAuthority} from './native-app-authority.mjs';
const assert=(v,e)=>{if(!v)throw Error(e)},sha=b=>createHash('sha256').update(b).digest('hex'),hash=f=>sha(fs.readFileSync(f));
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.replace(/[\\/]+$/,'').toLowerCase()===b.replace(/[\\/]+$/,'').toLowerCase();
const absolute=s=>typeof s==='string'&&path.win32.isAbsolute(s)&&path.win32.normalize(s)===s&&!/["\x00-\x1f\x7f]/.test(s);
const digest=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);
const keys=['schema','kind','ownerSid','shortcutPath','installRoot','resourceRoot','packageSha256','appSha256','stateDir'];
function validate(r,stateDir){assert(r&&Object.keys(r).length===keys.length&&keys.every(k=>k in r)&&r.schema===1&&r.kind==='windows-startup-shortcut'&&/^S-1-\d+(?:-\d+){1,15}$/.test(r.ownerSid)&&['shortcutPath','installRoot','resourceRoot','stateDir'].every(k=>absolute(r[k]))&&digest(r.packageSha256)&&digest(r.appSha256)&&same(r.stateDir,stateDir),'app_login_registration_invalid');assert(same(path.win32.dirname(path.win32.dirname(r.resourceRoot)),r.installRoot)&&path.win32.basename(path.win32.dirname(r.resourceRoot))==='versions'&&path.win32.basename(r.resourceRoot)===r.packageSha256,'app_login_installation_invalid');}
function regular(f){const s=fs.lstatSync(f);assert(s.isFile()&&!s.isSymbolicLink()&&same(fs.realpathSync(f),path.resolve(f)),'app_login_package_redirected');}
function pinned(root,manifest,name){const entry=manifest.files.find(f=>f.path===name);assert(entry&&digest(entry.sha256),'app_login_package_invalid');const file=path.join(root,...name.split('/'));regular(file);assert(hash(file)===entry.sha256,'app_login_package_changed');return file;}
async function packageIdentity(root,{full=false,expected,authority,ops}){
 assert(absolute(root),'app_login_package_invalid');const mf=path.join(root,'windows-package.json');regular(mf);const packageSha256=hash(mf),manifest=JSON.parse(fs.readFileSync(mf,'utf8'));
 assert(manifest.schema===1&&manifest.compiled===true&&Array.isArray(manifest.files)&&manifest.files.length<20000&&path.basename(root)===packageSha256&&path.basename(path.dirname(root))==='versions','app_login_installed_package_required');
 if(expected)assert(packageSha256===expected.packageSha256,'app_login_registered_package_changed');
 const app=pinned(root,manifest,'StyxPreview.exe');if(expected)assert(hash(app)===expected.appSha256,'app_login_registered_app_changed');
 if(authority){const runtimeFile=pinned(root,manifest,'windows-runtime.json'),runtime=JSON.parse(fs.readFileSync(runtimeFile));const current=ops.observeApp(root,runtime);assert(current.source==='current_windows_native_app'&&current.nativeAppPid===authority.nativeAppPid&&current.nativeAppGeneration===authority.nativeAppGeneration,'app_login_native_app_required');}
 if(full){const node=pinned(root,manifest,'runtime/node.exe'),verifier=pinned(root,manifest,'install-windows-preview.mjs');ops.run(node,[verifier,'verify'],{encoding:'utf8',timeout:120000,maxBuffer:16384,windowsHide:true,env:Object.fromEntries(Object.entries(process.env).filter(([k])=>!['NODE_OPTIONS','NODE_PATH'].includes(k.toUpperCase())))});}
 return {resourceRoot:root,installRoot:path.dirname(path.dirname(root)),packageSha256,appSha256:hash(app)};
}
function native(input,ops){
 assert(/^[A-Za-z0-9 .-]+\.lnk$/.test(ops.shortcutName??'Styx.lnk'),'app_login_shortcut_name_invalid');
 const data=Buffer.from(JSON.stringify({...input,shortcutName:ops.shortcutName??'Styx.lnk'})).toString('base64');
 const script=String.raw`$ErrorActionPreference='Stop'
$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${data}'))|ConvertFrom-Json
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$folder=[Environment]::GetFolderPath('Startup')
$link=Join-Path $folder $s.shortcutName
function Read-Link {
 $r=@{ownerSid=$sid;shortcutPath=$link;present=$false}
 if(Test-Path -LiteralPath $link){
  $f=Get-Item -LiteralPath $link -Force
  if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'app_login_shortcut_redirected'}
  if((Get-Acl -LiteralPath $link).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid){throw 'app_login_shortcut_foreign'}
  $w=New-Object -ComObject WScript.Shell;$l=$w.CreateShortcut($link)
  $r.present=$true;$r.sha256=(Get-FileHash -LiteralPath $link -Algorithm SHA256).Hash.ToLowerInvariant();$r.target=$l.TargetPath;$r.arguments=$l.Arguments;$r.workingDirectory=$l.WorkingDirectory
 }
 return $r
}
$r=Read-Link
if($s.action -ne 'read'){
 if($s.expected.ownerSid -ne $sid -or $s.expected.shortcutPath -ine $link -or $r.present -ne $s.expected.present){throw 'app_login_shortcut_changed'}
 if($r.present -and $r.sha256 -ne $s.expected.sha256){throw 'app_login_shortcut_changed'}
 if($s.action -eq 'remove'){if($r.present){Remove-Item -LiteralPath $link -Force}}
 elseif($s.action -eq 'create'){
  if($r.present){throw 'app_login_shortcut_changed'}
  $temp=Join-Path $s.stateDir ('app-login-'+[Guid]::NewGuid().ToString('N')+'.lnk')
  try{$w=New-Object -ComObject WScript.Shell;$l=$w.CreateShortcut($temp);$l.TargetPath=$s.target;$l.Arguments=$s.arguments;$l.WorkingDirectory=$s.workingDirectory;$l.Description='Styx';$l.Save();$acl=Get-Acl -LiteralPath $temp;$acl.SetOwner([Security.Principal.SecurityIdentifier]::new($sid));Set-Acl -LiteralPath $temp -AclObject $acl;[IO.File]::Move($temp,$link)}finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
 }else{throw 'app_login_action_invalid'}
 $r=Read-Link
}
$r|ConvertTo-Json -Compress`;
 const value=JSON.parse(String(ops.run('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:15000,maxBuffer:16384,windowsHide:true,stdio:['ignore','pipe','pipe']})).trim());
 assert(typeof value.present==='boolean'&&absolute(value.shortcutPath)&&path.win32.basename(value.shortcutPath)===(ops.shortcutName??'Styx.lnk')&&/^S-1-\d+(?:-\d+){1,15}$/.test(value.ownerSid),'app_login_native_observation_invalid');return value;
}
function args(stateDir){return '--startup --state-dir "'+path.win32.dirname(stateDir)+'"'}
function matches(observed,r){return observed.present&&same(observed.target,path.win32.join(r.resourceRoot,'StyxPreview.exe'))&&observed.arguments===args(r.stateDir)&&same(observed.workingDirectory,r.resourceRoot)&&same(observed.shortcutPath,r.shortcutPath)&&observed.ownerSid===r.ownerSid;}
async function context(input,options={},full=false){
 const ops={platform:process.platform,run:execFileSync,observeApp:observeWindowsNativeAppAuthority,...options};assert(ops.platform==='win32'&&absolute(input.stateDir),'app_login_windows_context_required');
 const registration=input.registration??null;if(registration)validate(registration,input.stateDir);
 const trusted=typeof input.trustedApp==='function'?await input.trustedApp():input.trustedApp;
 let identity;
 if(trusted){assert(trusted.authority?.source==='current_windows_native_app','app_login_native_app_required');identity=await packageIdentity(trusted.resourceRoot,{full,authority:trusted.authority,ops});if(registration)assert(same(identity.installRoot,registration.installRoot),'app_login_installation_changed');}
 else if(registration)identity=await packageIdentity(registration.resourceRoot,{full,expected:registration,ops});
 const observed=native({action:'read'},ops);
 if(registration)assert(observed.ownerSid===registration.ownerSid&&same(observed.shortcutPath,registration.shortcutPath),'app_login_owner_changed');
 const current=identity?{schema:1,kind:'windows-startup-shortcut',ownerSid:observed.ownerSid,shortcutPath:observed.shortcutPath,...identity,stateDir:input.stateDir}:null;
 const owned=observed.present&&!!registration&&(matches(observed,registration)||!!trusted&&matches(observed,current));
 return {ops,registration,current,observed,owned};
}
function view(c){const targetMatches=c.owned&&matches(c.observed,c.current);return {schema:1,status:c.observed.present?(c.owned?'registered_unverified':'needs_attention'):'not_registered',registration:{present:c.observed.present,owned:c.owned,targetMatches},systemApproval:'unknown',effective:c.observed.present?(c.owned?'registered_unverified':'needs_attention'):'not_registered',...(targetMatches&&JSON.stringify(c.registration)!==JSON.stringify(c.current)?{reconciledRegistration:c.current}:{})};}
export async function readWindowsAppLogin(input,options={}){return view(await context(input,options));}
const validatedPlans=new WeakSet();
async function makePlan(input,options,full){
 assert(typeof input.enabled==='boolean','app_login_enabled_required');const c=await context(input,options,full);
 assert(!c.observed.present||c.owned,'app_login_shortcut_foreign');if(input.enabled)assert(c.current,'app_login_native_registration_required');
 if(input.enabled&&c.observed.present)assert(matches(c.observed,c.current),'app_login_entry_requires_installer_update');
 return {schema:1,kind:'windows-app-login-plan',action:input.enabled?(c.observed.present?'none':'create'):(c.observed.present?'remove':'none'),before:c.observed,registration:input.enabled?c.current:c.registration,context:input};
}
export async function planWindowsAppLogin(input,options={}){const plan=await makePlan(input,options,true);validatedPlans.add(plan);return plan;}
export async function reconcileWindowsAppLogin(input,options={}){
 assert(input.trustedApp,'app_login_native_app_required');
 const current=await context(input,options);
 // The native App has already completed its startup package verification.
 // An identical registration needs no write. Still observe the current native
 // owner, manifest/executable pins and actual shortcut on every invocation.
 if(current.registration&&keys.every(key=>current.registration[key]===current.current[key])&&current.owned&&matches(current.observed,current.current)){
  const {reconciledRegistration,...unchanged}=view(current);return unchanged;
 }
 // A changed registration or shortcut retains the full rebind verification.
 return view(await context(input,options,true));
}
export async function controlWindowsAppLogin(plan,{authorize,...options}={}){
 assert(authorize===true&&plan?.schema===1&&plan.kind==='windows-app-login-plan','app_login_authorization_required');assert(validatedPlans.has(plan),'app_login_current_plan_required');validatedPlans.delete(plan);
 // This process just verified the full closure; revalidate manifest, live App,
 // executable pin and exact OS entry before the only shortcut mutation.
 const current=await makePlan(plan.context,options,false);
 assert(JSON.stringify(current)===JSON.stringify(plan),'app_login_plan_changed');const c=await context(plan.context,options);
 if(plan.action!=='none')native({action:plan.action,expected:plan.before,stateDir:plan.context.stateDir,target:path.win32.join(plan.registration.resourceRoot,'StyxPreview.exe'),arguments:args(plan.context.stateDir),workingDirectory:plan.registration.resourceRoot},c.ops);
 const after=await context({...plan.context,registration:plan.registration},options);assert(plan.context.enabled?after.owned:!after.observed.present,'app_login_apply_unverified');return {...view(after),operation:plan.action};
}
