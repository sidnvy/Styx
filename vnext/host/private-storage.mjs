import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

// PowerShell cold startup on loaded native Windows runners can exceed seven
// seconds. Keep ACL operations bounded without retrying a partially applied ACL.
const WINDOWS_ACL_TIMEOUT_MS = 30_000;

// The caller's wx handle remains open. A second handle permits existing
// read/write handles but denies deletion/rename while ownership is assigned.
// Check native file IDs before touching the security descriptor: paths alone
// cannot authorize changing a file that another actor replaced meanwhile.
const WINDOWS_NEW_FILE_ACL = String.raw`$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class StyxNewFileIdentity {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
  public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
 }
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 public static SafeFileHandle Parent(string path) {
  var h=CreateFileW(path,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
  if(h.IsInvalid)throw new Win32Exception();return h;
 }
 public static void Check(SafeFileHandle handle,ulong expected,bool directory) {
  Info value;if(!GetFileInformationByHandle(handle,out value))throw new Win32Exception();
  var id=((ulong)value.IndexHigh<<32)|value.IndexLow;
  if(id!=expected||(value.Attributes&0x400)!=0||((value.Attributes&0x10)!=0)!=directory)throw new InvalidOperationException();
 }
}
'@
$parent=$null;$stream=$null
try {
 $parent=[StyxNewFileIdentity]::Parent($env:STYX_NEW_FILE_PARENT)
 [StyxNewFileIdentity]::Check($parent,[UInt64]::Parse($env:STYX_NEW_FILE_PARENT_ID),$true)
 # The access-rights overload includes WRITE_DAC/WRITE_OWNER. ReadWrite-only
 # handles can verify file IDs but cannot assign their own security descriptor.
 $stream=New-Object IO.FileStream($env:STYX_NEW_PRIVATE_FILE,[IO.FileMode]::Open,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::ReadWrite,4096,[IO.FileOptions]::None)
 [StyxNewFileIdentity]::Check($stream.SafeFileHandle,[UInt64]::Parse($env:STYX_NEW_FILE_ID),$false)
 if($stream.Length -ne 0){throw 'new_private_file_not_empty'}
 $current=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $acl=New-Object Security.AccessControl.FileSecurity
 $acl.SetOwner($current);$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @($current.Value,'S-1-5-18','S-1-5-32-544')){
  $identity=New-Object Security.Principal.SecurityIdentifier($sid)
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','Allow')
  $acl.AddAccessRule($rule)
 }
 $stream.SetAccessControl($acl);$stream.Flush($true)
 [StyxNewFileIdentity]::Check($stream.SafeFileHandle,[UInt64]::Parse($env:STYX_NEW_FILE_ID),$false)
}finally{if($null -ne $stream){$stream.Dispose()};if($null -ne $parent){$parent.Dispose()}}
`;

// POSIX mode bits do not represent NTFS ACLs. Validate the actual Windows
// DACL and reject any Allow rule for a different OS user or generic group.
const WINDOWS_ACL_CHECK = [
  "$ErrorActionPreference='Stop'",
  'try {',
  // Windows PowerShell5 emits the JSON array as one pipeline object. An
  // array-subexpression would wrap it again, so foreach would receive an
  // Object[] and Get-Acl would return multiple descriptors at once. Direct
  // typed assignment preserves a flat path list on both PowerShell5 and7.
  '  [string[]]$files=ConvertFrom-Json -InputObject $env:STYX_PRIVATE_PATHS_TO_VERIFY',
  '  if($files.Count -lt 1 -or $files.Count -gt 32){exit 2}',
  '  $current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
  '  function IdentitySid($reference) {',
  '    $name=[String]$reference',
  "    if($name -match '^S-1-[0-9]+(-[0-9]+)+$'){return $name}",
  '    return (New-Object Security.Principal.NTAccount($name)).Translate(',
  '      [Security.Principal.SecurityIdentifier]).Value',
  '  }',
  "  $allowed=@($current,'S-1-5-18','S-1-5-32-544')",
  '  foreach($file in $files){',
  '    if([String]::IsNullOrWhiteSpace($file)){exit 2}',
  '    $acl=Get-Acl -LiteralPath $file',
  '    $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $acl.Sddl',
  '    if($null -eq $descriptor.DiscretionaryAcl){exit 2}',
  '    if((IdentitySid $acl.Owner) -ne $current){exit 2}',
  '    foreach($rule in $acl.Access){',
  '      if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow){',
  '        $principal=IdentitySid $rule.IdentityReference',
  '        if($allowed -notcontains $principal){exit 2}',
  '      }',
  '    }',
  '  }',
  '  exit 0',
  '}catch{exit 2}'
].join('\n');

function checkWindowsAcl(filenames,kind) {
  const encoded=Buffer.from(WINDOWS_ACL_CHECK,'utf16le').toString('base64');
  try{
    execFileSync('powershell.exe',[
      '-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded
    ],{env:{...process.env,STYX_PRIVATE_PATHS_TO_VERIFY:JSON.stringify(filenames)},
      windowsHide:true,timeout:WINDOWS_ACL_TIMEOUT_MS,stdio:['ignore','ignore','ignore']});
  }catch(e){throw Error('private_'+kind+(e.code==='ETIMEDOUT'
    ?'_acl_check_timed_out':'_acl_not_owner_only'))}
}
function inspectPrivatePath(filename,kind) {
  if(typeof filename!=='string'||!path.isAbsolute(filename))
    throw Error('private_'+kind+'_absolute_path_required');
  const info=fs.lstatSync(filename);
  if(info.isSymbolicLink()||(kind==='file'?!info.isFile():!info.isDirectory()))
    throw Error('private_'+kind+'_not_regular');
  if(process.platform!=='win32'){
    if(info.uid!==process.getuid())throw Error('private_'+kind+'_owner_mismatch');
    if(info.mode&0o077)throw Error('private_'+kind+'_permissions');
  }
  return info;
}
function requirePrivatePath(filename,kind) {
  const info=inspectPrivatePath(filename,kind);
  if(process.platform==='win32')checkWindowsAcl([filename],kind);
  return info;
}
export function requirePrivateFile(filename) {return requirePrivatePath(filename,'file')}
export function requirePrivateDirectory(folder) {return requirePrivatePath(folder,'directory')}

const sameFile=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
// Never repairs existing files. Windows elevated tokens commonly create files
// owned by Administrators even inside a user-owned private directory. Establish
// the caller's ownership/DACL on this empty, exclusive file before any secret.
export function openPrivateFile(filename,mode=0o600){
 if(typeof filename!=='string'||!path.isAbsolute(filename)||path.normalize(filename)!==filename)throw Error('private_file_absolute_path_required');
 if(![0o600,0o700].includes(mode))throw Error('private_file_creation_mode_invalid');
 const parent=path.dirname(filename);requirePrivateDirectory(parent);const parentInfo=fs.lstatSync(parent,{bigint:true});
 const fd=fs.openSync(filename,'wx',mode),created=fs.fstatSync(fd,{bigint:true});
 try{
  if(process.platform==='win32'){
   execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(WINDOWS_NEW_FILE_ACL,'utf16le').toString('base64')],{
    env:{...process.env,STYX_NEW_PRIVATE_FILE:filename,STYX_NEW_FILE_ID:created.ino.toString(),STYX_NEW_FILE_PARENT:parent,STYX_NEW_FILE_PARENT_ID:parentInfo.ino.toString()},
    windowsHide:true,timeout:WINDOWS_ACL_TIMEOUT_MS,stdio:['ignore','ignore','ignore']});
  }
  requirePrivateDirectory(parent);requirePrivateFile(filename);
  if(!sameFile(parentInfo,fs.lstatSync(parent,{bigint:true}))||!sameFile(created,fs.lstatSync(filename,{bigint:true}))||!sameFile(created,fs.fstatSync(fd,{bigint:true})))throw Error('private_file_creation_binding_changed');
  return fd;
 }catch(e){
  fs.closeSync(fd);
  // Delete only our own still-empty inode. A replaced path is never removed.
  try{const current=fs.lstatSync(filename,{bigint:true});if(current.isFile()&&current.size===0n&&sameFile(created,current))fs.unlinkSync(filename);}catch{}
  throw Error(e.code==='ETIMEDOUT'?'private_file_creation_timed_out':'private_file_creation_failed');
 }
}
export function writePrivateFile(filename,data,{mode=0o600,encoding='utf8'}={}){
 const fd=openPrivateFile(filename,mode),created=fs.fstatSync(fd,{bigint:true});let complete=false;
 try{fs.writeFileSync(fd,data,{encoding});fs.fsyncSync(fd);complete=true;}
 finally{
  fs.closeSync(fd);
  if(!complete)try{if(sameFile(created,fs.lstatSync(filename,{bigint:true})))fs.unlinkSync(filename);}catch{}
 }
}

// Publisher-signed PUBLIC payload staging only. Credentials continue to use
// openPrivateFile one at a time. Own wx handles stay open while one native
// invocation assigns the same owner/private DACL to at most 32 empty files.
// No existing file is repaired and no result is reusable authorization.
export function openPrivatePayloadFiles(entries){
 if(process.platform!=='win32')throw Error('windows_payload_batch_required');
 if(!Array.isArray(entries)||entries.length<1||entries.length>32||Array.from(entries).some(entry=>!entry||Object.keys(entry).some(k=>!['path','mode'].includes(k))||typeof entry.path!=='string'||!path.isAbsolute(entry.path)||path.normalize(entry.path)!==entry.path||![0o600,0o700].includes(entry.mode??0o600)))throw Error('private_payload_batch_invalid');
 const opened=[];
 try{
  for(const entry of entries){
   const parent=path.dirname(entry.path),parentInfo=fs.lstatSync(parent,{bigint:true});
   if(!parentInfo.isDirectory()||parentInfo.isSymbolicLink())throw Error('private_payload_parent_not_regular');
   const fd=fs.openSync(entry.path,'wx',entry.mode??0o600),created=fs.fstatSync(fd,{bigint:true});
   opened.push({path:entry.path,fd,created,parent,parentInfo});
  }
  const rows=opened.map(x=>({file:x.path,fileId:x.created.ino.toString(),parent:x.parent,parentId:x.parentInfo.ino.toString()}));
  for(const needle of ['$parent=$null;$stream=$null','$stream.SetAccessControl($acl);$stream.Flush($true)'])if(WINDOWS_NEW_FILE_ACL.split(needle).length!==2)throw Error('private_payload_native_contract_changed');
  const script=WINDOWS_NEW_FILE_ACL.replace('$parent=$null;$stream=$null',String.raw`[object[]]$items=ConvertFrom-Json -InputObject $env:STYX_NEW_PAYLOAD_FILES
if($items.Count -lt 1 -or $items.Count -gt 32){throw 'private_payload_batch_invalid'}
foreach($item in $items){
$env:STYX_NEW_PRIVATE_FILE=[String]$item.file
$env:STYX_NEW_FILE_ID=[String]$item.fileId
$env:STYX_NEW_FILE_PARENT=[String]$item.parent
$env:STYX_NEW_FILE_PARENT_ID=[String]$item.parentId
$parent=$null;$stream=$null`).replace('$stream.SetAccessControl($acl);$stream.Flush($true)',String.raw`$stream.SetAccessControl($acl);$stream.Flush($true)
 # Read back the actual descriptor through the same native-ID-checked handle
 # before the caller can write its first public payload byte.
 $observed=$stream.GetAccessControl()
 if($observed.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $current.Value){throw 'private_payload_owner_mismatch'}
 $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList ($observed.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
 if($null -eq $descriptor.DiscretionaryAcl){throw 'private_payload_null_dacl'}
 $allowed=@($current.Value,'S-1-5-18','S-1-5-32-544')
 foreach($rule in $observed.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $allowed -notcontains $rule.IdentityReference.Value){throw 'private_payload_broad_dacl'}
 }`)+ '\n}';
  // Bound environment data as well as path count; keep all original wx FDs
  // open across every native group until the caller receives them.
  for(let offset=0;offset<rows.length;){
   let end=Math.min(offset+32,rows.length),group=rows.slice(offset,end);
   while(JSON.stringify(group).length>16384&&end>offset+1)group=rows.slice(offset,--end);
   if(JSON.stringify(group).length>16384)throw Error('private_payload_batch_limit');
   execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{
    env:{...process.env,STYX_NEW_PAYLOAD_FILES:JSON.stringify(group)},windowsHide:true,timeout:WINDOWS_ACL_TIMEOUT_MS,stdio:['ignore','ignore','ignore']});
   offset=end;
  }
  for(const item of opened){
   const parent=fs.lstatSync(item.parent,{bigint:true}),file=fs.lstatSync(item.path,{bigint:true}),handle=fs.fstatSync(item.fd,{bigint:true});
   if(!parent.isDirectory()||parent.isSymbolicLink()||!file.isFile()||file.isSymbolicLink()||!sameFile(parent,item.parentInfo)||!sameFile(file,item.created)||!sameFile(handle,item.created)||handle.size!==0n)throw Error('private_payload_creation_binding_changed');
  }
  return opened.map(({path,fd})=>({path,fd}));
 }catch(error){
  for(const item of opened){fs.closeSync(item.fd);try{const parent=fs.lstatSync(item.parent,{bigint:true}),current=fs.lstatSync(item.path,{bigint:true});if(parent.isDirectory()&&!parent.isSymbolicLink()&&sameFile(parent,item.parentInfo)&&current.isFile()&&!current.isSymbolicLink()&&current.size===0n&&sameFile(current,item.created))fs.unlinkSync(item.path);}catch{}}
  throw Error(error.code==='ETIMEDOUT'?'private_payload_creation_timed_out':'private_payload_creation_failed');
 }
}

// One synchronous boundary, not a cache. Every path is freshly lstatted and
// every actual Windows DACL is checked on each invocation. Never carry this
// result across an await, callback or mutation as authorization for later use.
export function requirePrivatePaths(entries) {
  if(!Array.isArray(entries)||entries.length<1||entries.length>32||
      Array.from(entries).some(entry=>!entry||!['file','directory'].includes(entry.kind)||
        Object.keys(entry).some(key=>!['path','kind'].includes(key))))
    throw Error('private_paths_invalid');
  const files=entries.map(entry=>entry.path);
  if(JSON.stringify(files).length>16384)throw Error('private_paths_limit');
  const infos=entries.map(entry=>inspectPrivatePath(entry.path,entry.kind));
  if(process.platform==='win32')checkWindowsAcl(files,'paths');
  return infos;
}

// Apply ACLs only to a directory created by this invocation, before placing
// any secret in it. Existing directories are inspected without modification.
export function ensurePrivateDirectory(folder,{exclusive=false,bigint=false}={}) {
  if(typeof folder!=='string'||!path.isAbsolute(folder))
    throw Error('private_directory_absolute_path_required');
  if(typeof exclusive!=='boolean')throw Error('private_directory_exclusive_invalid');
  if(typeof bigint!=='boolean')throw Error('private_directory_identity_option_invalid');
  const verifiedIdentity=expected=>{
    if(!bigint)return requirePrivateDirectory(folder);
    const before=fs.lstatSync(folder,{bigint:true});
    if(!before.isDirectory()||before.isSymbolicLink()||expected&&!sameFile(before,expected))throw Error('private_directory_creation_binding_changed');
    requirePrivateDirectory(folder);
    const after=fs.lstatSync(folder,{bigint:true});
    if(!after.isDirectory()||after.isSymbolicLink()||!sameFile(before,after))throw Error('private_directory_creation_binding_changed');
    return after;
  };
  if(!exclusive){try{fs.lstatSync(folder);return verifiedIdentity()}
  catch(e){if(e.code!=='ENOENT')throw e}}
  // Non-recursive: callers must explicitly choose an existing parent. Never
  // create or change ACLs on arbitrary ancestor directories.
  const parent=bigint?path.dirname(folder):undefined,parentInfo=bigint?fs.lstatSync(parent,{bigint:true}):undefined;
  if(bigint&&(!parentInfo.isDirectory()||parentInfo.isSymbolicLink()))throw Error('private_directory_parent_not_regular');
  fs.mkdirSync(folder,{mode:0o700});
  const created=bigint?fs.lstatSync(folder,{bigint:true}):undefined;
  if(bigint&&(!created.isDirectory()||created.isSymbolicLink()))throw Error('private_directory_created_not_regular');
  try{
    if(process.platform==='win32'){
      let script=[
        "$ErrorActionPreference='Stop'",
        '$folder=$env:STYX_NEW_PRIVATE_DIRECTORY',
        '$item=Get-Item -LiteralPath $folder -Force',
        'if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){exit 2}',
        '$current=[Security.Principal.WindowsIdentity]::GetCurrent().User',
        '$acl=New-Object Security.AccessControl.DirectorySecurity',
        '$acl.SetOwner($current)',
        '$acl.SetAccessRuleProtection($true,$false)',
        "foreach($sid in @($current.Value,'S-1-5-18','S-1-5-32-544')){",
        '  $identity=New-Object Security.Principal.SecurityIdentifier($sid)',
        "  $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')",
        '  $acl.AddAccessRule($rule)',
        '}',
        'Set-Acl -LiteralPath $folder -AclObject $acl'
      ].join('\n');
      if(bigint){
        const marker='$parent=$null;$stream=$null';
        if(WINDOWS_NEW_FILE_ACL.split(marker).length!==2)throw Error('private_directory_native_contract_changed');
        const prefix=WINDOWS_NEW_FILE_ACL.slice(0,WINDOWS_NEW_FILE_ACL.indexOf(marker));
        script=prefix+String.raw`$parentHandle=$null;$directoryHandle=$null
try {
 $parentHandle=[StyxNewFileIdentity]::Parent($env:STYX_NEW_DIRECTORY_PARENT)
 [StyxNewFileIdentity]::Check($parentHandle,[UInt64]::Parse($env:STYX_NEW_DIRECTORY_PARENT_ID),$true)
 $directoryHandle=[StyxNewFileIdentity]::Parent($env:STYX_NEW_PRIVATE_DIRECTORY)
 [StyxNewFileIdentity]::Check($directoryHandle,[UInt64]::Parse($env:STYX_NEW_DIRECTORY_ID),$true)
`+script+String.raw`
 [StyxNewFileIdentity]::Check($directoryHandle,[UInt64]::Parse($env:STYX_NEW_DIRECTORY_ID),$true)
 [StyxNewFileIdentity]::Check($parentHandle,[UInt64]::Parse($env:STYX_NEW_DIRECTORY_PARENT_ID),$true)
}finally{if($null -ne $directoryHandle){$directoryHandle.Dispose()};if($null -ne $parentHandle){$parentHandle.Dispose()}}
`;
      }
      execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive',
        '-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{
        env:{...process.env,STYX_NEW_PRIVATE_DIRECTORY:folder,...(bigint?{STYX_NEW_DIRECTORY_ID:created.ino.toString(),STYX_NEW_DIRECTORY_PARENT:parent,STYX_NEW_DIRECTORY_PARENT_ID:parentInfo.ino.toString()}:{})},windowsHide:true,
        timeout:WINDOWS_ACL_TIMEOUT_MS,stdio:['ignore','ignore','ignore']});
    }
    if(bigint){const currentParent=fs.lstatSync(parent,{bigint:true});if(!currentParent.isDirectory()||currentParent.isSymbolicLink()||!sameFile(parentInfo,currentParent))throw Error('private_directory_creation_binding_changed');}
    return verifiedIdentity(created);
  }catch(e){
    // rmdir cannot delete files an external process may have placed here.
    try{
      if(!bigint)fs.rmdirSync(folder);
      else {const current=fs.lstatSync(folder,{bigint:true}),currentParent=fs.lstatSync(parent,{bigint:true});if(created.isDirectory()&&!created.isSymbolicLink()&&current.isDirectory()&&!current.isSymbolicLink()&&currentParent.isDirectory()&&!currentParent.isSymbolicLink()&&sameFile(created,current)&&sameFile(parentInfo,currentParent))fs.rmdirSync(folder);}
    }catch{}
    throw Error(e.code==='ETIMEDOUT'
      ?'private_directory_creation_timed_out':'private_directory_creation_failed');
  }
}
