import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

// PowerShell cold startup on loaded native Windows runners can exceed seven
// seconds. Keep ACL operations bounded without retrying a partially applied ACL.
const WINDOWS_ACL_TIMEOUT_MS = 30_000;

// POSIX mode bits do not represent NTFS ACLs. Validate the actual Windows
// DACL and reject any Allow rule for a different OS user or generic group.
const WINDOWS_ACL_CHECK = [
  "$ErrorActionPreference='Stop'",
  'try {',
  '  $files=@(ConvertFrom-Json $env:STYX_PRIVATE_PATHS_TO_VERIFY)',
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
export function ensurePrivateDirectory(folder) {
  if(typeof folder!=='string'||!path.isAbsolute(folder))
    throw Error('private_directory_absolute_path_required');
  try{fs.lstatSync(folder);return requirePrivateDirectory(folder)}
  catch(e){if(e.code!=='ENOENT')throw e}
  // Non-recursive: callers must explicitly choose an existing parent. Never
  // create or change ACLs on arbitrary ancestor directories.
  fs.mkdirSync(folder,{mode:0o700});
  try{
    if(process.platform==='win32'){
      const script=[
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
      execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive',
        '-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{
        env:{...process.env,STYX_NEW_PRIVATE_DIRECTORY:folder},windowsHide:true,
        timeout:WINDOWS_ACL_TIMEOUT_MS,stdio:['ignore','ignore','ignore']});
    }
    return requirePrivateDirectory(folder);
  }catch(e){
    // rmdir cannot delete files an external process may have placed here.
    try{fs.rmdirSync(folder)}catch{}
    throw Error(e.code==='ETIMEDOUT'
      ?'private_directory_creation_timed_out':'private_directory_creation_failed');
  }
}
