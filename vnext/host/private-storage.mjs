import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

// POSIX mode bits do not represent NTFS ACLs. Validate the actual Windows
// DACL and reject any Allow rule for a different OS user or generic group.
const WINDOWS_ACL_CHECK = [
  "$ErrorActionPreference='Stop'",
  'try {',
  '  $file=$env:STYX_PRIVATE_PATH_TO_VERIFY',
  '  if([String]::IsNullOrWhiteSpace($file)) { exit 2 }',
  '  $acl=Get-Acl -LiteralPath $file',
  '  $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $acl.Sddl',
  '  if($null -eq $descriptor.DiscretionaryAcl){exit 2}',
  '  $current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value',
  '  function IdentitySid($reference) {',
  '    $name=[String]$reference',
  "    if($name -match '^S-1-[0-9]+(-[0-9]+)+$'){return $name}",
  '    return (New-Object Security.Principal.NTAccount($name)).Translate(',
  '      [Security.Principal.SecurityIdentifier]).Value',
  '  }',
  '  if((IdentitySid $acl.Owner) -ne $current){exit 2}',
  "  $allowed=@($current,'S-1-5-18','S-1-5-32-544')",
  '  foreach($rule in $acl.Access){',
  '    if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow){',
  '      $principal=IdentitySid $rule.IdentityReference',
  '      if($allowed -notcontains $principal){exit 2}',
  '    }',
  '  }',
  '  exit 0',
  '}catch{exit 2}'
].join('\n');

function checkWindowsAcl(filename,kind) {
  const encoded=Buffer.from(WINDOWS_ACL_CHECK,'utf16le').toString('base64');
  try{
    execFileSync('powershell.exe',[
      '-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',encoded
    ],{env:{...process.env,STYX_PRIVATE_PATH_TO_VERIFY:filename},
      windowsHide:true,timeout:7000,stdio:['ignore','ignore','ignore']});
  }catch{throw Error('private_'+kind+'_acl_not_owner_only')}
}
function requirePrivatePath(filename,kind) {
  if(typeof filename!=='string'||!path.isAbsolute(filename))
    throw Error('private_'+kind+'_absolute_path_required');
  const info=fs.lstatSync(filename);
  if(info.isSymbolicLink()||(kind==='file'?!info.isFile():!info.isDirectory()))
    throw Error('private_'+kind+'_not_regular');
  if(process.platform==='win32') checkWindowsAcl(filename,kind);
  else if(info.uid!==process.getuid()) throw Error('private_'+kind+'_owner_mismatch');
  else if(info.mode&0o077) throw Error('private_'+kind+'_permissions');
  return info;
}
export function requirePrivateFile(filename) {return requirePrivatePath(filename,'file')}
export function requirePrivateDirectory(folder) {return requirePrivatePath(folder,'directory')}

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
        timeout:7000,stdio:['ignore','ignore','ignore']});
    }
    return requirePrivateDirectory(folder);
  }catch{
    // rmdir cannot delete files an external process may have placed here.
    try{fs.rmdirSync(folder)}catch{}
    throw Error('private_directory_creation_failed');
  }
}
