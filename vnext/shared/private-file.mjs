import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

// POSIX mode bits do not represent NTFS ACLs. Validate the actual Windows
// DACL and reject any Allow rule for a different OS user or generic group.
const WINDOWS_ACL_CHECK = [
  "$ErrorActionPreference='Stop'",
  'try {',
  '  $file=$env:STYX_PRIVATE_FILE_TO_VERIFY',
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

export function requirePrivateFile(filename) {
  if(typeof filename!=='string'||!path.isAbsolute(filename))
    throw Error('private_file_absolute_path_required');
  const info=fs.lstatSync(filename);
  if(!info.isFile()||info.isSymbolicLink())
    throw Error('private_file_not_regular');
  if(process.platform==='win32') {
    const encoded=Buffer.from(WINDOWS_ACL_CHECK,'utf16le').toString('base64');
    try{
      execFileSync('powershell.exe',[
        '-NoLogo','-NoProfile','-NonInteractive',
        '-EncodedCommand',encoded
      ],{
        env:{...process.env,STYX_PRIVATE_FILE_TO_VERIFY:filename},
        windowsHide:true,timeout:7000,
        stdio:['ignore','ignore','ignore']
      });
    }catch{
      throw Error('private_file_acl_not_owner_only');
    }
  }else if(info.uid!==process.getuid()) {
    throw Error('private_file_owner_mismatch');
  }else if(info.mode&0o077) {
    throw Error('private_file_permissions');
  }
  return info;
}
