using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

internal static class InstallRootCreationTest {
 static void Check(bool value,string message){if(!value)throw new Exception(message);}
 static string Dacl(string path){return Directory.GetAccessControl(path).GetSecurityDescriptorSddlForm(AccessControlSections.Access);}
 static int Create(string gate,string root){using(var p=Process.Start(new ProcessStartInfo(gate,"create-native-root \""+root+"\""){UseShellExecute=false,CreateNoWindow=true})){p.WaitForExit();return p.ExitCode;}}
 static int Main(string[] args){try{
  string parent=args[0],gate=args[1],sid=WindowsIdentity.GetCurrent().User.Value,before=Dacl(parent);
  string first=Path.Combine(parent,"New program parent"),root=Path.Combine(first,"Selected root 中文");
  Check(Create(gate,root)==0,"private_root_creation_failed");
  foreach(string directory in new[]{first,root}){
   var acl=Directory.GetAccessControl(directory);Check(acl.AreAccessRulesProtected,"new_root_not_protected");
   Check(acl.GetOwner(typeof(SecurityIdentifier)).Value==sid,"new_root_owner_changed");
   int count=0;foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))){
    string principal=rule.IdentityReference.Value;
    Check(principal==sid||principal=="S-1-5-18"||principal=="S-1-5-32-544","unexpected_principal");
    Check(rule.AccessControlType==AccessControlType.Allow&&rule.FileSystemRights==FileSystemRights.FullControl&&!rule.IsInherited,"new_root_rights_changed");
    Check(rule.InheritanceFlags==(InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit)&&rule.PropagationFlags==PropagationFlags.None,"new_root_inheritance_changed");count++;
   }Check(count==3,"new_root_rule_count_changed");
  }
  Check(Dacl(parent)==before,"existing_parent_acl_changed");
  string existing=Path.Combine(parent,"Existing unrelated directory");Directory.CreateDirectory(existing);string old=Dacl(existing);
  Check(Create(gate,existing)==0&&Dacl(existing)==old,"existing_directory_acl_changed");
  string collision=Path.Combine(parent,"existing-file");File.WriteAllText(collision,"preserve");
  Check(Create(gate,collision)==2&&File.ReadAllText(collision)=="preserve","existing_file_overwritten");
  Console.WriteLine("PASS atomic private creation, inheritance, existing directory/file and parent preservation");return 0;
 }catch(Exception error){Console.Error.WriteLine(error.Message);return 1;}}
}
