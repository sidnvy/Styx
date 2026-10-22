using System;using System.IO;using System.Diagnostics;using System.Collections.Generic;using System.Security.AccessControl;using System.Security.Principal;using System.Security.Cryptography;using System.Web.Script.Serialization;
class LoginOwnershipTest {
 static string Hash(string f){using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(File.ReadAllBytes(f))).Replace("-","").ToLowerInvariant();}
 static void Private(string f){var sid=WindowsIdentity.GetCurrent().User;var a=new FileSecurity();a.SetOwner(sid);a.SetAccessRuleProtection(true,false);a.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));File.SetAccessControl(f,a);}
 static int Gate(string exe,params string[] args){var q=Array.ConvertAll(args,s=>"\""+s+"\"");using(var p=Process.Start(new ProcessStartInfo(exe,"check-login "+String.Join(" ",q)){UseShellExecute=false,CreateNoWindow=true})){p.WaitForExit();return p.ExitCode;}}
 static void Check(bool ok,string why){if(!ok)throw new Exception(why);}
 static int Main(string[] args){string link=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup),"StyxLoginOwnershipTest-"+Guid.NewGuid().ToString("N")+".lnk");try{
  string root=Path.Combine(args[0],"Install"),stateRoot=Path.Combine(args[0],"State"),state=Path.Combine(stateRoot,"deployment");Directory.CreateDirectory(root);Directory.CreateDirectory(state);string manifest="{\"schema\":1,\"files\":[]}",temp=Path.Combine(root,"manifest");File.WriteAllText(temp,manifest);string pin=Hash(temp),version=Path.Combine(root,"versions",pin);Directory.CreateDirectory(version);File.Move(temp,Path.Combine(version,"windows-package.json"));File.WriteAllText(Path.Combine(version,"StyxPreview.exe"),"not an executable; data-only ownership fixture");File.WriteAllText(link,"not a runnable shortcut; gate-only fixture");Private(link);
  string dep=Path.Combine(state,"deployment.json"),sf=Path.Combine(state,"state.json");File.WriteAllText(dep,"{}");Private(dep);File.WriteAllText(sf,"{}");Private(sf);
  Check(Gate(args[1],root,stateRoot,version,link)==2,"unregistered_entry_adopted");
  var reg=new Dictionary<string,object>{{"schema",1},{"kind","windows-startup-shortcut"},{"ownerSid",WindowsIdentity.GetCurrent().User.Value},{"shortcutPath",link},{"installRoot",root},{"resourceRoot",version},{"packageSha256",pin},{"appSha256",Hash(Path.Combine(version,"StyxPreview.exe"))},{"stateDir",state}};
  var login=new Dictionary<string,object>{{"registration",reg},{"desiredEnabled",true}};
  var preferences=new Dictionary<string,object>{{"loginAtStartup",login}};
  var value=new Dictionary<string,object>{{"configSha256",Hash(dep)},{"appPreferences",preferences}};var json=new JavaScriptSerializer();File.WriteAllText(sf,json.Serialize(value));
  Check(Gate(args[1],root,stateRoot,version,link)==0,"owned_registration_rejected");reg["ownerSid"]="S-1-12-1-111-222-333-444";File.WriteAllText(sf,json.Serialize(value));Check(Gate(args[1],root,stateRoot,version,link)==2,"foreign_owner_adopted");Console.WriteLine("PASS unregistered/registered/foreign login ownership");return 0;
 }catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}finally{if(File.Exists(link))File.Delete(link);}}
}
