using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;

// Read-only Restart Manager admission. Never calls RmShutdown or RmRestart.
internal static class InstallGate {
 [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode)] static extern int RmStartSession(out uint handle,uint flags,StringBuilder key);
 [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode)] static extern int RmRegisterResources(uint handle,uint count,string[] files,uint applications,IntPtr processes,uint services,IntPtr names);
 [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint handle,out uint needed,ref uint count,IntPtr processes,ref uint reasons);
 [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint handle);
 static void Regular(string root){
  if((File.GetAttributes(root)&FileAttributes.ReparsePoint)!=0)throw new IOException();
 }
 static bool Image(string file){string ext=Path.GetExtension(file);return String.Equals(ext,".exe",StringComparison.OrdinalIgnoreCase)||String.Equals(ext,".dll",StringComparison.OrdinalIgnoreCase)||String.Equals(ext,".node",StringComparison.OrdinalIgnoreCase);}
 static void Package(string root,List<string> files){
  Regular(root);string manifest=Path.Combine(root,"windows-package.json");Regular(manifest);
  var value=new JavaScriptSerializer{MaxJsonLength=16*1024*1024}.Deserialize<Dictionary<string,object>>(File.ReadAllText(manifest));
  foreach(var entry in (System.Collections.IEnumerable)value["files"]){
   string relative=(string)((Dictionary<string,object>)entry)["path"];
   if(Path.IsPathRooted(relative)||relative.Contains(":")||relative.Contains("\\"))throw new IOException();
   foreach(string part in relative.Split('/'))if(part==""||part=="."||part=="..")throw new IOException();
   if(Image(relative))files.Add(Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar)));
  }

 }
 static void Files(string root,List<string> files){
  Regular(root);foreach(string file in Directory.GetFiles(root)){Regular(file);if(Image(file))files.Add(file);}
  // The package inventory supplies long paths directly to Restart Manager;
  // .NET Framework directory traversal must not truncate those paths.
  foreach(string name in new[]{"versions","releases"}){
   string versions=Path.Combine(root,name);if(!Directory.Exists(versions))continue;Regular(versions);
   foreach(string version in Directory.GetDirectories(versions))Package(version,files);
  }
 }
 static string Hash(string file){using(var s=SHA256.Create())using(var f=File.OpenRead(file))return BitConverter.ToString(s.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
 static bool Equal(string a,string b){return String.Equals(a,b,StringComparison.OrdinalIgnoreCase);}
 static void PrivateFile(string file,string sid){
  Regular(file);var acl=File.GetAccessControl(file);if(acl.GetOwner(typeof(SecurityIdentifier)).Value!=sid)throw new IOException();
  foreach(FileSystemAccessRule r in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))if(r.AccessControlType==AccessControlType.Allow&&r.IdentityReference.Value!=sid&&r.IdentityReference.Value!="S-1-5-18"&&r.IdentityReference.Value!="S-1-5-32-544")throw new IOException();
 }
 static Dictionary<string,object> Object(object value){return (Dictionary<string,object>)value;}
 static int LoginOwnership(string[] a){
  if(a.Length!=5)return 2;string root=Path.GetFullPath(a[1]),state=Path.Combine(Path.GetFullPath(a[2]),"deployment"),target=Path.GetFullPath(a[3]),link=Path.GetFullPath(a[4]);
  string sid=WindowsIdentity.GetCurrent().User.Value,record=Path.Combine(state,"state.json"),deployment=Path.Combine(state,"deployment.json");
  PrivateFile(record,sid);PrivateFile(deployment,sid);Regular(link);
  if(File.GetAccessControl(link).GetOwner(typeof(SecurityIdentifier)).Value!=sid)return 2;
  if(!Equal(Path.GetDirectoryName(link),Environment.GetFolderPath(Environment.SpecialFolder.Startup)))return 2;
  if(new FileInfo(record).Length>4*1024*1024)return 2;
  var value=new JavaScriptSerializer{MaxJsonLength=4*1024*1024}.Deserialize<Dictionary<string,object>>(File.ReadAllText(record));
  if((string)value["configSha256"]!=Hash(deployment))return 2;
  var registration=Object(Object(Object(value["appPreferences"])["loginAtStartup"])["registration"]);
  if((int)registration["schema"]!=1||(string)registration["kind"]!="windows-startup-shortcut"||(string)registration["ownerSid"]!=sid||!Equal((string)registration["shortcutPath"],link)||!Equal((string)registration["stateDir"],state)||!Equal((string)registration["installRoot"],root))return 2;
  string registered=(string)registration["resourceRoot"],registeredHash=(string)registration["packageSha256"];
  if(!Equal(registered,Path.Combine(root,"versions",registeredHash))||Hash(Path.Combine(registered,"windows-package.json"))!=registeredHash||Hash(Path.Combine(registered,"StyxPreview.exe"))!=(string)registration["appSha256"])return 2;
  string name=Path.GetFileName(target);if(!System.Text.RegularExpressions.Regex.IsMatch(name,"^[a-f0-9]{64}$")||!Equal(target,Path.Combine(root,"versions",name))||Hash(Path.Combine(target,"windows-package.json"))!=name)return 2;
  return 0;
 }
 static int Main(string[] args){
  try{
   if(args.Length>0&&args[0]=="check-login")return LoginOwnership(args);
   if(args.Length!=2||args[0]!="check"||!Path.IsPathRooted(args[1]))return 2;
   string root=Path.GetFullPath(args[1]);if(!Directory.Exists(root))return 0;
   var files=new List<string>();Files(root,files);if(files.Count==0)return 0;
   // Match running images, as Inno's standard filter does, plus Node addons.
   // Static SDK/source files are not evidence of a running App/Core process.
   uint handle;int result=RmStartSession(out handle,0,new StringBuilder(33));if(result!=0){Console.Error.WriteLine("restart_manager_start_error:"+result);return 2;}
   try{
    result=RmRegisterResources(handle,(uint)files.Count,files.ToArray(),0,IntPtr.Zero,0,IntPtr.Zero);if(result!=0){Console.Error.WriteLine("restart_manager_register_error:"+result);return 2;}
    uint needed,count=0,reasons=0;result=RmGetList(handle,out needed,ref count,IntPtr.Zero,ref reasons);
    if(result==234||needed>0)return 1;if(result!=0)Console.Error.WriteLine("restart_manager_list_error:"+result);return result==0?0:2;
   }finally{RmEndSession(handle);}
  }catch(Exception error){Console.Error.WriteLine("admission_read_error:"+error.GetType().Name);return 2;}
 }
}
