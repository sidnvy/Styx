using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;

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
 static int Main(string[] args){
  try{
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
