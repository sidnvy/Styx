using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
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
 [StructLayout(LayoutKind.Sequential)] struct DirectorySecurityAttributes { public int Length; public IntPtr Descriptor; public int InheritHandle; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string path,ref DirectorySecurityAttributes security);
 // Create only missing program directories, atomically with a private DACL.
 // Never retrofit ACLs onto an existing user-selected directory or its ancestors.
 static int CreateNativeRoot(string[] args){
  if(args.Length!=2||!Path.IsPathRooted(args[1]))return 2;
  string root=Path.GetFullPath(args[1]);var missing=new Stack<string>();string existing=root;
  while(!Directory.Exists(existing)){
   if(File.Exists(existing))return 2;missing.Push(existing);existing=Path.GetDirectoryName(existing);if(String.IsNullOrEmpty(existing))return 2;
  }
  for(string current=existing;!String.IsNullOrEmpty(current);current=Path.GetDirectoryName(current))Regular(current);
  var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
  foreach(string sid in new[]{WindowsIdentity.GetCurrent().User.Value,"S-1-5-18","S-1-5-32-544"})
   acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
  byte[] descriptor=acl.GetSecurityDescriptorBinaryForm();IntPtr memory=Marshal.AllocHGlobal(descriptor.Length);
  try{
   Marshal.Copy(descriptor,0,memory,descriptor.Length);var security=new DirectorySecurityAttributes{Length=Marshal.SizeOf(typeof(DirectorySecurityAttributes)),Descriptor=memory};
   while(missing.Count>0){string directory=missing.Pop();if(!CreateDirectoryW(Long(directory),ref security))throw new IOException("native_directory_create_error:"+Marshal.GetLastWin32Error());Regular(directory);}
   return 0;
  }finally{Marshal.FreeHGlobal(memory);}
 }
 // Package members under %LOCALAPPDATA%\Programs\Styx\versions\<sha256> exceed MAX_PATH
 // (deep Browser worker node_modules). Long paths use the extended-length prefix;
 // Main disables .NET legacy path handling before any System.IO call.
 static string Long(string path){return path.Length>=240&&path.Length>2&&path[1]==':'?@"\\?\"+path:path;}
 static void Regular(string root){
  if((File.GetAttributes(Long(root))&FileAttributes.ReparsePoint)!=0)throw new IOException();
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
 static string Hash(string file){using(var s=SHA256.Create())using(var f=File.OpenRead(Long(file)))return BitConverter.ToString(s.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
 static Dictionary<string,object> Object(object value){return (Dictionary<string,object>)value;}
 // This is the install engine's read-only native package admission. It does
 // not stage/select a runtime or claim old App/worker settlement from PID absence.
 const string NativePublisher="bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed";
 static string NativePath(string root,string relative){
  if(String.IsNullOrEmpty(relative)||relative.Length>=512||Path.IsPathRooted(relative)||relative.Contains(":")||relative.Contains("\\"))throw new IOException("native_path_invalid");
  foreach(string part in relative.Split('/'))if(part==""||part=="."||part==".."||part.EndsWith(" ")||part.EndsWith("."))throw new IOException("native_path_invalid");
  string path=Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar));
  for(string current=path;!String.IsNullOrEmpty(current);current=Path.GetDirectoryName(current))Regular(current);
  return path;
 }
 static string Bounded(string path,int limit){Regular(path);using(var file=new FileStream(Long(path),FileMode.Open,FileAccess.Read,FileShare.Read)){if(file.Length>limit)throw new IOException("native_material_bound");using(var reader=new StreamReader(file,new UTF8Encoding(false,true)))return reader.ReadToEnd();}}
 static string StringField(Dictionary<string,object> value,string name){object field;if(!value.TryGetValue(name,out field)||!(field is string))throw new IOException("native_field_invalid");return (string)field;}
 static void Collect(string root,string prefix,HashSet<string> actual){
  string directory=prefix==""?root:NativePath(root,prefix);Regular(directory);
  foreach(string file in Directory.GetFiles(Long(directory))){string relative=prefix==""?Path.GetFileName(file):prefix+"/"+Path.GetFileName(file);NativePath(root,relative);if(relative!="windows-package.json"){if(actual.Count>=8192||!actual.Add(relative))throw new IOException("native_inventory_bound");}}
  foreach(string child in Directory.GetDirectories(Long(directory))){string relative=prefix==""?Path.GetFileName(child):prefix+"/"+Path.GetFileName(child);if(relative.Split('/').Length>64)throw new IOException("native_inventory_depth");Collect(root,relative,actual);}
 }
 static string Pipe(System.IO.StreamReader reader){var text=new StringBuilder();var buffer=new char[4096];int count;while((count=reader.Read(buffer,0,buffer.Length))>0){if(text.Length+count>2097152)throw new IOException("native_reader_output_bound");text.Append(buffer,0,count);}return text.ToString();}
 static string Quote(string value){if(value.IndexOf('"')>=0||value.IndexOf('\0')>=0||value.EndsWith("\\"))throw new IOException("native_path_invalid");return "\""+value+"\"";}
 static int VerifyNative(string[] args){
  if(args.Length!=3||!Path.IsPathRooted(args[1])||!System.Text.RegularExpressions.Regex.IsMatch(args[2],"\\A[a-f0-9]{64}\\z"))return 2;
  string root=Path.GetFullPath(args[1]),manifest=NativePath(root,"windows-package.json");
  if(Hash(manifest)!=args[2])return 2;
  var codec=new JavaScriptSerializer{MaxJsonLength=16*1024*1024};var package=Object(codec.DeserializeObject(Bounded(manifest,16*1024*1024)));
  var provenance=Object(package["sourceProvenance"]);string revision=StringField(package,"sourceRevision");
  if(Convert.ToInt32(package["schema"])!=1||!Equals(package["nativeRuntime"],true)||!Equals(package["compiled"],true)||StringField(package,"arch")!="x64"||StringField(provenance,"status")!="SAME_REVISION_TRACKED_ARCHIVE_BOUND"||StringField(provenance,"sourceRevision")!=revision||!System.Text.RegularExpressions.Regex.IsMatch(revision,"\\A[a-f0-9]{40}\\z"))return 2;
  var actual=new HashSet<string>(StringComparer.OrdinalIgnoreCase);Collect(root,"",actual);
  var expected=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  foreach(var item in (System.Collections.IEnumerable)package["files"]){var row=Object(item);string relative=StringField(row,"path"),file=NativePath(root,relative);if(!expected.Add(relative)||!actual.Contains(relative)||new FileInfo(Long(file)).Length!=Convert.ToInt64(row["size"])||Hash(file)!=StringField(row,"sha256"))return 2;}
  if(!actual.SetEquals(expected)||Directory.Exists(Path.Combine(root,"vnext"))||Directory.Exists(Path.Combine(root,"runtime")))return 2;
  var descriptor=Object(codec.DeserializeObject(Bounded(NativePath(root,"windows-runtime.json"),16384)));var native=Object(descriptor["nativeRuntime"]);
  if(Convert.ToInt32(descriptor["schema"])!=1||Convert.ToInt32(native["schema"])!=1||StringField(native,"cli")!="native/bin/styx.exe"||StringField(native,"payload")!="native"||StringField(native,"publisher")!="native-publisher.pem"||StringField(native,"publisherSpkiSha256")!=NativePublisher)return 2;
  string cli=NativePath(root,"native/bin/styx.exe"),payload=NativePath(root,"native"),publisher=NativePath(root,"native-publisher.pem"),runtimeManifest=NativePath(root,"native/manifest.json");
  using(var held=new FileStream(cli,FileMode.Open,FileAccess.Read,FileShare.Read)){
   if(Hash(cli)!=StringField(native,"cliSha256")||Hash(runtimeManifest)!=StringField(native,"manifestSha256"))return 2;
   var info=new ProcessStartInfo(cli){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=true};
   info.Arguments="release verify --payload-dir "+Quote(payload)+" --publisher-file "+Quote(publisher)+" --expected-publisher "+NativePublisher+" --json";info.EnvironmentVariables.Remove("NODE_OPTIONS");info.EnvironmentVariables.Remove("NODE_PATH");info.EnvironmentVariables.Remove("STYX_NATIVE_STATE");info.EnvironmentVariables.Remove("STYX_NATIVE_RESOURCES");
   using(var child=new Process{StartInfo=info}){
    if(!child.Start())return 2;child.StandardInput.Close();Task<string> stdout=Task.Run(()=>Pipe(child.StandardOutput)),stderr=Task.Run(()=>Pipe(child.StandardError));
    try{
     if(!child.WaitForExit(150000))throw new IOException("native_reader_deadline");child.WaitForExit();string raw=stdout.GetAwaiter().GetResult();stderr.GetAwaiter().GetResult();if(child.ExitCode!=0)return 2;
     var report=Object(codec.DeserializeObject(raw));if(Convert.ToInt32(report["schema"])!=1||StringField(report,"scope")!="runtime_candidate"||StringField(report,"target")!="x86_64-pc-windows-msvc"||StringField(report,"source_revision")!=revision||StringField(report,"manifest_sha256")!=StringField(native,"manifestSha256")||StringField(report,"publisher_spki_sha256")!=NativePublisher||!Equals(report["installed"],false)||!Equals(report["runtime_launched"],false))return 2;
     if(Hash(cli)!=StringField(native,"cliSha256")||Hash(manifest)!=args[2])return 2;
     return 0;
    }finally{
     // Exact owned read-only verifier only. No App/worker is signalled here.
     if(!child.HasExited){child.Kill();child.WaitForExit();}child.WaitForExit();
     try{stdout.GetAwaiter().GetResult();}catch{}try{stderr.GetAwaiter().GetResult();}catch{}
    }
   }
  }
 }
 static int Main(string[] args){
  AppContext.SetSwitch("Switch.System.IO.UseLegacyPathHandling",false);
  AppContext.SetSwitch("Switch.System.IO.BlockLongPaths",false);
  try{
   // Per-user packages require TokenOwner to be the actual user. Do not
   // extract administrator-owned files and then attempt to repair ownership.
   if(args.Length==1&&args[0]=="check-native-user"){using(var identity=WindowsIdentity.GetCurrent())return identity.User!=null&&identity.Owner!=null&&identity.User.Value==identity.Owner.Value?0:2;}
   if(args.Length>0&&args[0]=="create-native-root")return CreateNativeRoot(args);
   if(args.Length>0&&args[0]=="verify-native")return VerifyNative(args);
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
