using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Threading;
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
 static bool Equal(string a,string b){return String.Equals(a.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar),b.TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar),StringComparison.OrdinalIgnoreCase);}
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
  Regular(target);string targetManifest=Path.Combine(target,"windows-package.json"),targetApp=Path.Combine(target,"StyxPreview.exe");Regular(targetManifest);Regular(targetApp);
  var targetPackage=new JavaScriptSerializer{MaxJsonLength=16*1024*1024}.Deserialize<Dictionary<string,object>>(File.ReadAllText(targetManifest));
  string appPin=null;foreach(var entry in (System.Collections.IEnumerable)targetPackage["files"]){var file=Object(entry);if((string)file["path"]=="StyxPreview.exe"){if(appPin!=null)return 2;appPin=(string)file["sha256"];}}
  if(appPin==null||Hash(targetApp)!=appPin)return 2;
  return 0;
 }
 // This is the install engine's read-only native package admission. It does
 // not stage/select a runtime or claim old App/worker settlement from PID absence.
 const string NativePublisher="f524e2e87f4cda2bc2b52d448233ae347b05c00730374f6b379a8aafe1cc2566";
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
 static void Match(object value,string key,string expected){if(StringField(Object(value),key)!=expected)throw new IOException("maintenance_binding_changed");}
 static Process OriginalChild(object hello,string version){
  var identity=Object(Object(hello)["core"]);int pid=Convert.ToInt32(identity["pid"]);if(pid<=0)throw new IOException("maintenance_child_unknown");var child=Process.GetProcessById(pid);
  try{IntPtr held=child.Handle;if(MaintenancePeer.Birth(child)!=StringField(identity,"creationFileTime")||MaintenancePeer.Owner(child)!=WindowsIdentity.GetCurrent().User.Value||!MaintenancePeer.Same(child.MainModule.FileName,Path.Combine(version,"native","bin","styx.exe")))throw new IOException("maintenance_child_changed");return child;}catch{child.Dispose();throw;}
 }
 static string ReadFrame(StreamReader reader){var line=new StringBuilder();for(int ch;(ch=reader.Read())>=0;){if(ch=='\n')return line.ToString().TrimEnd('\r');if(line.Length>=2097152)throw new IOException("maintenance_frame_bound");line.Append((char)ch);}throw new IOException("maintenance_eof_unknown");}
 static int MaintainNative(string[] a){
  if(a.Length!=4||!Path.IsPathRooted(a[1])||(a[2]!="upgrade"&&a[2]!="uninstall")||!(a[2]=="uninstall"?a[3]=="-":System.Text.RegularExpressions.Regex.IsMatch(a[3],"\\A[a-f0-9]{64}\\z")))return 2;
  string root=Path.GetFullPath(a[1]),action=a[2],candidate=a[3]=="-"?null:a[3];
  Mutex setup;if(!Mutex.TryOpenExisting("Global\\Styx.Install."+MaintenancePeer.Scope(root),out setup))return 3;
  using(setup){
  if(!Directory.Exists(root))return !File.Exists(root)&&action=="upgrade"?0:3;Regular(root);if(Directory.GetFileSystemEntries(root).Length==0)return action=="upgrade"?0:3;
  using(var pipe=new System.IO.Pipes.NamedPipeClientStream(".",MaintenancePeer.PipeName(root),System.IO.Pipes.PipeDirection.InOut,System.IO.Pipes.PipeOptions.None)){
   // Connection timeout precedes any mutation. Once a request is sent, retain
   // the exact peer/child handles and wait; never infer failure from a deadline.
   try{pipe.Connect(2000);}catch(TimeoutException){return 3;}
   using(var app=MaintenancePeer.Connected(pipe,true))using(var reader=new StreamReader(pipe,new UTF8Encoding(false,true),false,4096,true))using(var writer=new StreamWriter(pipe,new UTF8Encoding(false),4096,true){AutoFlush=true}){
    IntPtr originalAppHandle=app.Handle;string appBirth=MaintenancePeer.Birth(app),appImage=app.MainModule.FileName;Regular(appImage);
    string version=Path.GetDirectoryName(appImage),hash=Path.GetFileName(version);if(!System.Text.RegularExpressions.Regex.IsMatch(hash,"\\A[a-f0-9]{64}\\z")||!MaintenancePeer.Same(version,Path.Combine(root,"versions",hash))||Path.GetFileName(appImage)!="StyxPreview.exe")return 3;
    using(var imagePin=new FileStream(appImage,FileMode.Open,FileAccess.Read,FileShare.Read)){
     if(VerifyNative(new[]{"verify-native",version,hash})!=0)return 3;
     var codec=new JavaScriptSerializer{MaxJsonLength=2097152};var hello=Object(codec.DeserializeObject(ReadFrame(reader)));
     if(Convert.ToInt32(hello["schema"])!=1||StringField(hello,"kind")!="styx-native-maintenance-owner"||Convert.ToInt32(hello["pid"])!=app.Id||StringField(hello,"creationFileTime")!=appBirth||StringField(hello,"ownerSid")!=WindowsIdentity.GetCurrent().User.Value||!MaintenancePeer.Same(StringField(hello,"installRoot"),root)||!MaintenancePeer.Same(StringField(hello,"resources"),version)||StringField(hello,"packageSha256")!=hash)return 3;
     using(var child=OriginalChild(hello,version)){
      string childBirth=MaintenancePeer.Birth(child),request=Guid.NewGuid().ToString("N");
      var input=new Dictionary<string,object>{{"schema",1},{"operation",action},{"requestId",request},{"installRoot",root},{"packageSha256",hash},{"candidatePackageSha256",candidate}};
      writer.WriteLine(codec.Serialize(input));
      var reply=Object(codec.DeserializeObject(ReadFrame(reader)));if(StringField(reply,"status")!="settled")return 3;
      Match(reply,"requestId",request);Match(reply,"operation",action);Match(reply,"packageSha256",hash);if(!MaintenancePeer.Same(StringField(reply,"installRoot"),root)||!Equals(reply["candidatePackageSha256"],candidate))return 3;
      var prepared=Object(reply["prepared"]);var maintenance=Object(prepared["maintenance"]);
      if(Convert.ToInt32(maintenance["schema"])!=1||StringField(maintenance,"status")!="prepared"||StringField(maintenance,"scope")!="original_app"||StringField(maintenance,"runtimeReferences")!="outside_install_root"||!Equals(maintenance["statePreserved"],true)||!Equals(maintenance["operationsReplayed"],false)||!Equals(maintenance["requiresOwnedQuit"],true)||!System.Text.RegularExpressions.Regex.IsMatch(StringField(maintenance,"ticketId"),"\\A[a-f0-9]{32}\\z"))return 3;
      Match(maintenance,"requestId",request);Match(maintenance,"operation",action);Match(maintenance,"packageSha256",hash);if(!MaintenancePeer.Same(StringField(maintenance,"installRoot"),root)||!Equals(maintenance["candidatePackageSha256"],candidate))return 3;
      if(action=="uninstall"){var login=Object(reply["loginObservation"]);if(Convert.ToInt32(login["schema"])!=1||StringField(login,"platform")!="windows"||StringField(login,"status")!="not_registered")return 3;}
      var quitTicket=Object(reply["quitTicket"]);var ready=Object(quitTicket["maintenance"]);
      foreach(var pair in maintenance){object value;if(!ready.TryGetValue(pair.Key,out value)||!Equals(value,pair.Key=="status"?(object)"ready_to_exit":pair.Value))return 3;}
      var quit=Object(quitTicket["quit"]);if(StringField(quit,"status")!="ready_to_quit"||!System.Text.RegularExpressions.Regex.IsMatch(StringField(quit,"ticketId"),"\\A[a-f0-9]{32}\\z"))return 3;
      var joined=Object(reply["coreExit"]);if(Convert.ToInt32(joined["pid"])!=child.Id||StringField(joined,"creationFileTime")!=childBirth||Convert.ToInt32(joined["exitCode"])!=0||!Equals(joined["stdinEof"],true)||!Equals(joined["ioJoined"],true))return 3;
      child.WaitForExit();if(child.ExitCode!=0)return 3;
      app.WaitForExit();if(app.ExitCode!=0)return 3;
      // These are additional occupancy observations after positive owned waits,
      // never substitutes for Core's ticket or actual process settlement.
      Mutex active;if(Mutex.TryOpenExisting("Global\\Styx.App."+MaintenancePeer.Scope(root),out active)){active.Dispose();return 1;}
      if(!MaintenancePeer.SetupPresent(root))return 3;
     }
    }
   }
  }
  return Main(new[]{"check",root});
  }
 }

 static int Main(string[] args){
  AppContext.SetSwitch("Switch.System.IO.UseLegacyPathHandling",false);
  AppContext.SetSwitch("Switch.System.IO.BlockLongPaths",false);
  try{
   if(args.Length>0&&args[0]=="verify-native")return VerifyNative(args);
   if(args.Length>0&&args[0]=="maintain-native-install")return MaintainNative(args);
   if(args.Length==2&&args[0]=="check-native-install"&&Path.IsPathRooted(args[1])){
    string target=Path.GetFullPath(args[1]);if(!Directory.Exists(target)&&!File.Exists(target))return 0;Regular(target);
    // Existing installs require an original App/Core joined handoff. Restart
    // Manager idle, a timeout or a missing PID is not that proof.
    return Directory.Exists(target)&&Directory.GetFileSystemEntries(target).Length==0?0:3;
   }
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

 // A connected local pipe identifies a kernel process, never a caller PID claim.
 static class MaintenancePeer {
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint process);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint process);
  [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,uint rights,out IntPtr token);
  [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
  internal static string Birth(Process process){return process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(System.Globalization.CultureInfo.InvariantCulture);}
  internal static string Owner(Process process){IntPtr token;if(!OpenProcessToken(process.Handle,0x000A,out token))throw new IOException("maintenance_process_owner_unknown");try{using(var identity=new System.Security.Principal.WindowsIdentity(token))return identity.User.Value;}finally{CloseHandle(token);}}
  internal static Process Connected(System.IO.Pipes.PipeStream pipe,bool server){uint pid;bool ok=server?GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid):GetNamedPipeClientProcessId(pipe.SafePipeHandle,out pid);if(!ok||pid==0||pid>Int32.MaxValue)throw new IOException("maintenance_peer_unknown");var process=Process.GetProcessById((int)pid);try{IntPtr held=process.Handle;if(process.HasExited||Owner(process)!=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)throw new IOException("maintenance_peer_changed");return process;}catch{process.Dispose();throw;}}
  internal static bool Same(string a,string b){return String.Equals(Path.GetFullPath(a).TrimEnd('\\'),Path.GetFullPath(b).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase);}
  internal static string Scope(string root){using(var sha=System.Security.Cryptography.SHA256.Create())return BitConverter.ToString(sha.ComputeHash(System.Text.Encoding.Unicode.GetBytes(Path.GetFullPath(root).TrimEnd('\\').ToLowerInvariant()))).Replace("-","").ToLowerInvariant();}
  internal static string PipeName(string root){return "Styx.NativeMaintenance.v1."+System.Security.Principal.WindowsIdentity.GetCurrent().User.Value+"."+Scope(root);}
  internal static bool SetupPresent(string root){Mutex mutex;if(!Mutex.TryOpenExisting("Global\\Styx.Install."+Scope(root),out mutex))return false;mutex.Dispose();return true;}
 }
