using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace StyxNative {
 static class Json {
  internal static readonly JavaScriptSerializer Codec=new JavaScriptSerializer { MaxJsonLength=2097152 };
  internal static Dictionary<string,object> Obj(params object[] values){var d=new Dictionary<string,object>();for(int i=0;i<values.Length;i+=2)d[(string)values[i]]=values[i+1];return d;}
  internal static object Get(object obj,params string[] keys){foreach(string key in keys){var d=obj as Dictionary<string,object>;object next;if(d==null||!d.TryGetValue(key,out next))return null;obj=next;}return obj;}
  internal static string Str(object obj,params string[] keys){return Get(obj,keys) as string??"";}
  internal static bool Yes(object obj,params string[] keys){return Equals(Get(obj,keys),true);}
 }
 sealed class NativeOperationException:IOException { internal readonly string Code;internal readonly object Budget;internal readonly bool Preflight;internal NativeOperationException(string code,object budget=null,bool preflight=false){Code=code;Budget=budget;Preflight=preflight;} }
 // The installed outer package pins the bootstrap executable. Its hash is an
 // integrity boundary, not a substitute for Windows publisher authentication.
 sealed class NativeBootstrap:IDisposable {
  internal const string PublisherPin="f524e2e87f4cda2bc2b52d448233ae347b05c00730374f6b379a8aafe1cc2566";
  internal readonly string Root,Cli,Payload,Publisher,CliSha,ManifestSha;internal string Selection;
  readonly FileStream cliPin;
  internal static string Hash(Stream stream){using(var sha=System.Security.Cryptography.SHA256.Create()){stream.Position=0;string v=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();stream.Position=0;return v;}}
  internal static string ReadSmall(string path,int bound){NoRedirect(path);using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){if(f.Length>bound)throw new IOException("app_bootstrap_material_too_large");using(var r=new StreamReader(f))return r.ReadToEnd();}}
  internal static void NoRedirect(string path){string full=Path.GetFullPath(path);for(string current=full;!String.IsNullOrEmpty(current);current=Path.GetDirectoryName(current)){if((File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0)throw new IOException("app_redirected_path");}}
  internal NativeBootstrap(string root){
   Root=Path.GetFullPath(root);var m=Json.Codec.DeserializeObject(ReadSmall(Path.Combine(Root,"windows-runtime.json"),16384));var n=Json.Get(m,"nativeRuntime");
   if(Convert.ToInt32(Json.Get(m,"schema"))!=1||Convert.ToInt32(Json.Get(n,"schema"))!=1||Json.Str(n,"cli")!="native/bin/styx.exe"||Json.Str(n,"payload")!="native"||Json.Str(n,"publisher")!="native-publisher.pem"||Json.Str(n,"publisherSpkiSha256")!=PublisherPin)throw new IOException("app_native_runtime_required");
   Cli=Path.Combine(Root,"native","bin","styx.exe");Payload=Path.Combine(Root,"native");Publisher=Path.Combine(Root,"native-publisher.pem");CliSha=Json.Str(n,"cliSha256");ManifestSha=Json.Str(n,"manifestSha256");
   if(!System.Text.RegularExpressions.Regex.IsMatch(CliSha,"\\A[a-f0-9]{64}\\z")||!System.Text.RegularExpressions.Regex.IsMatch(ManifestSha,"\\A[a-f0-9]{64}\\z"))throw new IOException("app_native_hash_required");
   NoRedirect(Cli);cliPin=new FileStream(Cli,FileMode.Open,FileAccess.Read,FileShare.Read);try{Validate();}catch{cliPin.Dispose();throw;}
  }
  internal void Validate(){NoRedirect(Cli);NoRedirect(Payload);NoRedirect(Publisher);if(Hash(cliPin)!=CliSha)throw new IOException("app_native_cli_changed");using(var f=new FileStream(Path.Combine(Payload,"manifest.json"),FileMode.Open,FileAccess.Read,FileShare.Read))if(Hash(f)!=ManifestSha)throw new IOException("app_native_manifest_changed");}
  internal ProcessStartInfo StartInfo(string arguments){Validate();var info=new ProcessStartInfo(Cli,arguments){WorkingDirectory=Root,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};info.EnvironmentVariables.Remove("NODE_OPTIONS");info.EnvironmentVariables.Remove("NODE_PATH");info.EnvironmentVariables.Remove("STYX_NATIVE_STATE");info.EnvironmentVariables.Remove("STYX_NATIVE_RESOURCES");return info;}
  internal static string Quote(string value){if(value.IndexOf('"')>=0||value.IndexOf('\0')>=0||value.EndsWith("\\"))throw new IOException("app_fixed_path_invalid");return "\""+value+"\"";}
  public void Dispose(){cliPin.Dispose();}
 }
 static class PrivateAppFiles {
  static readonly System.Security.Principal.SecurityIdentifier User=System.Security.Principal.WindowsIdentity.GetCurrent().User;
  static readonly System.Security.Principal.SecurityIdentifier SystemSid=new System.Security.Principal.SecurityIdentifier("S-1-5-18"),Admins=new System.Security.Principal.SecurityIdentifier("S-1-5-32-544");
  static void Validate(string path,bool directory){NativeBootstrap.NoRedirect(path);System.Security.AccessControl.FileSystemSecurity security=directory?(System.Security.AccessControl.FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);if(!User.Equals(security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)))||!security.AreAccessRulesProtected)throw new IOException("app_private_owner_required");foreach(System.Security.AccessControl.FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier))){var sid=(System.Security.Principal.SecurityIdentifier)rule.IdentityReference;if(!sid.Equals(User)&&!sid.Equals(SystemSid)&&!sid.Equals(Admins))throw new IOException("app_private_acl_required");}}
  static System.Security.AccessControl.DirectorySecurity DirectoryAcl(){var acl=new System.Security.AccessControl.DirectorySecurity();acl.SetOwner(User);acl.SetAccessRuleProtection(true,false);foreach(var sid in new[]{User,SystemSid,Admins})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));return acl;}
  static void DirectoryPrivate(string path){if(File.Exists(path))throw new IOException("app_private_directory_required");if(!Directory.Exists(path)){string parent=Path.GetDirectoryName(path);if(!Directory.Exists(parent))throw new IOException("app_private_parent_missing");NativeBootstrap.NoRedirect(parent);Directory.CreateDirectory(path,DirectoryAcl());}Validate(path,true);}
  internal static string Prepare(string state,string selection,out string profile,out string candidate){
   // Only the original Core's fixed deployment child may enter migration. It is
   // validated as-is, never created, repaired, moved or replaced by the UI.
   string original=Path.Combine(state,"deployment");if(File.Exists(original))throw new NativeOperationException("app_legacy_migration_required");bool legacy=Directory.Exists(original);
   foreach(string name in legacy?new[]{"deployment.json","state.json",".styx-native-root-v1.json"}:new[]{"deployment.json","state.json","host","gateway","device","service.json",".styx-native-root-v1.json"})if(File.Exists(Path.Combine(state,name))||Directory.Exists(Path.Combine(state,name)))throw new NativeOperationException("app_legacy_migration_required");
   if(legacy)Validate(original,true);
   string container=Path.Combine(state,"native-rust-host-v1"),fresh=Path.Combine(container,"profile");if(legacy&&(File.Exists(fresh)||Directory.Exists(fresh)))throw new NativeOperationException("app_migration_scope_ambiguous");
   string defaultState=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"StyxPreview","WindowsFirst");if(String.Equals(state,defaultState,StringComparison.OrdinalIgnoreCase)&&!Directory.Exists(Path.GetDirectoryName(state)))DirectoryPrivate(Path.GetDirectoryName(state));
   DirectoryPrivate(state);DirectoryPrivate(container);string candidates=Path.Combine(container,"migration-candidates");DirectoryPrivate(candidates);string digest;using(var bytes=new MemoryStream(new System.Text.UTF8Encoding(false,true).GetBytes(selection)))digest=NativeBootstrap.Hash(bytes);string path=Path.Combine(candidates,digest+".json");candidate=path;
   if(!File.Exists(path)){
    var acl=new System.Security.AccessControl.FileSecurity();acl.SetOwner(User);acl.SetAccessRuleProtection(true,false);foreach(var sid in new[]{User,SystemSid,Admins})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
    using(var f=new FileStream(path,FileMode.CreateNew,System.Security.AccessControl.FileSystemRights.Read|System.Security.AccessControl.FileSystemRights.Write,FileShare.Read,4096,FileOptions.None,acl)){byte[] raw=new System.Text.UTF8Encoding(false,true).GetBytes(selection);f.Write(raw,0,raw.Length);f.Flush(true);}
   }
   Validate(path,false);if(NativeBootstrap.ReadSmall(path,16384)!=selection)throw new NativeOperationException("app_runtime_selection_changed");Validate(container,true);if(legacy){Validate(original,true);if(File.Exists(fresh)||Directory.Exists(fresh))throw new NativeOperationException("app_migration_scope_ambiguous");}profile=legacy?original:fresh;return container;
  }
 }
 sealed class Core:IDisposable {
  readonly SemaphoreSlim gate=new SemaphoreSlim(1,1);readonly NativeBootstrap bootstrap;readonly FileStream selectionPin;Process child;Task stderrDrain;Task<string> pendingRead;CancellationTokenRegistration cancellationRegistration;int sequence;int closed;bool childStarted;
  internal bool CleanupConfirmed {get;private set;}
  internal readonly string ProfileDirectory;
  internal static async Task<string> ReadLineBounded(StreamReader reader,int limit){var text=new System.Text.StringBuilder();var b=new char[1];while(await reader.ReadAsync(b,0,1).ConfigureAwait(false)!=0){if(b[0]=='\n')return text.ToString().TrimEnd('\r');if(text.Length>=limit)throw new IOException("app_frame_too_large");text.Append(b[0]);}if(text.Length!=0)throw new IOException("app_incomplete_frame");return null;}
  internal static async Task Drain(StreamReader reader){var b=new char[4096];while(await reader.ReadAsync(b,0,b.Length).ConfigureAwait(false)!=0){}}
  internal Core(NativeBootstrap verified,string state,CancellationToken cancellation){
   bootstrap=verified;string profile,selection;PrivateAppFiles.Prepare(state,verified.Selection,out profile,out selection);ProfileDirectory=profile;selectionPin=new FileStream(selection,FileMode.Open,FileAccess.Read,FileShare.Read);
   try{var info=bootstrap.StartInfo("__app-core --state-dir "+NativeBootstrap.Quote(ProfileDirectory)+" --runtime-selection-file "+NativeBootstrap.Quote(selection));info.RedirectStandardInput=true;
   child=new Process {StartInfo=info};cancellation.ThrowIfCancellationRequested();if(!child.Start())throw new IOException("app_child_not_started");childStarted=true;stderrDrain=Drain(child.StandardError);cancellationRegistration=cancellation.Register(Dispose);cancellation.ThrowIfCancellationRequested();}catch{Dispose();throw;}
  }
  internal async Task<object> Call(string operation,Dictionary<string,object> input){
   await gate.WaitAsync();try{var p=child;if(Volatile.Read(ref closed)!=0||p==null||p.HasExited||sequence==Int32.MaxValue)throw new IOException("app_core_unavailable");int id=++sequence;string request=Json.Codec.Serialize(Json.Obj("schema",1,"id",id,"operation",operation,"input",input));if(request.Length>65536)throw new IOException("app_request_too_large");
    await p.StandardInput.WriteLineAsync(request);await p.StandardInput.FlushAsync();pendingRead=ReadLineBounded(p.StandardOutput,2097152);if(await Task.WhenAny(pendingRead,Task.Delay(150000))!=pendingRead){Dispose();throw new IOException("app_result_unknown_no_replay");}
    string line=await pendingRead;pendingRead=null;if(line==null||Volatile.Read(ref closed)!=0)throw new IOException("app_result_unknown_no_replay");var response=Json.Codec.DeserializeObject(line);if(Convert.ToInt32(Json.Get(response,"id"))!=id){Dispose();throw new IOException("app_correlation_unknown_no_replay");}if(!Json.Yes(response,"ok"))throw new NativeOperationException(Json.Str(response,"error"));return Json.Get(response,"result");
   }catch(NativeOperationException){throw;}catch{Dispose();throw new IOException("app_result_unknown_no_replay");}finally{gate.Release();}
  }
  public void Dispose(){
   if(Interlocked.Exchange(ref closed,1)!=0)return;var p=child;bool clean=true;if(p!=null&&childStarted){try{p.StandardInput.Close();}catch{clean=false;}try{if(!p.WaitForExit(10000)){clean=false;try{p.Kill();}catch{}}p.WaitForExit();}catch{clean=false;throw new IOException("app_child_cleanup_unknown");}
    try{var reading=pendingRead;if(reading!=null)reading.GetAwaiter().GetResult();Drain(p.StandardOutput).GetAwaiter().GetResult();if(stderrDrain!=null)stderrDrain.GetAwaiter().GetResult();}catch{clean=false;}CleanupConfirmed=clean&&p.ExitCode==0;p.Dispose();child=null;
   }else if(p!=null){p.Dispose();child=null;}selectionPin.Dispose();bootstrap.Dispose();cancellationRegistration.Dispose();
  }
 }
 sealed class PackageProgress {internal string Phase;internal int Completed,Total;}
 sealed class VerificationTiming {
  readonly Stopwatch clock=Stopwatch.StartNew();readonly List<object> progress=new List<object>();double nodeReady=-1,childStarted=-1,childExited=-1;
  internal void BootstrapReady(){nodeReady=clock.Elapsed.TotalMilliseconds;}
  internal void ChildStarted(){childStarted=clock.Elapsed.TotalMilliseconds;}
  internal void ChildExited(){childExited=clock.Elapsed.TotalMilliseconds;}
  internal void Record(string phase,int completed,int total){if(progress.Count<160)progress.Add(Json.Obj("phase",phase,"completed",completed,"total",total,"elapsedMilliseconds",clock.Elapsed.TotalMilliseconds));}
  internal object Snapshot(){return Json.Obj("schema",2,"bootstrapReadyMilliseconds",nodeReady,"childStartedMilliseconds",childStarted,"childExitedMilliseconds",childExited,"progress",progress.ToArray());}
 }
 static class PackageVerifier {
  static string ReadOutput(Task<string> reading,Stopwatch clock){int remaining=150000-(int)Math.Min(150000,clock.ElapsedMilliseconds);if(remaining<=0||Task.WaitAny(new Task[]{reading},remaining)!=0)throw new IOException("app_verification_timeout");return reading.GetAwaiter().GetResult();}
  internal static NativeBootstrap Verify(string root,IProgress<PackageProgress> progress,CancellationToken cancellation,VerificationTiming timing){
   cancellation.ThrowIfCancellationRequested();var runtime=new NativeBootstrap(root);Process child=null;Task stderr=null;Task<string> reading=null;CancellationTokenRegistration stop=default(CancellationTokenRegistration);bool transferred=false,started=false;try{
    var info=runtime.StartInfo("release verify --payload-dir "+NativeBootstrap.Quote(runtime.Payload)+" --publisher-file "+NativeBootstrap.Quote(runtime.Publisher)+" --expected-publisher "+NativeBootstrap.PublisherPin+" --json --runtime-selection");timing.BootstrapReady();timing.Record("files",0,1);progress.Report(new PackageProgress {Phase="files",Completed=0,Total=1});child=new Process {StartInfo=info};if(!child.Start())throw new IOException("app_verify_child_not_started");started=true;timing.ChildStarted();stderr=Core.Drain(child.StandardError);stop=cancellation.Register(()=>{try{if(!child.HasExited)child.Kill();child.WaitForExit();if(stderr!=null)stderr.GetAwaiter().GetResult();}catch{}});var clock=Stopwatch.StartNew();
    reading=Core.ReadLineBounded(child.StandardOutput,16384);string line=ReadOutput(reading,clock);reading=Core.ReadLineBounded(child.StandardOutput,16384);string extra=ReadOutput(reading,clock);if(!child.WaitForExit(Math.Max(1,150000-(int)Math.Min(150000,clock.ElapsedMilliseconds))))throw new IOException("app_verification_timeout");child.WaitForExit();stderr.GetAwaiter().GetResult();timing.ChildExited();cancellation.ThrowIfCancellationRequested();if(child.ExitCode!=0||line==null||extra!=null)throw new IOException("app_native_release_unverified");var selection=Json.Codec.DeserializeObject(line);if(Convert.ToInt32(Json.Get(selection,"schema"))!=1||Json.Str(selection,"manifest_sha256")!=runtime.ManifestSha||Json.Str(selection,"publisher_spki_sha256")!=NativeBootstrap.PublisherPin||Json.Str(selection,"payload_path")!=runtime.Payload||Json.Str(selection,"publisher_file")!=runtime.Publisher)throw new IOException("app_native_selection_mismatch");
    runtime.Validate();runtime.Selection=line+"\n";timing.Record("files",1,1);progress.Report(new PackageProgress {Phase="files",Completed=1,Total=1});transferred=true;return runtime;
   }finally{stop.Dispose();if(child!=null){try{if(started){if(!child.HasExited){child.Kill();child.WaitForExit();}child.WaitForExit();if(reading!=null){try{reading.GetAwaiter().GetResult();}catch{}}if(stderr!=null)stderr.GetAwaiter().GetResult();}}finally{child.Dispose();}}if(!transferred)runtime.Dispose();}
  }
 }
 // Exact file-handle identity and deletion for the one Startup shortcut.
 // No unsafe code; every owned kernel handle and security descriptor is closed.
 sealed class NativeLoginFile:IDisposable {
  [StructLayout(LayoutKind.Sequential)]struct Information {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
  [StructLayout(LayoutKind.Sequential)]struct Disposition {public byte Delete;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file,out Information value);
  [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool SetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file,int kind,ref Disposition value,uint size);
  [DllImport("advapi32.dll")]static extern uint GetSecurityInfo(Microsoft.Win32.SafeHandles.SafeFileHandle file,int objectType,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr value);
  Microsoft.Win32.SafeHandles.SafeFileHandle handle;FileStream stream;internal readonly string Identity,Owner;readonly bool deleteAccess;
  internal NativeLoginFile(string path,bool canDelete,bool permitDelete){
   deleteAccess=canDelete;handle=CreateFileW(path,0x80000000u|(canDelete?0x00010000u:0u),1u|(permitDelete?4u:0u),IntPtr.Zero,3,0x00200000,IntPtr.Zero);
   try{
    if(handle.IsInvalid)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());Information info;if(!GetFileInformationByHandle(handle,out info))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    if((info.Attributes&((uint)FileAttributes.Directory|(uint)FileAttributes.ReparsePoint))!=0||info.Links!=1)throw new IOException("app_login_shortcut_redirected");
    Identity=info.Volume.ToString("x8")+":"+info.IndexHigh.ToString("x8")+info.IndexLow.ToString("x8")+":"+((uint)info.Created.dwHighDateTime).ToString("x8")+((uint)info.Created.dwLowDateTime).ToString("x8");
    IntPtr owner,group,dacl,sacl,descriptor;uint result=GetSecurityInfo(handle,1,1,out owner,out group,out dacl,out sacl,out descriptor);
    try{if(result!=0||owner==IntPtr.Zero)throw new IOException("app_login_shortcut_owner_unknown");Owner=new System.Security.Principal.SecurityIdentifier(owner).Value;}finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
    stream=new FileStream(handle,FileAccess.Read,4096,false);if(stream.Length>65536)throw new IOException("app_login_shortcut_too_large");
   }catch{Dispose();throw;}
  }
  internal string Digest(){if(stream==null)throw new ObjectDisposedException("NativeLoginFile");return NativeBootstrap.Hash(stream);}
  internal void Delete(){if(!deleteAccess||handle==null||handle.IsClosed)throw new IOException("app_login_delete_handle_required");var disposition=new Disposition {Delete=1};if(!SetFileInformationByHandle(handle,4,ref disposition,(uint)Marshal.SizeOf(typeof(Disposition))))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
  public void Dispose(){if(stream!=null){stream.Dispose();stream=null;}if(handle!=null){handle.Dispose();handle=null;}}
 }
 // Current-user OS adapter. No saved preference, registry StartupApproved,
 // service account, task scheduler or second management authority lives here.
 static class NativeLoginStartup {
  internal sealed class Observation:IDisposable {
   internal string Status,Fingerprint;
   internal NativeLoginFile Pin;
   internal Dictionary<string,object> Wire {get{return Json.Obj("schema",1,"platform","windows","status",Status,"fingerprint",Fingerprint);}}
   public void Dispose(){if(Pin!=null){Pin.Dispose();Pin=null;}}
  }
  internal sealed class Result {internal string Outcome;internal Observation Observation;}
  static object ComGet(object value,string name){return value.GetType().InvokeMember(name,System.Reflection.BindingFlags.GetProperty,null,value,null);}
  static void ComSet(object value,string name,object property){value.GetType().InvokeMember(name,System.Reflection.BindingFlags.SetProperty,null,value,new[]{property});}
  static object ComCall(object value,string name,params object[] args){return value.GetType().InvokeMember(name,System.Reflection.BindingFlags.InvokeMethod,null,value,args);}
  static void Release(object value){if(value!=null&&Marshal.IsComObject(value))Marshal.FinalReleaseComObject(value);}
  static bool Same(string left,string right){return !String.IsNullOrEmpty(left)&&!String.IsNullOrEmpty(right)&&Path.IsPathRooted(left)&&Path.IsPathRooted(right)&&String.Equals(Path.GetFullPath(left).TrimEnd('\\'),Path.GetFullPath(right).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase);}
  static string Fingerprint(params object[] values){using(var bytes=new MemoryStream(new System.Text.UTF8Encoding(false,true).GetBytes(Json.Codec.Serialize(values))))return NativeBootstrap.Hash(bytes);}
  static string ShortcutPath(){string folder=Environment.GetFolderPath(Environment.SpecialFolder.Startup);if(String.IsNullOrEmpty(folder)||!Path.IsPathRooted(folder)||!Directory.Exists(folder))throw new IOException("app_login_startup_unavailable");NativeBootstrap.NoRedirect(folder);return Path.Combine(folder,"Styx.lnk");}
  static string Arguments(string state){return "--startup --state-dir "+NativeBootstrap.Quote(Path.GetFullPath(state));}
  static string App(string root){string exe=Path.GetFullPath(Application.ExecutablePath);if(!Same(Path.GetDirectoryName(exe),root))throw new IOException("app_login_native_app_changed");NativeBootstrap.NoRedirect(exe);return exe;}
  internal static Observation Observe(string root,string state,bool retain=false){
   NativeLoginFile pin=null;
   try{
    string app=App(root),arguments=Arguments(state),link=ShortcutPath(),sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
    FileAttributes attributes;try{attributes=File.GetAttributes(link);}catch(FileNotFoundException){return new Observation {Status="not_registered",Fingerprint=Fingerprint(1,"windows",sid,link,app,arguments,Path.GetFullPath(root),false)};}catch(DirectoryNotFoundException){throw new IOException("app_login_startup_changed");}
    if((attributes&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0)return new Observation {Status="foreign",Fingerprint=Fingerprint(1,"windows",sid,link,(int)attributes)};
    NativeBootstrap.NoRedirect(link);pin=new NativeLoginFile(link,false,true);string owner=pin.Owner;
    object shell=null,shortcut=null;string target,observedArguments,workingDirectory,digest;
    {
     digest=pin.Digest();
     try{shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell",true));shortcut=ComCall(shell,"CreateShortcut",link);target=Convert.ToString(ComGet(shortcut,"TargetPath"));observedArguments=Convert.ToString(ComGet(shortcut,"Arguments"));workingDirectory=Convert.ToString(ComGet(shortcut,"WorkingDirectory"));}
     finally{Release(shortcut);Release(shell);}
     if(digest!=pin.Digest())throw new IOException("app_login_shortcut_changed");
    }
    NativeBootstrap.NoRedirect(link);bool owned=owner==sid&&Same(target,app)&&observedArguments==arguments&&Same(workingDirectory,root);
    // A retained pre-admission pin permits deletion but prevents file-ID reuse.
    // Reopen the path to refuse a replacement during the COM observation.
    using(var rebound=new NativeLoginFile(link,false,true)){if(rebound.Identity!=pin.Identity||rebound.Digest()!=digest||rebound.Owner!=owner)throw new IOException("app_login_shortcut_changed");}
    var observation=new Observation {Status=owned?"registered_unverified":"foreign",Fingerprint=Fingerprint(1,"windows",sid,link,app,arguments,Path.GetFullPath(root),true,owner,pin.Identity,digest,target,observedArguments,workingDirectory),Pin=retain?pin:null};if(retain)pin=null;return observation;
   }catch{return new Observation {Status="unknown",Fingerprint=null};}finally{if(pin!=null)pin.Dispose();}
  }
  internal static void CreateOwnedShortcut(string file,string app,string arguments,string directory){
   object shell=null,shortcut=null;try{shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell",true));shortcut=ComCall(shell,"CreateShortcut",file);ComSet(shortcut,"TargetPath",app);ComSet(shortcut,"Arguments",arguments);ComSet(shortcut,"WorkingDirectory",directory);ComSet(shortcut,"Description","Styx");ComCall(shortcut,"Save");}finally{Release(shortcut);Release(shell);}
   // An administrator token may otherwise create an Administrators-owned file.
   // Set only the owner; preserve the private state directory's inherited DACL.
   NativeBootstrap.NoRedirect(file);var security=File.GetAccessControl(file,System.Security.AccessControl.AccessControlSections.Owner);security.SetOwner(System.Security.Principal.WindowsIdentity.GetCurrent().User);File.SetAccessControl(file,security);
  }
  internal static NativeLoginFile OpenMatchedDeleteHandle(string link,NativeLoginFile observed){
   if(observed==null)throw new IOException("app_login_original_read_handle_required");
   var deleter=new NativeLoginFile(link,true,false);
   try{
    // WScript reads only under READ pins. Capture DELETE after every COM object
    // is released, then refuse even a same-byte replacement before capture.
    if(deleter.Identity!=observed.Identity||deleter.Owner!=observed.Owner||deleter.Digest()!=observed.Digest()){deleter.Dispose();return null;}
    return deleter;
   }catch{deleter.Dispose();throw;}
  }
  internal static Result Apply(string root,string state,bool enabled,Observation before){
   var current=Observe(root,state,true);
   string temporary=null;bool dispatched=false;
   try{
    if(current.Status!=before.Status||current.Fingerprint!=before.Fingerprint||String.IsNullOrEmpty(current.Fingerprint)||current.Status=="foreign"||current.Status=="unknown")return new Result {Outcome="failed",Observation=current};
    if(enabled&&current.Status=="registered_unverified"||!enabled&&current.Status=="not_registered")return new Result {Outcome="succeeded",Observation=current};
    string link=ShortcutPath();
    if(enabled){
     NativeBootstrap.NoRedirect(state);temporary=Path.Combine(state,"app-login-"+Guid.NewGuid().ToString("N")+".lnk");
     dispatched=true;CreateOwnedShortcut(temporary,App(root),Arguments(state),Path.GetFullPath(root));
     // Exclusive publication cannot overwrite a concurrently created entry.
     // The temporary shortcut lives in the private App state, never Startup.
     current.Dispose();current=Observe(root,state,true);if(current.Status!=before.Status||current.Fingerprint!=before.Fingerprint)return new Result {Outcome="failed",Observation=current};
     File.Move(temporary,link);temporary=null;
    }else{
     using(var deleter=OpenMatchedDeleteHandle(link,current.Pin)){
      if(deleter==null)return new Result {Outcome="failed",Observation=current};
      dispatched=true;deleter.Delete();
     }
     // Close DELETE and every pre-admission READ pin before independently
     // observing the resulting Startup name; never run COM under DELETE access.
     current.Dispose();before.Dispose();
    }
    var after=Observe(root,state);return new Result {Outcome=after.Status==(enabled?"registered_unverified":"not_registered")?"succeeded":"unknown",Observation=after};
   }catch{current.Dispose();if(dispatched)before.Dispose();return new Result {Outcome=dispatched?"unknown":"failed",Observation=Observe(root,state)};}
   finally{current.Dispose();if(temporary!=null){try{File.Delete(temporary);}catch{}}}
  }
 }
 sealed class StyxContext:ApplicationContext {
  readonly string root,state;readonly NotifyIcon tray;readonly Icon icon;readonly Form panel;readonly Settings settings;readonly CancellationTokenSource startupCancellation=new CancellationTokenSource();readonly Stopwatch startupClock=Stopwatch.StartNew();readonly bool startupTest,loginStartup;readonly System.Windows.Forms.Timer startupTimer;
  VerificationTiming verificationTiming;Core core;bool busy,closing,starting,startupHostUpdateAttempted,loginChangeUnconfirmed,actionsGatedDuringStartup=true;int mutationRevision,progressEvents;long firstPaintTicks=-1,verificationStartedTicks=-1,verifiedTicks=-1,readyTicks=-1;object snapshot;Task<object> observation;TaskCompletionSource<bool> mutationDone;readonly Label message;
  internal int ResultCode=2;
  internal object CurrentStatus { get { return snapshot; } }
  internal bool RustHost {get{return Json.Str(snapshot,"mode")=="rust_host";}}
  internal string ConfigurationDirectory {get{return core==null?"":core.ProfileDirectory;}}
  internal bool Supports(string operation){var values=Json.Get(snapshot,"supportedOperations") as object[];if(values==null)return false;foreach(var item in values)if(Equals(item,operation))return true;return false;}
  internal bool ManagementOnly { get { return !RustHost&&Json.Yes(snapshot,"loadingDetails"); } }
  internal bool MutationBusy { get { return busy||starting; } }
  internal bool LoginChangeAllowed {get{return !loginChangeUnconfirmed;}}
  [DllImport("user32.dll")]static extern bool DestroyIcon(IntPtr hIcon);
  internal static Icon BrandIcon(string file){using(var original=Image.FromFile(file))using(var bitmap=new Bitmap(original,new Size(32,32))){IntPtr handle=bitmap.GetHicon();try{return (Icon)Icon.FromHandle(handle).Clone();}finally{DestroyIcon(handle);}}}
  internal StyxContext(string resourceRoot,string stateDirectory,bool test,bool testStartup=false,bool fromLogin=false){
   root=resourceRoot;state=stateDirectory;startupTest=testStartup;loginStartup=fromLogin;icon=BrandIcon(Path.Combine(root,"styx-logo.png"));
   panel=Window("Styx",new Size(340,420));panel.ShowInTaskbar=false;panel.FormBorderStyle=FormBorderStyle.FixedToolWindow;
   var stack=Stack(panel);Logo(stack,64);Heading(stack,"Your computer, connected");
   message=Text(stack,"Open Settings to get started.",110);
   Button(stack,"Reconnect",Reconnect);
   Button(stack,"Pause connection",async()=>{await Run(async()=>{await Call("disconnect");await RefreshAfterMutation();});});
   Button(stack,"Settings",()=>{OpenSettings();return Task.FromResult(0);});
   panel.FormClosing+=(s,e)=>{if(!closing){e.Cancel=true;panel.Hide();}};
   settings=new Settings(this,icon);startupTimer=new System.Windows.Forms.Timer {Interval=50};startupTimer.Tick+=async(s,e)=>{startupTimer.Stop();await InitializeCore();};tray=new NotifyIcon { Icon=icon,Text="Styx — open to view connection",Visible=!test };
   var menu=new ContextMenuStrip();menu.Items.Add("Open Styx",null,(s,e)=>ShowPanel());menu.Items.Add("Settings",null,(s,e)=>OpenSettings());menu.Items.Add("Quit Styx",null,async(s,e)=>await RequestQuit());tray.ContextMenuStrip=menu;tray.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)ShowPanel();};
   if(!test){
    starting=true;settings.Startup("Opening Styx…",true,false);message.Text="Opening Styx…";
    // WM_TIMER runs after pending paints; BeginInvoke can overtake WM_PAINT.
    if(loginStartup){settings.CreateControl();settings.Handle.ToInt64();startupTimer.Start();}else{settings.Shown+=(s,e)=>startupTimer.Start();OpenSettings();}
   }
  }
  internal void RecordFirstPaint(){if(firstPaintTicks<0)firstPaintTicks=startupClock.ElapsedTicks;}
  internal async Task InitializeCore(){
   if(closing||core!=null)return;starting=true;settings.Startup("Checking app files…",true,false);message.Text="Checking app files…";Core pending=null;NativeBootstrap verifiedRuntime=null;string startupFailure="";bool packageVerified=false;
   try{
    actionsGatedDuringStartup&=settings.StartupActionsGated;if(!actionsGatedDuringStartup)throw new IOException();verificationStartedTicks=startupClock.ElapsedTicks;verificationTiming=new VerificationTiming();
    var progress=new Progress<PackageProgress>(value=>{if(closing||!starting)return;progressEvents++;actionsGatedDuringStartup&=settings.StartupActionsGated;settings.Startup(value.Phase=="files"?"Checking app files… "+value.Completed+" / "+value.Total:"Checking components…",true,false);});
    verifiedRuntime=await Task.Run(()=>PackageVerifier.Verify(root,progress,startupCancellation.Token,verificationTiming));packageVerified=true;verifiedTicks=startupClock.ElapsedTicks;
    if(closing){verifiedRuntime.Dispose();return;}settings.Startup("Opening connection settings…",true,false);
    pending=await Task.Run(()=>new Core(verifiedRuntime,state,startupCancellation.Token));if(closing){pending.Dispose();pending=null;return;}
    // Do not enable any action until the real Core answers its first status read.
    var latest=await pending.Call("startupStatus",Json.Obj());if(closing){pending.Dispose();pending=null;return;}
    if(Json.Str(latest,"mode")!="rust_host"||Json.Get(latest,"supportedOperations") as object[]==null)throw new IOException("app_rust_protocol_required");core=pending;pending=null;snapshot=latest;starting=false;readyTicks=startupClock.ElapsedTicks;PublishStatus();settings.Startup("",false,false);ResultCode=0;
    if(ManagementOnly){if(startupTest)await ObserveStatus();else LoadInitialDetails();}
    if(startupTest){WriteStartupReceipt(true,packageVerified);Quit();}else RecordStartupDiagnostics();return;
   }catch(NativeOperationException error){startupFailure=error.Code;}catch{}
   // Framework's C# compiler cannot await inside catch. Dispose the failed
   // owned child here without blocking the native window or replaying work.
   var failed=pending??core;core=null;if(failed!=null)await Task.Run(()=>failed.Dispose());else if(verifiedRuntime!=null)verifiedRuntime.Dispose();if(closing)return;starting=false;
   if(startupFailure=="app_migration_scope_ambiguous"){message.Text="Both original and fresh configurations exist. Styx will not choose or replace either configuration. Review them before continuing.";settings.Startup(message.Text,false,true);return;}
   if(startupFailure=="app_legacy_migration_required"){message.Text="This computer needs an explicit migration. Its original identity and settings were not changed.";settings.Startup(message.Text,false,true);return;}
   message.Text="Styx needs attention. Open Settings to retry.";
   settings.Startup(packageVerified?"Connection settings could not open. Retry to reconnect; your settings are retained.":"Styx could not finish checking the app. Keep the app folder intact, then retry.",false,true);
   if(startupTest){WriteStartupReceipt(false,packageVerified);Quit();}
  }
  object StartupTiming(){return Json.Obj("schema",1,"verification",verificationTiming.Snapshot(),"startup",Json.Obj("verificationStartedMilliseconds",(double)verificationStartedTicks*1000/Stopwatch.Frequency,"verifiedMilliseconds",(double)verifiedTicks*1000/Stopwatch.Frequency,"readyMilliseconds",(double)readyTicks*1000/Stopwatch.Frequency));}
  // Optional local diagnostics cannot delay enablement, fail startup, or execute
  // an unverified package. Before Core is trusted, timings remain in memory.
  async void RecordStartupDiagnostics(){if(RustHost)return;try{if(core!=null)await Call("startupDiagnostics",(Dictionary<string,object>)StartupTiming());}catch{}}
  void WriteStartupReceipt(bool success,bool packageVerified){
   bool paintedFirst=firstPaintTicks>=0&&verificationStartedTicks>=firstPaintTicks;
   bool gated=core==null||verifiedTicks>=verificationStartedTicks&&readyTicks>=verifiedTicks;
   ResultCode=success&&paintedFirst&&gated&&actionsGatedDuringStartup&&progressEvents>0?0:2;
   Directory.CreateDirectory(state);File.WriteAllText(Path.Combine(state,"native-startup-self-test.json"),Json.Codec.Serialize(Json.Obj("status",ResultCode==0?"PASS":"FAIL","windowPaintedBeforeVerification",paintedFirst,"packageVerified",packageVerified,"coreReady",core!=null,"coreGatedByVerification",gated,"controlsGatedWhileChecking",actionsGatedDuringStartup,"retryAvailable",settings.StartupRetryAvailable,"progressEvents",progressEvents,"verificationTiming",verificationTiming==null?null:verificationTiming.Snapshot(),"firstPaintMilliseconds",firstPaintTicks<0?-1:(double)firstPaintTicks*1000/Stopwatch.Frequency,"verificationStartedMilliseconds",verificationStartedTicks<0?-1:(double)verificationStartedTicks*1000/Stopwatch.Frequency,"verifiedMilliseconds",verifiedTicks<0?-1:(double)verifiedTicks*1000/Stopwatch.Frequency,"readyMilliseconds",readyTicks<0?-1:(double)readyTicks*1000/Stopwatch.Frequency,"interactiveDesktopAcceptance","NOT RUN","serviceMutation","NOT RUN")));
  }
  internal static Form Window(string title,Size size){return new Form { Text=title,ClientSize=size,StartPosition=FormStartPosition.CenterScreen,BackColor=Color.FromArgb(249,249,247),Font=new Font("Segoe UI",10),AutoScaleMode=AutoScaleMode.Dpi,MinimumSize=size };}
  internal static FlowLayoutPanel Stack(Control parent){var p=new FlowLayoutPanel { Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(24) };parent.Controls.Add(p);return p;}
  internal static Label Text(Control p,string text,int height){var l=new Label {Text=text,Width=p.ClientSize.Width>100?p.ClientSize.Width-55:440,Height=height,Margin=new Padding(0,5,0,10),AutoSize=false};p.Controls.Add(l);return l;}
  internal static void Heading(Control p,string text){var l=Text(p,text,40);l.Font=new Font("Segoe UI Semibold",17);}
  internal static Button Button(Control p,string text,Func<Task> action){var b=new Button {Text=text,AutoSize=true,MinimumSize=new Size(210,36),FlatStyle=FlatStyle.System,Margin=new Padding(0,5,0,5)};b.Click+=async(s,e)=>await action();p.Controls.Add(b);return b;}
  internal void Logo(Control p,int size){p.Controls.Add(new PictureBox { Image=Image.FromFile(Path.Combine(root,"styx-logo.png")),SizeMode=PictureBoxSizeMode.Zoom,Width=size,Height=size,Margin=new Padding(0,0,0,15) });}
  void ShowPanel(){var bounds=Screen.PrimaryScreen.WorkingArea;panel.Location=new Point(bounds.Right-panel.Width-12,bounds.Bottom-panel.Height-12);panel.Show();panel.Activate();}
  void OpenSettings(){settings.Show();settings.Activate();}
  // Fixed protocol result names only. Never display exception Message,
  // request data, upstream errors, file paths or credentials.
  static string NativeFailureCode(string code){
   switch(code){
    case "join_invalid":case "join_encoding":case "join_signature":case "seed_identity":
    case "app_input_invalid":case "app_home_unavailable":case "app_shell_unavailable":
    case "app_join_not_inspected":case "app_join_already_exists":case "app_join_input_unknown":
    case "app_input_writer_busy":case "app_scope_changed":case "app_instance_changed":
    case "native_join_invalid_input":case "native_join_candidate_untrusted":case "native_join_ca_rejected":
    case "native_join_identity_generation_failed":case "native_join_entropy_unavailable":
    case "native_join_app_scope_changed":case "native_join_already_exists":
    case "native_join_persistence_unknown":case "native_join_unknown_inspect":
    case "native_join_configuration_busy":case "native_join_busy":case "native_join_worker_unknown":
    case "native_join_platform_unsupported":case "native_join_response_rejected":
    case "app_migration_authorization_required":case "app_migration_owner_busy":case "app_migration_not_required":
    case "app_migration_in_progress":case "app_migration_pending":case "app_migration_original_transaction_required":
    case "app_migration_review_required":case "app_migration_review_mismatch":case "app_migration_plan_invalid":case "app_migration_scope_ambiguous":
    case "app_migration_observation_invalid":case "app_migration_observation_unavailable":
    case "native_migration_waiting_for_later_boot":return code;
    default:return "";
   }
  }
  internal async Task Run(Func<Task> action,string pending="Working…",string failure="The operation could not be confirmed. Refresh to review current state. Completed steps are retained; an interrupted operation is not automatically repeated."){
   if(busy||starting||core==null)return;string previousMessage=message.Text;busy=true;mutationDone=new TaskCompletionSource<bool>();mutationRevision++;settings.Enabled=false;message.Text=pending;settings.Feedback(pending);
   try{var reading=observation;if(reading!=null){try{await reading;}catch{}if(observation==reading)observation=null;}await action();if(settings.HasFeedback(pending))settings.Feedback("Operation completed. Review the current connection and test evidence below.");}
   catch(Exception error){string text=failure;var native=error as NativeOperationException;if(native!=null&&native.Code=="app_system_trust_not_supported")text="This native join currently requires an explicit Gateway CA in the invitation. System-trust-only joining is not supported; no CA or approval was fabricated.";else if(native!=null&&native.Code=="app_operation_not_supported")text="This operation is unavailable in the native Host slice. Existing settings were retained.";else if(native!=null&&native.Code=="host_payload_insufficient_space")text=SpaceFeedback(native.Budget,native.Preflight);else if(native!=null&&native.Code=="windows_native_app_binding_required")text="The desktop test could not start. This package could not verify the current native Styx app. Your settings are retained.";else if(native!=null&&native.Code=="desktop_acceptance_native_app_changed")text="The native Styx app changed during this desktop test. Create a new test in this app before continuing.";else if(native!=null&&native.Code=="app_login_result_unknown_no_replay")text="The login startup change is unconfirmed and will not be repeated. Check Windows startup settings. Quit and reopen Styx to read the system state.";else if(native!=null&&native.Code=="app_login_observation_changed")text="The Startup entry changed before the operation could finish. Styx preserved the current entry. Check its current state before making another explicit change.";else if(native!=null&&native.Code=="work_in_progress")text="A task is still running. Wait for it to finish before quitting or updating Styx.";else if(native!=null&&native.Code=="work_state_unknown")text="Styx could not confirm whether tasks are running. Keep it open and try again after checking the connection.";if(native!=null){string diagnostic=NativeFailureCode(native.Code);if(diagnostic.Length>0)text+="\nNative result: "+diagnostic;}message.Text="Connection needs attention. Open Settings to review the last result.";settings.Feedback(text);}
   finally{if(message.Text==pending)message.Text=previousMessage;settings.Enabled=true;busy=false;mutationDone.TrySetResult(true);}
   // A mutation invalidates an in-flight startup observation. Resume only that
   // read after settling; never replay the mutation or block the ready controls.
   if(!closing&&core!=null&&ManagementOnly)LoadInitialDetails();else await CompleteStartupUpdate();
  }
  internal async void FinishInviting(){if(core==null)return;try{while(busy)await mutationDone.Task;await Run(async()=>{await Call("closePairing");},"Closing invitation…","The pairing window could not be confirmed closed. Review the connection; the invitation retains its original expiry.");}catch{settings.Feedback("The pairing window could not be confirmed closed. Review the connection before inviting again.");}}
  internal async Task Read(Func<Task> action){try{await action();}catch{settings.ObservationFailed("This information could not be refreshed. Your entries and the last confirmed state are retained.");}}
  internal Task Reconnect(){return Run(async()=>{await Call("connect");await RefreshAfterMutation();settings.Feedback(ReconnectResult(snapshot));},"Reconnecting to this computer…","Reconnect could not be confirmed. Your settings are retained. Refresh status before retrying.");}
  internal static string ReconnectResult(object data){bool native=Json.Str(data,"mode")=="rust_host";string state=native?Json.Str(data,"foreground","status"):Json.Str(data,"status","foreground","status"),exec=native?Json.Str(data,"foreground","execConnection"):Json.Str(data,"status","foreground","execConnection");return state=="connected"&&exec=="connected"?"Reconnected. The Exec transport is online; tool execution and your ChatGPT account confirmation are checked separately.":state=="started"?"Reconnect requested. The connection is still starting. Refresh status to confirm the result.":"Reconnect has not established an Exec connection. Review the current state before retrying.";}
  internal async Task Refresh(){if(busy||starting||core==null)return;int revision=mutationRevision;try{await ObserveStatus();}catch{if(revision==mutationRevision)settings.ObservationFailed("Connection status could not refresh. You can keep editing and retry. Your last confirmed state is retained.");}}
  internal Task RefreshAfterMutation(){return ObserveStatus();}
  internal void ApplyPreparationResult(object latest){
   if(Json.Get(latest,"status")==null)throw new IOException();
   snapshot=latest;settings.ClearPreparationFeedback();PublishStatus();
  }
  async Task ObserveStatus(){
   if(observation!=null){await observation;return;}
   int revision=mutationRevision;var pending=Call("status");observation=pending;
   try{var latest=await pending;if(!closing&&revision==mutationRevision){snapshot=latest;PublishStatus();}}finally{if(observation==pending)observation=null;}
   await CompleteStartupUpdate();
  }
  async Task CompleteStartupUpdate(){
   if(RustHost)return;
   if(closing||busy||core==null||startupHostUpdateAttempted||Json.Str(snapshot,"status","nativeStartup","status")!="reconciliation_required"||Json.Str(snapshot,"status","nativeStartup","reason")!="host_payload_update_required"||!Json.Yes(snapshot,"status","nativeStartup","automaticUpdate"))return;
   // Core owns the decision. This launch attempts it once; failure remains an
   // explicit recovery action, including when later status reads say to update.
   startupHostUpdateAttempted=true;await UpdateRuntime(false);
  }
  void PublishStatus(){
   if(RustHost){string phase=Json.Str(snapshot,"foreground","status"),nativeExec=Json.Str(snapshot,"foreground","execConnection");message.Text=Json.Str(snapshot,"migration","status")=="waiting_for_later_boot"?"Migration is waiting for a later Windows restart. It is not complete; Windows will not restart automatically.":phase=="connected"&&nativeExec=="connected"?"Connected to this computer. Exec transport is online; tool execution is checked separately.":Json.Yes(snapshot,"admission_fenced")?"A result or cleanup needs review. Operations are fenced; no action is replayed.":"Connection is paused or awaiting approval. Open Settings to review.";tray.Text=phase=="connected"&&nativeExec=="connected"?"Styx — connected":"Styx — connection settings";settings.ShowStatus(snapshot);return;}
   if(Json.Yes(snapshot,"status","joinRecovery","rollbackRequired")){message.Text="Joining needs recovery. Open Settings to continue.";tray.Text="Styx — joining needs recovery";settings.ShowPage("join-interrupted");return;}
   if(ManagementOnly){message.Text="Reading connection settings… Component update and recovery are available.";tray.Text="Styx — connection not checked";settings.ShowPage("component-start");return;}
   if(Json.Str(snapshot,"status","nativeStartup","status")=="reconciliation_required"&&Json.Str(snapshot,"status","nativeStartup","reason").StartsWith("host_payload_")){message.Text="The installed Styx update needs its components reconciled.";tray.Text="Styx — component update";settings.ShowPage("update-recovery");return;}
   if(Json.Get(snapshot,"componentRecovery")!=null){message.Text="A component update needs review. Your settings and recovery record are retained.";tray.Text="Styx — update needs review";settings.ShowPage("update-recovery");if(settings.HasFeedback(""))settings.Feedback(message.Text);return;}
   var f=Json.Str(snapshot,"status","foreground","status");var exec=Json.Str(snapshot,"status","foreground","execConnection");
   message.Text=f=="connected"&&exec=="connected"?"Connected to this computer.\n\nExec transport is online. Tool execution and ChatGPT account confirmation are shown separately in Settings.":f=="started"?"Connecting…\n\nKeep Styx open while this computer connects.":"Connection is paused or unavailable.\n\nOpen Settings to review, prepare or reconnect.";
   tray.Text=f=="connected"&&exec=="connected"?"Styx — connected":"Styx — needs attention";settings.ShowStatus(snapshot);
  }
  internal async Task<object> Call(string op,Dictionary<string,object> input=null){
   if(core==null)throw new IOException();if(RustHost&&!Supports(op))throw new NativeOperationException("app_operation_not_supported");
   if(RustHost&&op=="appLifecycle"){
    var result=await core.Call("appLifecycle",Json.Obj("observation",NativeLoginStartup.Observe(root,state).Wire));if(Json.Str(result,"login","status")=="unknown")loginChangeUnconfirmed=true;return result;
   }
   if(RustHost&&op=="appLogin"){
    if(loginChangeUnconfirmed)throw new NativeOperationException("app_login_result_unknown_no_replay");if(input==null||input.Count!=1||!(Json.Get(input,"enabled") is bool))throw new NativeOperationException("app_input_invalid");bool enabled=Json.Yes(input,"enabled");using(var before=NativeLoginStartup.Observe(root,state,true)){
    var prepared=await core.Call("appLogin",Json.Obj("authorize",true,"enabled",enabled,"observation",before.Wire));string ticket=Json.Str(prepared,"login","ticketId");
    if(Json.Str(prepared,"login","status")!="authorized"||!Equals(Json.Get(prepared,"login","enabled"),enabled)||!System.Text.RegularExpressions.Regex.IsMatch(ticket,"^[a-f0-9]{32}$"))throw new IOException("app_login_authorization_invalid");
    var applied=NativeLoginStartup.Apply(root,state,enabled,before);if(applied.Outcome=="unknown")loginChangeUnconfirmed=true;object result;
    try{result=await core.Call("appLoginResult",Json.Obj("ticketId",ticket,"outcome",applied.Outcome,"observation",applied.Observation.Wire));}
    catch{loginChangeUnconfirmed=true;throw new NativeOperationException("app_login_result_unknown_no_replay");}
    if(applied.Outcome=="unknown"||Json.Str(result,"login","status")=="unknown"){loginChangeUnconfirmed=true;throw new NativeOperationException("app_login_result_unknown_no_replay");}
    if(applied.Outcome!="succeeded"||Json.Str(result,"login","status")!="succeeded")throw new NativeOperationException("app_login_observation_changed");return result;
    }
   }
   return await core.Call(op,input??Json.Obj());
  }
  internal static string SpaceFeedback(object budget,bool preflight){
   string text=preflight?"Not enough disk space. The upgrade has not started.":"Not enough disk space. The update remains incomplete; review recovery before continuing.";
   var volumes=Json.Get(budget,"volumes") as object[];
   if(volumes!=null)foreach(var volume in volumes){double required,available;if(!Double.TryParse(Convert.ToString(Json.Get(volume,"requiredBytes")),out required)||!Double.TryParse(Convert.ToString(Json.Get(volume,"availableBytes")),out available)||Double.IsNaN(required)||Double.IsNaN(available)||Double.IsInfinity(required)||Double.IsInfinity(available)||required<0||available<0||required>9007199254740991d||available>9007199254740991d)continue;text+="\nRequired: "+(required/1073741824d).ToString("0.00")+" GB; available: "+(available/1073741824d).ToString("0.00")+" GB.";}
   return text+"\nFree up disk space, then retry.";
  }
  internal Task UpdateRuntime(){return UpdateRuntime(true);}
  Task UpdateRuntime(bool confirm){return Run(async()=>{
   startupHostUpdateAttempted=true;
   if(confirm&&MessageBox.Show(settings,"Styx will close briefly to update its components, then reopen. Finish any running tasks before continuing.","Update Styx components",MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return;
   var prepared=await Call("runtimeUpgradePrepare");string ticket=Json.Str(prepared,"handoff","ticketId");
   if(Json.Str(prepared,"handoff","status")!="awaiting_exit"||!System.Text.RegularExpressions.Regex.IsMatch(ticket,"^[a-f0-9]{32}$"))throw new IOException();
   await AdmitQuit();
   var launched=await Call("runtimeUpgradeLaunch",Json.Obj("ticketId",ticket));if(Json.Str(launched,"status")!="launched"||Json.Str(launched,"ticketId")!=ticket)throw new IOException();
   settings.Feedback("The updater is ready. Closing Styx…");settings.BeginInvoke(new Action(Quit));
  },confirm?"Preparing the component update…":"Finishing the Styx update… Styx will close briefly and reopen.","The update could not be started. Keep Styx open and review the update status before trying again. Your settings and pairing are retained.");}
  async void LoadInitialDetails(){int revision=mutationRevision;try{await ObserveStatus();}catch{if(!closing&&revision==mutationRevision)settings.ObservationFailed("Connection settings could not be read. Update and recovery remain available. Refresh status to try again.");}}
  internal Task ReviewRuntime(){return Run(async()=>{
   var result=await Call("runtimeUpgradeStatus");string ticket=Json.Str(result,"handoff","ticketId"),status=Json.Str(result,"handoff","status"),transaction=Json.Str(result,"upgrade","transactionId");
   if(status=="not_started"||status=="cancelled"||status=="rolled_back"){settings.Feedback("No component update is waiting. You can check for an update again.");return;}
   bool migration=Json.Str(result,"upgrade","handoffTicketId")==ticket&&System.Text.RegularExpressions.Regex.IsMatch(transaction,"^[a-f0-9]{32}$")&&Json.Str(result,"upgrade","status")!="rolled_back";
   if(migration){if(MessageBox.Show(settings,"Return to the previous components? Styx will close briefly, restore the saved version and reopen. Your computer identity and pairing are retained.","Recover component update",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;await AdmitQuit();var launched=await Call("runtimeUpgradeRollback",Json.Obj("ticketId",ticket));if(Json.Str(launched,"status")!="launched"||Json.Str(launched,"ticketId")!=ticket)throw new IOException();settings.BeginInvoke(new Action(Quit));return;}
   if(status=="applied_stopped"){settings.Feedback("The components were updated. Reconnect this computer to check the connection.");return;}
   if(MessageBox.Show(settings,"Cancel the waiting update? Your existing components will stay installed.","Cancel component update",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;
   var cancelled=await Call("runtimeUpgradeCancel",Json.Obj("ticketId",ticket));if(Json.Str(cancelled,"handoff","status")!="cancelled")throw new IOException();settings.Feedback("The waiting update was cancelled. You can start it again when ready.");
  },"Checking the component update…","The update recovery could not be confirmed. Keep Styx open; your recovery record is retained.");}
  async Task AdmitQuit(){var result=await Call("quitAdmission");if(Json.Str(result,"quit","status")!="ready_to_quit"||!System.Text.RegularExpressions.Regex.IsMatch(Json.Str(result,"quit","ticketId"),"^[a-f0-9]{32}$"))throw new IOException();}
  internal Task RequestQuit(){
   if(starting||busy){OpenSettings();settings.Feedback("Wait for the current operation to finish before quitting Styx.");return Task.FromResult(0);}
   if(core==null){Quit();return Task.FromResult(0);}
   OpenSettings();return Run(async()=>{await AdmitQuit();settings.BeginInvoke(new Action(Quit));},"Checking running tasks…","Styx could not confirm that it is ready to quit. Keep it open and try again after checking the connection.");
  }
  internal void Quit(){if(closing)return;closing=true;if(core!=null){core.Dispose();if(!core.CleanupConfirmed){closing=false;settings.Feedback("The owned Rust process did not exit cleanly. No successful quit receipt is claimed; retain this result for recovery.");ResultCode=4;return;}}startupTimer.Stop();startupTimer.Dispose();startupCancellation.Cancel();tray.Visible=false;settings.Close();settings.Dispose();panel.Close();tray.Dispose();icon.Dispose();ExitThread();}
  internal void Verify(){var budget=Json.Obj("volumes",new object[]{Json.Obj("requiredBytes",2147483648d,"availableBytes",1073741824d)});if(!SpaceFeedback(budget,true).Contains("upgrade has not started")||SpaceFeedback(budget,false).Contains("upgrade has not started")||!SpaceFeedback(budget,true).Contains("Required:"))throw new Exception("space_feedback_failed");if(panel.Controls.Count!=1||settings.Controls.Count!=1||icon.Width<16)throw new Exception("native_shell_failed");settings.Verify();}
 }
 sealed class Settings:Form {
  sealed class CapabilityDraft {internal string Label=Environment.MachineName;internal bool Computer=true,Browser;internal int Channel;internal CheckState Persist=CheckState.Checked;}
  readonly StyxContext owner;readonly FlowLayoutPanel content,navigation;readonly TableLayoutPanel startupPanel;readonly Label startupText;readonly ProgressBar startupProgress;readonly Button retryStartup;readonly Label feedback,statusReadout,observationError;readonly Dictionary<string,CapabilityDraft> capabilityDrafts=new Dictionary<string,CapabilityDraft>();
  string migrationTransaction="",migrationPlanSha="",migrationCanonical="",migrationRenderKey="";bool migrationSubmitted;
  string page="welcome",requestedPage="overview",joinOrigin,joinCa,challengeId,tunnelDraft="",keyDraft="",readbackSubmitted;object acceptance;bool readbackInFlight,renderedRustMode,localCreationSubmitted;TextBox label,link,tunnel,key,desktopInput,challengePrompt;Label desktopInputLabel;Button confirmChat,updateRuntime;CheckBox computer,browser,persist;ComboBox channel;readonly System.Windows.Forms.Timer desktopTimer;
  internal Settings(StyxContext context,Icon icon){owner=context;Text="Styx Settings";Icon=icon;ClientSize=new Size(590,720);MinimumSize=new Size(550,650);Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(249,249,247);AutoScaleMode=AutoScaleMode.Dpi;StartPosition=FormStartPosition.CenterScreen;var outer=new TableLayoutPanel { Dock=DockStyle.Fill,RowCount=3,ColumnCount=1,Padding=new Padding(0) };outer.RowStyles.Add(new RowStyle(SizeType.Absolute,62));outer.RowStyles.Add(new RowStyle(SizeType.AutoSize));outer.RowStyles.Add(new RowStyle(SizeType.Percent,100));Controls.Add(outer);navigation=new FlowLayoutPanel { Dock=DockStyle.Fill,WrapContents=false,Padding=new Padding(15,8,0,0) };outer.Controls.Add(navigation,0,0);StyxContext.Button(navigation,"General",()=>{ShowPage("welcome");return Task.FromResult(0);}).MinimumSize=new Size(100,32);StyxContext.Button(navigation,"Computers",()=>{ShowPage("overview");return Task.FromResult(0);}).MinimumSize=new Size(100,32);StyxContext.Button(navigation,"ChatGPT",()=>{ShowPage("chat");return Task.FromResult(0);}).MinimumSize=new Size(100,32);foreach(Control item in navigation.Controls){item.AutoSize=false;item.Width=165;item.Height=36;}startupPanel=new TableLayoutPanel {Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,RowCount=2,Padding=new Padding(26,8,26,12),Visible=false};startupPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));startupPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));startupText=new Label {AutoSize=true,MaximumSize=new Size(390,0),Margin=new Padding(0,0,10,8)};startupProgress=new ProgressBar {Dock=DockStyle.Top,Height=8,Style=ProgressBarStyle.Marquee,MarqueeAnimationSpeed=25};retryStartup=new Button {Text="Retry",AutoSize=true,MinimumSize=new Size(75,32)};retryStartup.Click+=async(s,e)=>await owner.InitializeCore();startupPanel.Controls.Add(startupText,0,0);startupPanel.Controls.Add(retryStartup,1,0);startupPanel.Controls.Add(startupProgress,0,1);startupPanel.SetColumnSpan(startupProgress,2);startupText.Paint+=(s,e)=>owner.RecordFirstPaint();outer.Controls.Add(startupPanel,0,1);content=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(26)};outer.Controls.Add(content,0,2);feedback=new Label {Width=490,Height=100,ForeColor=Color.FromArgb(95,70,35)};statusReadout=new Label {Width=490,Height=140};observationError=new Label {Width=490,Height=65,ForeColor=Color.FromArgb(130,65,35)};desktopTimer=new System.Windows.Forms.Timer {Interval=1000};desktopTimer.Tick+=async(s,e)=>await ObserveDesktopReadback();desktopTimer.Start();FormClosing+=(s,e)=>{if(e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();if(InvitationPage(page))owner.FinishInviting();}};ShowPage("welcome");}
  internal bool StartupActionsGated {get{return !navigation.Enabled&&!content.Enabled;}}
  internal bool StartupRetryAvailable {get{return startupPanel.Visible&&retryStartup.Visible&&retryStartup.Enabled;}}
  internal void Startup(string text,bool checking,bool canRetry){
   startupPanel.Visible=checking||canRetry;startupText.Text=text;startupProgress.Visible=checking;retryStartup.Visible=canRetry;navigation.Enabled=!checking&&!canRetry;content.Enabled=!checking&&!canRetry;
  }
  void Action(string title,Func<Task> action,bool mutation=true){StyxContext.Button(content,title,()=>mutation?owner.Run(action):owner.Read(action));}
  void RefreshAction(){Action("Refresh status",owner.Refresh,false);}
  const string PreparationMessage="Preparing this computer…";
  internal void ClearPreparationFeedback(){if(HasFeedback(PreparationMessage)||HasFeedback("Preparing signed components…"))Feedback("");}
  static bool PendingJoin(object data){
   if(Json.Str(data,"status","deployment","mode")!="join-existing")return false;
   var steps=Json.Get(data,"status","deployment","steps") as object[];if(steps==null)return true;
   foreach(string id in new[]{"host.prepare","host.request","host.claim","host.doctor"}){
    bool complete=false;foreach(var step in steps)if(Json.Str(step,"id")==id&&Json.Str(step,"status")=="succeeded")complete=true;
    if(!complete)return true;
   }return false;
  }
  void PreparationAction(string title,Func<Task> before=null){
   Action(title,()=>owner.Run(async()=>{
    Exception failure=null;try{
     if(before!=null)await before();
     var prepared=await owner.Call("prepare");owner.ApplyPreparationResult(prepared);
     if(!PendingJoin(prepared)&&!Json.Str(prepared,"status","nativeStartup","reason").StartsWith("host_payload_")){await owner.Call("connect");ShowPage("overview");await owner.RefreshAfterMutation();}
    }catch(Exception error){failure=error;}
    if(failure!=null){
     // Read the saved result after a failure; never replay preparation.
     try{await owner.RefreshAfterMutation();}catch{}
     throw failure;
    }
   },PreparationMessage,"Connection not completed. Check your main computer or use a new invitation."),false);
  }
  Task ContinueJoiningView(){Feedback("");ShowPage("overview");ShowStatus(owner.CurrentStatus);return Task.FromResult(0);}
  static bool CanRecoverJoin(object data){return Json.Yes(data,"session","joinRecoverySupported")&&Json.Yes(data,"status","joinRecovery","canRecover");}
  void ReviewInvitationAction(){
   joinOrigin="";joinCa="";link=Input("Invitation link",true);
   Action("Review invitation",async()=>{
    joinOrigin="";joinCa="";var result=await owner.Call("inspectJoin",Json.Obj("link",link.Text));link.Clear();
    joinOrigin=Json.Str(result,"preview","origin");joinCa=Json.Str(result,"preview","caSha256");
    Feedback("Main computer: "+joinOrigin+"\nCertificate: "+(joinCa.Length>0?joinCa:"system trust")+"\nConfirm that these match your main computer.");
   });
  }
  TextBox Input(string title,bool secret=false){StyxContext.Text(content,title,22);var box=new TextBox {Width=490,UseSystemPasswordChar=secret,Margin=new Padding(0,0,0,12)};content.Controls.Add(box);return box;}
  void Explain(string text,int height=65){StyxContext.Text(content,text,height);}
  void Capabilities(){
   CapabilityDraft draft;if(!capabilityDrafts.TryGetValue(page,out draft)){draft=new CapabilityDraft();if(page=="capabilities"){var data=owner.CurrentStatus;draft.Computer=Json.Get(data,"status","deviceCapabilities","computer") is bool?Json.Yes(data,"status","deviceCapabilities","computer"):Json.Str(data,"status","deployment","roles","computer")=="requested";draft.Browser=Json.Get(data,"status","deviceCapabilities","browser") is bool?Json.Yes(data,"status","deviceCapabilities","browser"):Json.Str(data,"status","deployment","roles","browser")=="requested";draft.Persist=CheckState.Indeterminate;}capabilityDrafts[page]=draft;}
   label=Input("Computer name");label.Text=draft.Label;label.Enabled=page!="capabilities";label.TextChanged+=(s,e)=>draft.Label=((TextBox)s).Text;
   computer=new CheckBox {Text="Computer Use — control the signed-in desktop",Checked=draft.Computer,Width=490,Height=32};browser=new CheckBox {Text="Browser Automation — dedicated Styx profile",Checked=draft.Browser,Width=490,Height=32};content.Controls.Add(new CheckBox {Text="Exec — run commands on this computer",Checked=true,Enabled=false,Width=490,Height=32});content.Controls.Add(computer);content.Controls.Add(browser);computer.CheckedChanged+=(s,e)=>draft.Computer=((CheckBox)s).Checked;browser.CheckedChanged+=(s,e)=>draft.Browser=((CheckBox)s).Checked;
   channel=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList,Width=300};if(page=="capabilities")channel.Items.Add("Keep current browser choice");channel.Items.AddRange(new object[]{"Automatic (Chrome / Edge)","Microsoft Edge","Google Chrome"});channel.SelectedIndex=draft.Channel;channel.SelectedIndexChanged+=(s,e)=>draft.Channel=((ComboBox)s).SelectedIndex;content.Controls.Add(channel);
   persist=new CheckBox {Text="Keep website logins in the dedicated Styx profile",ThreeState=page=="capabilities",CheckState=draft.Persist,Width=490,Height=32};persist.CheckStateChanged+=(s,e)=>draft.Persist=((CheckBox)s).CheckState;content.Controls.Add(persist);Explain(page=="capabilities"?"An unchanged browser choice and a mixed login checkbox retain the saved preference. Browser Automation uses a separate Styx profile.":"Browser Automation uses a separate Styx profile. Your personal browser sessions stay separate.",65);
  }
  Dictionary<string,object> CapabilityChoice(){var values=Json.Obj("computer",computer.Checked,"browser",browser.Checked);int selected=channel.SelectedIndex-1;if(selected>=0)values["browserChannel"]=selected==1?"msedge":selected==2?"chrome":"auto";if(persist.CheckState!=CheckState.Indeterminate)values["persistLogin"]=persist.Checked;return values;}
  Dictionary<string,object> Choice(){var values=Json.Obj("label",label.Text.Trim(),"computer",computer.Checked,"browser",browser.Checked);if(label.Text.Trim().Length==0)throw new InvalidOperationException();values["browserChannel"]=channel.SelectedIndex==1?"msedge":channel.SelectedIndex==2?"chrome":"auto";values["persistLogin"]=persist.Checked;return values;}
  static bool InvitationPage(string name){return name=="add-computer"||name=="pending-computers";}
  async Task ReadLogin(){ApplyLogin(await owner.Call("appLifecycle"));}
  void ApplyLogin(object response){string state=Json.Str(response,"lifecycle","status"),operation=Json.Str(response,"login","status");Feedback(!owner.LoginChangeAllowed||operation=="unknown"?"The last login startup change is unconfirmed and will not be repeated. Check Windows startup settings. Quit and reopen Styx to read the system state.":operation=="pending"?"A login startup change is awaiting its result. Styx will not repeat it.":state=="not_registered"?"Login startup is off.":state=="registered_unverified"?"Login startup is registered. Windows can disable it independently; check Windows startup settings.":state=="foreign"?"The existing Startup entry belongs to another app or installation. Styx preserved it.":"Login startup could not be observed. Check Windows startup settings; no startup entry was changed.");}
  internal void ShowPage(string name){if(Json.Yes(owner.CurrentStatus,"status","joinRecovery","rollbackRequired"))name="join-interrupted";if(owner.ManagementOnly&&name!="update-recovery"){if(name!="component-start")requestedPage=name;name="component-start";}if(InvitationPage(page)&&!InvitationPage(name))owner.FinishInviting();page=name;updateRuntime=null;desktopInput=null;desktopInputLabel=null;challengePrompt=null;confirmChat=null;var previous=new Control[content.Controls.Count];content.Controls.CopyTo(previous,0);foreach(var item in previous)if(item!=feedback&&item!=statusReadout&&item!=observationError){var picture=item as PictureBox;if(picture!=null&&picture.Image!=null)picture.Image.Dispose();item.Dispose();}content.Controls.Clear();Status("");owner.Logo(content,48);StyxContext.Heading(content,name=="chat"?"Connect ChatGPT":(name=="overview"||name=="component-start"||name=="update-recovery")?"This computer":"Get started with Styx");
   renderedRustMode=owner.RustHost;if(renderedRustMode){ShowRustPage(name);return;}
   if(name=="welcome"){
    if(Json.Get(owner.CurrentStatus,"status","deployment")!=null){
     bool joining=PendingJoin(owner.CurrentStatus);Explain(joining?"Continue joining your main computer. Your identity and preparation are saved.":"This computer is already configured.");
     Action(joining?"Continue joining":"Open this computer",ContinueJoiningView,false);
     Action("Login startup",async()=>{ShowPage("login-startup");await ReadLogin();});
    }else{Explain("Set up this computer, or join a Gateway you already own.");Action("Set up this computer",()=>{ShowPage("create");return Task.FromResult(0);},false);Action("Join an existing Gateway",()=>{ShowPage("join");return Task.FromResult(0);},false);}
   }
   else if(name=="login-startup"){Explain("Start Styx in the system tray when you sign in. Quitting Styx stops this session only.",70);Action("Enable login startup",async()=>{ApplyLogin(await owner.Call("appLogin",Json.Obj("enabled",true)));});Action("Disable login startup",async()=>{ApplyLogin(await owner.Call("appLogin",Json.Obj("enabled",false)));});Action("Windows startup settings",()=>{Process.Start("ms-settings:startupapps");return Task.FromResult(0);},false);Action("Check status",ReadLogin);}
   else if(name=="create"||name=="join"){Capabilities();if(name=="join"){link=Input("Private pairing link");link.UseSystemPasswordChar=true;Action("Review pairing link",async()=>{joinOrigin="";joinCa="";var r=await owner.Call("inspectJoin",Json.Obj("link",link.Text));link.Clear();joinOrigin=Json.Str(r,"preview","origin");joinCa=Json.Str(r,"preview","caSha256");Feedback("Gateway: "+joinOrigin+"\nCertificate SHA-256: "+(joinCa.Length>0?joinCa:"system trust")+"\nSelect Approve and prepare only if these match your Gateway.");});}PreparationAction(name=="join"?"Approve and prepare":"Prepare this computer",async()=>{var choice=Choice();if(name=="join"){if(String.IsNullOrEmpty(joinOrigin))throw new InvalidOperationException();choice["approvedGatewayOrigin"]=joinOrigin;if(!String.IsNullOrEmpty(joinCa))choice["approvedCaSha256"]=joinCa;}await owner.Call(name=="join"?"join":"create",choice);ShowPage("overview");});Action("Return",()=>{ShowPage("welcome");return Task.FromResult(0);},false);}
   else if(name=="join-interrupted"){
    Explain("Changing the invitation was interrupted. Restore the previous invitation before continuing.",75);
    string transaction=Json.Str(owner.CurrentStatus,"status","joinRecovery","transactionId");
    if(Json.Yes(owner.CurrentStatus,"session","joinRecoverySupported")&&Json.Yes(owner.CurrentStatus,"status","joinRecovery","rollbackRequired")&&System.Text.RegularExpressions.Regex.IsMatch(transaction,"\\A[a-f0-9]{32}\\z"))Action("Restore previous invitation",async()=>{
     await owner.Call("rollbackJoin",Json.Obj("transactionId",transaction));await owner.RefreshAfterMutation();ShowPage("overview");ShowStatus(owner.CurrentStatus);
    });
    RefreshAction();
   }
   else if(name=="join-recover"){
    Explain("Use a new invitation from your main computer. Your capabilities and prepared components are kept.",70);
    ReviewInvitationAction();
    PreparationAction("Accept and continue",async()=>{
     if(!CanRecoverJoin(owner.CurrentStatus)||String.IsNullOrEmpty(joinOrigin))throw new InvalidOperationException();
     var confirmation=Json.Obj("approvedGatewayOrigin",joinOrigin);if(!String.IsNullOrEmpty(joinCa))confirmation["approvedCaSha256"]=joinCa;
     await owner.Call("recoverJoin",confirmation);joinOrigin="";joinCa="";Feedback(PreparationMessage);ShowPage("overview");
    });
    Action("Cancel",()=>{joinOrigin="";joinCa="";link.Clear();Feedback("");return ContinueJoiningView();},false);
   }
   else if(name=="overview"){updateRuntime=StyxContext.Button(content,"Update and reopen Styx",owner.UpdateRuntime);updateRuntime.Visible=CanUpdateRuntime(owner.CurrentStatus);if(Json.Yes(owner.CurrentStatus,"session","hostPayloadHandoffSupported"))StyxContext.Button(content,"Review component update",owner.ReviewRuntime);Explain("Connection and account checks are observed separately. Styx runs in your signed-in Windows session. Lock, logout, UAC and elevated applications can limit desktop control.",88);RefreshAction();PreparationAction("Continue preparation");Action("Reconnect",owner.Reconnect,false);Action("Pause",async()=>{await owner.Call("disconnect");await owner.RefreshAfterMutation();});Action("Add computer",async()=>{var r=await owner.Call("inviteComputer");ShowInvitation(r);});Action("Confirm joining computer",async()=>{ShowPendingComputers(await owner.Call("pendingComputers"));});Action("Paired computers",async()=>{var r=await owner.Call("devices");ShowDevices(r);});Action("Edit capabilities",()=>{ShowPage("capabilities");return Task.FromResult(0);},false);}
   else if(name=="component-start"){Explain("Reading connection settings… Component update and recovery remain available while this check completes.",65);updateRuntime=StyxContext.Button(content,"Update and reopen Styx",owner.UpdateRuntime);updateRuntime.Visible=CanUpdateRuntime(owner.CurrentStatus);if(Json.Yes(owner.CurrentStatus,"session","hostPayloadHandoffSupported"))StyxContext.Button(content,"Review component update",owner.ReviewRuntime);RefreshAction();Status(ComponentNotice(owner.CurrentStatus));}
   else if(name=="update-recovery"){Explain("Styx must finish updating its components before reconnecting this computer. If the update needs attention, review it below. Your identity and pairing are retained.",90);updateRuntime=StyxContext.Button(content,"Update and reopen Styx",owner.UpdateRuntime);updateRuntime.Visible=CanUpdateRuntime(owner.CurrentStatus);StyxContext.Button(content,"Review component update",owner.ReviewRuntime);}
   else if(name=="join-waiting"){Explain("Join your main computer",40);}
   else if(name=="add-computer"){Explain("On the other computer, open Styx and choose Join existing. Use the invitation below.",70);}
   else if(name=="pending-computers"){Explain("Compare the code shown on the joining computer. Confirm only when both codes match.",70);}
   else if(name=="capabilities"){Capabilities();Action("Apply capabilities",async()=>{await owner.Call("setCapabilities",CapabilityChoice());await owner.RefreshAfterMutation();});Explain("Your browser choice and saved-login preference are applied through the same Core capability settings.");}
   else if(name=="chat"){
    StyxContext.Heading(content,"1. Connect this computer");Explain("Sign in to the OpenAI Platform with the organization you will use in ChatGPT. Create a Secure MCP Tunnel. Copy its Tunnel ID and runtime key into the fields below.",100);Action("Open tunnel settings",()=>{Process.Start("https://platform.openai.com/settings/organization/tunnels");return Task.FromResult(0);},false);
    tunnel=Input("Tunnel ID");tunnel.Text=tunnelDraft;tunnel.TextChanged+=(s,e)=>tunnelDraft=((TextBox)s).Text;key=Input("Tunnel runtime key",true);key.Text=keyDraft;key.TextChanged+=(s,e)=>keyDraft=((TextBox)s).Text;
    Action("Save and connect tunnel",async()=>{var input=Json.Obj("tunnelId",tunnel.Text.Trim(),"runtimeKey",key.Text);await owner.Call("tunnelSave",input);await owner.Call("tunnelStart");await owner.RefreshAfterMutation();key.Clear();Feedback("Tunnel settings saved and start requested. Check the transport status below; tool execution and account confirmation remain separate.");});
    RefreshAction();StyxContext.Heading(content,"2. Install in ChatGPT");Explain("Open ChatGPT Plugins in the intended account and workspace. Choose Add custom MCP server, then Tunnel. Select the same tunnel and No authentication. Create the plugin and install it. Keep the runtime key in Styx.",130);Action("Open ChatGPT",()=>{Process.Start("https://chatgpt.com/");return Task.FromResult(0);},false);StyxContext.Heading(content,"3. Test in a new chat");Explain("Start a new chat with your Styx plugin selected. Create a test below, then copy its prompt into that chat.",75);Action("Create ChatGPT test",async()=>{ApplyAcceptance(Json.Get(await owner.Call("acceptanceBegin"),"acceptance"));Feedback("The test is ready. Run the current prompt through this Styx connection in your target ChatGPT chat.");});
    desktopInputLabel=StyxContext.Text(content,"桌面验收输入框",22);desktopInput=new TextBox {Width=490,Name="styx_desktop_acceptance_input",AccessibleName="桌面验收输入框",AccessibleDescription="Current Styx desktop acceptance challenge input",MaxLength=256};desktopInput.TextChanged+=(s,e)=>readbackSubmitted=null;content.Controls.Add(desktopInput);challengePrompt=new TextBox {Width=490,Height=180,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,AccessibleName="Current ChatGPT test prompt"};content.Controls.Add(challengePrompt);
    confirmChat=StyxContext.Button(content,"I saw the successful test in ChatGPT",()=>owner.Run(async()=>{if(!TargetProofReady(acceptance)||String.IsNullOrEmpty(challengeId))throw new InvalidOperationException();await owner.Call("acceptanceConfirm",Json.Obj("challengeId",challengeId));await owner.RefreshAfterMutation();Feedback("Your target-chat confirmation has been recorded with the tool evidence. Provider account identity is not independently verified.");}));
    Explain("Advanced: ZIP plugin setup is experimental. This Windows app keeps the Tunnel setup path. A running tunnel does not verify tool execution or your ChatGPT account.",75);RenderAcceptance();
   }
   if((page=="overview"||page=="chat")&&owner.CurrentStatus!=null)Status(EvidenceStatus(owner.CurrentStatus));content.Controls.Add(statusReadout);content.Controls.Add(observationError);content.Controls.Add(feedback);
  }
  void Unavailable(string title){var button=StyxContext.Button(content,title+" — unavailable in this native slice",()=>Task.FromResult(0));button.Enabled=false;}
  void NativeAction(string title,string operation,Func<Task> action){if(owner.Supports(operation))Action(title,action);else Unavailable(title);}
  string NativeStatus(object data){var enrollment=Json.Get(data,"enrollment");string text="Exec transport: "+Json.Str(data,"foreground","execConnection")+"\nHost: "+Json.Str(data,"foreground","status");if(Json.Get(data,"gateway")!=null)text+="\nLocal gateway address: "+Json.Str(data,"gateway","origin")+"\nLocal gateway: "+(Json.Yes(data,"gateway","running")&&Json.Yes(data,"gateway","listening")?"running":"status not confirmed");if(Json.Get(data,"migration")!=null)text+="\n"+MigrationStatus(data);else if(Json.Yes(data,"admission_fenced"))text+="\nThe last setup result is unconfirmed. Refresh status to review it; your existing settings have been retained.";string status=Json.Str(enrollment,"status");if(status.Length>0)text+="\nEnrollment: "+status+"\nDevice: "+Json.Str(enrollment,"device_id");if(status=="awaiting_approval")text+="\nCompare on your Gateway: "+Json.Str(enrollment,"comparison_code")+"\nFingerprint: "+Json.Str(enrollment,"fingerprint")+"\nApproval must be performed on the Gateway. Then check confirmation here.";return text+"\nTool execution, desktop control and target ChatGPT account acceptance are not inferred from connection status.";}
  void ShowRustPage(string name){
   if(MigrationPending(owner.CurrentStatus)||name=="migration"){page="migration";ShowMigrationPage();Status(NativeStatus(owner.CurrentStatus));content.Controls.Add(statusReadout);content.Controls.Add(observationError);content.Controls.Add(feedback);return;}
   if(name=="welcome"){
    if(localCreationSubmitted||Json.Yes(owner.CurrentStatus,"admission_fenced")||Json.Get(owner.CurrentStatus,"gateway")!=null||Json.Get(owner.CurrentStatus,"configuration")!=null||Json.Get(owner.CurrentStatus,"enrollment")!=null){Explain("Your existing settings and setup progress have been retained. Open this computer to review the current status.",65);Action("Open this computer",ContinueJoiningView,false);}
    else{Explain("Set up a local gateway and connect this computer, or join a gateway you already own.",65);NativeAction("Set up this computer","createLocal",()=>{ShowPage("create");return Task.FromResult(0);});NativeAction("Join an existing Gateway","inspectJoin",()=>{ShowPage("join");return Task.FromResult(0);});}
    NativeAction("Login startup","appLifecycle",async()=>{ShowPage("login-startup");await ReadLogin();});
   }else if(name=="login-startup"){
    Explain("Start Styx in the system tray when you sign in. Windows controls whether the registered entry is allowed to run. Quitting Styx keeps the next-login registration and does not restart this session.",110);
    if(owner.LoginChangeAllowed){NativeAction("Enable login startup","appLogin",async()=>{ApplyLogin(await owner.Call("appLogin",Json.Obj("enabled",true)));});NativeAction("Disable login startup","appLogin",async()=>{ApplyLogin(await owner.Call("appLogin",Json.Obj("enabled",false)));});}
    else Explain("The last change is unconfirmed. Styx will not repeat it. Check Windows startup settings, or quit and reopen Styx to read the system state.",85);
    Action("Windows startup settings",()=>{Process.Start("ms-settings:startupapps");return Task.FromResult(0);},false);NativeAction("Check status","appLifecycle",ReadLogin);
   }else if(name=="create"){
    Capabilities();computer.Checked=false;computer.Enabled=false;persist.Checked=false;persist.Enabled=false;
    channel.Items[0]="Choose Microsoft Edge or Google Chrome";channel.Enabled=browser.Checked;browser.CheckedChanged+=(s,e)=>channel.Enabled=browser.Checked;
    Explain("Styx sets up a local gateway and connects this computer. You can also enable Browser Automation. Computer Use is unavailable in this version.",85);
    NativeAction("Prepare this computer","createLocal",async()=>{
     if(localCreationSubmitted||Json.Yes(owner.CurrentStatus,"admission_fenced")||Json.Get(owner.CurrentStatus,"gateway")!=null||Json.Get(owner.CurrentStatus,"configuration")!=null||Json.Get(owner.CurrentStatus,"enrollment")!=null)throw new IOException("app_setup_requires_review");
     if(browser.Checked&&channel.SelectedIndex==0){Feedback("Choose Microsoft Edge or Google Chrome before requesting Browser Automation.");return;}
     var choice=Choice();if(!browser.Checked)choice["browserChannel"]=null;
     // Duplicate-submit guard only; Core owns all durable setup state. One
     // request, with Core's default port 22022. Failure only reads status.
     localCreationSubmitted=true;
     // The installed Framework compiler is C# 5: keep awaits outside
     // catch/finally while preserving the original mutation failure and stack.
     Exception setupFailure=null;
     try{await owner.Call("createLocal",choice);}catch(Exception failure){setupFailure=failure;}
     try{await owner.RefreshAfterMutation();}catch{}ShowPage("overview");
     if(setupFailure!=null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(setupFailure).Throw();
    });
    Action("Return",()=>{ShowPage("welcome");return Task.FromResult(0);},false);
   }else if(name=="join"){
    Capabilities();computer.Checked=false;computer.Enabled=false;persist.Checked=false;persist.Enabled=false;
    channel.Items[0]="Choose Microsoft Edge or Google Chrome";channel.Enabled=browser.Checked;browser.CheckedChanged+=(s,e)=>channel.Enabled=browser.Checked;
    Explain("Exec and headless Browser Automation are available. Choose an installed browser for a separate, temporary Styx profile. Computer Use is unavailable; no desktop permission is granted.",85);
    joinOrigin="";joinCa="";link=Input("Private pairing link",true);
    NativeAction("Review pairing link","inspectJoin",async()=>{joinOrigin="";joinCa="";string invitation=link.Text;link.Clear();var result=await owner.Call("inspectJoin",Json.Obj("link",invitation));if(String.IsNullOrEmpty(Json.Str(result,"inspectionId")))throw new IOException();joinOrigin=Json.Str(result,"preview","origin");joinCa=Json.Str(result,"preview","caSha256");Feedback("Gateway: "+joinOrigin+"\nCertificate SHA-256: "+(joinCa.Length>0?joinCa:"System trust is not supported in this slice")+"\nExpires: "+Convert.ToString(Json.Get(result,"preview","expiresAt"))+"\nApprove only after independently checking this Gateway and certificate.");});
    NativeAction("Approve Gateway and request to join","join",async()=>{if(String.IsNullOrEmpty(joinOrigin))throw new InvalidOperationException();if(String.IsNullOrEmpty(joinCa))throw new NativeOperationException("app_system_trust_not_supported");if(browser.Checked&&channel.SelectedIndex==0){Feedback("Choose Microsoft Edge or Google Chrome before requesting Browser Automation.");return;}var choice=Choice();if(!browser.Checked)choice["browserChannel"]=null;choice["approvedGatewayOrigin"]=joinOrigin;choice["approvedCaSha256"]=joinCa;joinOrigin="";joinCa="";var result=await owner.Call("join",choice);if(Json.Str(result,"status")!="awaiting_approval")throw new IOException();await owner.RefreshAfterMutation();ShowPage("overview");Feedback("Request submitted. Compare the original code on your Gateway and explicitly approve this device there.");});
    Action("Return",()=>{ShowPage("welcome");return Task.FromResult(0);},false);
   }else if(name=="overview"||name=="join-waiting"){
    Explain("Styx keeps your local connection and gateway running while the App is open. If you joined another computer, its gateway is still used.",85);RefreshAction();string enrollment=Json.Str(owner.CurrentStatus,"enrollment","status");
    if(enrollment=="awaiting_approval")NativeAction("Check confirmation","claimJoin",async()=>{var result=await owner.Call("claimJoin");string actual=Json.Str(result,"status");if(actual!="awaiting_approval"&&actual!="ready_to_connect")throw new IOException();await owner.RefreshAfterMutation();ShowPage("overview");Feedback(actual=="awaiting_approval"?"The Gateway has not approved this request. No connection was started.":"The Gateway confirmed this identity. Choose Reconnect to start the Host.");});
    NativeAction("Reconnect","connect",async()=>{await owner.Call("connect");await owner.RefreshAfterMutation();Feedback(StyxContext.ReconnectResult(owner.CurrentStatus));});NativeAction("Pause","disconnect",async()=>{await owner.Call("disconnect");await owner.RefreshAfterMutation();});
    Unavailable("Add or revoke computers");Unavailable("Edit capabilities");
    Explain("Runtime updates preserve your identity, pairing and settings. Both App roles are stopped first and stay stopped until you reconnect. The two configuration updates are separate transactions.",95);
    NativeAction("Stage runtime candidate","stageRuntime",async()=>{await owner.Call("stageRuntime",new Dictionary<string,object>{{"authorize",true}});await owner.RefreshAfterMutation();ShowPage("overview");});
    NativeAction("Check runtime update","runtimeUpdateStatus",async()=>{await owner.Call("runtimeUpdateStatus");await owner.RefreshAfterMutation();ShowPage("overview");});
    string updateState=Json.Str(owner.CurrentStatus,"runtimeUpdate","status"),updateTransaction=Json.Str(owner.CurrentStatus,"runtimeUpdate","transaction_id");
    if(updateState=="staged")NativeAction("Update runtime…","updateRuntime",async()=>{if(MessageBox.Show(this,"Update this App’s runtime components? Your identity, pairing and settings will be kept. Connections will pause; reconnect when the update completes. If it does not complete, use Recover update.","Update runtime",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;await owner.Call("updateRuntime",new Dictionary<string,object>{{"authorize",true},{"transactionId","app-runtime-"+Guid.NewGuid().ToString("N")}});await owner.RefreshAfterMutation();ShowPage("overview");});
    if(Json.Yes(owner.CurrentStatus,"runtimeUpdate","can_recover")&&ValidTransaction(updateTransaction))NativeAction("Recover original runtime update","recoverRuntimeUpdate",async()=>{await owner.Call("recoverRuntimeUpdate",new Dictionary<string,object>{{"authorize",true},{"transactionId",updateTransaction}});await owner.RefreshAfterMutation();ShowPage("overview");});
    if(!String.IsNullOrEmpty(updateState))Explain("Runtime update: "+updateState,40);
   }else if(name=="chat"){Explain("Use your Gateway's existing MCP connection in ChatGPT. This App does not yet configure a Tunnel or issue target-chat acceptance proofs.",100);Unavailable("Configure Secure MCP Tunnel");Unavailable("Create ChatGPT test");Action("Open ChatGPT",()=>{Process.Start("https://chatgpt.com/");return Task.FromResult(0);},false);RefreshAction();}
   else{Explain("This operation is not implemented by the native Host App. Existing identities and configuration are retained.",80);Unavailable("Legacy operation");Action("Open this computer",ContinueJoiningView,false);}
   Status(NativeStatus(owner.CurrentStatus));content.Controls.Add(statusReadout);content.Controls.Add(observationError);content.Controls.Add(feedback);
  }

  static bool MigrationPending(object data){return Json.Get(data,"migration")!=null&&Json.Str(data,"migration","status")!="committed";}
  static string MigrationRenderKey(object data){return Json.Str(data,"migration","status")+"|"+Json.Str(data,"migration","transaction_id")+"|"+Json.Yes(data,"migration","can_recover");}
  static bool ValidTransaction(string value){return !String.IsNullOrEmpty(value)&&value.Length<=128&&System.Text.RegularExpressions.Regex.IsMatch(value,"^[A-Za-z0-9._-]+$");}
  static bool ValidPlanSha(string value){return System.Text.RegularExpressions.Regex.IsMatch(value??"","^[a-f0-9]{64}$");}
  static string MigrationStatus(object data){
   string status=Json.Str(data,"migration","status");string text="Migration: "+status;
   if(status=="waiting_for_later_boot")return text+"\nStartup exclusion was recorded. A later Windows restart is required. Migration is incomplete; Styx does not restart Windows. After restarting, reopen this native App manually and recover this original transaction.";
   if(status=="running")return text+"\nThe original migration worker is still owned. Refresh status; do not submit another attempt.";
   if(status=="unknown")return text+"\nThe result is unconfirmed. Original records are retained; no action is automatically replayed.";
   if(status=="blocked")return text+"\nMigration is blocked. Keep the original configuration and transaction for review; do not create a replacement identity.";
   if(status=="committed")return text+"\nMigration committed. The Host remains stopped until you explicitly choose Reconnect.";
   return text+"\nThe original identity and configuration are retained. Review what will happen before preparing the migration.";
  }
  void ShowMigrationPage(){
   migrationRenderKey=MigrationRenderKey(owner.CurrentStatus);string status=Json.Str(owner.CurrentStatus,"migration","status"),original=Json.Str(owner.CurrentStatus,"migration","transaction_id");
   StyxContext.Heading(content,"Migrate this computer");Explain("Original configuration: "+owner.ConfigurationDirectory,65);Explain(MigrationStatus(owner.CurrentStatus),155);RefreshAction();
   if(status=="committed"){Action("Open this computer",ContinueJoiningView,false);return;}
   if(status=="required"&&original.Length==0&&!migrationSubmitted){
    Explain("Review the migration while keeping this computer's identity, pairing and settings. Styx checks the package publisher and original configuration before asking you to continue.",105);
    NativeAction("Review migration","reviewMigration",async()=>{
     if(migrationSubmitted)throw new NativeOperationException("app_migration_in_progress");
     if(migrationTransaction.Length==0)migrationTransaction=Guid.NewGuid().ToString("D");
     migrationPlanSha="";migrationCanonical="";
     var result=await owner.Call("reviewMigration",Json.Obj("transactionId",migrationTransaction,"run","stopped"));
     string tx=Json.Str(result,"transaction_id"),sha=Json.Str(result,"plan_sha256"),plan=Json.Str(result,"canonical_plan");
     if(Convert.ToInt32(Json.Get(result,"schema"))!=1||tx!=migrationTransaction||!ValidTransaction(tx)||!ValidPlanSha(sha)||plan.Length==0||plan.Length>65536)throw new NativeOperationException("app_migration_review_mismatch");
     byte[] bytes=new System.Text.UTF8Encoding(false,true).GetBytes(plan);using(var memory=new MemoryStream(bytes)){if(NativeBootstrap.Hash(memory)!=sha)throw new NativeOperationException("app_migration_review_mismatch");}
     var canonical=Json.Codec.DeserializeObject(plan);if(Json.Str(canonical,"action")!="migrate_windows_preserved_host_pair_after_restart"||Json.Str(canonical,"transaction_id")!=tx||Json.Str(canonical,"desired","host","run")!="stopped"||!ValidPlanSha(Json.Str(canonical,"candidate_manifest_sha256"))||!ValidPlanSha(Json.Str(canonical,"publisher_spki_sha256")))throw new NativeOperationException("app_migration_review_mismatch");
     migrationPlanSha=sha;migrationCanonical=plan;ShowPage("migration");Feedback("Review ready. Your identity, pairing and settings will be kept. Read what happens next, then choose whether to prepare the migration.");
    });
    if(ValidPlanSha(migrationPlanSha)&&migrationCanonical.Length>0){
     Explain("Keep this computer's identity, Gateway pairing and settings. After migration it stays paused until you choose Reconnect. Preparing requires a later Windows restart; Styx will not restart Windows automatically.",105);
     var plan=Json.Codec.DeserializeObject(migrationCanonical);var technicalToggle=new CheckBox {Text="Technical details",Width=490,Height=32,Checked=false};content.Controls.Add(technicalToggle);
     var technical=new FlowLayoutPanel {Width=490,Height=345,FlowDirection=FlowDirection.TopDown,WrapContents=false,Visible=false};
     var canonical=new TextBox {Width=480,Height=330,Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,WordWrap=false,Text="Candidate manifest SHA-256: "+Json.Str(plan,"candidate_manifest_sha256")+"\r\nPublisher SPKI SHA-256: "+Json.Str(plan,"publisher_spki_sha256")+"\r\nReviewed transaction: "+migrationTransaction+"\r\nPlan SHA-256: "+migrationPlanSha+"\r\n\r\nCanonical plan:\r\n"+migrationCanonical};canonical.AccessibleName="Exact reviewed migration plan";technical.Controls.Add(canonical);content.Controls.Add(technical);technicalToggle.CheckedChanged+=(s,e)=>technical.Visible=technicalToggle.Checked;
     var consent=new CheckBox {Text="Keep my identity and settings, and prepare this migration",Width=490,Height=50,Checked=false};content.Controls.Add(consent);
     if(owner.Supports("startMigration")){
      var approve=StyxContext.Button(content,"Prepare migration",()=>owner.Run(async()=>{
       if(!consent.Checked||migrationSubmitted||!ValidPlanSha(migrationPlanSha))throw new NativeOperationException("app_migration_authorization_required");
       string tx=migrationTransaction,sha=migrationPlanSha;migrationSubmitted=true;consent.Checked=false;
       await owner.Call("startMigration",Json.Obj("transactionId",tx,"authorize",true,"run","stopped","planSha256",sha));
       await owner.RefreshAfterMutation();ShowPage("migration");Feedback("Migration was submitted once. Refresh its original transaction; no restart or repeated mutation is automatic.");
      },"Submitting the reviewed migration…"));approve.Enabled=false;consent.CheckedChanged+=(s,e)=>approve.Enabled=consent.Checked&&!migrationSubmitted;
     }else Unavailable("Prepare migration");
    }
   }else if(ValidTransaction(original)&&Json.Yes(owner.CurrentStatus,"migration","can_recover")&&!migrationSubmitted&&status!="waiting_for_later_boot"&&status!="running"){
    Explain("Recover inspects only the original recorded transaction. It does not create a new identity, new transaction or new approval, and cannot turn an unknown operation into a successful result.",85);
    NativeAction("Recover original migration","recoverMigration",async()=>{
     string tx=Json.Str(owner.CurrentStatus,"migration","transaction_id");if(!ValidTransaction(tx)||tx!=original||!Json.Yes(owner.CurrentStatus,"migration","can_recover"))throw new NativeOperationException("app_migration_original_transaction_required");
     migrationSubmitted=true;await owner.Call("recoverMigration",Json.Obj("transactionId",tx,"authorize",true,"run","stopped"));await owner.RefreshAfterMutation();ShowPage("migration");Feedback("Recovery was submitted once for the original transaction. Refresh to observe its result; no operation is retried automatically.");
    });
   }else if(migrationSubmitted&&status=="required")Explain("An attempt was already submitted in this App. Its result must be inspected; this window will not submit it again.",70);
  }

  bool ShowJoinProgress(object snapshot){
   var steps=Json.Get(snapshot,"status","deployment","steps") as object[];
   if(Json.Str(snapshot,"status","deployment","mode")!="join-existing"||steps==null)return false;
   var byId=new Dictionary<string,object>();foreach(var step in steps)byId[Json.Str(step,"id")]=step;
   object incomplete=null,requested=null;byId.TryGetValue("host.request",out requested);
   foreach(string id in new[]{"host.prepare","host.request","host.claim","host.doctor"}){object step;if(!byId.TryGetValue(id,out step)){ShowPage("join-waiting");Status("This joining request needs review. Your identity and progress have been retained.");RefreshAction();return true;}if(Json.Str(step,"status")!="succeeded"){incomplete=step;break;}}
   if(incomplete==null)return false;
   ClearPreparationFeedback();ShowPage("join-waiting");string state=Json.Str(incomplete,"status"),stepId=Json.Str(incomplete,"id"),code=Json.Str(requested,"comparison_code");bool retry=false;
   if(stepId=="host.claim"&&state=="awaiting_approval"){
    Status(String.IsNullOrEmpty(code)?"This request was created by an earlier version. Use advanced device review on your main computer to confirm this full fingerprint before continuing:\n\n"+Json.Str(requested,"fingerprint")+"":"Your confirmation code: "+code+"\n\nConfirm the same code on your main computer, then check here.");retry=true;
   }else if(state=="pending"){
    Status("Preparation is not finished. Continue to prepare this computer and submit its joining request.");retry=true;
   }else if(stepId=="host.claim"&&state=="blocked"){
    Status("The confirmation result could not be checked. Check the connection to your main computer, then try again. This does not mean approval is still pending.");retry=true;
   }else if(stepId=="host.doctor"&&state=="blocked"){
    Status("Your main computer has confirmed this device. A local component check needs attention. Review this computer before checking again.");retry=Json.Yes(incomplete,"retryable");
   }else if(stepId=="host.request"&&state=="uncertain"){
    Status("Connection not completed. Check your main computer’s address or use a new invitation.");
   }else if(state=="running")Status("Preparation is in progress, or its result has not been recorded. Refresh status to check. The operation will not be repeated automatically.");
   else Status("Preparation needs attention. Refresh status to review the result. Your identity and progress have been retained; failed or interrupted installation and enrollment steps will not be repeated automatically.");
   if(retry)PreparationAction(stepId=="host.doctor"?"Check this computer again":state=="pending"?"Continue preparation":"Check confirmation");
   if(CanRecoverJoin(snapshot))Action("Use a new invitation",()=>{Feedback("");ShowPage("join-recover");return Task.FromResult(0);},false);
   RefreshAction();return true;
  }
  void ShowInvitation(object result){
   ShowPage("add-computer");
   if(Json.Str(result,"status")=="select_network_interface"){
    Explain("Choose the address the other computer can reach.",40);var choice=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList,Width=350};var addresses=Json.Get(result,"candidates") as object[];if(addresses!=null)foreach(var address in addresses)if(address is string)choice.Items.Add(address);if(choice.Items.Count>0)choice.SelectedIndex=0;content.Controls.Add(choice);
    Action("Create invitation",async()=>{if(choice.SelectedItem==null)throw new InvalidOperationException();ShowInvitation(await owner.Call("inviteComputer",Json.Obj("listenHost",choice.SelectedItem.ToString())));});return;
   }
   if(Json.Str(result,"status")!="waiting_for_computer"){
    Feedback("The network connection for another computer needs attention. Your existing ChatGPT connection is retained.");
    string setup=Json.Str(result,"ingress","setup","status");if(setup=="needs_reconciliation"||setup=="preparing"||setup=="running"){
     Action("Retry network preparation",async()=>{await owner.Call("recoverIngress",Json.Obj("action","retry"));ShowInvitation(await owner.Call("inviteComputer"));});
     Action("Undo network preparation",async()=>{await owner.Call("recoverIngress",Json.Obj("action","rollback"));ShowPage("overview");Feedback("Network preparation was undone. Existing identities and device approvals were retained.");});
    }return;
   }
   string invitation=Json.Str(result,"invitation","link");var box=Input("Invitation",true);box.Text=invitation;box.ReadOnly=true;
   Action("Copy invitation",()=>{Clipboard.SetText(invitation);Feedback("Invitation copied. Open it on the joining computer before it expires.");return Task.FromResult(0);});
   Action("Check joining requests",async()=>{ShowPendingComputers(await owner.Call("pendingComputers"));});
   Action("Done inviting",()=>{ShowPage("overview");return Task.FromResult(0);},false);
  }

  void ShowPendingComputers(object result){ShowPage("pending-computers");var rows=Json.Get(result,"pending") as object[];if(rows==null||rows.Length==0){Feedback("Waiting for another computer to request to join.");Action("Check again",async()=>{ShowPendingComputers(await owner.Call("pendingComputers"));});return;}foreach(var row in rows){string id=Json.Str(row,"request_id"),code=Json.Str(row,"comparison_code"),name=Json.Str(row,"label");Explain(name+"\n"+code,65);Action("Confirm "+name,async()=>{if(String.IsNullOrEmpty(code)||MessageBox.Show("Does the joining computer show "+code+"?","Confirm computer",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;await owner.Call("approveComputer",Json.Obj("requestId",id,"comparisonCode",code));Feedback("Confirmed. Waiting for this computer to connect. Continue in Styx on that computer.");});}}
  void ShowDevices(object value){ShowPage("overview");var rows=Json.Get(value,"devices","devices") as object[]??Json.Get(value,"devices") as object[];if(rows==null){Feedback("Computer list is unavailable for this Gateway. Refresh to review current state.");return;}foreach(var row in rows){string id=Json.Str(row,"device_id");if(String.IsNullOrEmpty(id))continue;string title=Json.Str(row,"label")+(Json.Yes(row,"is_default")?" (default)":"");Explain(title,28);Action("Use "+title+" by default",async()=>{await owner.Call("setDefault",Json.Obj("deviceId",id));await owner.RefreshAfterMutation();});Action("Remove "+title,async()=>{if(MessageBox.Show("Revoke this computer's Gateway access?", "Styx",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;await owner.Call("revokeDevice",Json.Obj("deviceId",id));await owner.RefreshAfterMutation();});}}
  void SetText(Label target,string text,int minimum){target.Text=text;target.Height=String.IsNullOrEmpty(text)?0:Math.Max(minimum,TextRenderer.MeasureText(text,Font,new Size(490,0),TextFormatFlags.WordBreak).Height+20);}
  internal void Feedback(string text){SetText(feedback,text,60);}
  internal bool HasFeedback(string text){return feedback.Text==text;}
  void Status(string text){SetText(statusReadout,text,65);}
  internal void ObservationFailed(string text){SetText(observationError,text,45);}
  internal static bool TargetProofReady(object value){return Json.Str(value,"requestProof","status")=="verified"&&(Json.Str(value,"desktop","status")=="verified"||Json.Str(value,"desktop","status")=="not_required")&&(Json.Str(value,"browser","status")=="verified"||Json.Str(value,"browser","status")=="not_required");}
  static string Proof(string state){return state=="verified"?"verified through MCP":state=="not_required"?"not requested":"not yet verified";}
  internal static bool CanUpdateRuntime(object data){return Json.Yes(data,"session","hostPayloadHandoffSupported")&&Json.Str(data,"status","components","host","status")=="update_available";}
  internal static string ComponentNotice(object data){string state=Json.Str(data,"status","components","host","status");
   if(state=="publisher_changed")return "Runtime components have not been updated. A publisher trust migration is required; existing settings and connections are retained.\n\n";
   if(state=="update_available")return "A component update is available. Update and reopen Styx to use the version included with this app.\n\n";
   if(state=="same_version_conflict"||state=="candidate_unverified"||state=="unavailable"||state=="needs_recovery")return "Runtime update status needs review. Check installation or recovery; do not reset pairing.\n\n";
   return "";
  }
  internal static string EvidenceStatus(object data){var value=Json.Get(data,"acceptance")??Json.Get(data,"journey","acceptance");string account=Json.Str(value,"targetChatConfirmation","status")=="user_confirmed"?"user confirmed; provider identity not verified":TargetProofReady(value)?"awaiting your confirmation in the target chat":"waiting for the current tool test";return ComponentNotice(data)+"Exec transport: "+Json.Str(data,"journey","readiness","exec","status")+"\nExec tool test: "+Proof(Json.Str(value,"requestProof","status"))+"\nComputer Use test: "+Proof(Json.Str(value,"desktop","status"))+"\nBrowser test: "+Proof(Json.Str(value,"browser","status"))+"\nChatGPT account: "+account+"\nTunnel transport: "+Json.Str(data,"journey","tunnel","transport");}
  void ApplyAcceptance(object value){string latest=Json.Str(value,"challenge","id");if(challengeId!=latest){challengeId=latest;readbackSubmitted=null;if(desktopInput!=null)desktopInput.Clear();}acceptance=value;RenderAcceptance();if(page=="chat")Status(EvidenceStatus(Json.Obj("acceptance",value,"journey",Json.Get(owner.CurrentStatus,"journey"),"status",Json.Get(owner.CurrentStatus,"status"))));}
  bool CurrentChallenge(){object expiry=Json.Get(acceptance,"challenge","expiresAt");return !String.IsNullOrEmpty(challengeId)&&expiry!=null&&Convert.ToDouble(expiry)>DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();}
  void RenderAcceptance(){if(page!="chat")return;if(challengePrompt!=null){challengePrompt.Text=Json.Str(acceptance,"challenge","prompt");challengePrompt.Visible=!String.IsNullOrEmpty(challengePrompt.Text);}if(confirmChat!=null)confirmChat.Enabled=TargetProofReady(acceptance)&&CurrentChallenge();if(desktopInput!=null){bool requested=!String.IsNullOrEmpty(Json.Str(acceptance,"challenge","desktopValue"));desktopInput.Enabled=requested&&CurrentChallenge();desktopInput.Visible=requested;if(desktopInputLabel!=null)desktopInputLabel.Visible=requested;}}
  async Task ObserveDesktopReadback(){
   if(readbackInFlight||owner.MutationBusy||page!="chat"||!Visible||desktopInput==null||!desktopInput.Visible||!desktopInput.Enabled||desktopInput.FindForm()!=this||!desktopInput.IsHandleCreated||!IsHandleCreated||!Json.Yes(owner.CurrentStatus,"session","desktopAcceptanceSupported"))return;
   if(!content.RectangleToScreen(content.ClientRectangle).IntersectsWith(desktopInput.RectangleToScreen(desktopInput.ClientRectangle)))return;
   string id=challengeId,expected=Json.Str(acceptance,"challenge","desktopValue"),actual=desktopInput.Text;object expiry=Json.Get(acceptance,"challenge","expiresAt");long window=Handle.ToInt64();
   if(String.IsNullOrEmpty(id)||String.IsNullOrEmpty(expected)||actual!=expected||expiry==null||Convert.ToDouble(expiry)<=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()||window<1||Json.Str(acceptance,"desktop","status")=="verified"||readbackSubmitted==id+":"+window)return;
   readbackInFlight=true;try{var result=await owner.Call("acceptanceDesktopReadback",Json.Obj("challengeId",id,"value",actual,"pid",Process.GetCurrentProcess().Id,"windowId",window));if(challengeId==id&&desktopInput!=null&&desktopInput.Text==actual){readbackSubmitted=id+":"+window;ApplyAcceptance(Json.Get(result,"acceptance"));}}
   catch(NativeOperationException error){readbackSubmitted=id+":"+window;Feedback(error.Code=="desktop_acceptance_native_app_changed"?"The native Styx app changed. Create a new desktop test before continuing.":"The desktop readback could not be confirmed. Refresh status and create a new test before retrying.");}catch{readbackSubmitted=id+":"+window;Feedback("The desktop readback could not be confirmed. Refresh status and create a new test before retrying.");}finally{readbackInFlight=false;}
  }
  internal void ShowStatus(object data){
   if(owner.RustHost){SetText(observationError,"",0);if(MigrationPending(data)||page=="migration"){string key=MigrationRenderKey(data);if(!renderedRustMode||page!="migration"||migrationRenderKey!=key){ShowPage("migration");return;}Status(NativeStatus(data));return;}if(!renderedRustMode){ShowPage(page=="welcome"&&(Json.Get(data,"configuration")!=null||Json.Get(data,"enrollment")!=null)?"overview":page);return;}if(page=="welcome"&&(Json.Get(data,"configuration")!=null||Json.Get(data,"enrollment")!=null)){ShowPage("overview");return;}if(page=="overview"||page=="join-waiting"){ShowPage("overview");return;}Status(NativeStatus(data));return;}
   if(page=="join-interrupted"&&!Json.Yes(data,"status","joinRecovery","rollbackRequired"))ShowPage("overview");
   if(page=="component-start"&&!owner.ManagementOnly)ShowPage(requestedPage);
   if(updateRuntime!=null)updateRuntime.Visible=CanUpdateRuntime(data);
   SetText(observationError,"",0);var latest=Json.Get(data,"acceptance");
   // A fresh observation may follow another Cua attempt that set the same text.
   // Permit a new local readback for pending proof; never replay desktop input.
   if(challengeId==Json.Str(latest,"challenge","id")&&Json.Str(latest,"desktop","status")=="pending")readbackSubmitted=null;ApplyAcceptance(latest);
   if(page=="welcome"&&Json.Get(data,"status","deployment")!=null)ShowPage("overview");
   if(page=="welcome"&&Json.Get(data,"status","deployment")==null)Status(!Json.Yes(data,"session","artifactsAvailable")?"This preview needs a verified signed Host bundle before preparing a computer.":!Json.Yes(data,"session","localGatewayAvailable")?"A trusted TLS helper is missing. Creating a new Gateway is unavailable; joining an existing Gateway is supported when Host artifacts are present.":"Choose setup or join to continue.");
   if((page=="overview"||page=="join-waiting")&&ShowJoinProgress(data))return;if(page=="join-waiting")ShowPage("overview");if(page=="overview"||page=="chat")Status(EvidenceStatus(data));
  }
  protected override void Dispose(bool disposing){if(disposing)desktopTimer.Dispose();base.Dispose(disposing);}
  internal void Verify(){if(!InvitationPage("add-computer")||!InvitationPage("pending-computers")||InvitationPage("overview"))throw new Exception("invitation_scope_failed");foreach(string name in new[]{"welcome","create","join","overview","capabilities","chat","join-waiting","add-computer","pending-computers"}){ShowPage(name);if(content.Controls.Count<3)throw new Exception("native_page_failed");}
   // Render the public HTTP shape through the actual JSON deserializer. These
   // checks cover known waiting/failed UI regressions, not desktop acceptance.
   var steps=new object[]{Json.Obj("id","host.prepare","status","succeeded"),Json.Obj("id","host.request","status","succeeded","comparison_code","ABCD-0123-EF45-6789"),Json.Obj("id","host.claim","status","awaiting_approval"),Json.Obj("id","host.doctor","status","pending")};
   var response=Json.Obj("status",Json.Obj("deployment",Json.Obj("mode","join-existing","steps",steps)));
   if(!ShowJoinProgress(Json.Codec.DeserializeObject(Json.Codec.Serialize(response)))||!statusReadout.Text.Contains("ABCD-0123-EF45-6789"))throw new Exception("join_comparison_not_visible");
   steps[0]=Json.Obj("id","host.prepare","status","uncertain");ShowJoinProgress(Json.Codec.DeserializeObject(Json.Codec.Serialize(response)));
   int actions=0;foreach(Control control in content.Controls)if(control is Button)actions++;
   if(actions!=1||statusReadout.Text.Contains("confirmation code"))throw new Exception("failed_preparation_misreported_as_waiting");
   steps[0]=Json.Obj("id","host.prepare","status","succeeded");steps[1]=Json.Obj("id","host.request","status","uncertain");
   Feedback("Preparing signed components…");owner.ApplyPreparationResult(Json.Codec.DeserializeObject(Json.Codec.Serialize(response)));
   if(!PendingJoin(owner.CurrentStatus)||HasFeedback("Preparing signed components…")||!statusReadout.Text.Contains("Connection not completed"))throw new Exception("join_result_not_adopted_or_progress_stale");
   ShowPage("welcome");bool continued=false;foreach(Control control in content.Controls)if(control is Button){if(control.Text=="Set up this computer"||control.Text=="Join an existing Gateway")throw new Exception("existing_join_offered_recreation");if(control.Text=="Continue joining"){continued=true;break;}}
   ContinueJoiningView();if(!continued||page!="join-waiting"||HasFeedback("Preparing signed components…"))throw new Exception("existing_join_cannot_resume_view");
   ((Dictionary<string,object>)response["status"])["joinRecovery"]=Json.Obj("canRecover",true);
   response["session"]=Json.Obj("joinRecoverySupported",true);owner.ApplyPreparationResult(Json.Codec.DeserializeObject(Json.Codec.Serialize(response)));
   bool recoveryVisible=false;foreach(Control control in content.Controls)if(control is Button&&control.Text=="Use a new invitation")recoveryVisible=true;
   if(!recoveryVisible)throw new Exception("join_recovery_not_visible");ShowPage("join-recover");
   foreach(Control control in content.Controls)if(control is CheckBox||control is ComboBox)throw new Exception("join_recovery_reselects_capabilities");
   ContinueJoiningView();if(page!="join-waiting")throw new Exception("join_review_cancel_lost_progress");
   owner.ApplyPreparationResult(Json.Obj("session",Json.Obj("joinRecoverySupported",true),"status",Json.Obj("joinRecovery",Json.Obj("rollbackRequired",true,"transactionId",new string('a',32)))));
   ShowPage("welcome");bool restoreVisible=false;foreach(Control control in content.Controls)if(control is Button){if(control.Text=="Set up this computer")throw new Exception("interrupted_join_offered_create");if(control.Text=="Restore previous invitation")restoreVisible=true;}
   if(page!="join-interrupted"||!restoreVisible)throw new Exception("interrupted_join_has_no_recovery");
   owner.ApplyPreparationResult(Json.Obj("status",Json.Obj()));
   // Exercise actual controls and response application without a desktop session.
   ShowPage("chat");tunnel.Text="tunnel_draft_fixture";key.Text="draft-runtime-key";Feedback("Keep this operation failure");ShowStatus(Json.Obj("status",Json.Obj()));
   if(!Enabled||owner.MutationBusy||key.Text!="draft-runtime-key"||tunnel.Text!="tunnel_draft_fixture"||feedback.Text!="Keep this operation failure")throw new Exception("refresh_discarded_tunnel_draft_or_error");
   ShowPage("overview");ShowPage("chat");if(key.Text!="draft-runtime-key"||tunnel.Text!="tunnel_draft_fixture")throw new Exception("navigation_discarded_tunnel_draft");
   ShowPage("capabilities");var untouched=CapabilityChoice();if(untouched.ContainsKey("browserChannel")||untouched.ContainsKey("persistLogin"))throw new Exception("unknown_browser_preference_overwritten");computer.Checked=false;browser.Checked=true;channel.SelectedIndex=3;persist.CheckState=CheckState.Unchecked;ShowStatus(Json.Obj("status",Json.Obj("deployment",Json.Obj("roles",Json.Obj("computer","requested","browser","disabled")))));ShowPage("overview");ShowPage("capabilities");var edited=CapabilityChoice();if(computer.Checked||!browser.Checked||channel.SelectedIndex!=3||persist.Checked||(string)edited["browserChannel"]!="chrome")throw new Exception("refresh_discarded_capability_draft");
   ShowPage("join");label.Text="Joining draft";computer.Checked=false;browser.Checked=true;channel.SelectedIndex=1;persist.Checked=false;ShowPage("overview");ShowPage("join");var joining=Choice();if((string)joining["label"]!="Joining draft"||(bool)joining["computer"]||!(bool)joining["browser"]||(string)joining["browserChannel"]!="msedge"||(bool)joining["persistLogin"])throw new Exception("joining_capability_choice_discarded");
   var proof=Json.Obj("requestProof",Json.Obj("status","verified"),"desktop",Json.Obj("status","verified"),"browser",Json.Obj("status","not_required"),"targetChatConfirmation",Json.Obj("status","pending"),"complete",false,"challenge",Json.Obj("id",new string('a',32),"expiresAt",DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()+60000,"desktopValue","STYX_GUI_"+new string('a',32),"prompt","Current native desktop challenge"));
   if(!TargetProofReady(proof)||!EvidenceStatus(Json.Obj("acceptance",proof)).Contains("awaiting your confirmation"))throw new Exception("tool_proof_conflated_with_account_confirmation");ShowPage("chat");ApplyAcceptance(proof);if(!confirmChat.Enabled||desktopInput.AccessibleName!="桌面验收输入框"||desktopInput.Text.Length!=0)throw new Exception("native_challenge_control_failed");desktopInput.Text=Json.Str(proof,"challenge","desktopValue");ApplyAcceptance(proof);if(desktopInput.Text.Length==0)throw new Exception("same_challenge_discarded_input");((Dictionary<string,object>)proof["challenge"])["id"]=new string('b',32);ApplyAcceptance(proof);if(desktopInput.Text.Length!=0)throw new Exception("changed_challenge_retained_old_input");((Dictionary<string,object>)proof["desktop"])["status"]="pending";ApplyAcceptance(proof);if(confirmChat.Enabled)throw new Exception("unverified_desktop_allowed_account_confirmation");
   desktopInput.Text=Json.Str(proof,"challenge","desktopValue");readbackSubmitted="same-value-attempt";ShowStatus(Json.Obj("acceptance",proof));if(readbackSubmitted!=null||desktopInput.Text!=Json.Str(proof,"challenge","desktopValue"))throw new Exception("pending_same_value_readback_cannot_retry");((Dictionary<string,object>)proof["desktop"])["status"]="verified";readbackSubmitted="verified-attempt";ShowStatus(Json.Obj("acceptance",proof));if(readbackSubmitted!="verified-attempt")throw new Exception("verified_readback_repeated");
   if(!StyxContext.ReconnectResult(Json.Obj("status",Json.Obj("foreground",Json.Obj("status","connected","execConnection","connected")))).StartsWith("Reconnected.")||!StyxContext.ReconnectResult(Json.Obj("status",Json.Obj("foreground",Json.Obj("status","started")))).Contains("still starting")||StyxContext.ReconnectResult(Json.Obj()).StartsWith("Reconnected."))throw new Exception("reconnect_feedback_overclaimed");
   keyDraft="";tunnelDraft="";Feedback("");ShowPage("welcome");Show();CreateControl();PerformLayout();Application.DoEvents();using(var image=new Bitmap(Width,Height)){DrawToBitmap(image,new Rectangle(0,0,Width,Height));image.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"native-settings.png"));}}
 }
 static class InstallCoordination {
  // Inno owns versioned program files; Core state remains outside the install tree.
  static Mutex appMutex;
  internal static string Scope(string resources){
   string root=Path.GetFullPath(resources).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar);
   var parent=Directory.GetParent(root);string name=Path.GetFileName(root);
   if(parent!=null&&((parent.Name=="versions"&&System.Text.RegularExpressions.Regex.IsMatch(name,"^[a-f0-9]{64}$"))||(parent.Name=="releases"&&System.Text.RegularExpressions.Regex.IsMatch(name,"^[a-f0-9-]{36}$"))))root=parent.Parent.FullName;
   using(var sha=System.Security.Cryptography.SHA256.Create())return BitConverter.ToString(sha.ComputeHash(System.Text.Encoding.Unicode.GetBytes(root.ToLowerInvariant()))).Replace("-","").ToLowerInvariant();
  }
  internal static bool Enter(string resources){
   string scope=Scope(resources);appMutex=new Mutex(false,"Global\\Styx.App."+scope);
   Mutex setup;if(Mutex.TryOpenExisting("Global\\Styx.Install."+scope,out setup)){setup.Dispose();return false;}return true;
  }
  internal static void KeepAlive(){GC.KeepAlive(appMutex);}
 }
 static class Program {
  [STAThread]static int Main(string[] args){
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);string root=AppDomain.CurrentDomain.BaseDirectory;
   string state=Environment.GetEnvironmentVariable("STYX_NATIVE_STATE")??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"StyxPreview","WindowsFirst");bool test=false,startupTest=false,stateSet=false,fromLogin=false;
   try{
    for(int index=0;index<args.Length;index++){
     if(args[index]=="--self-test"&&!test&&!startupTest)test=true;
     else if(args[index]=="--self-test-startup"&&!test&&!startupTest)startupTest=true;
     else if(args[index]=="--startup"&&!fromLogin)fromLogin=true;
     else if(args[index]=="--state-dir"&&!stateSet&&index+1<args.Length){state=args[++index];stateSet=true;}
     else throw new ArgumentException();
    }
    if(!Path.IsPathRooted(state))throw new ArgumentException();state=Path.GetFullPath(state);
    if(!InstallCoordination.Enter(root)){if(!test&&!startupTest)MessageBox.Show("Styx is being installed or updated. Open it again when Setup has finished.","Styx",MessageBoxButtons.OK,MessageBoxIcon.Information);return 3;}
    var app=new StyxContext(root,state,test,startupTest,fromLogin);
    if(test){app.Verify();app.Quit();File.WriteAllText(Path.Combine(root,"native-self-test.json"),"{\"status\":\"PASS\",\"pages\":9,\"uiConstruction\":true,\"joinStateRendering\":true,\"editingAndEvidenceState\":true,\"desktopAcceptance\":\"NOT RUN\",\"serviceMutation\":\"NOT RUN\"}");return 0;}
    Application.Run(app);InstallCoordination.KeepAlive();return startupTest?app.ResultCode:0;
   }catch{if(!test&&!startupTest)MessageBox.Show("Styx could not open. Check that the app resources and runtime are present.","Styx",MessageBoxButtons.OK,MessageBoxIcon.Information);return 2;}
  }
 }
}
