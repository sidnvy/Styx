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
 sealed class NativeOperationException:IOException { internal readonly string Code;internal readonly object Budget,Retirement;internal readonly bool Preflight,JoinNotSent;internal NativeOperationException(string code,object budget=null,bool preflight=false,object retirement=null,bool joinNotSent=false){Code=code;Budget=budget;Preflight=preflight;Retirement=retirement;JoinNotSent=joinNotSent;} }
 // The installed outer package pins the bootstrap executable. Its hash is an
 // integrity boundary, not a substitute for Windows publisher authentication.
 sealed class NativeBootstrap:IDisposable {
  internal const string PublisherPin="bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed";
  internal readonly string Root,Cli,Payload,Publisher,CliSha,ManifestSha;internal string Selection;
  readonly FileStream cliPin;
  internal static string Hash(Stream stream){using(var sha=System.Security.Cryptography.SHA256.Create()){stream.Position=0;string v=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();stream.Position=0;return v;}}
  internal static string ReadSmall(string path,int bound){NoRedirect(path);using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){if(f.Length>bound)throw new IOException("app_bootstrap_material_too_large");using(var r=new StreamReader(f))return r.ReadToEnd();}}
  internal static void NoRedirect(string path){string full=Path.GetFullPath(path);if((File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new IOException("app_redirected_path");}
  internal NativeBootstrap(string root){
   Root=Path.GetFullPath(root);var m=Json.Codec.DeserializeObject(ReadSmall(Path.Combine(Root,"windows-runtime.json"),16384));var n=Json.Get(m,"nativeRuntime");
   if(Convert.ToInt32(Json.Get(m,"schema"))!=1||Convert.ToInt32(Json.Get(n,"schema"))!=1||Json.Str(n,"cli")!="native/bin/styx.exe"||Json.Str(n,"payload")!="native"||Json.Str(n,"publisher")!="native-publisher.pem"||Json.Str(n,"publisherSpkiSha256")!=PublisherPin)throw new IOException("app_native_runtime_required");
   Cli=Path.Combine(Root,"native","bin","styx.exe");Payload=Path.Combine(Root,"native");Publisher=Path.Combine(Root,"native-publisher.pem");CliSha=Json.Str(n,"cliSha256");ManifestSha=Json.Str(n,"manifestSha256");
   if(!System.Text.RegularExpressions.Regex.IsMatch(CliSha,"\\A[a-f0-9]{64}\\z")||!System.Text.RegularExpressions.Regex.IsMatch(ManifestSha,"\\A[a-f0-9]{64}\\z"))throw new IOException("app_native_hash_required");
   NoRedirect(Cli);cliPin=new FileStream(Cli,FileMode.Open,FileAccess.Read,FileShare.Read);try{Validate();}catch{cliPin.Dispose();throw;}
  }
  internal void Validate(){if(!File.Exists(Cli)||!Directory.Exists(Payload)||!File.Exists(Publisher))throw new IOException("app_native_runtime_required");}
  internal ProcessStartInfo StartInfo(string arguments){Validate();var info=new ProcessStartInfo(Cli,arguments){WorkingDirectory=Root,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};info.EnvironmentVariables.Remove("NODE_OPTIONS");info.EnvironmentVariables.Remove("NODE_PATH");info.EnvironmentVariables.Remove("STYX_NATIVE_STATE");info.EnvironmentVariables.Remove("STYX_NATIVE_RESOURCES");return info;}
  internal static string Quote(string value){if(value.IndexOf('"')>=0||value.IndexOf('\0')>=0||value.EndsWith("\\"))throw new IOException("app_fixed_path_invalid");return "\""+value+"\"";}
  public void Dispose(){cliPin.Dispose();}
 }
 static class PrivateAppFiles {
  static readonly System.Security.Principal.SecurityIdentifier User=System.Security.Principal.WindowsIdentity.GetCurrent().User;
  static readonly System.Security.Principal.SecurityIdentifier SystemSid=new System.Security.Principal.SecurityIdentifier("S-1-5-18"),Admins=new System.Security.Principal.SecurityIdentifier("S-1-5-32-544");
  static void Validate(string path,bool directory){NativeBootstrap.NoRedirect(path);System.Security.AccessControl.FileSystemSecurity security=directory?(System.Security.AccessControl.FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);if(!User.Equals(security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier))))throw new IOException("app_private_owner_required");foreach(System.Security.AccessControl.FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier))){var sid=(System.Security.Principal.SecurityIdentifier)rule.IdentityReference;if(rule.AccessControlType==System.Security.AccessControl.AccessControlType.Allow&&!sid.Equals(User)&&!sid.Equals(SystemSid)&&!sid.Equals(Admins)&&(rule.FileSystemRights & (System.Security.AccessControl.FileSystemRights.ReadData|System.Security.AccessControl.FileSystemRights.WriteData|System.Security.AccessControl.FileSystemRights.AppendData|System.Security.AccessControl.FileSystemRights.Delete|System.Security.AccessControl.FileSystemRights.ChangePermissions|System.Security.AccessControl.FileSystemRights.TakeOwnership))!=0)throw new IOException("app_private_acl_required");}}
  static System.Security.AccessControl.DirectorySecurity DirectoryAcl(){var acl=new System.Security.AccessControl.DirectorySecurity();acl.SetOwner(User);acl.SetAccessRuleProtection(true,false);foreach(var sid in new[]{User,SystemSid,Admins})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));return acl;}
  static void DirectoryPrivate(string path){if(File.Exists(path))throw new IOException("app_private_directory_required");if(!Directory.Exists(path)){string parent=Path.GetDirectoryName(path);if(!Directory.Exists(parent))throw new IOException("app_private_parent_missing");Directory.CreateDirectory(path,DirectoryAcl());}Validate(path,true);}
  internal static void PrepareOwnerDirectory(string state){
   foreach(string name in new[]{"deployment","deployment.json","state.json","host","gateway","device","service.json",".styx-native-root-v1.json"})if(File.Exists(Path.Combine(state,name))||Directory.Exists(Path.Combine(state,name)))throw new NativeOperationException("app_legacy_install_present");
   string standard=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"StyxPreview","WindowsFirst");
   if(String.Equals(state,standard,StringComparison.OrdinalIgnoreCase)&&!Directory.Exists(Path.GetDirectoryName(state)))DirectoryPrivate(Path.GetDirectoryName(state));
   DirectoryPrivate(state);
  }
  internal static string Prepare(string state,string selection,out string profile,out string candidate){
   // Refuse old installations before creating any state or candidate files.
   // The UI never adopts, repairs, moves or replaces the old layout.
   foreach(string name in new[]{"deployment","deployment.json","state.json","host","gateway","device","service.json",".styx-native-root-v1.json"})if(File.Exists(Path.Combine(state,name))||Directory.Exists(Path.Combine(state,name)))throw new NativeOperationException("app_legacy_install_present");
   string container=Path.Combine(state,"native-rust-host-v1"),fresh=Path.Combine(container,"profile");
   string defaultState=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"StyxPreview","WindowsFirst");if(String.Equals(state,defaultState,StringComparison.OrdinalIgnoreCase)&&!Directory.Exists(Path.GetDirectoryName(state)))DirectoryPrivate(Path.GetDirectoryName(state));
   DirectoryPrivate(state);DirectoryPrivate(container);string candidates=Path.Combine(container,"migration-candidates");DirectoryPrivate(candidates);string digest;using(var bytes=new MemoryStream(new System.Text.UTF8Encoding(false,true).GetBytes(selection)))digest=NativeBootstrap.Hash(bytes);string path=Path.Combine(candidates,digest+".json");candidate=path;
   if(!File.Exists(path)){
    var acl=new System.Security.AccessControl.FileSecurity();acl.SetOwner(User);acl.SetAccessRuleProtection(true,false);foreach(var sid in new[]{User,SystemSid,Admins})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
    using(var f=new FileStream(path,FileMode.CreateNew,System.Security.AccessControl.FileSystemRights.Read|System.Security.AccessControl.FileSystemRights.Write,FileShare.Read,4096,FileOptions.None,acl)){byte[] raw=new System.Text.UTF8Encoding(false,true).GetBytes(selection);f.Write(raw,0,raw.Length);f.Flush(true);}
   }
   Validate(path,false);if(NativeBootstrap.ReadSmall(path,16384)!=selection)throw new NativeOperationException("app_runtime_selection_changed");Validate(container,true);profile=fresh;return container;
  }
 }
 sealed class Core:IDisposable {
  readonly SemaphoreSlim gate=new SemaphoreSlim(1,1);readonly NativeBootstrap bootstrap;readonly FileStream selectionPin;Process child;Task stderrDrain;Task<string> pendingRead;CancellationTokenRegistration cancellationRegistration;int sequence;int closed;bool childStarted;
  internal bool CleanupConfirmed {get;private set;}
  internal object ObservedExit {get;private set;}
  internal readonly string ProfileDirectory;
  internal static async Task<string> ReadLineBounded(StreamReader reader,int limit){var text=new System.Text.StringBuilder();var b=new char[1];while(await reader.ReadAsync(b,0,1).ConfigureAwait(false)!=0){if(b[0]=='\n')return text.ToString().TrimEnd('\r');if(text.Length>=limit)throw new IOException("app_frame_too_large");text.Append(b[0]);}if(text.Length!=0)throw new IOException("app_incomplete_frame");return null;}
  internal static async Task Drain(StreamReader reader){var b=new char[4096];while(await reader.ReadAsync(b,0,b.Length).ConfigureAwait(false)!=0){}}
#if STYX_QUIT_TEST
  // Standalone lifecycle regression only. The release builder never defines
  // STYX_QUIT_TEST; product Core construction still requires NativeBootstrap.
  internal Core(Process fixture){bootstrap=null;selectionPin=null;ProfileDirectory=null;child=fixture;childStarted=true;stderrDrain=Drain(fixture.StandardError);}
#endif
  void ReleasePins(){if(selectionPin!=null)selectionPin.Dispose();if(bootstrap!=null)bootstrap.Dispose();}
  internal Core(NativeBootstrap verified,string state,CancellationToken cancellation){
   bootstrap=verified;string profile,selection;PrivateAppFiles.Prepare(state,verified.Selection,out profile,out selection);ProfileDirectory=profile;selectionPin=new FileStream(selection,FileMode.Open,FileAccess.Read,FileShare.Read);
   try{var info=bootstrap.StartInfo("__app-core --state-dir "+NativeBootstrap.Quote(ProfileDirectory)+" --runtime-selection-file "+NativeBootstrap.Quote(selection));info.RedirectStandardInput=true;
   child=new Process {StartInfo=info};cancellation.ThrowIfCancellationRequested();if(!child.Start())throw new IOException("app_child_not_started");childStarted=true;stderrDrain=Drain(child.StandardError);cancellationRegistration=cancellation.Register(Dispose);cancellation.ThrowIfCancellationRequested();}catch{Dispose();throw;}
  }
  internal async Task<object> Call(string operation,Dictionary<string,object> input){
   Task failedCleanup=null;bool dispatchStarted=false;await gate.WaitAsync();try{var p=child;if(Volatile.Read(ref closed)!=0||p==null||p.HasExited||sequence==Int32.MaxValue)throw new IOException("app_core_unavailable");int id=++sequence;string request=Json.Codec.Serialize(Json.Obj("schema",1,"id",id,"operation",operation,"input",input));if(request.Length>65536)throw new IOException("app_request_too_large");
    dispatchStarted=true;await p.StandardInput.WriteLineAsync(request);await p.StandardInput.FlushAsync();pendingRead=ReadLineBounded(p.StandardOutput,2097152);
    string line=await pendingRead;pendingRead=null;if(line==null||Volatile.Read(ref closed)!=0)throw new IOException("app_result_unknown_no_replay");var response=Json.Codec.DeserializeObject(line);if(Convert.ToInt32(Json.Get(response,"id"))!=id){throw new IOException("app_correlation_unknown_no_replay");}if(!Json.Yes(response,"ok"))throw new NativeOperationException(Json.Str(response,"error"),retirement:Json.Get(response,"retirement"),joinNotSent:Json.Yes(response,"retryable")&&Json.Get(response,"uncertain") is bool&&!Json.Yes(response,"uncertain"));return Json.Get(response,"result");
   }catch(NativeOperationException){throw;}catch{if(!dispatchStarted)throw;if(Volatile.Read(ref shutdownCustody)!=1&&Interlocked.Exchange(ref closed,1)==0)failedCleanup=Task.Run(()=>DisposeOriginal());}finally{gate.Release();}
   if(failedCleanup!=null)await failedCleanup;throw new IOException("app_result_unknown_no_replay");
  }
  int shutdownCustody;
  internal object MaintenanceIdentity(){var p=child;if(p==null||Volatile.Read(ref closed)!=0||p.HasExited)throw new IOException("maintenance_core_unavailable");IntPtr held=p.Handle;return Json.Obj("pid",p.Id,"creationFileTime",MaintenancePeer.Birth(p));}
  internal async Task BeginShutdown(){await gate.WaitAsync();try{if(Volatile.Read(ref closed)!=0||pendingRead!=null||child==null||child.HasExited||Interlocked.CompareExchange(ref shutdownCustody,1,0)!=0)throw new IOException("maintenance_core_custody_unavailable");}finally{gate.Release();}}
  internal void CancelShutdown(){if(Volatile.Read(ref closed)!=0||pendingRead!=null)throw new IOException("maintenance_core_custody_unknown");Interlocked.Exchange(ref shutdownCustody,0);}
  internal Task<object> SettleQuit(){return SettleOwnedExit(true);}
  internal Task<object> SettleMaintenance(){return SettleOwnedExit(false);}
  async Task<object> SettleOwnedExit(bool quit){
   await gate.WaitAsync();try{
    var p=child;
    if(p==null||(!quit&&pendingRead!=null)||(Volatile.Read(ref shutdownCustody)!=1&&!(quit&&p.HasExited))||Interlocked.CompareExchange(ref closed,1,0)!=0)throw new IOException("maintenance_core_custody_unknown");
    Interlocked.Exchange(ref shutdownCustody,1);
    int pid=p.Id;string birth=MaintenancePeer.Birth(p);p.StandardInput.Close();
    // If the original reply was lost, close only this owner's stdin and join
    // the same read before draining. EOF invokes Core's existing owned cleanup;
    // no RPC, action or process signal is repeated.
    var reading=pendingRead;if(reading!=null){try{await reading;}catch(IOException){}pendingRead=null;}
    // No deadline or signal: keep this exact Process and both readers until
    // EOF and actual exit. The original exit code determines local cleanup status.
    var stdout=Drain(p.StandardOutput);await Task.Run(()=>p.WaitForExit());await stdout;if(stderrDrain!=null)await stderrDrain;
    int code=p.ExitCode;
    ObservedExit=Json.Obj("pid",pid,"creationFileTime",birth,"exitCode",code,"stdinEof",true,"ioJoined",true);
    CleanupConfirmed=code==0;
    if(!quit&&!CleanupConfirmed)throw new IOException("maintenance_core_exit_unconfirmed");
    ReleasePins();cancellationRegistration.Dispose();p.Dispose();child=null;
    return ObservedExit;
   }finally{gate.Release();}
  }
  public void Dispose(){
   // Maintenance retains its original handles on uncertainty; it never enters
   // the ordinary EOF cleanup path. Both retain the original process until actual exit.
   if(Volatile.Read(ref shutdownCustody)==1)return;
   if(Interlocked.Exchange(ref closed,1)!=0)return;DisposeOriginal();
  }
  void DisposeOriginal(){
   var p=child;bool clean=true;if(p!=null&&childStarted){
    try{p.StandardInput.Close();}catch{clean=false;}
    // Join a retained response reader before starting another stdout reader.
    // Drain both pipes before waiting: a child can block on a full pipe while
    // exiting, so waiting first would deadlock ordinary EOF cleanup.
    var reading=pendingRead;if(reading!=null){try{reading.GetAwaiter().GetResult();}catch{clean=false;}pendingRead=null;}
    var stdout=Drain(p.StandardOutput);
    try{p.WaitForExit();}catch{throw new IOException("app_child_cleanup_unknown");}
    try{stdout.GetAwaiter().GetResult();}catch{clean=false;}
    try{if(stderrDrain!=null)stderrDrain.GetAwaiter().GetResult();}catch{clean=false;}
    ObservedExit=Json.Obj("pid",p.Id,"creationFileTime",MaintenancePeer.Birth(p),"exitCode",p.ExitCode,"stdinEof",true,"ioJoined",clean);CleanupConfirmed=clean&&p.ExitCode==0;p.Dispose();child=null;
   }else if(p!=null){p.Dispose();child=null;}ReleasePins();cancellationRegistration.Dispose();
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
    var info=runtime.StartInfo("release installed-selection --payload-dir "+NativeBootstrap.Quote(runtime.Payload)+" --publisher-file "+NativeBootstrap.Quote(runtime.Publisher)+" --expected-publisher "+NativeBootstrap.PublisherPin);timing.BootstrapReady();timing.Record("files",0,1);progress.Report(new PackageProgress {Phase="files",Completed=0,Total=1});child=new Process {StartInfo=info};if(!child.Start())throw new IOException("app_verify_child_not_started");started=true;timing.ChildStarted();stderr=Core.Drain(child.StandardError);stop=cancellation.Register(()=>{try{if(!child.HasExited)child.Kill();child.WaitForExit();if(stderr!=null)stderr.GetAwaiter().GetResult();}catch{}});var clock=Stopwatch.StartNew();
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
  readonly string root,state;readonly NotifyIcon tray;readonly Icon icon;readonly Form panel;readonly Settings settings;readonly CancellationTokenSource startupCancellation=new CancellationTokenSource();readonly Stopwatch startupClock=Stopwatch.StartNew();readonly bool startupTest,loginStartup;readonly System.Windows.Forms.Timer startupTimer,statusTimer;
  VerificationTiming verificationTiming;Core core;bool busy,closing,starting,loginChangeUnconfirmed,actionsGatedDuringStartup=true;int mutationRevision,progressEvents;long firstPaintTicks=-1,verificationStartedTicks=-1,verifiedTicks=-1,readyTicks=-1;object snapshot;Task<object> observation;TaskCompletionSource<bool> mutationDone;readonly Label message;
  internal int ResultCode=0;
  LocalAppControl localControl;Task<object> quitWork;string quitPhase="running";object startupCoreExit;
  internal object CurrentStatus { get { return snapshot; } }
  internal bool RustHost {get{return Json.Str(snapshot,"mode")=="rust_host";}}
  internal bool Supports(string operation){var values=Json.Get(snapshot,"supportedOperations") as object[];if(values==null)return false;foreach(var item in values)if(Equals(item,operation))return true;return false;}
  internal bool LoginChangeAllowed {get{return !loginChangeUnconfirmed;}}
  [DllImport("user32.dll")]static extern bool DestroyIcon(IntPtr hIcon);
  internal static Icon BrandIcon(string file){using(var original=Image.FromFile(file))using(var bitmap=new Bitmap(original,new Size(32,32))){IntPtr handle=bitmap.GetHicon();try{return (Icon)Icon.FromHandle(handle).Clone();}finally{DestroyIcon(handle);}}}
  internal StyxContext(string resourceRoot,string stateDirectory,bool test,bool testStartup=false,bool fromLogin=false,LocalAppControl control=null){
   root=resourceRoot;state=stateDirectory;startupTest=testStartup;loginStartup=fromLogin;icon=BrandIcon(Path.Combine(root,"styx-logo.png"));
   panel=Window("Styx",new Size(340,420));panel.ShowInTaskbar=false;panel.FormBorderStyle=FormBorderStyle.FixedToolWindow;
   var stack=Stack(panel);Logo(stack,64);Heading(stack,"Your computer, connected");
   message=Text(stack,"Open Settings to get started.",110);
   Button(stack,"This computer",()=>{OpenSettings("overview");return Task.FromResult(0);});
   Button(stack,"ChatGPT",()=>{OpenSettings("chat");return Task.FromResult(0);});
   Button(stack,"General",()=>{OpenSettings("general");return Task.FromResult(0);});
   Button(stack,"Quit Styx",RequestQuit);
   panel.FormClosing+=(s,e)=>{if(!closing){e.Cancel=true;panel.Hide();}};
   settings=new Settings(this,icon);
   localControl=control;
   if(localControl!=null){settings.CreateControl();var handle=settings.Handle;localControl.Start(LocalControlOnUi,()=>settings.BeginInvoke(new Action(Quit)));}
   startupTimer=new System.Windows.Forms.Timer {Interval=50};startupTimer.Tick+=async(s,e)=>{startupTimer.Stop();await InitializeCore();};tray=new NotifyIcon { Icon=icon,Text="Styx — open to view connection",Visible=!test };
   statusTimer=new System.Windows.Forms.Timer {Interval=1000};statusTimer.Tick+=async(s,e)=>{if(!closing&&!busy&&!starting&&core!=null&&observation==null)await Refresh();};
   var menu=new ContextMenuStrip();menu.Items.Add(UI("Open Styx"),null,(s,e)=>ShowPanel());menu.Items.Add(UI("Computers"),null,(s,e)=>OpenSettings("overview"));menu.Items.Add(UI("ChatGPT"),null,(s,e)=>OpenSettings("chat"));menu.Items.Add(UI("General"),null,(s,e)=>OpenSettings("general"));menu.Items.Add(UI("Quit Styx"),null,async(s,e)=>await RequestQuit());tray.ContextMenuStrip=menu;tray.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)ShowPanel();};
   if(!test){
    starting=true;settings.Startup("Opening Styx…",true,false);message.Text="Opening Styx…";
    // WM_TIMER runs after pending paints; BeginInvoke can overtake WM_PAINT.
    if(loginStartup){settings.CreateControl();settings.Handle.ToInt64();startupTimer.Start();}else{settings.Shown+=(s,e)=>startupTimer.Start();OpenSettings();}
   }
  }
  System.IO.Pipes.NamedPipeServerStream maintenancePipe;Task<bool> maintenanceOwner;bool maintenanceAttempted;
  static bool Hex(string text,int size){return System.Text.RegularExpressions.Regex.IsMatch(text,"\\A[a-f0-9]{"+size+"}\\z");}
  string MaintenanceRoot(){string resources=Path.GetFullPath(root).TrimEnd('\\');string hash=Path.GetFileName(resources);var versions=Directory.GetParent(resources);if(versions==null||versions.Name!="versions"||versions.Parent==null||!Hex(hash,64))throw new IOException("maintenance_installed_scope_required");return versions.Parent.FullName;}
  Task<object> MaintenanceOnUi(Func<Task<object>> action){var done=new TaskCompletionSource<object>();settings.BeginInvoke(new Action(async()=>{try{done.TrySetResult(await action());}catch(Exception error){done.TrySetException(error);}}));return done.Task;}
  object MaintenanceHello(string install){if(closing||starting||core==null)throw new IOException("maintenance_owner_not_ready");using(var self=Process.GetCurrentProcess())return Json.Obj("schema",1,"kind","styx-native-maintenance-owner","pid",self.Id,"creationFileTime",MaintenancePeer.Birth(self),"ownerSid",System.Security.Principal.WindowsIdentity.GetCurrent().User.Value,"installRoot",install,"resources",Path.GetFullPath(root).TrimEnd('\\'),"packageSha256",Path.GetFileName(Path.GetFullPath(root).TrimEnd('\\')),"core",core.MaintenanceIdentity());}
  void StartMaintenanceOwner(){
   if(startupTest||maintenanceOwner!=null||!Supports("prepareAppMaintenance"))return;
   try{
    string install=MaintenanceRoot();NativeBootstrap.NoRedirect(root);string package=Path.Combine(root,"windows-package.json");NativeBootstrap.NoRedirect(package);using(var pin=new FileStream(package,FileMode.Open,FileAccess.Read,FileShare.Read))if(NativeBootstrap.Hash(pin)!=Path.GetFileName(Path.GetFullPath(root).TrimEnd('\\')))return;
    var acl=new System.IO.Pipes.PipeSecurity();var user=System.Security.Principal.WindowsIdentity.GetCurrent().User;acl.SetOwner(user);acl.SetAccessRuleProtection(true,false);foreach(string sid in new[]{user.Value,"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new System.IO.Pipes.PipeAccessRule(new System.Security.Principal.SecurityIdentifier(sid),System.IO.Pipes.PipeAccessRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
    maintenancePipe=new System.IO.Pipes.NamedPipeServerStream(MaintenancePeer.PipeName(install),System.IO.Pipes.PipeDirection.InOut,1,System.IO.Pipes.PipeTransmissionMode.Byte,System.IO.Pipes.PipeOptions.Asynchronous,4096,4096,acl);
    var pipe=maintenancePipe;maintenanceOwner=Task.Run(async()=>{bool settled=false;
     try{
      await Task.Factory.FromAsync(pipe.BeginWaitForConnection,pipe.EndWaitForConnection,null);using(var requester=MaintenancePeer.Connected(pipe,false)){
       string image=requester.MainModule.FileName;NativeBootstrap.NoRedirect(image);if(Path.GetFileName(image)!="StyxInstallGate.exe"||!MaintenancePeer.SetupPresent(install))throw new IOException("maintenance_requester_unconfirmed");
       // Preview helper paths do not establish publisher trust. The current
       // user still approves the exact operation in this original App below.
       using(var imagePin=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read))using(var reader=new StreamReader(pipe,new System.Text.UTF8Encoding(false,true),false,4096,true))using(var writer=new StreamWriter(pipe,new System.Text.UTF8Encoding(false),4096,true){AutoFlush=true}){
        var codec=new JavaScriptSerializer {MaxJsonLength=2097152};object hello=await MaintenanceOnUi(()=>Task.FromResult(MaintenanceHello(install)));await writer.WriteLineAsync(codec.Serialize(hello));
        string line=await Core.ReadLineBounded(reader,65536);if(line==null)throw new IOException("maintenance_request_missing");var request=codec.DeserializeObject(line);var result=await MaintenanceOnUi(()=>MaintainOriginalApp(install,request,requester));await writer.WriteLineAsync(codec.Serialize(result));await writer.FlushAsync();
        settled=Json.Str(result,"status")=="settled";
       }
      }
     }catch{if(!closing)try{settings.BeginInvoke(new Action(()=>{if(busy)settings.Feedback("The installation handoff is unconfirmed. Keep this App open for review. No operation will be repeated.");}));}catch{}}
     finally{pipe.Dispose();}
     return settled;
    });
    maintenanceOwner.ContinueWith(done=>{if(done.Status==TaskStatus.RanToCompletion&&done.Result)try{settings.BeginInvoke(new Action(Quit));}catch{}},TaskScheduler.Default);
   }catch{if(maintenancePipe!=null){maintenancePipe.Dispose();maintenancePipe=null;}}
  }
  void ValidateMaintenance(object value,object request,string expected,string ticket=null){
   if(!Equals(Json.Get(value,"schema"),1)||Json.Str(value,"status")!=expected||!Hex(Json.Str(value,"ticketId"),32)||ticket!=null&&Json.Str(value,"ticketId")!=ticket||Json.Str(value,"scope")!="original_app"||Json.Str(value,"runtimeReferences")!="outside_install_root"||!Json.Yes(value,"statePreserved")||!Equals(Json.Get(value,"operationsReplayed"),false)||!Json.Yes(value,"requiresOwnedQuit"))throw new IOException("maintenance_ticket_invalid");
   foreach(string field in new[]{"requestId","operation","installRoot","packageSha256","candidatePackageSha256"})if(!Equals(Json.Get(value,field),Json.Get(request,field)))throw new IOException("maintenance_ticket_changed");
  }
  async Task<object> MaintainOriginalApp(string install,object request,Process requester){
   string action=Json.Str(request,"operation"),hash=Path.GetFileName(Path.GetFullPath(root).TrimEnd('\\')),candidate=Json.Str(request,"candidatePackageSha256");
   if(closing||starting||busy||core==null||maintenanceAttempted||!RustHost||!Supports("prepareAppMaintenance")||!Equals(Json.Get(request,"schema"),1)||!Hex(Json.Str(request,"requestId"),32)||(action!="upgrade"&&action!="uninstall")||!Equals(Json.Get(request,"installRoot"),install)||Json.Str(request,"packageSha256")!=hash||(action=="upgrade"?!Hex(candidate,64):Json.Get(request,"candidatePackageSha256")!=null)||!MaintenancePeer.SetupPresent(install))return Json.Obj("status","blocked");
   busy=true;mutationDone=new TaskCompletionSource<bool>();OpenSettings();string prompt=action=="upgrade"?"Setup requests an upgrade of this Styx installation. Running tasks must finish before the original App can close. Device identity, pairing and settings will be retained. Continue?":"Setup requests uninstalling this Styx installation. Its owned login startup entry will be removed through this App. Device identity, pairing and settings will be retained. Continue?";
   if(MessageBox.Show(settings,prompt,"Styx installation",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK){busy=false;mutationDone.TrySetResult(true);return Json.Obj("status","cancelled");}
   if(requester.HasExited||!MaintenancePeer.SetupPresent(install)){busy=false;mutationDone.TrySetResult(true);return Json.Obj("status","blocked");}
   maintenanceAttempted=true;mutationRevision++;settings.Enabled=false;settings.Feedback("Preparing the original App for Setup…");object prepared=null,login=null,quit=null,exit=null;Exception failure=null;bool custody=false,mutationDispatched=false;
   try{
    var reading=observation;if(reading!=null){try{await reading;}catch{}if(observation==reading)observation=null;}
    await core.BeginShutdown();custody=true;
    if(action=="uninstall"){
     if(loginChangeUnconfirmed)throw new NativeOperationException("app_login_result_unknown_no_replay");using(var before=NativeLoginStartup.Observe(root,state)){if(before.Status=="registered_unverified"){mutationDispatched=true;await Call("appLogin",Json.Obj("enabled",false));}else if(before.Status!="not_registered")throw new NativeOperationException("app_login_observation_changed");}
     using(var current=NativeLoginStartup.Observe(root,state)){if(current.Status!="not_registered"||loginChangeUnconfirmed)throw new NativeOperationException("app_login_result_unknown_no_replay");login=current.Wire;}
    }
    var input=Json.Obj("schema",1,"authorize",true,"operation",action,"requestId",Json.Str(request,"requestId"),"installRoot",install,"packageSha256",hash,"candidatePackageSha256",Json.Get(request,"candidatePackageSha256"),"loginObservation",login);
    mutationDispatched=true;prepared=await core.Call("prepareAppMaintenance",input);ValidateMaintenance(Json.Get(prepared,"maintenance"),request,"prepared");
    // Exactly one original Core admission, retaining every drain/custody field.
    quit=await core.Call("quitAdmission",Json.Obj());if(Json.Str(quit,"quit","status")!="ready_to_quit"||!Hex(Json.Str(quit,"quit","ticketId"),32))throw new IOException("maintenance_quit_unconfirmed");ValidateMaintenance(Json.Get(quit,"maintenance"),request,"ready_to_exit",Json.Str(prepared,"maintenance","ticketId"));
    exit=await core.SettleMaintenance();
   }catch(Exception error){failure=error;}
   if(failure!=null){
    bool released=!custody;
    // Only a local preflight before any dispatched mutation can release custody.
    // A rejected maintenance Quit fences the original Core as unknown, even if
    // its error names a busy task. Never cancel or replay that original attempt.
    if(custody&&!mutationDispatched){try{core.CancelShutdown();released=true;}catch{}}
    if(released){busy=false;settings.Enabled=true;mutationDone.TrySetResult(true);settings.Feedback("Setup could not prepare this App. No program files were changed. Review the connection before starting a new Setup attempt.");}else settings.Feedback("The installation handoff is unconfirmed. Keep this App open for review. No operation will be repeated.");
    return Json.Obj("status",released?"blocked":"unknown");
   }
   return Json.Obj("schema",1,"status","settled","requestId",Json.Str(request,"requestId"),"operation",action,"installRoot",install,"packageSha256",hash,"candidatePackageSha256",Json.Get(request,"candidatePackageSha256"),"prepared",prepared,"quitTicket",quit,"loginObservation",login,"coreExit",exit);
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
    if(Json.Str(latest,"mode")!="rust_host"||Json.Get(latest,"supportedOperations") as object[]==null)throw new IOException("app_rust_protocol_required");core=pending;pending=null;snapshot=latest;starting=false;readyTicks=startupClock.ElapsedTicks;PublishStatus();settings.Startup("",false,false);ResultCode=0;StartMaintenanceOwner();if(!startupTest)statusTimer.Start();
    if(startupTest){WriteStartupReceipt(true,packageVerified);Quit();}return;
   }catch(NativeOperationException error){startupFailure=error.Code;}catch{}
   // Framework's C# compiler cannot await inside catch. Dispose the failed
   // owned child here without blocking the native window or replaying work.
   var failed=pending??core;core=null;if(failed!=null){await Task.Run(()=>failed.Dispose());if(!failed.CleanupConfirmed){startupCoreExit=failed.ObservedExit;ResultCode=4;if(startupCoreExit==null)core=failed;}}else if(verifiedRuntime!=null)verifiedRuntime.Dispose();if(closing)return;starting=false;
   if(startupFailure=="app_legacy_install_present"){message.Text="An older Styx installation was found in this profile. Remove it before using this version; Styx did not change it.";settings.Startup(message.Text,false,true);return;}
   message.Text="Styx needs attention. Open Settings to retry.";
   settings.Startup(packageVerified?"Connection settings could not open. Retry to reconnect; your settings are retained.":"Styx could not finish checking the app. Keep the app folder intact, then retry.",false,true);
   if(startupTest){WriteStartupReceipt(false,packageVerified);Quit();}
  }
  void WriteStartupReceipt(bool success,bool packageVerified){
   bool paintedFirst=firstPaintTicks>=0&&verificationStartedTicks>=firstPaintTicks;
   bool gated=core==null||verifiedTicks>=verificationStartedTicks&&readyTicks>=verifiedTicks;
   ResultCode=success&&paintedFirst&&gated&&actionsGatedDuringStartup&&progressEvents>0?0:2;
   Directory.CreateDirectory(state);string receipt=Path.Combine(state,"native-startup-self-test.json");if(File.Exists(receipt))receipt=Path.Combine(state,"native-startup-self-test-"+Guid.NewGuid().ToString("N")+".json");
   byte[] bytes=System.Text.Encoding.UTF8.GetBytes(Json.Codec.Serialize(Json.Obj("status",ResultCode==0?"PASS":"FAIL","windowPaintedBeforeVerification",paintedFirst,"packageVerified",packageVerified,"coreReady",core!=null,"coreGatedByVerification",gated,"controlsGatedWhileChecking",actionsGatedDuringStartup,"retryAvailable",settings.StartupRetryAvailable,"progressEvents",progressEvents,"verificationTiming",verificationTiming==null?null:verificationTiming.Snapshot(),"firstPaintMilliseconds",firstPaintTicks<0?-1:(double)firstPaintTicks*1000/Stopwatch.Frequency,"verificationStartedMilliseconds",verificationStartedTicks<0?-1:(double)verificationStartedTicks*1000/Stopwatch.Frequency,"verifiedMilliseconds",verifiedTicks<0?-1:(double)verifiedTicks*1000/Stopwatch.Frequency,"readyMilliseconds",readyTicks<0?-1:(double)readyTicks*1000/Stopwatch.Frequency,"interactiveDesktopAcceptance","NOT RUN","serviceMutation","NOT RUN")));using(var output=new FileStream(receipt,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){output.Write(bytes,0,bytes.Length);output.Flush(true);}
  }
  static readonly Dictionary<string,string> ChineseText=new Dictionary<string,string>{
   {"Computers","电脑"},
   {"This computer","这台电脑"},
   {"General","通用"},
   {"Settings","设置"},
   {"Styx Settings","Styx 设置"},
   {"Open Styx","打开 Styx"},
   {"Quit Styx","退出 Styx"},
   {"Your computer, connected","连接你的电脑"},
   {"Reconnect","重新连接"},
   {"Refresh status","刷新状态"},
   {"Connection settings","连接设置"},
   {"About Styx","关于 Styx"},
   {"Startup","启动"},
   {"Login startup…","登录时启动…"},
   {"Update Styx…","更新 Styx…"},
   {"Update Styx","更新 Styx"},
   {"What ChatGPT can do on this computer","允许 ChatGPT 在这台电脑上做什么"},
   {"Other computers","其他电脑"},
   {"Computers…","管理电脑…"},
   {"Add computer…","添加电脑…"},
   {"Join another Gateway…","加入其他中心…"},
   {"Change this computer's role…","更改这台电脑的角色…"},
   {"This computer's capabilities…","这台电脑的能力…"},
   {"Check approval","检查批准状态"},
   {"Back to General","返回通用"},
   {"This computer is connected.","这台电脑已连接。"},
   {"This computer is connected. Computer Use needs attention.","这台电脑已连接，电脑操作功能需要处理。"},
   {"Connecting this computer…","正在连接这台电脑…"},
   {"This computer is offline. Reconnect when you are ready.","这台电脑尚未连接，可以重新连接。"},
   {"Set up this computer or join an existing Styx.","设置这台电脑，或加入已有 Styx。"},
   {"Styx needs attention. Your settings and pairing are retained.","Styx 需要处理，设置与配对已保留。"},
   {"Waiting for the original invitation to be approved.","正在等待原邀请的批准。"},
   {"This computer no longer has access to its main computer. Review connection settings.","这台电脑已无法访问原中心，请查看连接设置。"},
   {"Connect this computer to change its capabilities.","连接后可更改这台电脑的能力。"},
   {"Turning off a capability stops its existing tasks. Other capabilities and the Gateway connection keep running.","关闭一项能力会停止它的现有任务，其他能力与连接保持运行。"},
   {"This computer is connected through your main computer. Manage the ChatGPT connection there.","这台电脑通过管理电脑连接，请在管理电脑上设置 ChatGPT。"},
   {"Closing the window keeps Styx running in the system tray. Choose Quit Styx to stop this session.","关闭窗口后 Styx 会在托盘继续运行，选择“退出 Styx”停止本机任务和连接。"},
   {"Styx is updated and connected.","Styx 已更新并连接。"},
   {"Styx is updated. Connection needs attention.","Styx 已更新，连接需要处理。"},
   {"An update is in progress. Keep Styx open.","正在更新，请保持 Styx 打开。"},
   {"The update needs attention. Update Styx continues the original update when recovery is available; your settings are retained.","更新需要处理。再次选择“更新 Styx”会在可恢复时继续原更新，设置会保留。"},
   {"Updating Styx… Keep the app open.","正在更新 Styx，请保持 App 打开…"},
   {"Styx is up to date.","Styx 已是当前版本。"},
   {"Styx will finish the update and reconnect this computer. Running tasks will stop; your settings and pairing will be kept.","Styx 会完成更新并重新连接这台电脑。正在运行的任务会停止，设置与配对会保留。"},
   {"The update needs attention. Your settings and pairing are retained. Review the current status before continuing the same update.","更新需要处理，设置与配对已保留。请查看当前状态后继续原更新。"},
   {"Settings saved.","设置已保存。"},
   {"Working…","正在处理…"},
   {"Get started with Styx","开始使用 Styx"},
   {"Set up this computer","设置这台电脑"},
   {"Managed on the main computer","由管理电脑统一管理"},
   {"This computer uses the main computer's Styx connection. Configure ChatGPT on the computer that invited you.","这台电脑使用管理电脑的 Styx 连接，请在邀请你的电脑上配置 ChatGPT。"},
   {"Computer Use","操作电脑"},
   {"Browser","操作浏览器"},
   {"Exec","运行命令"}
  };
  internal static string UI(string value){string translated;return System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName=="zh"&&ChineseText.TryGetValue(value,out translated)?translated:value;}
  internal static Form Window(string title,Size size){return new Form { Text=UI(title),ClientSize=size,StartPosition=FormStartPosition.CenterScreen,BackColor=Color.FromArgb(249,249,247),Font=new Font("Segoe UI",10),AutoScaleMode=AutoScaleMode.Dpi,MinimumSize=size };}
  internal static FlowLayoutPanel Stack(Control parent){var p=new FlowLayoutPanel { Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(24) };parent.Controls.Add(p);return p;}
  internal static Label Text(Control p,string text,int height){
   var l=new Label {Text=UI(text),AutoSize=true,MaximumSize=new Size(p.ClientSize.Width>100?p.ClientSize.Width-55:440,0),Margin=new Padding(0,4,0,10)};
   EventHandler resize=(sender,args)=>{if(!l.IsDisposed)l.MaximumSize=new Size(Math.Max(120,p.ClientSize.Width-55),0);};p.SizeChanged+=resize;l.Disposed+=(sender,args)=>p.SizeChanged-=resize;p.Controls.Add(l);return l;
  }
  internal static void Heading(Control p,string text){var l=Text(p,text,40);l.Font=new Font("Segoe UI Semibold",17);}
  internal static Button Button(Control p,string text,Func<Task> action){var b=new Button {Text=UI(text),Tag=text,AutoSize=true,MinimumSize=new Size(210,36),FlatStyle=FlatStyle.System,Margin=new Padding(0,5,0,5)};b.Click+=async(s,e)=>await action();p.Controls.Add(b);return b;}
  internal void Logo(Control p,int size){p.Controls.Add(new PictureBox { Image=Image.FromFile(Path.Combine(root,"styx-logo.png")),SizeMode=PictureBoxSizeMode.Zoom,Width=size,Height=size,Margin=new Padding(0,0,0,15) });}
  void ShowPanel(){var bounds=Screen.PrimaryScreen.WorkingArea;panel.Location=new Point(bounds.Right-panel.Width-12,bounds.Bottom-panel.Height-12);panel.Show();panel.Activate();}
  void OpenSettings(string section=null){if(section!=null)settings.ShowPage(section);settings.Show();settings.Activate();}
  // Fixed protocol result names only. Never display exception Message,
  // request data, upstream errors, file paths or credentials.
  static string NativeFailureCode(string code){
   switch(code){
    case "join_invalid":case "join_encoding":case "join_signature":case "seed_identity":
    case "app_input_invalid":case "app_lan_address_invalid":case "app_home_unavailable":case "app_shell_unavailable":
    case "app_join_not_inspected":case "app_join_already_exists":case "app_join_input_unknown":
    case "app_input_writer_busy":case "app_scope_changed":case "app_instance_changed":
    case "app_runtime_selection_invalid":case "app_runtime_reader_unsupported":
    case "app_runtime_bootstrap_changed":case "app_runtime_bootstrap_writer_changed":
    case "app_runtime_bootstrap_storage_unknown":case "app_runtime_bootstrap_unknown":
    case "app_setup_already_exists":
    case "pairing_code_invalid_or_expired":case "pairing_gateway_unreachable":case "pairing_gateway_timeout":case "pairing_link_expired_or_invalid":case "pairing_gateway_confirmation_mismatch":
    case "pairing_certificate_confirmation_mismatch":case "pairing_certificate_expired":case "app_clock_unavailable":
    case "native_join_invalid_input":case "native_join_candidate_untrusted":case "native_join_ca_rejected":
    case "native_join_identity_generation_failed":case "native_join_entropy_unavailable":
    case "native_join_app_scope_changed":case "native_join_already_exists":
    case "native_join_persistence_unknown":case "native_join_unknown_inspect":
    case "native_join_configuration_busy":case "native_join_busy":case "native_join_worker_unknown":
    case "native_join_platform_unsupported":case "native_join_response_rejected":return code;
    default:return "";
   }
  }
  internal async Task Run(Func<Task> action,string pending="Working…",string failure="The operation could not be confirmed. Refresh to review current state. Completed steps are retained; an interrupted operation is not automatically repeated."){
   if(busy||starting||core==null)return;string previousMessage=message.Text;busy=true;mutationDone=new TaskCompletionSource<bool>();mutationRevision++;settings.Startup(UI(pending),true,false);message.Text=UI(pending);settings.Feedback(pending);
   try{var reading=observation;if(reading!=null){try{await reading;}catch{}if(observation==reading)observation=null;}await action();if(settings.HasFeedback(pending))settings.Feedback("Settings saved.");}
   catch(Exception error){string text=failure;var native=error as NativeOperationException;if(native!=null&&native.JoinNotSent)text="The pairing request was not sent. Check network access and allow styx incoming connections in the hub computer’s system prompt. Then paste a new invitation, review it and submit again. Styx will not retry automatically.";else if(native!=null&&(native.Code=="pairing_gateway_unreachable"||native.Code=="pairing_gateway_timeout"))text="Cannot reach the Gateway. Check the address and connection.";else if(native!=null&&(native.Code=="pairing_code_invalid_or_expired"||native.Code=="pairing_link_expired_or_invalid"))text="This invitation is invalid or has expired. Get a new invitation from your Gateway and review it before submitting again. Styx will not retry automatically.";else if(native!=null&&native.Code=="app_system_trust_not_supported")text="This native join currently requires an explicit Gateway CA in the invitation. System-trust-only joining is not supported; no CA or approval was fabricated.";else if(native!=null&&Array.IndexOf(new[]{"app_lan_address_invalid","app_network_interface_changed","app_network_interface_required","app_network_interfaces_unavailable","tunnel_client_unavailable"},native.Code)>=0)text="Select an available LAN or VPN network. If the network changed, detect networks again. Setup was not submitted.";else if(native!=null&&native.Code=="tunnel_client_unavailable")text="Use a Gateway package that includes the Tunnel client.";else if(native!=null&&native.Code=="app_operation_not_supported")text="This operation is unavailable in the native Host slice. Existing settings were retained.";else if(native!=null&&native.Code=="host_payload_insufficient_space")text=SpaceFeedback(native.Budget,native.Preflight);else if(native!=null&&native.Code=="windows_native_app_binding_required")text="The desktop test could not start. This package could not verify the current native Styx app. Your settings are retained.";else if(native!=null&&native.Code=="desktop_acceptance_native_app_changed")text="The native Styx app changed during this desktop test. Create a new test in this app before continuing.";else if(native!=null&&native.Code=="app_login_result_unknown_no_replay")text="The login startup change is unconfirmed and will not be repeated. Check Windows startup settings. Quit and reopen Styx to read the system state.";else if(native!=null&&native.Code=="app_login_observation_changed")text="The Startup entry changed before the operation could finish. Styx preserved the current entry. Check its current state before making another explicit change.";else if(native!=null&&native.Code=="work_in_progress")text="A task is still running. Wait for it to finish before quitting or updating Styx.";else if(native!=null&&native.Code=="work_state_unknown")text="Styx could not confirm whether tasks are running. Keep it open and try again after checking the connection.";if(native!=null){string diagnostic=NativeFailureCode(native.Code);if(diagnostic.Length>0)text+="\nNative result: "+diagnostic;}message.Text="Connection needs attention. Open Settings to review the last result.";settings.Feedback(text);}
   finally{if(message.Text==pending)message.Text=previousMessage;settings.Startup("",false,false);busy=false;mutationDone.TrySetResult(true);}
  }
  internal async Task Read(Func<Task> action){try{await action();}catch{settings.ObservationFailed("This information could not be refreshed. Your entries and the last confirmed state are retained.");}}
  internal async Task Refresh(){if(busy||starting||core==null)return;int revision=mutationRevision;try{await ObserveStatus();}catch{if(revision==mutationRevision)settings.ObservationFailed("Connection status could not refresh. You can keep editing and retry. Your last confirmed state is retained.");}}
  internal Task RefreshAfterMutation(){return ObserveStatus();}
  internal void ApplyPreparationResult(object latest){
   if(Json.Get(latest,"status")==null)throw new IOException();
   snapshot=latest;PublishStatus();
  }
  async Task ObserveStatus(){
   if(observation!=null){await observation;return;}
   int revision=mutationRevision;var pending=Call("status");observation=pending;
   try{var latest=await pending;if(!closing&&revision==mutationRevision){snapshot=latest;PublishStatus();}}finally{if(observation==pending)observation=null;}
  }
  void PublishStatus(){
   if(RustHost){message.Text=UI(ConnectionText(snapshot));tray.Text=Connected(snapshot)?"Styx — connected":"Styx — connection settings";settings.ShowStatus(snapshot);return;}
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
  internal Task UpdateStyx(){
   if(busy||starting||core==null||!Supports("updateStyx"))return Task.FromResult(0);
   if(MessageBox.Show(settings,UI("Styx will finish the update and reconnect this computer. Running tasks will stop; your settings and pairing will be kept."),UI("Update Styx"),MessageBoxButtons.OKCancel,MessageBoxIcon.Information)!=DialogResult.OK)return Task.FromResult(0);
   return Run(async()=>{tray.Text=UI("Updating Styx… Keep the app open.");await Call("updateStyx",Json.Obj("authorize",true));await RefreshAfterMutation();settings.ShowPage("general");settings.Feedback(UI("Styx is up to date."));},"Updating Styx… Keep the app open.","The update needs attention. Your settings and pairing are retained. Review the current status before continuing the same update.");
  }
  internal static string ConnectionText(object data){
   if(Json.Yes(data,"admission_fenced"))return "Styx needs attention. Your settings and pairing are retained.";
   string enrollment=Json.Str(data,"enrollment","status");
   if(enrollment=="awaiting_approval")return "Waiting for the original invitation to be approved.";
   if(enrollment=="rejected"||Json.Str(data,"foreground","error")=="gateway_wss_admission_refused")return "This computer no longer has access to its main computer. Review connection settings.";
   if(Connected(data))return String.IsNullOrEmpty(Json.Str(data,"foreground","computerStartupError"))?"This computer is connected.":"This computer is connected. Computer Use needs attention.";
   if(Json.Str(data,"foreground","status")=="started")return "Connecting this computer…";
   if(Json.Get(data,"configuration")==null&&Json.Get(data,"enrollment")==null&&Json.Get(data,"gateway")==null)return "Set up this computer or join an existing Styx.";
   return "This computer is offline. Reconnect when you are ready.";
  }
  internal static bool Connected(object data){return Json.Str(data,"foreground","status")=="connected"&&Json.Str(data,"foreground","execConnection")=="connected";}
  object QuitReply(string status,string code=null,object exit=null){return Json.Obj("status",status,"code",code,"coreExit",exit);}
  async Task<object> LocalControlOnUi(string operation){
   var done=new TaskCompletionSource<object>();
   settings.BeginInvoke(new Action(async()=>{
    try{
     if(operation=="identity"){object identity=null;try{if(core!=null)identity=core.MaintenanceIdentity();}catch(IOException){}done.TrySetResult(identity);}
     else if(operation=="status")done.TrySetResult(Json.Obj("status",quitPhase,"starting",starting,"busy",busy));
     else if(operation=="show"){OpenSettings();done.TrySetResult(Json.Obj("status","shown"));}
     else if(operation=="quit")done.TrySetResult(await RequestQuitResult());
     else throw new IOException("app_control_operation_invalid");
    }catch{done.TrySetResult(QuitReply("unknown","app_quit_unconfirmed"));}
   }));
   return await done.Task;
  }
  internal Task<object> RequestQuitResult(){
   if(quitWork!=null&&quitPhase=="running"&&quitWork.IsCompleted)quitWork=null;
   if(quitWork!=null)return quitWork;
   if(starting||busy)return Task.FromResult(QuitReply("busy",starting?"app_starting":"app_operation_in_progress"));
   quitWork=PrepareQuit();return quitWork;
  }
  async Task<object> PrepareQuit(){
   busy=true;mutationDone=new TaskCompletionSource<bool>();quitPhase="stopping";mutationRevision++;settings.Enabled=false;
   message.Text="Stopping Styx…";settings.Feedback("Stopping this Styx instance and its tasks…");
   var reading=observation;
   if(reading!=null){try{await reading;}catch{}if(observation==reading)observation=null;}

   string failure=null;
   if(core!=null&&core.ObservedExit==null){
    try{
     await core.BeginShutdown();
     var result=await core.Call("quitAdmission",Json.Obj());
     if(Json.Str(result,"quit","status")!="ready_to_quit")throw new IOException();
    }catch(NativeOperationException error){
     if(error.Code=="app_runtime_update_in_progress"||error.Code=="app_login_in_progress"){
      core.CancelShutdown();
      quitPhase="running";busy=false;settings.Enabled=true;mutationDone.TrySetResult(true);
      return QuitReply("busy",error.Code);
     }
     failure="app_quit_admission_unconfirmed";
    }catch{failure="app_quit_admission_unconfirmed";}

    // Closing this child's input joins the original Rust work, including after
    // a lost reply. The same request is never dispatched a second time.
    try{await core.SettleQuit();}catch{failure="app_quit_unconfirmed";}
   }
   object exit=core==null?startupCoreExit:core.ObservedExit;
   if(core!=null&&exit==null){
    ResultCode=4;quitPhase="unknown";
    settings.Feedback("Styx could not confirm that its local process stopped.");
    return QuitReply(quitPhase,"app_quit_unconfirmed");
   }
   if(exit!=null&&(core==null||!core.CleanupConfirmed))
    failure="app_core_exited_unclean";
   if(failure!=null)ResultCode=4;
   quitPhase="ready_to_exit";
   return QuitReply(quitPhase,failure,exit);
  }
  internal async Task RequestQuit(){
   var result=await RequestQuitResult();
   if(Json.Str(result,"status")=="ready_to_exit")Quit();
   else if(Json.Str(result,"status")=="busy"){OpenSettings();settings.Feedback("Styx is finishing another operation. Try Quit again when it finishes.");}
  }
  internal void Quit(){if(closing)return;closing=true;if(core!=null){core.Dispose();if(!core.CleanupConfirmed&&core.ObservedExit==null){closing=false;settings.Feedback("The owned Rust process did not exit cleanly. No successful quit receipt is claimed; retain this result for recovery.");ResultCode=4;return;}if(!core.CleanupConfirmed)ResultCode=4;}if(localControl!=null)localControl.Dispose();if(maintenancePipe!=null)maintenancePipe.Dispose();startupTimer.Stop();startupTimer.Dispose();statusTimer.Stop();statusTimer.Dispose();startupCancellation.Cancel();tray.Visible=false;settings.Close();settings.Dispose();panel.Close();tray.Dispose();icon.Dispose();ExitThread();}
  internal void Verify(){var budget=Json.Obj("volumes",new object[]{Json.Obj("requiredBytes",2147483648d,"availableBytes",1073741824d)});if(!SpaceFeedback(budget,true).Contains("upgrade has not started")||SpaceFeedback(budget,false).Contains("upgrade has not started")||!SpaceFeedback(budget,true).Contains("Required:"))throw new Exception("space_feedback_failed");if(panel.Controls.Count!=1||settings.Controls.Count!=1||icon.Width<16)throw new Exception("native_shell_failed");settings.Verify();}
 }
 sealed class Settings:Form {
  sealed class CapabilityDraft {internal string Label=Environment.MachineName,LanAddress="";internal bool Exec=true,Computer,Browser,AllowRemoteHosts;internal int Channel;internal CheckState Persist=CheckState.Checked;}
  readonly StyxContext owner;readonly FlowLayoutPanel content,navigation;readonly TableLayoutPanel startupPanel;readonly Label startupText;readonly ProgressBar startupProgress;readonly Button retryStartup;readonly Label feedback,statusReadout,observationError;readonly Dictionary<string,CapabilityDraft> capabilityDrafts=new Dictionary<string,CapabilityDraft>();
  string renderedRustOverviewKey="";
  string page="welcome",joinOrigin,joinCa;bool localCreationSubmitted;TextBox label,link;CheckBox exec,computer,browser,persist;ComboBox channel;
  internal Settings(StyxContext context,Icon icon){owner=context;Text=StyxContext.UI("Styx Settings");Icon=icon;ClientSize=new Size(590,720);MinimumSize=new Size(550,650);Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(249,249,247);AutoScaleMode=AutoScaleMode.Dpi;StartPosition=FormStartPosition.CenterScreen;var outer=new TableLayoutPanel { Dock=DockStyle.Fill,RowCount=3,ColumnCount=1,Padding=new Padding(0) };outer.RowStyles.Add(new RowStyle(SizeType.Absolute,62));outer.RowStyles.Add(new RowStyle(SizeType.AutoSize));outer.RowStyles.Add(new RowStyle(SizeType.Percent,100));Controls.Add(outer);navigation=new FlowLayoutPanel { Dock=DockStyle.Fill,WrapContents=false,Padding=new Padding(15,8,0,0) };outer.Controls.Add(navigation,0,0);StyxContext.Button(navigation,"Computers",()=>{ShowPage("overview");return Task.FromResult(0);}).MinimumSize=new Size(100,32);StyxContext.Button(navigation,"ChatGPT",()=>{ShowPage("chat");return Task.FromResult(0);}).MinimumSize=new Size(100,32);StyxContext.Button(navigation,"General",()=>{ShowPage("general");return Task.FromResult(0);}).MinimumSize=new Size(100,32);foreach(Control item in navigation.Controls){item.AutoSize=false;item.Width=165;item.Height=36;}startupPanel=new TableLayoutPanel {Dock=DockStyle.Top,AutoSize=true,ColumnCount=2,RowCount=2,Padding=new Padding(26,8,26,12),Visible=false};startupPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));startupPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));startupText=new Label {AutoSize=true,MaximumSize=new Size(390,0),Margin=new Padding(0,0,10,8)};startupProgress=new ProgressBar {Dock=DockStyle.Top,Height=8,Style=ProgressBarStyle.Marquee,MarqueeAnimationSpeed=25};retryStartup=new Button {Text="Retry",AutoSize=true,MinimumSize=new Size(75,32)};retryStartup.Click+=async(s,e)=>await owner.InitializeCore();startupPanel.Controls.Add(startupText,0,0);startupPanel.Controls.Add(retryStartup,1,0);startupPanel.Controls.Add(startupProgress,0,1);startupPanel.SetColumnSpan(startupProgress,2);startupText.Paint+=(s,e)=>owner.RecordFirstPaint();outer.Controls.Add(startupPanel,0,1);content=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(26)};outer.Controls.Add(content,0,2);content.SizeChanged+=(sender,args)=>{foreach(Control child in content.Controls){if(child is Label||child is TextBox||child is CheckBox){child.Width=Math.Max(280,content.ClientSize.Width-content.Padding.Horizontal-22);}}};feedback=new Label {Width=490,Height=100,ForeColor=Color.FromArgb(95,70,35)};statusReadout=new Label {Width=490,Height=140};observationError=new Label {Width=490,Height=65,ForeColor=Color.FromArgb(130,65,35)};FormClosing+=(s,e)=>{if(e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};ShowPage("welcome");}
  internal bool StartupActionsGated {get{return !navigation.Enabled&&!content.Enabled;}}
  internal bool StartupRetryAvailable {get{return startupPanel.Visible&&retryStartup.Visible&&retryStartup.Enabled;}}
  internal void Startup(string text,bool checking,bool canRetry){
   startupPanel.Visible=checking||canRetry;startupText.Text=text;startupProgress.Visible=checking;retryStartup.Visible=canRetry;navigation.Enabled=!checking&&!canRetry;content.Enabled=!checking&&!canRetry;
  }
  void Action(string title,Func<Task> action,bool mutation=true,string pending="Working…"){StyxContext.Button(content,title,()=>mutation?owner.Run(action,pending):owner.Read(action));}
  void RefreshAction(){Action("Refresh status",owner.Refresh,false);}
  internal const string JoinRequestProgress="Preparing this computer and sending join request…";
  Task ContinueJoiningView(){Feedback("");ShowPage("overview");ShowStatus(owner.CurrentStatus);return Task.FromResult(0);}
  TextBox Input(string title,bool secret=false){StyxContext.Text(content,title,22);var box=new TextBox {Width=490,UseSystemPasswordChar=secret,Margin=new Padding(0,0,0,12)};content.Controls.Add(box);return box;}
  void Explain(string text,int height=65){StyxContext.Text(content,text,height);}
  void Capabilities(){
   CapabilityDraft draft;if(!capabilityDrafts.TryGetValue(page,out draft)){draft=new CapabilityDraft();capabilityDrafts[page]=draft;}
   label=Input("Computer name");label.Text=draft.Label;label.TextChanged+=(s,e)=>draft.Label=((TextBox)s).Text;
   exec=new CheckBox {Text="Exec — run commands on this computer",Checked=draft.Exec,Width=490,Height=32};
   computer=new CheckBox {Text="Computer Use — control the signed-in desktop",Checked=draft.Computer,Width=490,Height=32};
   browser=new CheckBox {Text="Browser Automation — dedicated Styx profile",Checked=draft.Browser,Width=490,Height=32};
   content.Controls.Add(exec);content.Controls.Add(computer);content.Controls.Add(browser);
   exec.CheckedChanged+=(s,e)=>draft.Exec=((CheckBox)s).Checked;computer.CheckedChanged+=(s,e)=>draft.Computer=((CheckBox)s).Checked;browser.CheckedChanged+=(s,e)=>draft.Browser=((CheckBox)s).Checked;
   channel=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList,Width=300,AccessibleName="Browser"};channel.Items.AddRange(new object[]{"Automatic (Chrome / Edge)","Microsoft Edge","Google Chrome"});channel.SelectedIndex=draft.Channel;channel.SelectedIndexChanged+=(s,e)=>draft.Channel=((ComboBox)s).SelectedIndex;content.Controls.Add(channel);
   persist=new CheckBox {Text="Keep website logins in the dedicated Styx profile",CheckState=draft.Persist,Width=490,Height=32};persist.CheckStateChanged+=(s,e)=>draft.Persist=((CheckBox)s).CheckState;content.Controls.Add(persist);Explain("Browser Automation uses a separate Styx profile. Your personal browser sessions stay separate.",65);
  }
  Dictionary<string,object> Choice(){var values=Json.Obj("label",label.Text.Trim(),"computer",computer.Checked,"browser",browser.Checked);values["exec"]=exec.Checked;if(label.Text.Trim().Length==0)throw new InvalidOperationException();values["browserChannel"]=channel.SelectedIndex==1?"msedge":channel.SelectedIndex==2?"chrome":"auto";values["persistLogin"]=persist.Checked;return values;}
  async Task ReadLogin(){ApplyLogin(await owner.Call("appLifecycle"));}
  void ApplyLogin(object response){string state=Json.Str(response,"lifecycle","status"),operation=Json.Str(response,"login","status");Feedback(!owner.LoginChangeAllowed||operation=="unknown"?"The last login startup change is unconfirmed and will not be repeated. Check Windows startup settings. Quit and reopen Styx to read the system state.":operation=="pending"?"A login startup change is awaiting its result. Styx will not repeat it.":state=="not_registered"?"Login startup is off.":state=="registered_unverified"?"Login startup is registered. Windows can disable it independently; check Windows startup settings.":state=="foreign"?"The existing Startup entry belongs to another app or installation. Styx preserved it.":"Login startup could not be observed. Check Windows startup settings; no startup entry was changed.");}
  bool NativeSetupEmpty(object data){return Json.Str(data,"mode")=="rust_host"&&!Json.Yes(data,"admission_fenced")&&Json.Get(data,"gateway")==null&&Json.Get(data,"configuration")==null&&Json.Get(data,"enrollment")==null;}
  bool CanResumeLocal(){return !localCreationSubmitted&&owner.Supports("resumeLocal")&&Json.Str(owner.CurrentStatus,"enrollment","status")=="local_setup_pre_invite"&&Json.Yes(owner.CurrentStatus,"enrollment","can_resume_local");}
  bool NeedsNativeSetup(object data){return !localCreationSubmitted&&NativeSetupEmpty(data);}
  internal void ShowPage(string name){if(owner.RustHost&&CanResumeLocal()&&(name=="overview"||name=="welcome"))name="create";if(owner.RustHost&&name=="overview"&&NeedsNativeSetup(owner.CurrentStatus))name="welcome";page=name;foreach(Control tab in navigation.Controls){bool selected=(string)tab.Tag==(name=="general"||name=="login-startup"?"General":name=="chat"?"ChatGPT":"Computers");tab.BackColor=selected?Color.FromArgb(225,233,240):Color.FromArgb(249,249,247);}var previous=new Control[content.Controls.Count];content.Controls.CopyTo(previous,0);foreach(var item in previous)if(item!=feedback&&item!=statusReadout&&item!=observationError){var picture=item as PictureBox;if(picture!=null&&picture.Image!=null)picture.Image.Dispose();item.Dispose();}content.Controls.Clear();Status("");if(!owner.RustHost||name=="welcome"||name=="create"||name=="join")owner.Logo(content,48);StyxContext.Heading(content,name=="general"?"General":name=="login-startup"?"Startup":name=="chat"?"ChatGPT":(name=="overview"||name=="component-start"||name=="update-recovery")?"Computers":"Get started with Styx");
   ShowRustPage(name);
  }
  void Unavailable(string title){var button=StyxContext.Button(content,title+" — unavailable",()=>Task.FromResult(0));button.Enabled=false;}
  Task ChangeRole(){return ChangeRoleAndShow("welcome");}
  bool JoinNeedsReview(object data){return Json.Yes(data,"admission_fenced")||(localCreationSubmitted&&Json.Get(data,"gateway")==null&&Json.Get(data,"configuration")==null&&Json.Get(data,"enrollment")==null);}
  async Task JoinGateway(){
   if(JoinNeedsReview(owner.CurrentStatus)){Feedback("The previous setup result is unconfirmed. Refresh status and review it before changing Gateway. Your existing settings are retained.");return;}
   if(NeedsNativeSetup(owner.CurrentStatus)){Feedback("");ShowPage("join");return;}
   await ChangeRoleAndShow("join");
  }
  void JoinGatewayAction(){
   bool fresh=NeedsNativeSetup(owner.CurrentStatus);string title=fresh?"Join an existing Gateway":"Join another Gateway…";
   if(!owner.Supports(fresh?"inspectJoin":"retireRole")){Unavailable(title);return;}
   var button=StyxContext.Button(content,title,()=>owner.Run(JoinGateway));button.Enabled=!JoinNeedsReview(owner.CurrentStatus);
   if(!button.Enabled)Explain("Your previous setup result is unconfirmed. Review the status below before changing Gateway. Existing settings and pairing are retained.",85);
   else if(!fresh)Explain("You will review a change of role before disconnecting this computer and pairing with another Gateway.",65);
  }
  void ApplySetupFailure(Exception failure,object observed){
   var native=failure as NativeOperationException;
   // A closed input refusal AND a successful post-failure Rust observation
   // must show no retained/published setup. Never infer this from a stale
   // snapshot, an error string alone or a lost transport response.
   if(native!=null&&NativeSetupEmpty(observed)&&Array.IndexOf(new[]{"app_input_invalid","app_lan_address_invalid","app_network_interface_changed","app_network_interface_required","app_network_interfaces_unavailable","tunnel_client_unavailable"},native.Code)>=0)localCreationSubmitted=false;
  }
  async Task ChangeRoleAndShow(string destination){
   if(MessageBox.Show(this,"This computer will disconnect, back up its current settings, and be paired again.","Change this computer's role…",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;
   var stopped=await owner.Call("quitAdmission");if(Json.Str(stopped,"quit","status")!="ready_to_quit")throw new IOException();
   // The C# 5 compiler does not allow await inside catch blocks.
   NativeOperationException refusal=null;object result=null;
   try{result=await owner.Call("retireRole",Json.Obj("allowOtherDevices",false));}catch(NativeOperationException failure){if(failure.Code=="app_cleanup_unknown"){Feedback("This computer has stopped, but the Gateway did not confirm cleanup. Quit and reopen Styx, then change this computer's role to pair again. No settings reset was repeated.");return;}if(failure.Code!="role_retire_gateway_has_devices")throw;refusal=failure;}
   if(refusal!=null){
    var devices=Json.Get(refusal.Retirement,"otherDevices") as object[];if(devices==null||devices.Length==0)throw new IOException();
    var names=new System.Text.StringBuilder();foreach(var device in devices)names.AppendLine(Json.Str(device,"label")+" ("+Json.Str(device,"deviceId")+")");
    using(var dialog=StyxContext.Window("Change this computer's role…",new Size(520,380))){var stack=StyxContext.Stack(dialog);StyxContext.Text(stack,names.ToString(),210);var confirm=StyxContext.Button(stack,"Disconnect these devices too",()=>Task.FromResult(0));confirm.DialogResult=DialogResult.OK;var cancel=StyxContext.Button(stack,"Cancel",()=>Task.FromResult(0));cancel.DialogResult=DialogResult.Cancel;dialog.CancelButton=cancel;if(dialog.ShowDialog(this)!=DialogResult.OK)return;}
    result=await owner.Call("retireRole",Json.Obj("allowOtherDevices",true));
   }
   if(Json.Yes(result,"retirement","restartRequired"))throw new IOException();
   localCreationSubmitted=false;joinOrigin="";joinCa="";await owner.RefreshAfterMutation();
   // Retirement and its fresh status must both prove a clean setup boundary.
   // Never enter Join with pending, fenced or retained role state.
   ShowPage(destination=="join"&&NeedsNativeSetup(owner.CurrentStatus)?"join":"welcome");
  }
  void NativeAction(string title,string operation,Func<Task> action,string pending="Working…"){if(owner.Supports(operation))Action(title,action,true,pending);else Unavailable(title);}
  void CustomMcpGuide(){
   StyxContext.Heading(content,"1. Connect the Gateway to Tunnel");
   Explain("Configure Tunnel on the computer running your Gateway, then check that Tunnel is ready. Joined computers share this Gateway's single Styx plugin; they do not need another Tunnel or plugin.",100);
   StyxContext.Heading(content,"2. Open ChatGPT Plugins");
   Explain("In your intended ChatGPT account and workspace, choose Add > Add custom MCP server. If this Gateway already has a working Styx connection, keep using it.",85);
   Action("Open ChatGPT Plugins",()=>{Process.Start("https://chatgpt.com/plugins");return Task.FromResult(0);},false);
   StyxContext.Heading(content,"3. Set the name and icon");
   Explain("Name: Styx. Save the icon below, then upload it using Choose icon.",55);
   Action("Save Styx icon (under 10 KB)…",()=>{
    var bytes=File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"styx-custom-mcp-icon.png"));
    if(bytes.Length>10000)throw new IOException("The upload icon exceeds the ChatGPT size limit.");
    using(var dialog=new SaveFileDialog {Title="Save Styx upload icon",FileName="Styx.png",Filter="PNG image|*.png",DefaultExt="png",AddExtension=true,OverwritePrompt=true}){
     if(dialog.ShowDialog(this)==DialogResult.OK){File.WriteAllBytes(dialog.FileName,bytes);Feedback("Icon saved. Upload it using Choose icon in ChatGPT.");}
    }
    return Task.FromResult(0);
   },false);
   StyxContext.Heading(content,"4. Fill in the connection fields");
   Explain("Connection: Tunnel\nTunnel ID: the same Tunnel ID saved on your Gateway\nAuthentication: No authentication\nKeep the runtime API key in Styx only; do not paste it into ChatGPT.",120);
   StyxContext.Heading(content,"5. Connect and try Styx");
   Explain("Review the notice, choose Create as a plugin, then Connect. Choose Try in chat and send: List my Styx computers. Check that your Gateway and joined computers appear.",100);
   Explain("If Add custom MCP server is missing, check Developer mode and workspace permissions.",65);
  }
  async Task ShowNativeComputers(){
   var response=await owner.Call("computers");ShowPage("overview");
   var rows=Json.Get(response,"devices") as object[]??new object[0];
   Action("Review pending invitations",ShowNativePending);
   foreach(var row in rows){
    string id=Json.Str(row,"device_id"),name=Json.Str(row,"label");
    Explain(name+" · "+Json.Str(row,"platform")+" · "+(Json.Get(row,"online") is bool?(Json.Yes(row,"online")?"Connected":"Disconnected"):"Status unknown"),40);
    if(!Json.Yes(row,"is_local"))Action("Remove "+name,async()=>{
     if(MessageBox.Show("Revoke access for "+name+"?\n"+id,"Remove computer",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
     await owner.Call("revokeComputer",Json.Obj("authorize",true,"deviceId",id));await ShowNativeComputers();
    });
   }
  }
  async Task InviteNativeComputer(){
   if(!Json.Yes(owner.CurrentStatus,"gateway","lan","enabled")){Feedback("Network joining is not configured. During setup, enable other computers to join and select an available LAN or VPN network.");return;}
   var invitation=await owner.Call("inviteComputer",Json.Obj("authorize",true));
   ShowPage("overview");Explain("On the other computer enter this Gateway address and pairing code. The code authorizes one computer and expires in ten minutes.",90);
   string link=Json.Str(invitation,"link");
   Explain(link,65);
   Action("Copy invitation",()=>{Clipboard.SetText(link);Feedback("Invitation copied. It expires after 10 minutes.");return Task.FromResult(0);},false);
  }
  async Task ShowNativePending(){
   var response=await owner.Call("pendingComputers");ShowPage("overview");
   var rows=Json.Get(response,"pending") as object[]??new object[0];
   if(rows.Length==0)Explain("Waiting for the other computer to request joining.",45);
   foreach(var row in rows){
    string code=Json.Str(row,"comparison_code"),id=Json.Str(row,"device_id"),fingerprint=Json.Str(row,"fingerprint"),request=Json.Str(row,"request_id");
    Explain(id+"\nPublic key fingerprint: "+fingerprint+"\nPairing code: "+code,120);
    Action("Confirm "+code,async()=>{
     if(MessageBox.Show("Does the other computer show this exact code?\n\n"+code+"\n\nApprove requested features: Commands"+(Json.Yes(row,"browser_requested")?", Browser":"")+(Json.Yes(row,"computer_requested")?", Computer Use":""),"Confirm computer",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;
     await owner.Call("approveComputer",Json.Obj("authorize",true,"requestId",request,"deviceId",id,"fingerprint",fingerprint,"comparisonCode",code,"enableComputer",Json.Yes(row,"computer_requested"),"enableBrowser",Json.Yes(row,"browser_requested")));
     await ShowNativePending();Feedback("Approved. Continue joining on the other computer.");
    });
    NativeAction("Reject "+code,"rejectComputer",async()=>{
     if(MessageBox.Show("Reject this exact joining request?\n\nDevice: "+id+"\nFingerprint: "+fingerprint+"\nPairing code: "+code+"\n\nNo access will be granted. The other computer can apply again with a new invitation.","Reject joining request",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
     await owner.Call("rejectComputer",Json.Obj("authorize",true,"requestId",request,"deviceId",id,"fingerprint",fingerprint,"comparisonCode",code));
     await ShowNativePending();Feedback("Request rejected. No access was granted.");
    });
   }
   Action("Refresh joining requests",ShowNativePending);
  }
  async Task EditNativeTunnel(){
   var current=await owner.Call("tunnelStatus");
   using(var dialog=StyxContext.Window("Connect ChatGPT through Tunnel",new Size(560,480))){
    var stack=StyxContext.Stack(dialog);
    StyxContext.Text(stack,"Use the Tunnel ID and runtime API key from your OpenAI Platform tunnel. Saving briefly pauses this App's connections, then reconnects. Finish active tasks first.",90);
    StyxContext.Text(stack,"Tunnel ID",25);var id=new TextBox {Text=Json.Str(current,"tunnelId"),Width=490,AccessibleName="Tunnel ID"};stack.Controls.Add(id);
    StyxContext.Text(stack,"Runtime API key (leave blank to retain the saved key)",40);var key=new TextBox {Width=490,UseSystemPasswordChar=true,AccessibleName="Runtime API key"};stack.Controls.Add(key);
    var save=StyxContext.Button(stack,"Save and connect",()=>Task.FromResult(0));save.DialogResult=DialogResult.OK;
    var cancel=StyxContext.Button(stack,"Cancel",()=>Task.FromResult(0));cancel.DialogResult=DialogResult.Cancel;dialog.CancelButton=cancel;
    if(dialog.ShowDialog(this)!=DialogResult.OK){key.Clear();return;}
    var input=Json.Obj("authorize",true,"tunnelId",id.Text.Trim());if(!String.IsNullOrEmpty(key.Text))input["apiKey"]=key.Text;key.Clear();
    try{await owner.Call("tunnelSave",input);}finally{input.Remove("apiKey");}
    await owner.RefreshAfterMutation();ShowPage("chat");Feedback("Tunnel configuration saved. Check Tunnel status before connecting in ChatGPT.");
   }
  }
  async Task EditNativePlugin(){
   var response=await owner.Call("pluginRead");var current=Json.Get(response,"plugin");var presentation=Json.Get(current,"presentation");var selection=Json.Get(current,"selection");object chosenIcon=Json.Get(presentation,"icon");var defaultIcon=Json.Get(current,"defaultIcon");
   using(var dialog=new Form {Text="Styx plugin details",ClientSize=new Size(620,700),MinimumSize=new Size(560,650),StartPosition=FormStartPosition.CenterParent,Font=Font,AutoScaleMode=AutoScaleMode.Dpi}){
    var layout=new TableLayoutPanel {Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Padding=new Padding(20)};layout.RowStyles.Add(new RowStyle(SizeType.Percent,100));layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));dialog.Controls.Add(layout);
    var fields=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true};layout.Controls.Add(fields,0,0);
    Func<string,string,bool,TextBox> field=(label,value,multiline)=>{fields.Controls.Add(new Label {Text=label,AutoSize=true,Margin=new Padding(0,12,0,4)});var input=new TextBox {Text=value,Width=540,Multiline=multiline,Height=multiline?95:30,AccessibleName=label,ScrollBars=multiline?ScrollBars.Vertical:ScrollBars.None};fields.Controls.Add(input);return input;};
    var name=field("Plugin name",Json.Str(presentation,"displayName"),false);var shortText=field("Short description",Json.Str(presentation,"shortDescription"),false);var longText=field("Full description",Json.Str(presentation,"longDescription"),true);var id=field("Plugin identity",Json.Str(selection,"pluginId"),false);id.ReadOnly=Json.Yes(current,"profileSaved");
    fields.Controls.Add(new Label {Text="Keep the existing identity when updating. Changing the display name keeps this identity.",Width=540,Height=45});
    var previews=new FlowLayoutPanel {Width=540,Height=135};var large=new PictureBox {Width=128,Height=128,SizeMode=PictureBoxSizeMode.Zoom,AccessibleName="Large plugin icon"};var small=new PictureBox {Width=24,Height=24,SizeMode=PictureBoxSizeMode.Zoom,AccessibleName="Small plugin icon"};previews.Controls.Add(large);previews.Controls.Add(small);fields.Controls.Add(previews);
    Action render=()=>{string encoded=Json.Str(chosenIcon??defaultIcon,"dataBase64");if(encoded.Length>350000)throw new IOException("plugin_icon_too_large");byte[] bytes=Convert.FromBase64String(encoded);using(var stream=new MemoryStream(bytes))using(var image=Image.FromStream(stream)){var oldLarge=large.Image;var oldSmall=small.Image;large.Image=new Bitmap(image);small.Image=new Bitmap(image);if(oldLarge!=null)oldLarge.Dispose();if(oldSmall!=null)oldSmall.Dispose();}};
    render();var iconActions=new FlowLayoutPanel {Width=540,Height=40};fields.Controls.Add(iconActions);
    StyxContext.Button(iconActions,"Choose PNG…",()=>{using(var picker=new OpenFileDialog {Filter="PNG image|*.png",CheckFileExists=true}){if(picker.ShowDialog(dialog)==DialogResult.OK){var info=new FileInfo(picker.FileName);if(info.Length>256*1024)throw new IOException("Use a PNG no larger than 256 KB.");byte[] bytes=File.ReadAllBytes(picker.FileName);var previous=chosenIcon;chosenIcon=Json.Obj("mimeType","image/png","dataBase64",Convert.ToBase64String(bytes));try{render();}catch{chosenIcon=previous;throw;}}}return Task.FromResult(0);});
    StyxContext.Button(iconActions,"Restore Styx logo",()=>{chosenIcon=null;render();return Task.FromResult(0);});
    fields.Controls.Add(new Label {Text="Square PNG · 48–1024 pixels · up to 256 KB. Both icon sizes use the same image.",Width=540,Height=45});
    var message=new Label {Width=540,Height=60,ForeColor=Color.FromArgb(140,50,35)};fields.Controls.Add(message);
    var actions=new FlowLayoutPanel {Dock=DockStyle.Fill,AutoSize=true,FlowDirection=FlowDirection.RightToLeft};layout.Controls.Add(actions,0,1);var cancel=new Button {Text="Cancel",AutoSize=true,DialogResult=DialogResult.Cancel};actions.Controls.Add(cancel);dialog.CancelButton=cancel;
    var export=new Button {Text="Save and export ZIP…",AutoSize=true};actions.Controls.Add(export);dialog.AcceptButton=export;
    export.Click+=async(s,e)=>{using(var picker=new SaveFileDialog {Filter="Plugin ZIP|*.zip",FileName="styx-native.zip",AddExtension=true,OverwritePrompt=true}){if(picker.ShowDialog(dialog)!=DialogResult.OK)return;export.Enabled=false;cancel.Enabled=false;dialog.ControlBox=false;try{
      var selected=Json.Obj("mode","update","accountLabel","","pluginUrl","","revision",Json.Get(selection,"revision"),"pluginId",id.Text);
      var saved=await owner.Call("pluginSave",Json.Obj("authorize",true,"presentation",Json.Obj("displayName",name.Text,"shortDescription",shortText.Text,"longDescription",longText.Text,"icon",chosenIcon),"selection",selected));
      current=Json.Get(saved,"plugin");selection=Json.Get(current,"selection");id.ReadOnly=true;
      var archive=await owner.Call("pluginExport",Json.Obj("authorize",true));string encoded=Json.Str(archive,"archiveBase64");if(encoded.Length>1400000)throw new IOException();byte[] bytes=Convert.FromBase64String(encoded);if(bytes.Length<4||bytes[0]!=80||bytes[1]!=75||bytes[2]!=3||bytes[3]!=4)throw new IOException();
      File.WriteAllBytes(picker.FileName,bytes);message.Text="ZIP saved. Update the existing plugin in ChatGPT. Installation and tool acceptance are still to be checked.";
     }catch(Exception){message.Text="Save or export could not be confirmed. Check your Gateway connection and refresh plugin details before retrying. Completed saves are retained.";export.Visible=false;}finally{cancel.Enabled=true;dialog.ControlBox=true;}}};
    try{dialog.ShowDialog(this);}finally{if(large.Image!=null)large.Image.Dispose();if(small.Image!=null)small.Image.Dispose();}
   }
  }
  string NativeSettingsStatus(object data){return StyxContext.ConnectionText(data);}
  static string NativeOverviewKey(object data){return Json.Codec.Serialize(new object[]{Json.Str(data,"enrollment","status"),Json.Str(data,"foreground","error"),Json.Str(data,"foreground","status"),Json.Str(data,"foreground","execConnection"),Json.Get(data,"capabilities"),Json.Str(data,"runtimeUpdate","status"),Json.Yes(data,"runtimeUpdate","can_recover"),Json.Str(data,"runtimeUpdate","transaction_id"),Json.Get(data,"supportedOperations")});}
  sealed class NetworkChoice {
   internal string Name,Address;
   public override string ToString(){return String.IsNullOrEmpty(Address)?Name:Name+" · "+Address;}
  }
  void HostCapabilities(){
   if(!owner.Supports("hostCapabilities")){Explain("Connect this computer to change its capabilities.",45);return;}
    Explain("Turning off a capability stops its existing tasks. Other capabilities and the Gateway connection keep running.",80);
    foreach(string capability in new[]{"exec","browser","computer"}){
     string selectedCapability=capability;
     var toggle=new CheckBox {Text=StyxContext.UI(capability=="computer"?"Computer Use":capability=="browser"?"Browser":"Exec"),Checked=Json.Yes(owner.CurrentStatus,"capabilities","configured",capability),Width=490,Height=32};
     content.Controls.Add(toggle);
     toggle.CheckedChanged+=async(sender,args)=>{toggle.Enabled=false;try{var result=await owner.Call("hostCapabilities",Json.Obj(selectedCapability,toggle.Checked));await owner.RefreshAfterMutation();if(!Json.Yes(result,"applied"))Feedback("Settings have not fully applied. Refresh to check their status.");}catch(Exception){Feedback("The setting result is unconfirmed. Refresh the status before trying again.");}finally{if(!toggle.IsDisposed)toggle.Enabled=true;}};
    }
  }
  void UpdateStatus(){
   string update=Json.Str(owner.CurrentStatus,"runtimeUpdate","status");
   if(update=="committed")Explain(StyxContext.Connected(owner.CurrentStatus)?"Styx is updated and connected.":"Styx is updated. Connection needs attention.",50);
   else if(update=="staging"||update=="staged"||update=="updating")Explain("An update is in progress. Keep Styx open.",50);
   else if(update=="unknown")Explain("The update needs attention. Update Styx continues the original update when recovery is available; your settings are retained.",75);
  }
  void ShowRustPage(string name){
   if(name=="general"){
    StyxContext.Heading(content,"Connection settings");JoinGatewayAction();
    NativeAction("Change this computer's role…","retireRole",ChangeRole);
    StyxContext.Heading(content,"Startup");
    Explain("Closing the window keeps Styx running in the system tray. Choose Quit Styx to stop this session.");
    StyxContext.Button(content,"Quit Styx",owner.RequestQuit);
    NativeAction("Login startup…","appLifecycle",async()=>{ShowPage("login-startup");await ReadLogin();});
    StyxContext.Heading(content,"About Styx");Explain("Styx " + Application.ProductVersion,35);
    if(owner.Supports("updateStyx"))StyxContext.Button(content,"Update Styx…",owner.UpdateStyx);
    else Unavailable("Update Styx…");
    UpdateStatus();
   }else if(name=="host-capabilities"){
    HostCapabilities();
    Action("Refresh",async()=>{await owner.RefreshAfterMutation();ShowPage("host-capabilities");},false);
    Action("Back to General",()=>{ShowPage("general");return Task.FromResult(0);},false);
   }else if(name=="welcome"){

    if(!NeedsNativeSetup(owner.CurrentStatus)){Explain("Your existing settings and setup progress have been retained. Open this computer to review the current status.",65);Action("Open this computer",ContinueJoiningView,false);}
    else{Explain("Set up a local gateway and connect this computer, or join a gateway you already own.",65);NativeAction("Set up this computer","createLocal",()=>{Feedback("");ShowPage("create");return Task.FromResult(0);});JoinGatewayAction();}
    NativeAction("Change this computer's role…","retireRole",ChangeRole);
    NativeAction("Login startup","appLifecycle",async()=>{ShowPage("login-startup");await ReadLogin();});
   }else if(name=="login-startup"){
    Explain("Start Styx in the system tray when you sign in. Windows controls whether the registered entry is allowed to run. Quitting Styx keeps the next-login registration and does not restart this session.",110);
    if(owner.LoginChangeAllowed){NativeAction("Enable login startup","appLogin",async()=>{ApplyLogin(await owner.Call("appLogin",Json.Obj("enabled",true)));});NativeAction("Disable login startup","appLogin",async()=>{ApplyLogin(await owner.Call("appLogin",Json.Obj("enabled",false)));});}
    else Explain("The last change is unconfirmed. Styx will not repeat it. Check Windows startup settings, or quit and reopen Styx to read the system state.",85);
    Action("Windows startup settings",()=>{Process.Start("ms-settings:startupapps");return Task.FromResult(0);},false);NativeAction("Check status","appLifecycle",ReadLogin);
   }else if(name=="create"){
    Capabilities();persist.Checked=false;persist.Enabled=false;
    channel.Items[0]="Choose Microsoft Edge or Google Chrome";channel.Enabled=browser.Checked;browser.CheckedChanged+=(s,e)=>channel.Enabled=browser.Checked;
    Explain("Styx sets up a local gateway and connects this computer. Computer Use is optional and controls only your signed-in desktop when it is available.",85);
    bool resuming=CanResumeLocal();
    var setupTunnel=Input("Tunnel ID");
    var setupKey=Input("Tunnel runtime API key",true);
    bool detecting=false; CheckBox allowLan=null; TextBox lanAddress=null;
    if(!resuming){
     var localDraft=capabilityDrafts[page];
     allowLan=new CheckBox {Text="Let other computers on my network join this Gateway",Checked=localDraft.AllowRemoteHosts,Width=490,Height=48};content.Controls.Add(allowLan);
     var lanLabel=StyxContext.Text(content,"Network for other computers",22);
     var networks=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList,Width=490,AccessibleName="Network for other computers"};content.Controls.Add(networks);
     networks.Items.Add(new NetworkChoice {Name="Automatic",Address=""});networks.SelectedIndex=0;
     var lanHint=StyxContext.Text(content,"Available LAN and VPN addresses are detected automatically. Other computers need access to the selected network.",65);
     var manual=new CheckBox {Text="Advanced: manual interface address",Width=490,Height=32};content.Controls.Add(manual);
     lanAddress=new TextBox {Text=localDraft.LanAddress,Width=490,AccessibleName="Manual interface IPv4 address",Margin=new Padding(0,0,0,12)};content.Controls.Add(lanAddress);
     Func<Task> discover=async()=>{
      if(detecting||networks.IsDisposed||page!="create")return;detecting=true;networks.Enabled=false;
      try{
       var result=await owner.Call("networkInterfaces");if(networks.IsDisposed||page!="create")return;
       var rows=Json.Get(result,"interfaces") as object[]??new object[0];string preferred=String.IsNullOrEmpty(localDraft.LanAddress)?Json.Str(result,"recommendedAddress"):localDraft.LanAddress;
       networks.Items.Clear();networks.Items.Add(new NetworkChoice {Name="Automatic",Address=""});int selected=0;
       foreach(var row in rows){string address=Json.Str(row,"address");if(String.IsNullOrEmpty(address))continue;networks.Items.Add(new NetworkChoice {Name=Json.Str(row,"name"),Address=address});if(address==preferred)selected=networks.Items.Count-1;}
       networks.SelectedIndex=selected;if(!manual.Checked)lanAddress.Text=((NetworkChoice)networks.SelectedItem).Address;
       lanHint.Text=rows.Length==0?"No available LAN or VPN network was found. Connect a network and detect again, or turn off joining for now.":"Available LAN and VPN addresses are detected automatically. Other computers need access to the selected network.";
      }catch{if(!lanHint.IsDisposed)lanHint.Text="This computer's network interfaces could not be read. Detect again.";}
      finally{detecting=false;if(!networks.IsDisposed)networks.Enabled=!manual.Checked;}
     };
     var detect=StyxContext.Button(content,"Detect networks again",()=>owner.Read(discover));
     Action showNetworks=()=>{lanLabel.Visible=networks.Visible=lanHint.Visible=manual.Visible=detect.Visible=allowLan.Checked;lanAddress.Visible=allowLan.Checked&&manual.Checked;networks.Enabled=!detecting&&!manual.Checked;};
     showNetworks();
     allowLan.CheckedChanged+=async(s,e)=>{localDraft.AllowRemoteHosts=allowLan.Checked;showNetworks();if(allowLan.Checked)await owner.Read(discover);};
     manual.CheckedChanged+=(s,e)=>{showNetworks();if(!manual.Checked&&networks.SelectedItem!=null)lanAddress.Text=((NetworkChoice)networks.SelectedItem).Address;};
     networks.SelectedIndexChanged+=(s,e)=>{if(!manual.Checked&&networks.SelectedItem!=null)lanAddress.Text=((NetworkChoice)networks.SelectedItem).Address;};
     lanAddress.TextChanged+=(s,e)=>localDraft.LanAddress=lanAddress.Text;
     if(allowLan.Checked)BeginInvoke(new Action(async()=>await owner.Read(discover)));
    }
    string operation=resuming?"resumeLocal":"createLocal";
    NativeAction(resuming?"Continue setup":"Prepare this computer",operation,async()=>{
     if(resuming&&!CanResumeLocal())throw new IOException("app_local_checkpoint_refused");
     if(detecting){Feedback("Wait for network detection to finish before continuing.");return;}
     if(!resuming&&!NeedsNativeSetup(owner.CurrentStatus))throw new IOException("app_setup_requires_review");
     if(browser.Checked&&channel.SelectedIndex==0){Feedback("Choose Microsoft Edge or Google Chrome before requesting Browser Automation.");return;}
     string tunnelId=setupTunnel.Text.Trim();
     if(!System.Text.RegularExpressions.Regex.IsMatch(tunnelId,@"\Atunnel_[A-Za-z0-9_-]{8,128}\z")||
        !System.Text.RegularExpressions.Regex.IsMatch(setupKey.Text,@"\Ask-[A-Za-z0-9_-]{16,512}\z")){
      Feedback("Enter the Tunnel ID and runtime API key from OpenAI Platform to create your Gateway.");return;
     }
     var choice=Choice();if(!browser.Checked)choice["browserChannel"]=null;
     if(resuming){
      var origin=new Uri(Json.Str(owner.CurrentStatus,"gateway","origin"));
      choice["port"]=origin.Port;
     }else{
      choice["allowRemoteHosts"]=allowLan.Checked;
      if(allowLan.Checked&&!String.IsNullOrWhiteSpace(lanAddress.Text))choice["lanAddress"]=lanAddress.Text.Trim();
     }
     // Duplicate-submit guard only; Core owns all durable setup state. One
     // request, with Core's default port 22022. Failure only reads status.
     choice["tunnel"]=Json.Obj("tunnelId",tunnelId,"apiKey",setupKey.Text);setupKey.Clear();
     localCreationSubmitted=true;
     // The installed Framework compiler is C# 5: keep awaits outside
     // catch/finally while preserving the original mutation failure and stack.
     Exception setupFailure=null;
     try{await owner.Call(operation,choice);}catch(Exception failure){setupFailure=failure;}finally{choice.Remove("tunnel");}
     object observed=null;try{await owner.RefreshAfterMutation();observed=owner.CurrentStatus;}catch{}
     ApplySetupFailure(setupFailure,observed);ShowPage(setupFailure!=null&&!localCreationSubmitted?"create":"overview");
     if(setupFailure!=null)System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(setupFailure).Throw();
    });
    Action("Return",()=>{ShowPage("welcome");return Task.FromResult(0);},false);
   }else if(name=="join"){
    Capabilities();persist.Checked=false;persist.Enabled=false;
    channel.Items[0]="Choose Microsoft Edge or Google Chrome";channel.Enabled=browser.Checked;browser.CheckedChanged+=(s,e)=>channel.Enabled=browser.Checked;
    Explain("Choose the features to enable on this computer. Computer Use requires an available signed-in desktop. Browser Automation uses a separate, temporary profile.",85);
    joinOrigin="";joinCa="";link=Input("Gateway address and pairing code (or paste invitation)",true);
    NativeAction("Review pairing link","inspectJoin",async()=>{joinOrigin="";joinCa="";string invitation=link.Text;link.Clear();var result=await owner.Call("inspectJoin",Json.Obj("link",invitation));if(String.IsNullOrEmpty(Json.Str(result,"inspectionId")))throw new IOException();joinOrigin=Json.Str(result,"preview","origin");joinCa=Json.Str(result,"preview","caSha256");Feedback("Gateway: "+joinOrigin+"\nCertificate SHA-256: "+(joinCa.Length>0?joinCa:"System trust is not supported in this slice")+"\nExpires: "+Convert.ToString(Json.Get(result,"preview","expiresAt"))+"\nConfirm this Gateway to join.");});
    NativeAction("Trust this Gateway and send request","join",async()=>{if(String.IsNullOrEmpty(joinOrigin))throw new InvalidOperationException();if(String.IsNullOrEmpty(joinCa))throw new NativeOperationException("app_system_trust_not_supported");if(browser.Checked&&channel.SelectedIndex==0){Feedback("Choose Microsoft Edge or Google Chrome before requesting Browser Automation.");return;}var choice=Choice();if(!browser.Checked)choice["browserChannel"]=null;choice["approvedGatewayOrigin"]=joinOrigin;choice["approvedCaSha256"]=joinCa;joinOrigin="";joinCa="";var result=await owner.Call("join",choice);string joined=Json.Str(result,"status");if(joined!="ready_to_connect"&&joined!="awaiting_approval")throw new IOException();await owner.RefreshAfterMutation();ShowPage("overview");Feedback(joined=="ready_to_connect"?"This computer is paired.":"Waiting for approval of the original invitation.");},JoinRequestProgress);
    Action("Return",()=>{ShowPage("welcome");return Task.FromResult(0);},false);
   }else if(name=="overview"||name=="join-waiting"){
    string enrollment=Json.Str(owner.CurrentStatus,"enrollment","status");
    StyxContext.Heading(content,"This computer");
    Explain(NativeSettingsStatus(owner.CurrentStatus),55);
    if(enrollment=="awaiting_approval"){
     Explain("Waiting for the original invitation to be approved.",45);
     NativeAction("Check approval","claimJoin",async()=>{await owner.Call("claimJoin");await owner.RefreshAfterMutation();ShowPage("overview");});
    }else if(!StyxContext.Connected(owner.CurrentStatus)&&Json.Str(owner.CurrentStatus,"foreground","status")!="started"&&Json.Str(owner.CurrentStatus,"foreground","error")!="gateway_wss_admission_refused")NativeAction("Reconnect","connect",async()=>{await owner.Call("connect");await owner.RefreshAfterMutation();ShowPage("overview");});
    StyxContext.Heading(content,"What ChatGPT can do on this computer");
    HostCapabilities();
    if(Json.Get(owner.CurrentStatus,"gateway")!=null){
     StyxContext.Heading(content,"Other computers");
     NativeAction("Computers…","computers",ShowNativeComputers);
     NativeAction("Add computer…","inviteComputer",InviteNativeComputer);
    }else Explain("This computer is connected through your main computer. Manage the ChatGPT connection there.",65);
   }else if(name=="chat"){
    if(owner.Supports("tunnelSave")){NativeAction("Configure Tunnel…","tunnelSave",EditNativeTunnel);NativeAction("Check Tunnel status","tunnelStatus",async()=>{var value=await owner.Call("tunnelStatus");Feedback(Json.Str(value,"tunnelId")+"\n"+Json.Str(value,"status")+" / "+Json.Str(value,"transport"));});}
    if(owner.Supports("tunnelSave")){CustomMcpGuide();RefreshAction();}
    else if(NeedsNativeSetup(owner.CurrentStatus)){
     StyxContext.Heading(content,"Finish setting up Styx");
     Explain("Set up this computer or join an existing Gateway first. Then configure ChatGPT on your main computer.");
     Action("Open setup",()=>{ShowPage("welcome");return Task.FromResult(0);},false);
    }else{
     StyxContext.Heading(content,"Managed on the main computer");
     Explain("This computer uses the main computer's Styx connection. Configure ChatGPT on the computer that invited you.");
     Action("Open ChatGPT Plugins",()=>{Process.Start("https://chatgpt.com/plugins");return Task.FromResult(0);},false);
    }
   }
   else{Explain("This operation is not implemented by the native Host App. Existing identities and configuration are retained.",80);Unavailable("Legacy operation");Action("Open this computer",ContinueJoiningView,false);}
   if(name=="overview"||name=="join-waiting"||name=="general")renderedRustOverviewKey=NativeOverviewKey(owner.CurrentStatus);
   Status("");content.Controls.Add(statusReadout);content.Controls.Add(observationError);content.Controls.Add(feedback);
  }

  void SetText(Label target,string text,int minimum){target.Text=StyxContext.UI(text);target.Height=String.IsNullOrEmpty(text)?0:Math.Max(minimum,TextRenderer.MeasureText(text,Font,new Size(490,0),TextFormatFlags.WordBreak).Height+20);}
  internal void Feedback(string text){SetText(feedback,text,60);}
  internal bool HasFeedback(string text){return feedback.Text==text;}
  void Status(string text){SetText(statusReadout,text,65);}
  internal void ObservationFailed(string text){SetText(observationError,text,45);}
  internal void ShowStatus(object data){
   if(owner.RustHost){SetText(observationError,"",0);if(page=="welcome"&&!NeedsNativeSetup(data)){ShowPage("overview");return;}if((page=="overview"||page=="join-waiting"||page=="general")&&renderedRustOverviewKey!=NativeOverviewKey(data)){ShowPage(page);return;}Status("");return;}
  }
  internal void Verify(){
   owner.ApplyPreparationResult(Json.Obj("mode","rust_host","status",Json.Obj(),"supportedOperations",new object[]{"createLocal","inspectJoin"}));
   foreach(string name in new[]{"welcome","create","join","overview","general","chat","login-startup"}){ShowPage(name);if(content.Controls.Count<3)throw new Exception("native_page_failed");}
   ShowPage("join");label.Text="Joining draft";exec.Checked=false;computer.Checked=false;browser.Checked=true;channel.SelectedIndex=1;
   Feedback("Keep this operation failure");
   ShowStatus(owner.CurrentStatus);if(feedback.Text!="Keep this operation failure")throw new Exception("refresh_discarded_error");
   ShowPage("general");ShowPage("join");var joining=Choice();if((string)joining["label"]!="Joining draft"||(bool)joining["exec"]||(bool)joining["computer"]||!(bool)joining["browser"]||(string)joining["browserChannel"]!="msedge")throw new Exception("joining_capability_choice_discarded");
   // Actual native controls: tab navigation must retain fresh setup, while
   // existing, pending and fenced roles must never offer recreation.
   object previousStatus=owner.CurrentStatus;
   owner.ApplyPreparationResult(Json.Obj("mode","rust_host","status",Json.Obj(),"supportedOperations",new object[]{"createLocal","inspectJoin"}));
   ShowPage("general");ShowPage("chat");ShowPage("overview");
   bool freshJoin=false;foreach(Control control in content.Controls)if(control is Button&&control.Text=="Join an existing Gateway"&&control.Enabled)freshJoin=true;
   if(page!="welcome"||!freshJoin)throw new Exception("native_fresh_tab_navigation_lost_join");
   foreach(string field in new[]{"configuration","enrollment","gateway","admission_fenced"}){
    var existing=Json.Obj("mode","rust_host","status",Json.Obj(),"supportedOperations",new object[]{"createLocal","inspectJoin"});
    existing[field]=field=="admission_fenced"?(object)true:Json.Obj("status","retained");
    owner.ApplyPreparationResult(existing);ShowPage("overview");
    if(page=="welcome")throw new Exception("native_retained_role_navigation_offered_fresh_setup");
   }
   owner.ApplyPreparationResult(previousStatus);
   Feedback("");ShowPage("welcome");Show();CreateControl();PerformLayout();Application.DoEvents();using(var image=new Bitmap(Width,Height)){DrawToBitmap(image,new Rectangle(0,0,Width,Height));image.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"native-settings.png"));}}
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
 // Local current-user owner endpoint. It requests the same Quit path as the
 // tray; it cannot execute commands, change a profile or stop another owner.
 sealed class LocalAppControl:IDisposable {
  [StructLayout(LayoutKind.Sequential)]struct Information {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle file,out Information info);
  readonly Microsoft.Win32.SafeHandles.SafeFileHandle profilePin;
  readonly System.IO.Pipes.NamedPipeServerStream[] pipes;
  readonly string root,state,sid;Task serving;int disposed;
  internal LocalAppControl(string resources,string directory){
   root=Path.GetFullPath(resources).TrimEnd('\\');state=Path.GetFullPath(directory).TrimEnd('\\');
   PrivateAppFiles.PrepareOwnerDirectory(state);NativeBootstrap.NoRedirect(state);
   sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
   profilePin=CreateFileW(state,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   try{
    Information info;if(profilePin.IsInvalid||!GetFileInformationByHandle(profilePin,out info)||(info.Attributes&0x410)!=0x10)throw new IOException("app_control_profile_refused");
    ulong fileId=((ulong)info.IndexHigh<<32)|info.IndexLow;
    string name="Styx.AppControl.v1."+sid+"."+((ulong)info.Volume).ToString("x16")+"."+fileId.ToString("x16");
    var security=new System.IO.Pipes.PipeSecurity();var user=new System.Security.Principal.SecurityIdentifier(sid);security.SetOwner(user);security.SetAccessRuleProtection(true,false);security.AddAccessRule(new System.IO.Pipes.PipeAccessRule(user,System.IO.Pipes.PipeAccessRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
    pipes=new System.IO.Pipes.NamedPipeServerStream[2];
    try{for(int i=0;i<pipes.Length;i++)pipes[i]=new System.IO.Pipes.NamedPipeServerStream(name,System.IO.Pipes.PipeDirection.InOut,2,System.IO.Pipes.PipeTransmissionMode.Byte,System.IO.Pipes.PipeOptions.Asynchronous,4096,4096,security);}catch{foreach(var item in pipes)if(item!=null)item.Dispose();throw;}
   }catch{profilePin.Dispose();throw;}
  }
  static Task<string> Frame(StreamReader reader){return Core.ReadLineBounded(reader,8192);}
  internal void Start(Func<string,Task<object>> onUi,Action exit){
   if(serving!=null)throw new IOException("app_control_already_started");
   var tasks=new Task[pipes.Length];for(int i=0;i<pipes.Length;i++)tasks[i]=Serve(pipes[i],onUi,exit);serving=Task.WhenAll(tasks);
  }
  Task Serve(System.IO.Pipes.NamedPipeServerStream pipe,Func<string,Task<object>> onUi,Action exit){
   return Task.Run(async()=>{
    while(Volatile.Read(ref disposed)==0){
     bool ready=false;
     try{
      await Task.Factory.FromAsync(pipe.BeginWaitForConnection,pipe.EndWaitForConnection,null).ConfigureAwait(false);
      using(var peer=MaintenancePeer.Connected(pipe,false)){
       // The caller is the fixed CLI bundled with this original App. A path,
       // caller-supplied PID or a second profile does not confer authority.
       if(!MaintenancePeer.Same(peer.MainModule.FileName,Path.Combine(root,"native","bin","styx.exe")))throw new IOException("app_control_caller_refused");
       using(var reader=new StreamReader(pipe,new System.Text.UTF8Encoding(false,true),false,4096,true))
       using(var writer=new StreamWriter(pipe,new System.Text.UTF8Encoding(false,true),4096,true)){
        var codec=new JavaScriptSerializer {MaxJsonLength=8192};
        using(var self=Process.GetCurrentProcess()){
         var core=await onUi("identity").ConfigureAwait(false);
         await writer.WriteLineAsync(codec.Serialize(Json.Obj("schema",1,"kind","styx-local-app-owner","pid",self.Id,"creationFileTime",MaintenancePeer.Birth(self),"ownerSid",sid,"stateDirectory",state,"core",core))).ConfigureAwait(false);await writer.FlushAsync().ConfigureAwait(false);
        }
        string line=await Frame(reader).ConfigureAwait(false);if(line==null)throw new IOException("app_control_request_missing");
        var request=codec.DeserializeObject(line);var fields=request as Dictionary<string,object>;
        string operation=Json.Str(request,"operation"),id=Json.Str(request,"id");
        if(fields==null||fields.Count!=4||!Equals(Json.Get(request,"schema"),1)||!System.Text.RegularExpressions.Regex.IsMatch(id,"\\A[a-f0-9]{32}\\z")||(operation!="quit"&&operation!="status")||!MaintenancePeer.Same(Json.Str(request,"stateDirectory"),state)||peer.HasExited)throw new IOException("app_control_request_invalid");
        // Await the original UI task. Client disconnect/timeout cannot cancel,
        // replay or substitute its admitted shutdown.
        object result=await onUi(operation).ConfigureAwait(false);ready=operation=="quit"&&Json.Str(result,"status")=="ready_to_exit";
        await writer.WriteLineAsync(codec.Serialize(Json.Obj("schema",1,"id",id,"result",result))).ConfigureAwait(false);await writer.FlushAsync().ConfigureAwait(false);
       }
      }
     }catch(IOException){}catch(ObjectDisposedException){break;}catch(System.ComponentModel.Win32Exception){}catch(InvalidOperationException){}catch(ArgumentException){}
     finally{
      if(ready){try{exit();}catch(InvalidOperationException){} }
      if(Volatile.Read(ref disposed)==0){try{pipe.Disconnect();}catch(IOException){}catch(InvalidOperationException){}}
     }
    }
   });
  }
  public void Dispose(){if(Interlocked.Exchange(ref disposed,1)==0){foreach(var item in pipes)item.Dispose();profilePin.Dispose();}}
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
    LocalAppControl control=null;
    if(!test&&!startupTest){try{control=new LocalAppControl(root,state);}catch(IOException){MessageBox.Show("Styx could not open its local control connection. Your settings have been retained.","Styx",MessageBoxButtons.OK,MessageBoxIcon.Information);return 3;}}
    var app=new StyxContext(root,state,test,startupTest,fromLogin,control);
    if(test){app.Verify();app.Quit();File.WriteAllText(Path.Combine(root,"native-self-test.json"),"{\"status\":\"PASS\",\"pages\":7,\"uiConstruction\":true,\"nativeSetupStateRendering\":true,\"editingState\":true,\"desktopAcceptance\":\"NOT RUN\",\"serviceMutation\":\"NOT RUN\"}");return 0;}
    Application.Run(app);InstallCoordination.KeepAlive();return app.ResultCode;
   }catch{if(!test&&!startupTest)MessageBox.Show("Styx could not open. Check that the app resources and runtime are present.","Styx",MessageBoxButtons.OK,MessageBoxIcon.Information);return 2;}
  }
 }
}
