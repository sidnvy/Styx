using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace StyxNative {
 // A connected local pipe identifies a kernel process, never a caller PID claim.
 static class LocalProcessPeer {
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint process);
  [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe,out uint process);
  [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr process,uint rights,out IntPtr token);
  [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
  internal static string Birth(Process process){return process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(System.Globalization.CultureInfo.InvariantCulture);}
  internal static string Owner(Process process){IntPtr token;if(!OpenProcessToken(process.Handle,0x000A,out token))throw new IOException("app_process_owner_unknown");try{using(var identity=new System.Security.Principal.WindowsIdentity(token))return identity.User.Value;}finally{CloseHandle(token);}}
  internal static Process Connected(System.IO.Pipes.PipeStream pipe,bool server){uint pid;bool ok=server?GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid):GetNamedPipeClientProcessId(pipe.SafePipeHandle,out pid);if(!ok||pid==0||pid>Int32.MaxValue)throw new IOException("app_peer_unknown");var process=Process.GetProcessById((int)pid);try{IntPtr held=process.Handle;if(process.HasExited||Owner(process)!=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value)throw new IOException("app_peer_changed");return process;}catch{process.Dispose();throw;}}
  internal static bool Same(string a,string b){return String.Equals(Path.GetFullPath(a).TrimEnd('\\'),Path.GetFullPath(b).TrimEnd('\\'),StringComparison.OrdinalIgnoreCase);}
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
      using(var peer=LocalProcessPeer.Connected(pipe,false)){
       // The caller is the fixed CLI bundled with this original App. A path,
       // caller-supplied PID or a second profile does not confer authority.
       if(!LocalProcessPeer.Same(peer.MainModule.FileName,Path.Combine(root,"native","bin","styx.exe")))throw new IOException("app_control_caller_refused");
       using(var reader=new StreamReader(pipe,new System.Text.UTF8Encoding(false,true),false,4096,true))
       using(var writer=new StreamWriter(pipe,new System.Text.UTF8Encoding(false,true),4096,true)){
        var codec=new JavaScriptSerializer {MaxJsonLength=8192};
        using(var self=Process.GetCurrentProcess()){
         var core=await onUi("identity").ConfigureAwait(false);
         await writer.WriteLineAsync(codec.Serialize(Json.Obj("schema",1,"kind","styx-local-app-owner","pid",self.Id,"creationFileTime",LocalProcessPeer.Birth(self),"ownerSid",sid,"stateDirectory",state,"core",core))).ConfigureAwait(false);await writer.FlushAsync().ConfigureAwait(false);
        }
        string line=await Frame(reader).ConfigureAwait(false);if(line==null)throw new IOException("app_control_request_missing");
        var request=codec.DeserializeObject(line);var fields=request as Dictionary<string,object>;
        string operation=Json.Str(request,"operation"),id=Json.Str(request,"id");
        if(fields==null||fields.Count!=4||!Equals(Json.Get(request,"schema"),1)||!System.Text.RegularExpressions.Regex.IsMatch(id,"\\A[a-f0-9]{32}\\z")||(operation!="quit"&&operation!="status")||!LocalProcessPeer.Same(Json.Str(request,"stateDirectory"),state)||peer.HasExited)throw new IOException("app_control_request_invalid");
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
}
