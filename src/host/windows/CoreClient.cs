using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace StyxNative {
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
  internal object OwnedIdentity(){var p=child;if(p==null||Volatile.Read(ref closed)!=0||p.HasExited)throw new IOException("app_core_unavailable");IntPtr held=p.Handle;return Json.Obj("pid",p.Id,"creationFileTime",LocalProcessPeer.Birth(p));}
  internal async Task BeginShutdown(){await gate.WaitAsync();try{if(Volatile.Read(ref closed)!=0||pendingRead!=null||child==null||child.HasExited||Interlocked.CompareExchange(ref shutdownCustody,1,0)!=0)throw new IOException("app_core_custody_unavailable");}finally{gate.Release();}}
  internal void CancelShutdown(){if(Volatile.Read(ref closed)!=0||pendingRead!=null)throw new IOException("app_core_custody_unknown");Interlocked.Exchange(ref shutdownCustody,0);}
  internal async Task<object> SettleQuit(){
   await gate.WaitAsync();try{
    var p=child;
    if(p==null||(Volatile.Read(ref shutdownCustody)!=1&&!p.HasExited)||Interlocked.CompareExchange(ref closed,1,0)!=0)throw new IOException("app_core_custody_unknown");
    Interlocked.Exchange(ref shutdownCustody,1);
    int pid=p.Id;string birth=LocalProcessPeer.Birth(p);p.StandardInput.Close();
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
    ReleasePins();cancellationRegistration.Dispose();p.Dispose();child=null;
    return ObservedExit;
   }finally{gate.Release();}
  }
  public void Dispose(){
   // An explicit Quit retains its original process and readers until actual exit.
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
    ObservedExit=Json.Obj("pid",p.Id,"creationFileTime",LocalProcessPeer.Birth(p),"exitCode",p.ExitCode,"stdinEof",true,"ioJoined",clean);CleanupConfirmed=clean&&p.ExitCode==0;p.Dispose();child=null;
   }else if(p!=null){p.Dispose();child=null;}ReleasePins();cancellationRegistration.Dispose();
  }
 }
}
