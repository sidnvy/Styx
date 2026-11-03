// Native WinForms/Core pipe regression fixtures, never a signed product App or
// Host/Gateway acceptance. Compiled separately with STYX_QUIT_TEST only.
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace StyxNative {
 static class QuitLifecycleTest {
  const BindingFlags Fields=BindingFlags.Instance|BindingFlags.NonPublic;
  static object Get(object value,string name){return value.GetType().GetField(name,Fields).GetValue(value);}
  static void Set(object value,string name,object data){value.GetType().GetField(name,Fields).SetValue(value,data);}
  static void Check(bool value,string code){if(!value)throw new Exception(code);}
  static async Task Until(Func<bool> ready,int seconds){var until=DateTime.UtcNow.AddSeconds(seconds);while(!ready()){if(DateTime.UtcNow>until)throw new Exception("fixture_deadline");await Task.Delay(20);}}
  static int Child(string mode,string dir){
   if(mode=="worker"){Console.In.ReadLine();return 0;}
   using(var worker=new Process {StartInfo=new ProcessStartInfo(Application.ExecutablePath,"--child worker \""+dir+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true}}){
    if(mode=="active"){worker.Start();File.WriteAllText(Path.Combine(dir,"worker"),worker.Id.ToString());}
    File.WriteAllText(Path.Combine(dir,"core-ready"),"ready");
    if(mode=="failed"||mode=="startup-failed"||mode=="crashed"){return 101;}
    string line;int calls=0;
    while((line=Console.ReadLine())!=null){
     var request=Json.Codec.DeserializeObject(line);calls++;File.WriteAllText(Path.Combine(dir,"calls"),calls.ToString());
     if(mode.StartsWith("observe",StringComparison.Ordinal)&&Json.Str(request,"operation")=="status"){
      string state=calls==1?"connected":"disconnected";System.Threading.Thread.Sleep(150);
      Console.WriteLine(Json.Codec.Serialize(Json.Obj("id",Convert.ToInt32(Json.Get(request,"id")),"ok",true,"result",Json.Obj("mode","rust_host","supportedOperations",new object[]{"status","quitAdmission","fixtureFailure"},"foreground",Json.Obj("status",state=="connected"?"connected":"started","execConnection",state)))));Console.Out.Flush();continue;
     }
     if(mode=="observe-mutation"&&Json.Str(request,"operation")=="fixtureFailure"){
      Console.WriteLine(Json.Codec.Serialize(Json.Obj("id",Convert.ToInt32(Json.Get(request,"id")),"ok",false,"error","fixture_failure")));Console.Out.Flush();continue;
     }
     bool refuse=mode=="busy"&&!File.Exists(Path.Combine(dir,"release"));
     if(worker.IdSafe()!=0){worker.StandardInput.Close();worker.WaitForExit();File.WriteAllText(Path.Combine(dir,"worker-exit"),worker.ExitCode.ToString());}
     if(mode=="active"||mode=="disconnected"||mode=="busy")System.Threading.Thread.Sleep(150);
     int id=Convert.ToInt32(Json.Get(request,"id"));
     Console.WriteLine(Json.Codec.Serialize(Json.Obj("id",mode=="lost"?id+1:id,"ok",!refuse,"error",refuse?"app_runtime_update_in_progress":null,"result",Json.Obj("quit",Json.Obj("status","ready_to_quit","ticketId",new string('a',32))))));Console.Out.Flush();
    }
    if(mode=="slow"||mode=="dispose")while(!File.Exists(Path.Combine(dir,"release")))System.Threading.Thread.Sleep(20);
    // Larger than ordinary OS pipe buffers: the owner must drain while waiting.
    Console.Out.Write(new string('x',128*1024));Console.Error.Write(new string('e',128*1024));
    return 0;
   }
  }
  static int IdSafe(this Process p){try{return p.Id;}catch(InvalidOperationException){return 0;}}
  [STAThread]static int Main(string[] args){
   if(args.Length==3&&args[0]=="--child")return Child(args[1],args[2]);
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   string resources=args[0],dir=args[1],mode=args[2];Directory.CreateDirectory(dir);
   if(mode=="reservation"){
    using(var first=new LocalAppControl(resources,Path.Combine(dir,"profile"))){
     bool refused=false;try{using(var duplicate=new LocalAppControl(resources,Path.Combine(dir,"profile"))){} }catch(IOException){refused=true;}
     Check(refused,"duplicate_profile_owner_accepted");using(var other=new LocalAppControl(resources,Path.Combine(dir,"other-profile"))){}
    }
    File.WriteAllText(Path.Combine(dir,"result.json"),Json.Codec.Serialize(Json.Obj("status","PASS","mode",mode,"scope","native_profile_pipe_reservation_not_host_acceptance")));return 0;
   }
   if(mode=="bootstrap"){
    string payload=Path.Combine(dir,"native"),bin=Path.Combine(payload,"bin");Directory.CreateDirectory(bin);string cli=Path.Combine(bin,"styx.exe");File.Copy(Application.ExecutablePath,cli);string manifest=Path.Combine(payload,"manifest.json");File.WriteAllText(manifest,"{}");File.WriteAllText(Path.Combine(dir,"native-publisher.pem"),"public fixture only");string cliSha,manifestSha;using(var f=File.OpenRead(cli))cliSha=NativeBootstrap.Hash(f);using(var f=File.OpenRead(manifest))manifestSha=NativeBootstrap.Hash(f);
    File.WriteAllText(Path.Combine(dir,"windows-runtime.json"),Json.Codec.Serialize(Json.Obj("schema",1,"nativeRuntime",Json.Obj("schema",1,"cli","native/bin/styx.exe","payload","native","publisher","native-publisher.pem","publisherSpkiSha256",NativeBootstrap.PublisherPin,"cliSha256",cliSha,"manifestSha256",manifestSha))));
    using(var pin=new NativeBootstrap(dir)){
     bool writeRefused=false,replaceRefused=false;try{File.WriteAllText(cli,"changed");}catch(IOException){writeRefused=true;}try{File.Move(cli,cli+".moved");}catch(IOException){replaceRefused=true;}
     Check(writeRefused&&replaceRefused,"original_cli_pin_did_not_exclude_write_and_delete");pin.Validate();pin.Validate();
    }
    File.WriteAllText(cli,"changed after dispose");bool changed=false;try{using(var pin=new NativeBootstrap(dir)){} }catch(IOException){changed=true;}Check(changed,"new_lifetime_skipped_hash");
    File.WriteAllText(Path.Combine(dir,"result.json"),Json.Codec.Serialize(Json.Obj("status","PASS","mode",mode,"scope","real_file_pin_not_signed_payload_acceptance")));return 0;
   }
   var context=new StyxContext(resources,dir,true);var settings=(Settings)Get(context,"settings");settings.CreateControl();var handle=settings.Handle;
   int code=2;Process child=null,owned=null;Core core=null;
   settings.BeginInvoke(new Action(async()=>{
    try{
     owned=new Process {StartInfo=new ProcessStartInfo(Application.ExecutablePath,"--child "+mode+" \""+dir+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true}};
     Check(owned.Start(),"child_start_failed");child=Process.GetProcessById(owned.Id);var held=child.Handle;core=new Core(owned);Set(context,"core",core);
     await Until(()=>File.Exists(Path.Combine(dir,"core-ready")),5);
     if(mode=="failed"||mode=="startup-failed"||mode=="crashed"){await Task.Run(()=>child.WaitForExit());if(mode!="crashed"){core.Dispose();Check(core.ObservedExit!=null&&!core.CleanupConfirmed,"abnormal_exit_not_observed");}if(mode=="startup-failed"){Set(context,"core",null);Set(context,"startupCoreExit",core.ObservedExit);}}
     if(mode=="dispose"){
      var disposing=Task.Run(()=>core.Dispose());await Task.Delay(10500);Check(!child.HasExited&&!disposing.IsCompleted,"ordinary_cleanup_force_killed_original_core");File.WriteAllText(Path.Combine(dir,"release"),"release");await disposing;Check(core.CleanupConfirmed,"ordinary_eof_not_joined");
     }
     if(mode.StartsWith("observe",StringComparison.Ordinal)){
      Set(context,"snapshot",Json.Obj("mode","rust_host","supportedOperations",new object[]{"status","quitAdmission","fixtureFailure"},"foreground",Json.Obj("status","started","execConnection","connecting")));
      Set(context,"snapshot",Json.Obj("mode","rust_host","supportedOperations",new object[]{"status","quitAdmission","fixtureFailure"},"configuration",Json.Obj(),"foreground",Json.Obj("status","started","execConnection","connecting")));settings.ShowStatus(Get(context,"snapshot"));
      var content=(FlowLayoutPanel)Get(settings,"content");var draft=new TextBox {Text="keep this draft"};content.Controls.Add(draft);
      if(mode=="observe-mutation"){
       var reading=(Task)typeof(StyxContext).GetMethod("ObserveStatus",Fields).Invoke(context,null);
       await Until(()=>File.Exists(Path.Combine(dir,"calls")),5);
       await context.Run(async()=>{await context.Call("fixtureFailure");},"changing fixture…","fixture mutation failed");await reading;
       Check(settings.Enabled&&settings.HasFeedback("fixture mutation failed"),"mutation_feedback_or_controls_lost");
       Check(Json.Str(Get(context,"snapshot"),"foreground","execConnection")=="connecting","invalidated_read_overwrote_mutation");
      }
      var timer=(System.Windows.Forms.Timer)Get(context,"statusTimer");timer.Start();
      if(mode=="observe")await Until(()=>Json.Str(Get(context,"snapshot"),"foreground","execConnection")=="connected",5);
      await Until(()=>Json.Str(Get(context,"snapshot"),"foreground","execConnection")=="disconnected",5);timer.Stop();
      Check(File.ReadAllText(Path.Combine(dir,"calls"))==(mode=="observe"?"2":"3"),"status_observation_backlog");if(mode=="observe-mutation")Check(settings.HasFeedback("fixture mutation failed"),"poll_erased_mutation_failure");Check(!draft.IsDisposed&&draft.Parent==content&&draft.Text=="keep this draft","observation_rebuilt_controls_or_lost_draft");
     }
     var first=context.RequestQuitResult();var second=context.RequestQuitResult();Check(Object.ReferenceEquals(first,second),"quit_dispatched_twice");
     if(mode=="slow"){
      await Task.Delay(10500);Check(!child.HasExited&&!first.IsCompleted,"quit_force_killed_original_core");
      var status=(Task<object>)typeof(StyxContext).GetMethod("LocalControlOnUi",Fields).Invoke(context,new object[]{"status"});Check(Json.Str(await status,"status")=="stopping","pending_quit_status_missing");File.WriteAllText(Path.Combine(dir,"release"),"release");
     }
     var result=await first;
     if(mode=="busy"){
      Check(Json.Str(result,"status")=="busy"&&!child.HasExited,"busy_core_was_stopped");Check(File.ReadAllText(Path.Combine(dir,"calls"))=="1","busy_quit_replayed");File.WriteAllText(Path.Combine(dir,"release"),"release");result=await context.RequestQuitResult();
     }
     Check(Json.Str(result,"status")=="ready_to_exit"&&child.HasExited,"quit_did_not_wait_for_exit");
     if(mode=="lost"){
      Check(Json.Str(result,"code")=="app_quit_admission_unconfirmed"&&context.ResultCode==4,"lost_response_promoted_to_clean");
      Check(File.ReadAllText(Path.Combine(dir,"calls"))=="1","unknown_quit_replayed");
     }else if(mode=="failed"||mode=="startup-failed"||mode=="crashed"){
      Check(Json.Str(result,"code")!=null&&context.ResultCode==4,"abnormal_exit_reported_clean");
     }else Check(child.ExitCode==0&&core.CleanupConfirmed,"clean_exit_not_confirmed");
     if(mode=="active")Check(File.ReadAllText(Path.Combine(dir,"worker-exit"))=="0","owned_worker_not_joined");
     File.WriteAllText(Path.Combine(dir,"result.json"),Json.Codec.Serialize(Json.Obj("status","PASS","mode",mode,"quitStatus",Json.Str(result,"status"),"scope","native_winforms_pipe_lifecycle_fixture_not_host_acceptance","coreExit",child.ExitCode,"cleanupConfirmed",core.CleanupConfirmed,"calls",File.Exists(Path.Combine(dir,"calls"))?File.ReadAllText(Path.Combine(dir,"calls")):"0")));code=0;
    }catch(Exception e){File.WriteAllText(Path.Combine(dir,"failure.txt"),e.ToString());}
    {
     if(child!=null&&!child.HasExited){try{owned.StandardInput.Close();File.WriteAllText(Path.Combine(dir,"release"),"cleanup");await Task.Run(()=>child.WaitForExit());if(core!=null)await core.SettleQuit();}catch{}}
     context.Quit();Application.ExitThread();
    }
   }));
   Application.Run(context);return code;
  }
 }
}
