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
     bool refuse=mode=="busy"&&!File.Exists(Path.Combine(dir,"release"));
     if(worker.IdSafe()!=0){worker.StandardInput.Close();worker.WaitForExit();File.WriteAllText(Path.Combine(dir,"worker-exit"),worker.ExitCode.ToString());}
     if(mode=="active"||mode=="disconnected"||mode=="busy")System.Threading.Thread.Sleep(150);
     int id=Convert.ToInt32(Json.Get(request,"id"));
     Console.WriteLine(Json.Codec.Serialize(Json.Obj("id",mode=="lost"?id+1:id,"ok",!refuse,"error",refuse?"app_runtime_update_in_progress":null,"result",Json.Obj("quit",Json.Obj("status","ready_to_quit","ticketId",new string('a',32))))));Console.Out.Flush();
    }
    if(mode=="slow")while(!File.Exists(Path.Combine(dir,"release")))System.Threading.Thread.Sleep(20);
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
   var context=new StyxContext(resources,dir,true);var settings=(Settings)Get(context,"settings");settings.CreateControl();var handle=settings.Handle;
   int code=2;Process child=null,owned=null;Core core=null;
   settings.BeginInvoke(new Action(async()=>{
    try{
     owned=new Process {StartInfo=new ProcessStartInfo(Application.ExecutablePath,"--child "+mode+" \""+dir+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true}};
     Check(owned.Start(),"child_start_failed");child=Process.GetProcessById(owned.Id);var held=child.Handle;core=new Core(owned);Set(context,"core",core);
     await Until(()=>File.Exists(Path.Combine(dir,"core-ready")),5);
     if(mode=="failed"||mode=="startup-failed"||mode=="crashed"){await Task.Run(()=>child.WaitForExit());if(mode!="crashed"){core.Dispose();Check(core.ObservedExit!=null&&!core.CleanupConfirmed,"abnormal_exit_not_observed");}if(mode=="startup-failed"){Set(context,"core",null);Set(context,"startupCoreExit",core.ObservedExit);}}
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
