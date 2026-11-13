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
  static Button FindButton(Settings settings,string title){foreach(Control c in ((FlowLayoutPanel)Get(settings,"content")).Controls)if(c is Button&&c.Text==title)return (Button)c;return null;}
  static bool HasText(Settings settings,string text){foreach(Control c in ((FlowLayoutPanel)Get(settings,"content")).Controls)if(c.Text.Contains(text))return true;return false;}
  static async Task Until(Func<bool> ready,int seconds){var until=DateTime.UtcNow.AddSeconds(seconds);while(!ready()){if(DateTime.UtcNow>until)throw new Exception("fixture_deadline");await Task.Delay(20);}}
  static int Child(string mode,string dir){
   if(mode=="worker"){Console.In.ReadLine();return 0;}
   using(var worker=new Process {StartInfo=new ProcessStartInfo(Application.ExecutablePath,"--child worker \""+dir+"\""){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true}}){
    if(mode=="active"){worker.Start();File.WriteAllText(Path.Combine(dir,"worker"),worker.Id.ToString());}
    File.WriteAllText(Path.Combine(dir,"core-ready"),"ready");
    if(mode=="failed"||mode=="startup-failed"||mode=="crashed"){return 101;}
    string line;int calls=0,quitCalls=0;
    while((line=Console.ReadLine())!=null){
     var request=Json.Codec.DeserializeObject(line);calls++;File.WriteAllText(Path.Combine(dir,"calls"),calls.ToString());
     if(Json.Str(request,"operation")=="quitAdmission"){quitCalls++;File.WriteAllText(Path.Combine(dir,"quit-calls"),quitCalls.ToString());}
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
   if(mode=="capability-draft"){
    var operations=new object[]{"status","quitAdmission","createLocal","inspectJoin","join","retireRole"};
    var fresh=Json.Obj("mode","rust_host","supportedOperations",operations);
    Set(context,"snapshot",fresh);settings.ShowPage("general");
    var freshJoin=FindButton(settings,"Join an existing Gateway");Check(freshJoin!=null&&freshJoin.Enabled,"fresh_general_join_missing");
    ((Task)typeof(Settings).GetMethod("JoinGateway",Fields).Invoke(settings,null)).GetAwaiter().GetResult();
    Check(Equals(Get(settings,"page"),"join"),"fresh_join_entry_did_not_open_join");
    var setupFailure=typeof(Settings).GetMethod("ApplySetupFailure",Fields);
    foreach(string inputCode in new[]{"app_input_invalid","app_lan_address_invalid","app_network_interface_changed","app_network_interface_required","app_network_interfaces_unavailable"}){
     Set(settings,"localCreationSubmitted",true);setupFailure.Invoke(settings,new object[]{new NativeOperationException(inputCode),fresh});
     Check(Equals(Get(settings,"localCreationSubmitted"),false),"known_pre_input_refusal_kept_submit_guard");
     settings.ShowPage("general");Check(FindButton(settings,"Join an existing Gateway")!=null,"known_pre_input_refusal_hid_join");
    }
    foreach(Exception failure in new Exception[]{new IOException("unconfirmed transport"),new NativeOperationException("app_runtime_bootstrap_unknown")}){
     Set(settings,"localCreationSubmitted",true);setupFailure.Invoke(settings,new object[]{failure,fresh});
     Check(Equals(Get(settings,"localCreationSubmitted"),true),"unknown_setup_cleared_submit_guard");
     settings.ShowPage("general");var blocked=FindButton(settings,"Join another Gateway…");
     Check(blocked!=null&&!blocked.Enabled&&HasText(settings,"unconfirmed"),"unknown_setup_offered_new_join");
    }
    foreach(object observed in new object[]{null,Json.Obj("admission_fenced",true),Json.Obj("enrollment",Json.Obj("status","incomplete"))}){
     Set(settings,"localCreationSubmitted",true);setupFailure.Invoke(settings,new object[]{new NativeOperationException("app_input_invalid"),observed});
     Check(Equals(Get(settings,"localCreationSubmitted"),true),"input_error_without_fresh_empty_status_cleared_guard");
    }
    Set(settings,"localCreationSubmitted",false);
    foreach(string field in new[]{"gateway","configuration","enrollment","admission_fenced"}){
     Set(context,"snapshot",fresh);settings.ShowPage("welcome");
     var retained=Json.Obj("mode","rust_host","supportedOperations",operations);
     retained[field]=field=="admission_fenced"?(object)true:Json.Obj("status","incomplete");
     Set(context,"snapshot",retained);settings.ShowStatus(retained);
     Check(Equals(Get(settings,"page"),"overview"),"retained_setup_status_left_welcome_join");
     settings.ShowPage("general");var another=FindButton(settings,"Join another Gateway…");
     Check(another!=null&&another.Enabled==(field!="admission_fenced"),"retained_gateway_entry_ignored_review_boundary");
     if(field=="admission_fenced")Check(HasText(settings,"unconfirmed"),"fenced_setup_warning_hidden");
    }
    Set(context,"snapshot",Json.Obj("mode","rust_host","enrollment",Json.Obj("status","awaiting_approval"),"supportedOperations",operations));
    settings.ShowPage("general");Check(FindButton(settings,"Join another Gateway…")!=null&&FindButton(settings,"Join an existing Gateway")==null,"pending_join_offered_direct_fresh_setup");
    settings.ShowPage("overview");Check(HasText(settings,"Join request sent — waiting for Gateway approval")&&FindButton(settings,"Check Gateway approval")!=null,"pending_join_did_not_explain_gateway_approval");
    Set(context,"snapshot",Json.Obj("mode","rust_host","gateway",Json.Obj(),"supportedOperations",new object[]{"tunnelSave","tunnelStatus"}));settings.ShowPage("chat");
    foreach(string step in new[]{"1. Connect the Gateway to Tunnel","2. Open ChatGPT Plugins","3. Set the name and icon","4. Fill in the connection fields","5. Connect and try Styx"})Check(HasText(settings,step),"chatgpt_setup_step_missing");
    Check(HasText(settings,"single Styx plugin")&&HasText(settings,"Authentication: No authentication")&&HasText(settings,"runtime API key in Styx only"),"chatgpt_gateway_fields_or_key_boundary_missing");
    Set(context,"snapshot",fresh);settings.ShowPage("chat");Check(!HasText(settings,"4. Fill in the connection fields"),"host_offered_gateway_tunnel_configuration");
    foreach(string page in new[]{"create","join"}){
     settings.ShowPage(page);var computer=(CheckBox)Get(settings,"computer");Check(computer.Enabled&&!computer.Checked,"fresh_desktop_not_explicit_opt_in");computer.Checked=true;
     var choice=(System.Collections.Generic.Dictionary<string,object>)typeof(Settings).GetMethod("Choice",Fields).Invoke(settings,null);Check(Equals(choice["computer"],true),"desktop_choice_not_sent_to_core");
     settings.ShowPage("overview");settings.ShowPage(page);Check(((CheckBox)Get(settings,"computer")).Enabled&&((CheckBox)Get(settings,"computer")).Checked,"desktop_draft_reset_on_navigation");
    }
    File.WriteAllText(Path.Combine(dir,"result.json"),Json.Codec.Serialize(Json.Obj("status","PASS","mode",mode,"scope","native_controls_choice_not_setup_or_pairing_acceptance")));context.Quit();return 0;
   }
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
      if(mode=="observe"){
       // Exercise the real message loop while a once-only write is deferred.
       // No network or join response is fabricated by this callback fixture.
       settings.Show();var releaseWrite=new TaskCompletionSource<bool>();int dispatches=0;
       var waiting=context.Run(async()=>{dispatches++;await releaseWrite.Task;},Settings.JoinRequestProgress);
       try{
        var progress=(ProgressBar)Get(settings,"startupProgress");var area=(TableLayoutPanel)Get(settings,"startupPanel");
        Check(settings.Enabled&&area.Visible&&progress.Visible&&progress.Style==ProgressBarStyle.Marquee,"pending_write_disabled_window_or_hid_progress");
        Check(((Label)Get(settings,"startupText")).Text==Settings.JoinRequestProgress,"pending_join_progress_not_explicit");
        Check(!((FlowLayoutPanel)Get(settings,"navigation")).Enabled&&!((FlowLayoutPanel)Get(settings,"content")).Enabled,"pending_write_inputs_not_locked");
        bool pumped=false;settings.BeginInvoke(new Action(()=>{pumped=true;}));await Until(()=>pumped,5);
        await context.Run(()=>{dispatches++;return Task.FromResult(0);},Settings.JoinRequestProgress);
        Check(dispatches==1&&!waiting.IsCompleted,"pending_write_was_replayed_or_not_deferred");
       }finally{releaseWrite.TrySetResult(true);}
       await waiting;
       Check(settings.Enabled&&!context.MutationBusy&&!((TableLayoutPanel)Get(settings,"startupPanel")).Visible&&((FlowLayoutPanel)Get(settings,"content")).Enabled&&((FlowLayoutPanel)Get(settings,"navigation")).Enabled,"completed_write_did_not_release_busy_ui");
       settings.Hide();
      }
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
     File.WriteAllText(Path.Combine(dir,"result.json"),Json.Codec.Serialize(Json.Obj("status","PASS","mode",mode,"quitStatus",Json.Str(result,"status"),"scope","native_winforms_pipe_lifecycle_fixture_not_host_acceptance","coreExit",child.ExitCode,"cleanupConfirmed",core.CleanupConfirmed,"calls",File.Exists(Path.Combine(dir,"calls"))?File.ReadAllText(Path.Combine(dir,"calls")):"0","quitCalls",File.Exists(Path.Combine(dir,"quit-calls"))?File.ReadAllText(Path.Combine(dir,"quit-calls")):"0")));code=0;
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
