using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
namespace StyxNative {
 static class UiSettleTest {
  static readonly BindingFlags Fields=BindingFlags.Instance|BindingFlags.NonPublic;
  static object Get(object value,string name){return value.GetType().GetField(name,Fields).GetValue(value);}
  static void Set(object value,string name,object data){value.GetType().GetField(name,Fields).SetValue(value,data);}
  static void Check(bool valid,string name){if(!valid)throw new Exception(name);}
  [STAThread]static int Main(string[] args){
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   int result=2;var context=new StyxContext(args[0],args[1],true);var settings=(Settings)Get(context,"settings");
   settings.Shown+=async(sender,eventArgs)=>{
    try {
     Set(context,"core",new Core(args[0],args[1],CancellationToken.None));
     Set(context,"snapshot",Json.Obj("loadingDetails",true,"session",Json.Obj("hostPayloadHandoffSupported",true)));
     settings.ShowPage("chat");
     var observation=(Task)typeof(StyxContext).GetMethod("ObserveStatus",Fields).Invoke(context,null);
     if(args[2].StartsWith("auto-")){
      await observation;
      var first=await context.Call("counts");int expected=args[2]=="auto-fails"?1:0;
      Check(Convert.ToInt32(Json.Get(first,"updates"))==expected,"bootstrap_update_not_once_or_unapproved");
      Check(!context.ManagementOnly&&(string)Get(settings,"page")=="update-recovery","bootstrap_reconciliation_hidden_as_reading");
      if(expected==1)Check(((Label)Get(settings,"feedback")).Text.Contains("The update could not be started"),"bootstrap_failure_missing");
      await context.Refresh();var later=await context.Call("counts");
      Check(Convert.ToInt32(Json.Get(later,"updates"))==expected,"bootstrap_failure_replayed_on_refresh");
      Check(settings.Enabled&&!context.MutationBusy,"bootstrap_failure_disabled_recovery");
      File.WriteAllText(args[3],"PASS");result=0;return;
     }
     const string failure="Fixture update failed; review before retrying.";
     await context.Run(async()=>{await context.Call("runtimeUpgradePrepare");},"Preparing fixture update…",failure);
     Check(settings.Enabled&&!context.MutationBusy,"controls_not_reenabled");
     var deadline=DateTime.UtcNow.AddSeconds(4);
     while(context.ManagementOnly&&DateTime.UtcNow<deadline&&((Label)Get(settings,"observationError")).Text.Length==0)await Task.Delay(20);
     var counts=await context.Call("counts");
     Check(Convert.ToInt32(Json.Get(counts,"updates"))==1,"mutation_replayed");
     Check(Convert.ToInt32(Json.Get(counts,"reads"))==2,"invalidated_read_not_replaced_once");
     Check(settings.HasFeedback(failure),"mutation_failure_lost");
     if(args[2]=="read-fails"){
      Check(context.ManagementOnly,"unknown_misreported_as_ready");
      Check(((Label)Get(settings,"observationError")).Text.Contains("Refresh status"),"read_retry_not_available");
      await Task.Delay(200);counts=await context.Call("counts");Check(Convert.ToInt32(Json.Get(counts,"reads"))==2,"read_retried_without_user");
     }else{
      Check(!context.ManagementOnly,"reading_stuck_after_failure");
      Check((string)Get(settings,"page")== (args[2]=="recovery"?"update-recovery":"chat"),"requested_page_not_restored");
      if(args[2]=="success")Check(((TextBox)Get(settings,"tunnel")).Enabled,"settings_not_editable");
     }
     await observation;File.WriteAllText(args[3],"PASS");result=0;
    }catch(Exception error){File.WriteAllText(args[3],error.ToString());}
    finally{context.Quit();}
   };
   settings.Show();Application.Run(context);return result;
  }
 }
}
