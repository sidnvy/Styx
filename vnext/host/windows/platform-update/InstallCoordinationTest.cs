using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using StyxNative;

internal static class InstallCoordinationTest {
 static void Check(bool condition,string reason){if(!condition)throw new Exception(reason);}
 static int Gate(string binary,string root){using(var p=Process.Start(new ProcessStartInfo(binary,"check \""+root+"\""){UseShellExecute=false,CreateNoWindow=true})){p.WaitForExit();return p.ExitCode;}}
 [STAThread]static int Main(string[] args){
  if(args.Length==1&&args[0]=="child"){Console.WriteLine("ready");Console.Out.Flush();Console.ReadLine();return 0;}
  try{
   string root=args[0],gate=args[1],version=Path.Combine(root,"versions",new string('a',64));Directory.CreateDirectory(version);
   string scope=InstallCoordination.Scope(root);Check(scope==InstallCoordination.Scope(version),"version_mutex_mismatch");
   Check(scope==InstallCoordination.Scope(Path.Combine(root,"releases","11111111-1111-1111-1111-111111111111")),"legacy_mutex_mismatch");
   using(var setup=new Mutex(false,"Global\\Styx.Install."+scope))Check(!InstallCoordination.Enter(version),"app_started_during_setup");
   Check(InstallCoordination.Enter(version),"app_did_not_recover_after_setup");
   Mutex held;Check(Mutex.TryOpenExisting("Global\\Styx.App."+scope,out held),"app_mutex_not_held");held.Dispose();
   string child=Path.Combine(version,"fixture.exe");File.Copy(System.Reflection.Assembly.GetExecutingAssembly().Location,child);
   File.WriteAllText(Path.Combine(version,"windows-package.json"),"{\"files\":[{\"path\":\"fixture.exe\"}]}");
   Check(Gate(gate,root)==0,"idle_install_rejected");
   using(var p=Process.Start(new ProcessStartInfo(child,"child"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true})){
    try{Check(p.StandardOutput.ReadLine()=="ready","child_not_ready");Check(Gate(gate,root)==1,"restart_manager_missed_running_package");}
    finally{p.StandardInput.Close();if(!p.WaitForExit(5000)){p.Kill();p.WaitForExit();}}
   }
   Check(Gate(gate,root)==0,"normal_exit_not_observed");Console.WriteLine("PASS mutex scope, setup admission, native Restart Manager busy/idle");return 0;
  }catch(Exception error){Console.Error.WriteLine(error.Message);return 1;}
 }
}
