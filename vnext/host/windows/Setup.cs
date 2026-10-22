using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Threading;
using System.Security.Principal;
using System.Windows.Forms;
internal sealed class StyxSetup:Form {
 readonly Label status=new Label();readonly Button install=new Button(),rollback=new Button(),open=new Button();readonly ProgressBar progress=new ProgressBar();readonly CheckBox desktop=new CheckBox();
 readonly string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Programs","Styx");string staging;bool busy;readonly Mutex installationMutex=new Mutex(false,"Local\\Styx.Setup."+WindowsIdentity.GetCurrent().User.Value);
 StyxSetup(){Text="Styx Setup";ClientSize=new Size(490,310);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;StartPosition=FormStartPosition.CenterScreen;
  var title=new Label{Text="Install Styx",Font=new Font(SystemFonts.MessageBoxFont.FontFamily,20),AutoSize=true,Location=new Point(26,24)};
  status.SetBounds(28,75,434,85);status.Text="Install for your Windows account. Device settings and paired computers are kept when updating.\n\nDevelopment preview — publisher signature is not verified.";
  progress.SetBounds(28,175,434,12);desktop.SetBounds(28,198,420,24);desktop.Text="Add a desktop shortcut";desktop.Checked=true;
  install.Text=File.Exists(Path.Combine(root,"installation.json"))?"Update":"Install";install.SetBounds(350,253,112,30);rollback.Text="Restore previous";rollback.SetBounds(28,253,145,30);rollback.Enabled=File.Exists(Path.Combine(root,"installation.json"));open.Text="Open Styx";open.SetBounds(225,253,112,30);open.Visible=false;
  Controls.AddRange(new Control[]{title,status,progress,desktop,install,rollback,open});install.Click+=async(s,e)=>await Run(false);rollback.Click+=async(s,e)=>await Run(true);open.Click+=(s,e)=>{try{Process.Start(new ProcessStartInfo(Path.Combine(root,"Styx.exe")){UseShellExecute=true});Close();}catch{status.Text="Styx could not open. Your installation has been retained. Try opening Styx from the Start menu.";}};
  FormClosing+=(s,e)=>{if(busy)e.Cancel=true;};FormClosed+=(s,e)=>{if(staging!=null)try{Directory.Delete(staging,true);}catch{}};
 }
 static string Quote(string text){if(text.Contains("\"")||text.Contains("\r")||text.Contains("\n"))throw new ArgumentException();return "\""+text+"\"";}
 void Report(string message){BeginInvoke((Action)(()=>status.Text=message));}
 void Extract(){staging=Path.Combine(Path.GetTempPath(),"StyxSetup-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(staging);
  using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("StyxPayload.zip"))using(var zip=new ZipArchive(stream,ZipArchiveMode.Read)){
   int done=0;foreach(var entry in zip.Entries){var destination=Path.GetFullPath(Path.Combine(staging,entry.FullName));if(!destination.StartsWith(staging+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException();Directory.CreateDirectory(Path.GetDirectoryName(destination));using(var input=entry.Open())using(var output=new FileStream(destination,FileMode.CreateNew))input.CopyTo(output);if(++done%128==0)Report("Preparing installation… "+done+" / "+zip.Entries.Count);}
  }
 }
 static string LinkTarget(string file){var type=Type.GetTypeFromProgID("WScript.Shell");object shell=null,link=null;try{shell=Activator.CreateInstance(type);link=type.InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{file});return (string)link.GetType().InvokeMember("TargetPath",BindingFlags.GetProperty,null,link,null);}finally{if(link!=null)Marshal.ReleaseComObject(link);if(shell!=null)Marshal.ReleaseComObject(shell);}}
 static void Shortcut(string file,string target,bool preflight){if(File.Exists(file)&&!String.Equals(LinkTarget(file),target,StringComparison.OrdinalIgnoreCase))throw new IOException("A different Styx shortcut already exists: "+file);if(preflight)return;var type=Type.GetTypeFromProgID("WScript.Shell");object shell=null,link=null;try{shell=Activator.CreateInstance(type);link=type.InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{file});var t=link.GetType();t.InvokeMember("TargetPath",BindingFlags.SetProperty,null,link,new object[]{target});t.InvokeMember("WorkingDirectory",BindingFlags.SetProperty,null,link,new object[]{Path.GetDirectoryName(target)});t.InvokeMember("Description",BindingFlags.SetProperty,null,link,new object[]{"Styx"});t.InvokeMember("Save",BindingFlags.InvokeMethod,null,link,null);}finally{if(link!=null)Marshal.ReleaseComObject(link);if(shell!=null)Marshal.ReleaseComObject(shell);}}
 async Task Run(bool restore){bool ownsMutex;try{ownsMutex=installationMutex.WaitOne(0);}catch(AbandonedMutexException){ownsMutex=true;}if(!ownsMutex){status.Text="Another Styx Setup is running. Close it, then retry here.";return;}busy=true;install.Enabled=false;rollback.Enabled=false;desktop.Enabled=false;progress.Style=ProgressBarStyle.Marquee;status.Text=restore?"Checking the previous version…":"Preparing installation…";
  try{string target=Path.Combine(root,"Styx.exe"),start=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),"Styx.lnk"),desk=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),"Styx.lnk");bool addDesktop=desktop.Checked;
   // COM shortcut operations stay on the STA UI thread; existing unrelated links are never replaced.
   Shortcut(start,target,true);if(addDesktop)Shortcut(desk,target,true);
   await Task.Run(()=>{if(staging==null)Extract();Directory.CreateDirectory(Path.GetDirectoryName(root));var package=Path.Combine(staging,"package");var info=new ProcessStartInfo(Path.Combine(package,"runtime","node.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};info.Arguments=Quote(Path.Combine(package,"vnext","host","windows","setup-install.mjs"))+" "+(restore?"rollback":"install")+" "+Quote(root)+(restore?"":" "+Quote(Path.Combine(staging,"StyxLauncher.exe")))+" --native-mutex-held";
    using(var child=new Process{StartInfo=info}){child.OutputDataReceived+=(s,e)=>{if(e.Data!=null)Report(restore?"Verifying and restoring the previous version…":"Checking files and installing Styx…");};child.Start();child.BeginOutputReadLine();var error=child.StandardError.ReadToEnd();child.WaitForExit();if(child.ExitCode!=0)throw new InvalidOperationException(error.Length>0?error:"The installation could not be completed.");}
   });Shortcut(start,target,false);if(addDesktop)Shortcut(desk,target,false);status.Text=restore?"Previous version restored. Close Styx if it is running, then open it again. Your device settings are kept.":"Styx is installed. If Styx is already running, quit it before opening this version. Your device settings are kept.";open.Visible=true;install.Text="Done";install.Visible=false;rollback.Visible=false;
  }catch(Exception error){status.Text="Setup could not finish. Existing versions and device settings are retained.\n"+error.Message;install.Text="Retry";install.Enabled=true;rollback.Enabled=File.Exists(Path.Combine(root,"installation.json"));desktop.Enabled=true;}
  finally{busy=false;progress.Style=ProgressBarStyle.Blocks;installationMutex.ReleaseMutex();}
 }
 [STAThread]static void Main(){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new StyxSetup());}
}
