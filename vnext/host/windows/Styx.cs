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
 sealed class Core:IDisposable {
  readonly SemaphoreSlim gate=new SemaphoreSlim(1,1); Process child;int sequence;
  internal Core(string root,string state){
   var manifest=Json.Codec.DeserializeObject(File.ReadAllText(Path.Combine(root,"windows-runtime.json")));
   string binary=Path.Combine(root,"runtime","node.exe");string expected=Json.Str(manifest,"node","sha256");
   using(var sha=System.Security.Cryptography.SHA256.Create())using(var stream=File.OpenRead(binary)){string actual=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();if(actual!=expected)throw new IOException();}
   var info=new ProcessStartInfo(Path.Combine(root,"runtime","node.exe"),"\""+Path.Combine(root,"vnext","host","windows","core-bridge.mjs")+"\"");
   info.WorkingDirectory=root;info.UseShellExecute=false;info.CreateNoWindow=true;info.RedirectStandardInput=true;info.RedirectStandardOutput=true;info.RedirectStandardError=true;
   info.EnvironmentVariables["STYX_NATIVE_RESOURCES"]=root;info.EnvironmentVariables["STYX_NATIVE_STATE"]=state;
   child=new Process { StartInfo=info };child.ErrorDataReceived+=(s,e)=>{};child.Start();child.BeginErrorReadLine();
  }
  internal async Task<object> Call(string operation,Dictionary<string,object> input){
   await gate.WaitAsync();try{if(child==null||child.HasExited)throw new IOException();int id=++sequence;
    await child.StandardInput.WriteLineAsync(Json.Codec.Serialize(Json.Obj("schema",1,"id",id,"operation",operation,"input",input)));await child.StandardInput.FlushAsync();
    // Mutations are not replayed after a lost response. The user returns to Settings.
    var read=child.StandardOutput.ReadLineAsync();if(await Task.WhenAny(read,Task.Delay(150000))!=read){Dispose();throw new IOException();}
    var line=await read;if(line==null||line.Length>2097152)throw new IOException();var response=Json.Codec.DeserializeObject(line);
    if(!Json.Yes(response,"ok")||Convert.ToInt32(Json.Get(response,"id"))!=id)throw new IOException();return Json.Get(response,"result");
   }finally{gate.Release();}
  }
  public void Dispose(){var p=child;child=null;if(p==null)return;try{p.StandardInput.Close();if(!p.WaitForExit(10000))p.Kill();}catch{}p.Dispose();}
 }
 sealed class StyxContext:ApplicationContext {
  readonly string root;readonly NotifyIcon tray;readonly Icon icon;readonly Form panel;readonly Settings settings;Core core;bool busy,closing;object snapshot;readonly Label message;
  [DllImport("user32.dll")]static extern bool DestroyIcon(IntPtr hIcon);
  internal static Icon BrandIcon(string file){using(var original=Image.FromFile(file))using(var bitmap=new Bitmap(original,new Size(32,32))){IntPtr handle=bitmap.GetHicon();try{return (Icon)Icon.FromHandle(handle).Clone();}finally{DestroyIcon(handle);}}}
  internal StyxContext(string resourceRoot,string state,bool test){
   root=resourceRoot;icon=BrandIcon(Path.Combine(root,"styx-logo.png"));
   panel=Window("Styx",new Size(340,420));panel.ShowInTaskbar=false;panel.FormBorderStyle=FormBorderStyle.FixedToolWindow;
   var stack=Stack(panel);Logo(stack,64);Heading(stack,"Your computer, connected");
   message=Text(stack,"Open Settings to get started.",110);
   Button(stack,"Reconnect",async()=>{await Run(async()=>{await Call("connect");await Refresh();});});
   Button(stack,"Pause connection",async()=>{await Run(async()=>{await Call("disconnect");await Refresh();});});
   Button(stack,"Settings",()=>{OpenSettings();return Task.FromResult(0);});
   panel.FormClosing+=(s,e)=>{if(!closing){e.Cancel=true;panel.Hide();}};
   settings=new Settings(this,icon);tray=new NotifyIcon { Icon=icon,Text="Styx — open to view connection",Visible=!test };
   var menu=new ContextMenuStrip();menu.Items.Add("Open Styx",null,(s,e)=>ShowPanel());menu.Items.Add("Settings",null,(s,e)=>OpenSettings());menu.Items.Add("Quit Styx",null,(s,e)=>Quit());tray.ContextMenuStrip=menu;tray.MouseClick+=(s,e)=>{if(e.Button==MouseButtons.Left)ShowPanel();};
   if(!test){try{core=new Core(root,state);}catch{message.Text="Connection unavailable. Open Settings to review the installation.";}settings.Shown+=async(s,e)=>await Run(Refresh);OpenSettings();}
  }
  internal static Form Window(string title,Size size){return new Form { Text=title,ClientSize=size,StartPosition=FormStartPosition.CenterScreen,BackColor=Color.FromArgb(249,249,247),Font=new Font("Segoe UI",10),AutoScaleMode=AutoScaleMode.Dpi,MinimumSize=size };}
  internal static FlowLayoutPanel Stack(Control parent){var p=new FlowLayoutPanel { Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(24) };parent.Controls.Add(p);return p;}
  internal static Label Text(Control p,string text,int height){var l=new Label {Text=text,Width=p.ClientSize.Width>100?p.ClientSize.Width-55:440,Height=height,Margin=new Padding(0,5,0,10),AutoSize=false};p.Controls.Add(l);return l;}
  internal static void Heading(Control p,string text){var l=Text(p,text,40);l.Font=new Font("Segoe UI Semibold",17);}
  internal static Button Button(Control p,string text,Func<Task> action){var b=new Button {Text=text,AutoSize=true,MinimumSize=new Size(210,36),FlatStyle=FlatStyle.System,Margin=new Padding(0,5,0,5)};b.Click+=async(s,e)=>await action();p.Controls.Add(b);return b;}
  internal void Logo(Control p,int size){p.Controls.Add(new PictureBox { Image=Image.FromFile(Path.Combine(root,"styx-logo.png")),SizeMode=PictureBoxSizeMode.Zoom,Width=size,Height=size,Margin=new Padding(0,0,0,15) });}
  void ShowPanel(){var bounds=Screen.PrimaryScreen.WorkingArea;panel.Location=new Point(bounds.Right-panel.Width-12,bounds.Bottom-panel.Height-12);panel.Show();panel.Activate();}
  void OpenSettings(){settings.Show();settings.Activate();}
  internal async Task Run(Func<Task> action){if(busy)return;busy=true;settings.Enabled=false;message.Text="Checking this computer…";try{await action();}catch{message.Text="Connection needs attention. Return to Settings and refresh before retrying.";settings.Feedback("The operation could not be confirmed. Refresh to review current state. Completed steps are retained; an interrupted operation is not automatically repeated.");}finally{settings.Enabled=true;busy=false;}}
  internal async Task<object> Call(string op,Dictionary<string,object> input=null){if(core==null)throw new IOException();return await core.Call(op,input??Json.Obj());}
  internal async Task Refresh(){snapshot=await Call("status");var f=Json.Str(snapshot,"status","foreground","status");var exec=Json.Str(snapshot,"status","foreground","execConnection");
   message.Text=f=="connected"&&exec=="connected"?"Connected to this computer.\n\nExec transport is online. Tool and ChatGPT checks are shown in Settings.":f=="started"?"Connecting…\n\nKeep Styx open while this computer connects.":"Connection is paused or unavailable.\n\nOpen Settings to review, prepare or reconnect.";
   tray.Text=f=="connected"?"Styx — connected":"Styx — needs attention";settings.ShowStatus(snapshot);
  }
  internal void Quit(){if(closing)return;closing=true;tray.Visible=false;settings.Close();panel.Close();if(core!=null)core.Dispose();tray.Dispose();icon.Dispose();ExitThread();}
  internal void Verify(){if(panel.Controls.Count!=1||settings.Controls.Count!=1||icon.Width<16)throw new Exception("native_shell_failed");settings.Verify();}
 }
 sealed class Settings:Form {
  readonly StyxContext owner;readonly FlowLayoutPanel content;readonly Label feedback;string page="welcome",joinOrigin,joinCa,challengeId;TextBox label,link,tunnel,key;CheckBox computer,browser,persist;ComboBox channel;
  internal Settings(StyxContext context,Icon icon){owner=context;Text="Styx Settings";Icon=icon;ClientSize=new Size(590,720);MinimumSize=new Size(550,650);Font=new Font("Segoe UI",10);BackColor=Color.FromArgb(249,249,247);AutoScaleMode=AutoScaleMode.Dpi;StartPosition=FormStartPosition.CenterScreen;var outer=new TableLayoutPanel { Dock=DockStyle.Fill,RowCount=2,ColumnCount=1,Padding=new Padding(0) };outer.RowStyles.Add(new RowStyle(SizeType.Absolute,62));outer.RowStyles.Add(new RowStyle(SizeType.Percent,100));Controls.Add(outer);var nav=new FlowLayoutPanel { Dock=DockStyle.Fill,WrapContents=false,Padding=new Padding(15,8,0,0) };outer.Controls.Add(nav,0,0);StyxContext.Button(nav,"General",()=>{ShowPage("welcome");return Task.FromResult(0);}).MinimumSize=new Size(100,32);StyxContext.Button(nav,"Computers",()=>{ShowPage("overview");return Task.FromResult(0);}).MinimumSize=new Size(100,32);StyxContext.Button(nav,"ChatGPT",()=>{ShowPage("chat");return Task.FromResult(0);}).MinimumSize=new Size(100,32);foreach(Control item in nav.Controls){item.AutoSize=false;item.Width=165;item.Height=36;}content=new FlowLayoutPanel {Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(26)};outer.Controls.Add(content,0,1);feedback=new Label {Width=490,Height=100,ForeColor=Color.FromArgb(95,70,35)};FormClosing+=(s,e)=>{if(e.CloseReason==CloseReason.UserClosing){e.Cancel=true;Hide();}};ShowPage("welcome");}
  void Action(string title,Func<Task> action){StyxContext.Button(content,title,()=>owner.Run(action));}
  TextBox Input(string title,bool secret=false){StyxContext.Text(content,title,22);var box=new TextBox {Width=490,UseSystemPasswordChar=secret,Margin=new Padding(0,0,0,12)};content.Controls.Add(box);return box;}
  void Explain(string text,int height=65){StyxContext.Text(content,text,height);}
  void Capabilities(){label=Input("Computer name");label.Text=Environment.MachineName;computer=new CheckBox {Text="Computer Use — control the signed-in desktop",Checked=true,Width=490,Height=32};browser=new CheckBox {Text="Browser Automation — dedicated Styx profile",Checked=false,Width=490,Height=32};content.Controls.Add(new CheckBox {Text="Exec — run commands on this computer",Checked=true,Enabled=false,Width=490,Height=32});content.Controls.Add(computer);content.Controls.Add(browser);channel=new ComboBox {DropDownStyle=ComboBoxStyle.DropDownList,Width=240};channel.Items.AddRange(new object[]{"Automatic (Chrome / Edge)","Microsoft Edge","Google Chrome"});channel.SelectedIndex=0;content.Controls.Add(channel);persist=new CheckBox {Text="Keep website logins in the dedicated Styx profile",Checked=true,Width=490,Height=32};content.Controls.Add(persist);Explain("Browser Automation uses a separate Styx profile. Your personal browser sessions stay separate.",55);}
  Dictionary<string,object> Choice(){var values=Json.Obj("label",label.Text.Trim(),"computer",computer.Checked,"browser",browser.Checked);if(label.Text.Trim().Length==0)throw new InvalidOperationException();values["browserChannel"]=channel.SelectedIndex==1?"msedge":channel.SelectedIndex==2?"chrome":"auto";values["persistLogin"]=persist.Checked;return values;}
  internal void ShowPage(string name){page=name;content.Controls.Clear();owner.Logo(content,48);StyxContext.Heading(content,name=="chat"?"Connect ChatGPT":name=="overview"?"This computer":"Get started with Styx");
   if(name=="welcome"){Explain("Set up this computer, or join a Gateway you already own.");Action("Set up this computer",()=>{ShowPage("create");return Task.FromResult(0);});Action("Join an existing Gateway",()=>{ShowPage("join");return Task.FromResult(0);});}
   else if(name=="create"||name=="join"){Capabilities();if(name=="join"){link=Input("Private pairing link");link.UseSystemPasswordChar=true;Action("Review pairing link",async()=>{var r=await owner.Call("inspectJoin",Json.Obj("link",link.Text));link.Clear();joinOrigin=Json.Str(r,"preview","origin");joinCa=Json.Str(r,"preview","caSha256");Feedback("Gateway: "+joinOrigin+"\nCertificate SHA-256: "+(joinCa.Length>0?joinCa:"system trust")+"\nSelect Approve and prepare only if these match your Gateway.");});}Action(name=="join"?"Approve and prepare":"Prepare this computer",async()=>{var choice=Choice();if(name=="join"){if(String.IsNullOrEmpty(joinOrigin))throw new InvalidOperationException();choice["approvedGatewayOrigin"]=joinOrigin;if(!String.IsNullOrEmpty(joinCa))choice["approvedCaSha256"]=joinCa;}await owner.Call(name=="join"?"join":"create",choice);ShowPage("overview");Feedback("Preparing signed components…");await owner.Call("prepare");await owner.Call("connect");await owner.Refresh();});Action("Return",()=>{ShowPage("welcome");return Task.FromResult(0);});}
   else if(name=="overview"){Explain("Connection and account checks are observed separately. Styx runs in your signed-in Windows session. Lock, logout, UAC and elevated applications can limit desktop control.",88);Action("Refresh status",owner.Refresh);Action("Continue preparation",async()=>{await owner.Call("prepare");await owner.Refresh();});Action("Reconnect",async()=>{await owner.Call("connect");await owner.Refresh();});Action("Pause",async()=>{await owner.Call("disconnect");await owner.Refresh();});Action("Paired computers",async()=>{var r=await owner.Call("devices");ShowDevices(r);});Action("Edit capabilities",()=>{ShowPage("capabilities");return Task.FromResult(0);});}
   else if(name=="capabilities"){Capabilities();Action("Apply capabilities",async()=>{await owner.Call("setCapabilities",Json.Obj("computer",computer.Checked,"browser",browser.Checked,"browserChannel",channel.SelectedIndex==1?"msedge":channel.SelectedIndex==2?"chrome":"auto","persistLogin",persist.Checked));await owner.Refresh();});Explain("Your browser choice and saved-login preference are applied through the same Core capability settings.");}
   else if(name=="chat"){Explain("In ChatGPT, choose Add custom MCP → Tunnel. Create a Secure MCP Tunnel in your OpenAI organization, then enter its ID and runtime key here.",90);Action("Open tunnel settings",()=>{Process.Start("https://platform.openai.com/settings/organization/tunnels");return Task.FromResult(0);});tunnel=Input("Tunnel ID");key=Input("Tunnel runtime key",true);Action("Save and connect tunnel",async()=>{var input=Json.Obj("tunnelId",tunnel.Text.Trim(),"runtimeKey",key.Text);await owner.Call("tunnelSave",input);await owner.Call("tunnelStart");await owner.Refresh();key.Clear();});Action("Create ChatGPT test",async()=>{var r=await owner.Call("acceptanceBegin");challengeId=Json.Str(r,"acceptance","challenge","id");Feedback(Json.Str(r,"acceptance","challenge","prompt"));});Action("I saw the successful test in ChatGPT",async()=>{if(String.IsNullOrEmpty(challengeId))throw new InvalidOperationException();await owner.Call("acceptanceConfirm",Json.Obj("challengeId",challengeId));await owner.Refresh();});Explain("Advanced: ZIP plugin setup is experimental. This first Windows app uses Tunnel. A running tunnel alone does not verify your ChatGPT connection.",75);}
   content.Controls.Add(feedback);Feedback("");
  }
  void ShowDevices(object value){ShowPage("overview");var rows=Json.Get(value,"devices","devices") as object[]??Json.Get(value,"devices") as object[];if(rows==null){Feedback("Computer list is unavailable for this Gateway. Refresh to review current state.");return;}foreach(var row in rows){string id=Json.Str(row,"device_id");if(String.IsNullOrEmpty(id))continue;string title=Json.Str(row,"label")+(Json.Yes(row,"is_default")?" (default)":"");Explain(title,28);Action("Use "+title+" by default",async()=>{await owner.Call("setDefault",Json.Obj("deviceId",id));await owner.Refresh();});Action("Remove "+title,async()=>{if(MessageBox.Show("Revoke this computer's Gateway access?", "Styx",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;await owner.Call("revokeDevice",Json.Obj("deviceId",id));await owner.Refresh();});}}
  internal void Feedback(string text){feedback.Text=text;feedback.Height=Math.Max(100,TextRenderer.MeasureText(text,Font,new Size(490,0),TextFormatFlags.WordBreak).Height+20);}
  internal void ShowStatus(object data){if(page=="welcome"&&Json.Get(data,"status","deployment")!=null)ShowPage("overview");if(page=="welcome"&&Json.Get(data,"status","deployment")==null)Feedback(!Json.Yes(data,"session","artifactsAvailable")?"This preview needs a verified signed Host bundle before preparing a computer.":!Json.Yes(data,"session","localGatewayAvailable")?"A trusted TLS helper is missing. Creating a new Gateway is unavailable; joining an existing Gateway is supported when Host artifacts are present.":"Choose setup or join to continue.");if(page=="overview")Feedback("Exec: "+Json.Str(data,"journey","readiness","exec","status")+"\nComputer Use: "+Json.Str(data,"journey","readiness","desktop","status")+"\nBrowser: "+Json.Str(data,"journey","readiness","browser","status")+"\nChatGPT: "+Json.Str(data,"journey","account","status")+"\nTunnel: "+Json.Str(data,"journey","tunnel","transport"));}
  internal void Verify(){foreach(string name in new[]{"welcome","create","join","overview","capabilities","chat"}){ShowPage(name);if(content.Controls.Count<3)throw new Exception("native_page_failed");}ShowPage("welcome");Show();CreateControl();PerformLayout();Application.DoEvents();using(var image=new Bitmap(Width,Height)){DrawToBitmap(image,new Rectangle(0,0,Width,Height));image.Save(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"native-settings.png"));}}
 }
 static class Program {
  [STAThread]static int Main(string[] args){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);string root=AppDomain.CurrentDomain.BaseDirectory;string state=Environment.GetEnvironmentVariable("STYX_NATIVE_STATE")??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"StyxPreview","WindowsFirst");bool test=args.Length==1&&args[0]=="--self-test";try{var app=new StyxContext(root,state,test);if(test){app.Verify();app.Quit();File.WriteAllText(Path.Combine(root,"native-self-test.json"),"{\"status\":\"PASS\",\"pages\":6,\"uiConstruction\":true,\"desktopAcceptance\":\"NOT RUN\",\"serviceMutation\":\"NOT RUN\"}");return 0;}Application.Run(app);return 0;}catch{if(!test)MessageBox.Show("Styx could not open. Check that the app resources and runtime are present.","Styx",MessageBoxButtons.OK,MessageBoxIcon.Information);return 2;}}
 }
}
