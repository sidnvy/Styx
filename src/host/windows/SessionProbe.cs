// Read-only native session/App query. Never switches desktop or synthesizes input.
using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
class StyxSessionProbe {
 [DllImport("user32.dll",SetLastError=true)]static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll")]static extern bool CloseDesktop(IntPtr desktop);
 [DllImport("user32.dll")]static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool GetUserObjectInformation(IntPtr handle,int index,StringBuilder value,uint length,out uint needed);
 static string Name(IntPtr handle){var name=new StringBuilder(256);uint needed;return handle!=IntPtr.Zero&&GetUserObjectInformation(handle,2,name,512,out needed)?name.ToString():"unavailable";}
 static string Json(string value){var result=new StringBuilder("\"");foreach(char c in value){if(c=='\\'||c=='\"')result.Append('\\').Append(c);else if(c<32)result.Append("\\u").Append(((int)c).ToString("x4",CultureInfo.InvariantCulture));else result.Append(c);}return result.Append('\"').ToString();}
 static string App(int pid){
  try{using(var app=Process.GetProcessById(pid)){
   long ticks=app.StartTime.ToUniversalTime().Ticks;string image=app.MainModule.FileName;int session=app.SessionId;
   app.Refresh();if(app.HasExited||app.Id!=pid||app.StartTime.ToUniversalTime().Ticks!=ticks||String.IsNullOrEmpty(image))return null;
   return "{\"pid\":"+pid.ToString(CultureInfo.InvariantCulture)+",\"executablePath\":"+Json(image)+",\"sessionId\":"+session.ToString(CultureInfo.InvariantCulture)+",\"startTimeUtcTicks\":"+Json(ticks.ToString(CultureInfo.InvariantCulture))+"}";
  }}catch{return null;}
 }
 static int Main(string[] args){
  int appPid=0;if(args.Length!=0&&(args.Length!=2||args[0]!="--app-pid"||!Int32.TryParse(args[1],NumberStyles.None,CultureInfo.InvariantCulture,out appPid)||appPid<1)){Console.WriteLine("{\"schema\":1,\"status\":\"invalid_app_query\",\"computerAcceptance\":\"NOT RUN\"}");return 64;}
  int session=Process.GetCurrentProcess().SessionId;bool interactive=Environment.UserInteractive;string station=Name(GetProcessWindowStation()),desktop="unavailable";IntPtr h=OpenInputDesktop(0,false,1);try{desktop=Name(h);}finally{if(h!=IntPtr.Zero)CloseDesktop(h);}
  bool allowed=interactive&&session>0&&station=="WinSta0"&&desktop=="Default";string app=args.Length==2?App(appPid):null;
  string status=allowed?(args.Length==2&&app==null?"app_unavailable":"available"):"session_unavailable";
  Console.WriteLine("{\"schema\":1,\"status\":"+Json(status)+",\"sessionId\":"+session.ToString(CultureInfo.InvariantCulture)+",\"interactive\":"+(interactive?"true":"false")+",\"windowStation\":"+Json(station=="WinSta0"?"WinSta0":"unavailable")+",\"inputDesktop\":"+Json(desktop=="Default"?"Default":"unavailable")+",\"computerAcceptance\":\"NOT RUN\""+(args.Length==2?",\"app\":"+(app??"null"):"")+"}");return 0;
 }
}
