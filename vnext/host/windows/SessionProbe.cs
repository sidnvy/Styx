// Read-only native session preflight. Never switches desktop or synthesizes input.
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
class StyxSessionProbe {
 [DllImport("user32.dll",SetLastError=true)]static extern IntPtr OpenInputDesktop(uint flags,bool inherit,uint access);
 [DllImport("user32.dll")]static extern bool CloseDesktop(IntPtr desktop);
 [DllImport("user32.dll")]static extern IntPtr GetProcessWindowStation();
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool GetUserObjectInformation(IntPtr handle,int index,StringBuilder value,uint length,out uint needed);
 static string Name(IntPtr handle){var name=new StringBuilder(256);uint needed;return handle!=IntPtr.Zero&&GetUserObjectInformation(handle,2,name,512,out needed)?name.ToString():"unavailable";}
 static int Main(){int session=Process.GetCurrentProcess().SessionId;bool interactive=Environment.UserInteractive;string station=Name(GetProcessWindowStation()),desktop="unavailable";IntPtr h=OpenInputDesktop(0,false,1);try{desktop=Name(h);}finally{if(h!=IntPtr.Zero)CloseDesktop(h);}bool allowed=interactive&&session>0&&station=="WinSta0"&&desktop=="Default";string status=allowed?"available":"session_unavailable";
 Console.WriteLine("{\"schema\":1,\"status\":\""+status+"\",\"sessionId\":"+session+",\"interactive\":"+(interactive?"true":"false")+",\"windowStation\":\""+(station=="WinSta0"?"WinSta0":"unavailable")+"\",\"inputDesktop\":\""+(desktop=="Default"?"Default":"unavailable")+"\",\"computerAcceptance\":\"NOT RUN\"}");return 0;}
}
