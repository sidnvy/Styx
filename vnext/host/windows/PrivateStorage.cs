// Read-only adapter to Windows security APIs. No ACL repair and no cached grants.
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;

class StyxPrivateStorage {
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
 static extern uint GetNamedSecurityInfoW(string name, int type, uint information,
   out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
 [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
 static extern uint GetFileAttributesW(string name);

 static bool Check(string file, string current) {
  if(String.IsNullOrWhiteSpace(file)||!file.StartsWith(@"\\?\",StringComparison.Ordinal)||file.IndexOf('\0')>=0)return false;
  uint attributes=GetFileAttributesW(file);
  if(attributes==UInt32.MaxValue||(attributes&0x400)!=0)return false;
  IntPtr owner,group,dacl,sacl,descriptor=IntPtr.Zero;
  try {
   if(GetNamedSecurityInfoW(file,1,1|4,out owner,out group,out dacl,out sacl,out descriptor)!=0||
      descriptor==IntPtr.Zero||owner==IntPtr.Zero||dacl==IntPtr.Zero)return false;
   uint size=GetSecurityDescriptorLength(descriptor);
   if(size<20||size>1024*1024)return false;
   var bytes=new byte[size];Marshal.Copy(descriptor,bytes,0,(int)size);
   var acl=new RawSecurityDescriptor(bytes,0);
   if(acl.Owner==null||acl.Owner.Value!=current||acl.DiscretionaryAcl==null)return false;
   foreach(GenericAce entry in acl.DiscretionaryAcl) {
    var rule=entry as QualifiedAce;
    if(rule==null)return false;
    if(rule.AceQualifier==AceQualifier.AccessDenied)continue;
    if(rule.AceQualifier!=AceQualifier.AccessAllowed)return false;
    string sid=rule.SecurityIdentifier.Value;
    if(sid!=current&&sid!="S-1-5-18"&&sid!="S-1-5-32-544")return false;
   }
   return true;
  } finally {if(descriptor!=IntPtr.Zero)LocalFree(descriptor);}
 }
 static int Main(string[] args) {
  try {
   if(args.Length!=1||args[0]!="--check")return 2;
   Console.InputEncoding=new UTF8Encoding(false,true);
   // Bound input without printing paths or security descriptors.
   char[] buffer=new char[65537];int length=0,read;
   while(length<buffer.Length&&(read=Console.In.Read(buffer,length,buffer.Length-length))>0)length+=read;
   if(length>65536)return 2;
   var files=new JavaScriptSerializer().Deserialize<string[]>(new string(buffer,0,length));
   if(files==null||files.Length<1||files.Length>32)return 2;
   using(var identity=WindowsIdentity.GetCurrent()) {
    if(identity.User==null)return 2;
    foreach(string file in files)if(!Check(file,identity.User.Value))return 2;
   }
   return 0;
  }catch{return 2;}
 }
}
