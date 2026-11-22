using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Web.Script.Serialization;

namespace StyxNative {
 static class Json {
  internal static readonly JavaScriptSerializer Codec=new JavaScriptSerializer { MaxJsonLength=2097152 };
  internal static Dictionary<string,object> Obj(params object[] values){var d=new Dictionary<string,object>();for(int i=0;i<values.Length;i+=2)d[(string)values[i]]=values[i+1];return d;}
  internal static object Get(object obj,params string[] keys){foreach(string key in keys){var d=obj as Dictionary<string,object>;object next;if(d==null||!d.TryGetValue(key,out next))return null;obj=next;}return obj;}
  internal static string Str(object obj,params string[] keys){return Get(obj,keys) as string??"";}
  internal static bool Yes(object obj,params string[] keys){return Equals(Get(obj,keys),true);}
 }
 sealed class NativeOperationException:IOException { internal readonly string Code;internal readonly object Budget,Retirement;internal readonly bool Preflight,JoinNotSent;internal NativeOperationException(string code,object budget=null,bool preflight=false,object retirement=null,bool joinNotSent=false){Code=code;Budget=budget;Preflight=preflight;Retirement=retirement;JoinNotSent=joinNotSent;} }
 // The installed outer package pins the bootstrap executable. Its hash is an
 // integrity boundary, not a substitute for Windows publisher authentication.
 sealed class NativeBootstrap:IDisposable {
  internal const string PublisherPin="bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed";
  internal readonly string Root,Cli,Payload,Publisher,CliSha,ManifestSha;internal string Selection;
  readonly FileStream cliPin;
  internal static string Hash(Stream stream){using(var sha=System.Security.Cryptography.SHA256.Create()){stream.Position=0;string v=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();stream.Position=0;return v;}}
  internal static string ReadSmall(string path,int bound){NoRedirect(path);using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){if(f.Length>bound)throw new IOException("app_bootstrap_material_too_large");using(var r=new StreamReader(f))return r.ReadToEnd();}}
  internal static void NoRedirect(string path){string full=Path.GetFullPath(path);if((File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new IOException("app_redirected_path");}
  internal NativeBootstrap(string root){
   Root=Path.GetFullPath(root);var m=Json.Codec.DeserializeObject(ReadSmall(Path.Combine(Root,"windows-runtime.json"),16384));var n=Json.Get(m,"nativeRuntime");
   if(Convert.ToInt32(Json.Get(m,"schema"))!=1||Convert.ToInt32(Json.Get(n,"schema"))!=1||Json.Str(n,"cli")!="native/bin/styx.exe"||Json.Str(n,"payload")!="native"||Json.Str(n,"publisher")!="native-publisher.pem"||Json.Str(n,"publisherSpkiSha256")!=PublisherPin)throw new IOException("app_native_runtime_required");
   Cli=Path.Combine(Root,"native","bin","styx.exe");Payload=Path.Combine(Root,"native");Publisher=Path.Combine(Root,"native-publisher.pem");CliSha=Json.Str(n,"cliSha256");ManifestSha=Json.Str(n,"manifestSha256");
   if(!System.Text.RegularExpressions.Regex.IsMatch(CliSha,"\\A[a-f0-9]{64}\\z")||!System.Text.RegularExpressions.Regex.IsMatch(ManifestSha,"\\A[a-f0-9]{64}\\z"))throw new IOException("app_native_hash_required");
   NoRedirect(Cli);cliPin=new FileStream(Cli,FileMode.Open,FileAccess.Read,FileShare.Read);try{Validate();}catch{cliPin.Dispose();throw;}
  }
  internal void Validate(){if(!File.Exists(Cli)||!Directory.Exists(Payload)||!File.Exists(Publisher))throw new IOException("app_native_runtime_required");}
  internal ProcessStartInfo StartInfo(string arguments){Validate();var info=new ProcessStartInfo(Cli,arguments){WorkingDirectory=Root,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};info.EnvironmentVariables.Remove("NODE_OPTIONS");info.EnvironmentVariables.Remove("NODE_PATH");info.EnvironmentVariables.Remove("STYX_NATIVE_STATE");info.EnvironmentVariables.Remove("STYX_NATIVE_RESOURCES");return info;}
  internal static string Quote(string value){if(value.IndexOf('"')>=0||value.IndexOf('\0')>=0||value.EndsWith("\\"))throw new IOException("app_fixed_path_invalid");return "\""+value+"\"";}
  public void Dispose(){cliPin.Dispose();}
 }
 static class PrivateAppFiles {
  static readonly System.Security.Principal.SecurityIdentifier User=System.Security.Principal.WindowsIdentity.GetCurrent().User;
  static readonly System.Security.Principal.SecurityIdentifier SystemSid=new System.Security.Principal.SecurityIdentifier("S-1-5-18"),Admins=new System.Security.Principal.SecurityIdentifier("S-1-5-32-544");
  static void Validate(string path,bool directory){NativeBootstrap.NoRedirect(path);System.Security.AccessControl.FileSystemSecurity security=directory?(System.Security.AccessControl.FileSystemSecurity)Directory.GetAccessControl(path):File.GetAccessControl(path);if(!User.Equals(security.GetOwner(typeof(System.Security.Principal.SecurityIdentifier))))throw new IOException("app_private_owner_required");foreach(System.Security.AccessControl.FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier))){var sid=(System.Security.Principal.SecurityIdentifier)rule.IdentityReference;if(rule.AccessControlType==System.Security.AccessControl.AccessControlType.Allow&&!sid.Equals(User)&&!sid.Equals(SystemSid)&&!sid.Equals(Admins)&&(rule.FileSystemRights & (System.Security.AccessControl.FileSystemRights.ReadData|System.Security.AccessControl.FileSystemRights.WriteData|System.Security.AccessControl.FileSystemRights.AppendData|System.Security.AccessControl.FileSystemRights.Delete|System.Security.AccessControl.FileSystemRights.ChangePermissions|System.Security.AccessControl.FileSystemRights.TakeOwnership))!=0)throw new IOException("app_private_acl_required");}}
  static System.Security.AccessControl.DirectorySecurity DirectoryAcl(){var acl=new System.Security.AccessControl.DirectorySecurity();acl.SetOwner(User);acl.SetAccessRuleProtection(true,false);foreach(var sid in new[]{User,SystemSid,Admins})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.InheritanceFlags.ContainerInherit|System.Security.AccessControl.InheritanceFlags.ObjectInherit,System.Security.AccessControl.PropagationFlags.None,System.Security.AccessControl.AccessControlType.Allow));return acl;}
  static void DirectoryPrivate(string path){if(File.Exists(path))throw new IOException("app_private_directory_required");if(!Directory.Exists(path)){string parent=Path.GetDirectoryName(path);if(!Directory.Exists(parent))throw new IOException("app_private_parent_missing");Directory.CreateDirectory(path,DirectoryAcl());}Validate(path,true);}
  internal static void PrepareOwnerDirectory(string state){
   foreach(string name in new[]{"deployment","deployment.json","state.json","host","gateway","device","service.json",".styx-native-root-v1.json"})if(File.Exists(Path.Combine(state,name))||Directory.Exists(Path.Combine(state,name)))throw new NativeOperationException("app_legacy_install_present");
   string standard=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"StyxPreview","WindowsFirst");
   if(String.Equals(state,standard,StringComparison.OrdinalIgnoreCase)&&!Directory.Exists(Path.GetDirectoryName(state)))DirectoryPrivate(Path.GetDirectoryName(state));
   DirectoryPrivate(state);
  }
  internal static string Prepare(string state,string selection,out string profile,out string candidate){
   // Refuse old installations before creating any state or candidate files.
   // The UI never adopts, repairs, moves or replaces the old layout.
   foreach(string name in new[]{"deployment","deployment.json","state.json","host","gateway","device","service.json",".styx-native-root-v1.json"})if(File.Exists(Path.Combine(state,name))||Directory.Exists(Path.Combine(state,name)))throw new NativeOperationException("app_legacy_install_present");
   string container=Path.Combine(state,"native-rust-host-v1"),fresh=Path.Combine(container,"profile");
   string defaultState=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"StyxPreview","WindowsFirst");if(String.Equals(state,defaultState,StringComparison.OrdinalIgnoreCase)&&!Directory.Exists(Path.GetDirectoryName(state)))DirectoryPrivate(Path.GetDirectoryName(state));
   DirectoryPrivate(state);DirectoryPrivate(container);string candidates=Path.Combine(container,"migration-candidates");DirectoryPrivate(candidates);string digest;using(var bytes=new MemoryStream(new System.Text.UTF8Encoding(false,true).GetBytes(selection)))digest=NativeBootstrap.Hash(bytes);string path=Path.Combine(candidates,digest+".json");candidate=path;
   if(!File.Exists(path)){
    var acl=new System.Security.AccessControl.FileSecurity();acl.SetOwner(User);acl.SetAccessRuleProtection(true,false);foreach(var sid in new[]{User,SystemSid,Admins})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(sid,System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
    using(var f=new FileStream(path,FileMode.CreateNew,System.Security.AccessControl.FileSystemRights.Read|System.Security.AccessControl.FileSystemRights.Write,FileShare.Read,4096,FileOptions.None,acl)){byte[] raw=new System.Text.UTF8Encoding(false,true).GetBytes(selection);f.Write(raw,0,raw.Length);f.Flush(true);}
   }
   Validate(path,false);if(NativeBootstrap.ReadSmall(path,16384)!=selection)throw new NativeOperationException("app_runtime_selection_changed");Validate(container,true);profile=fresh;return container;
  }
 }
}
