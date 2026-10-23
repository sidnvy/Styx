using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
using System.Windows.Forms;
internal static class StyxLauncher {
 static string Digest(string file){using(var sha=SHA256.Create())using(var stream=File.OpenRead(file))return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
 internal static string Resolve(string root){
  var receipt=new JavaScriptSerializer{MaxJsonLength=16*1024*1024}.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(root,"installation.json")));
  if((string)receipt["kind"]!="styx-windows-user-install"||!String.Equals((string)receipt["root"],root,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException();
  var id=(string)receipt["current"];Guid parsed;if(!Guid.TryParseExact(id,"D",out parsed))throw new InvalidDataException();
  var folder=Path.Combine(root,"releases",id);foreach(var p in new[]{root,Path.Combine(root,"releases"),folder})if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException();
  var manifest=Path.Combine(folder,"windows-package.json");string expected=null;
  foreach(var raw in (System.Collections.IEnumerable)receipt["releases"]){var release=(Dictionary<string,object>)raw;if((string)release["id"]==id)expected=(string)release["packageSha256"];}
  if(expected==null||(File.GetAttributes(manifest)&FileAttributes.ReparsePoint)!=0||Digest(manifest)!=expected)throw new InvalidDataException();
  var package=new JavaScriptSerializer{MaxJsonLength=16*1024*1024}.Deserialize<Dictionary<string,object>>(File.ReadAllText(manifest));
  var exe=Path.Combine(folder,"StyxPreview.exe");string executableHash=null;
  foreach(var raw in (System.Collections.IEnumerable)package["files"]){var member=(Dictionary<string,object>)raw;if((string)member["path"]=="StyxPreview.exe")executableHash=(string)member["sha256"];}
  if(executableHash==null||(File.GetAttributes(exe)&FileAttributes.ReparsePoint)!=0||Digest(exe)!=executableHash)throw new InvalidDataException();return exe;
 }
 [STAThread]static int Main(string[] args){try{if(args.Length!=0)throw new ArgumentException();var exe=Resolve(AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));Process.Start(new ProcessStartInfo(exe){UseShellExecute=true,WorkingDirectory=Path.GetDirectoryName(exe)});return 0;}catch{MessageBox.Show("Styx could not open this installation. Run Styx Setup to review or restore the previous version. Your device settings have been retained.","Styx",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}}
}
