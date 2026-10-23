import AppKit
import Foundation
import Darwin
@_silgen_name("proc_pidinfo") func procInfo(_ pid:Int32,_ flavor:Int32,_ arg:UInt64,_ buffer:UnsafeMutableRawPointer?,_ size:Int32)->Int32
@_silgen_name("proc_pidpath") func procPath(_ pid:Int32,_ buffer:UnsafeMutableRawPointer?,_ size:UInt32)->Int32
func identity(_ pid:Int32)->String? {
 var b=[UInt8](repeating:0,count:136)
 let n=b.withUnsafeMutableBytes{procInfo(pid,3,0,$0.baseAddress,136)}
 if n != 136{return nil}
 let time=b.withUnsafeBytes{($0.loadUnaligned(fromByteOffset:120,as:UInt64.self),$0.loadUnaligned(fromByteOffset:128,as:UInt64.self))}
 var path=[UInt8](repeating:0,count:4096)
 if path.withUnsafeMutableBytes({procPath(pid,$0.baseAddress,4096)})<=0{return nil}
 let exe=String(cString:path.map{CChar(bitPattern:$0)})
 return "\(pid):\(time.0):\(time.1):\(exe)"
}
func socketStat(_ path:String)->stat?{
 var s=stat()
 if lstat(path,&s) != 0{return nil}
 if s.st_mode & S_IFMT != S_IFSOCK || s.st_uid != geteuid(){return nil}
 return s
}

let fm=FileManager.default
func saveAt(_ root:String,_ name:String,_ value:[String:Any]){
 if let data=try? JSONSerialization.data(withJSONObject:value,options:[.sortedKeys]){
  try? data.write(to:URL(fileURLWithPath:root+"/"+name),options:.atomic)
 }
}
func canonical(_ path:String)->String?{
 guard let p=realpath(path,nil) else{return nil};defer{free(p)};return String(cString:p)
}
func privateRoot(_ root:String)->Bool{
 var s=stat()
 return root.hasPrefix("/private/tmp/styx-gb-") && canonical(root)==root &&
  lstat(root,&s)==0 && s.st_mode & S_IFMT == S_IFDIR && s.st_uid==geteuid() && s.st_mode & 0o077 == 0
}
// Only called after this run's driver/process group is proven gone. Refuse live,
// foreign, symlink and replaced sockets. Same-UID hostile races remain out of scope.
func removeStale(_ path:String)->Bool{
 guard let first=socketStat(path) else {var s=stat();return lstat(path,&s) != 0 && errno==ENOENT}
 let fd=Darwin.socket(AF_UNIX,SOCK_STREAM,0)
 if fd<0{return false};defer{close(fd)}
 var addr=sockaddr_un();addr.sun_family=sa_family_t(AF_UNIX)
 let bytes=Array(path.utf8)+[0]
 let capacity=MemoryLayout.size(ofValue:addr.sun_path)
 if bytes.count>capacity{return false}
 withUnsafeMutableBytes(of:&addr.sun_path){$0.copyBytes(from:bytes)}
 addr.sun_len=UInt8(MemoryLayout<sockaddr_un>.size)
 let result=withUnsafePointer(to:&addr){ptr in
  ptr.withMemoryRebound(to:sockaddr.self,capacity:1){connect(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size))}
 }
 let error=errno
 guard result != 0,error==ECONNREFUSED,let last=socketStat(path),
       first.st_dev==last.st_dev,first.st_ino==last.st_ino else{return false}
 return unlink(path)==0
}
let args=CommandLine.arguments
if args.count==3 && args[1]=="--identity",let pid=Int32(args[2]){print(identity(pid) ?? "absent");exit(0)}
if args.count>1 && args[1]=="--guard" {
 signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL)
 guard args.count==5,let parent=Int32(args[2]),parent>1,privateRoot(args[4]) else{exit(64)}
 let stamp=args[3],root=args[4]
 // Never share the supervised group: the host must be group leader before spawn.
 if setpgid(0,0) != 0 && getpgrp() != getpid(){exit(67)}
 guard getpgrp() != parent,identity(parent)==stamp,getpgid(parent)==parent else{exit(67)}
 saveAt(root,"guard-ready.json",["guard_pid":getpid(),"guard_identity":identity(getpid())!,
  "host_pid":parent,"host_identity":stamp,"process_group":parent])
 while identity(parent)==stamp{usleep(10000)}
 // A dedicated, non-escaping group closes the spawn-to-PID-handoff gap.
 var empty=kill(-parent,0) != 0 && errno==ESRCH
 if !empty{_ = kill(-parent,SIGTERM)}
 for _ in 0..<100{
  empty=kill(-parent,0) != 0 && errno==ESRCH
  if empty{break};usleep(20000)
 }
 if !empty{_ = kill(-parent,SIGKILL)}
 for _ in 0..<100{
  empty=kill(-parent,0) != 0 && errno==ESRCH
  if empty{break};usleep(20000)
 }
 let cleaned=empty && removeStale(root+"/driver.sock")
 saveAt(root,"guard-cleanup.json",["group_gone":empty,"socket_removed":cleaned,"guard_pid":getpid()])
 exit(cleaned ? 0:68)
}
guard args.count==3 else{exit(64)}
let root=args[1],binary=args[2],socket=root+"/driver.sock"
var existing=stat()
guard privateRoot(root),lstat(socket,&existing) != 0,errno==ENOENT,fm.fileExists(atPath:binary) else{exit(65)}
let hostStamp=identity(getpid())!
func save(_ name:String,_ value:[String:Any]){saveAt(root,name,value)}
let config=(try? Data(contentsOf:URL(fileURLWithPath:root+"/test-config.json"))).flatMap{
 (try? JSONSerialization.jsonObject(with:$0)) as? [String:String]
} ?? [:]
// Deterministic test-only barriers, limited to this private run directory.
func stage(_ phase:String,_ fields:[String:Any]=[:]){
 var record=fields;record["phase"]=phase;record["host_pid"]=getpid()
 save("stage-"+phase+".json",record)
 if config["pause_at"]==phase{
  for _ in 0..<1500{if fm.fileExists(atPath:root+"/release"){return};usleep(20000)}
  exit(69)
 }
}
func spawnDriver()->pid_t?{
 var actions:posix_spawn_file_actions_t?
 var attr:posix_spawnattr_t?
 guard posix_spawn_file_actions_init(&actions)==0,posix_spawnattr_init(&attr)==0 else{return nil}
 defer{posix_spawn_file_actions_destroy(&actions);posix_spawnattr_destroy(&attr)}
 let fd=open(root+"/daemon.log",O_WRONLY|O_CREAT|O_EXCL,0o600)
 guard fd>=0 else{return nil};defer{close(fd)}
 posix_spawn_file_actions_adddup2(&actions,fd,STDOUT_FILENO)
 posix_spawn_file_actions_adddup2(&actions,fd,STDERR_FILENO)
 var defaults=sigset_t();sigemptyset(&defaults);sigaddset(&defaults,SIGTERM);sigaddset(&defaults,SIGINT)
 posix_spawnattr_setsigdefault(&attr,&defaults)
 posix_spawnattr_setflags(&attr,Int16(POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_SETSIGDEF))
 posix_spawnattr_setpgroup(&attr,getpid())
 let strings=[binary,"serve","--embedded","--no-overlay","--socket",socket,"--pid-file",root+"/driver.pid","--host-bundle-id",Bundle.main.bundleIdentifier!]
 let env=["PATH=/usr/bin:/bin","HOME="+NSHomeDirectory(),"CUA_DRIVER_EMBEDDED=1","CUA_DRIVER_EMBEDDED_HOST_PID="+String(getpid())]
 var argv=strings.map{strdup($0)}+[nil],envp=env.map{strdup($0)}+[nil]
 defer{for p in argv{free(p)};for p in envp{free(p)}}
 var pid:pid_t=0
 let result=argv.withUnsafeMutableBufferPointer{a in envp.withUnsafeMutableBufferPointer{e in
  posix_spawn(&pid,binary,&actions,&attr,a.baseAddress!,e.baseAddress!)
 }}
 return result==0 ? pid:nil
}
class Delegate:NSObject,NSApplicationDelegate{
 var daemon:pid_t?;var daemonStamp:String?;var guardProcess:Process?
 var signals:[DispatchSourceSignal]=[];var stopping=false;var timer:Timer?
 var window:NSWindow?;var field:NSTextField?;var count=0
 func fixture(){
  let w=NSWindow(contentRect:NSRect(x:100,y:100,width:560,height:220),styleMask:[.titled,.closable],backing:.buffered,defer:false)
  w.title="Styx GUI Broker Isolated Scratch 20261017";w.isReleasedWhenClosed=false
  let label=NSTextField(labelWithString:"Isolated prototype — only this window is a test target")
  label.frame=NSRect(x:24,y:165,width:510,height:26);w.contentView?.addSubview(label)
  let f=NSTextField(string:"styx_initial");f.frame=NSRect(x:24,y:105,width:480,height:32)
  f.setAccessibilityIdentifier("styx_scratch_text");w.contentView?.addSubview(f);field=f
  let button=NSButton(title:"Styx Increment",target:self,action:#selector(increment))
  button.frame=NSRect(x:24,y:40,width:180,height:36);button.setAccessibilityIdentifier("styx_increment")
  w.contentView?.addSubview(button);window=w;w.makeKeyAndOrderFront(nil)
  save("fixture.json",["button_count":count,"value":f.stringValue])
 }
 @objc func increment(){
  count+=1;save("fixture.json",["button_count":count,"value":field?.stringValue ?? ""])
 }
 func applicationDidFinishLaunching(_ notification:Notification){
  guard Bundle.main.bundleIdentifier=="com.styx.prototype.guibroker20261017" else{exit(66)}
  for sig in [SIGTERM,SIGINT]{
   signal(sig,SIG_IGN)
   let source=DispatchSource.makeSignalSource(signal:sig,queue:.main)
   source.setEventHandler{[weak self] in self?.stop();NSApp.terminate(nil)}
   source.resume();signals.append(source)
  }
  stage("before_guard")
  guard setpgid(0,0)==0 || getpgrp()==getpid() else{exit(67)}
  let watcher=Process();watcher.executableURL=Bundle.main.executableURL
  watcher.arguments=["--guard",String(getpid()),hostStamp,root]
  watcher.standardOutput=FileHandle.nullDevice;watcher.standardError=FileHandle.nullDevice
  do{try watcher.run()}catch{save("failed.json",["error":"guard_spawn_failed"]);NSApp.terminate(nil);return}
  guardProcess=watcher
  stage("guard_spawned",["guard_pid":watcher.processIdentifier,"guard_identity":identity(watcher.processIdentifier) ?? "pending"])
  for _ in 0..<250{if fm.fileExists(atPath:root+"/guard-ready.json"){break};if !watcher.isRunning{break};usleep(10000)}
  guard watcher.isRunning,let data=try? Data(contentsOf:URL(fileURLWithPath:root+"/guard-ready.json")),
    let record=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any],
    record["host_identity"] as? String==hostStamp,record["guard_pid"] as? Int32==watcher.processIdentifier
    else{stop();NSApp.terminate(nil);return}
  stage("guard_armed")
  guard let pid=spawnDriver() else{save("failed.json",["error":"driver_spawn_failed"]);stop();NSApp.terminate(nil);return}
  daemon=pid
  // Intentionally before the daemon identity/ready receipt is handed off.
  stage("spawn_returned")
  guard getpgid(pid)==getpid(),let stamp=identity(pid) else{stop();NSApp.terminate(nil);return}
  daemonStamp=stamp
  stage("child_registered",["daemon_pid":pid,"daemon_identity":stamp,"process_group":getpgid(pid)])
  var ticks=0;var ready=false
  timer=Timer.scheduledTimer(withTimeInterval:0.02,repeats:true){[weak self] t in
   guard let self=self else{return};ticks+=1
   var status:Int32=0
   if waitpid(pid,&status,WNOHANG)==pid{self.daemon=nil;t.invalidate();self.stop();NSApp.terminate(nil);return}
   if identity(watcher.processIdentifier)==nil || (!ready && ticks>500){t.invalidate();self.stop();NSApp.terminate(nil);return}
   if !ready,let s=socketStat(socket){
    stage("socket_created",["daemon_pid":pid,"daemon_identity":stamp])
    ready=true
    save("ready.json",["phase":"socket_created","host_pid":getpid(),"host_identity":hostStamp,"daemon_pid":pid,
     "daemon_identity":stamp,"guard_pid":watcher.processIdentifier,"socket":socket,"socket_dev":s.st_dev,
     "socket_ino":s.st_ino,"generation":UUID().uuidString,"bundle":Bundle.main.bundleIdentifier!,"process_group":getpgid(pid)])
    self.fixture()
   }
  }
 }
 func stop(){
  if stopping{return};stopping=true;timer?.invalidate()
  var exited=true
  if let pid=daemon{
   if daemonStamp==nil || identity(pid)==daemonStamp{_ = kill(pid,SIGTERM)}
   var status:Int32=0;var reaped=false
   for _ in 0..<100{let n=waitpid(pid,&status,WNOHANG);if n==pid || (n<0 && errno==ECHILD){reaped=true;break};usleep(20000)}
   if !reaped{if daemonStamp==nil || identity(pid)==daemonStamp{_ = kill(pid,SIGKILL)};reaped=waitpid(pid,&status,0)==pid}
   exited=reaped && identity(pid)==nil
  }
  let cleaned=exited && removeStale(socket)
  if let g=guardProcess,g.isRunning{g.terminate();g.waitUntilExit()}
  save("stopped.json",["daemon_exited":exited,"socket_removed":cleaned])
 }
 func applicationWillTerminate(_ n:Notification){stop()}
}
let app=NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate=Delegate();app.delegate=delegate
app.run()
