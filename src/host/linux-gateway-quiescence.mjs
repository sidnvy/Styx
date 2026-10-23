// Linux kernel executable exclusion plus a complete same-user argv scan.
// O_WRONLY is intentional, O_TRUNC/O_CREAT and write calls are never used.
// While these descriptors are open, Linux refuses execution of the corresponding
// current inodes. This supplements inaccessible /proc/PID/exe; it never excuses
// an unreadable argv, an external interpreter using this state, or an unknown
// installed file. This is an observation, not a hostile same-UID security boundary.
import fs from 'node:fs';
import path from 'node:path';
import {requirePrivateDirectory,requirePrivateFile} from './private-storage.mjs';
const fail=code=>{throw Error(code)};
const same=(a,b)=>a.dev===b.dev&&a.ino===b.ino;
function startIdentity(stat){const tail=stat.slice(stat.lastIndexOf(')')+2).split(' ');if(!/^[1-9][0-9]*$/.test(tail[19]??''))fail('gateway_process_quiescence_unknown');return {startTicks:tail[19],state:tail[0]}}
export function observeLinuxGatewayProcesses({stateDir,installRoot},{procRoot='/proc',filesystem=fs}={}){
 if(process.platform!=='linux')fail('linux_gateway_quiescence_required');
 const held=[],executableInodes=[],inaccessibleExecutablePids=[];
 try{
  // Inspect every executable regular file, including the stable service Node
  // and every retained generation. Do not infer coverage from a path basename.
  const walk=dir=>{
   requirePrivateDirectory(dir);
   for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
    const file=path.join(dir,entry.name),before=fs.lstatSync(file);
    if(before.isSymbolicLink())fail('gateway_process_quiescence_unknown');
    if(before.isDirectory()){walk(file);continue}
    if(!before.isFile())fail('gateway_process_quiescence_unknown');
    if(!(before.mode&0o111))continue;
    requirePrivateFile(file);
    let fd;try{fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK)}
    catch(error){if(error.code==='ETXTBSY')fail('gateway_runtime_process_still_running');fail('gateway_process_quiescence_unknown')}
    held.push(fd);const observed=fs.fstatSync(fd);
    if(!same(before,observed)||!same(observed,fs.lstatSync(file))||!observed.isFile())fail('gateway_process_quiescence_unknown');
    executableInodes.push({file:path.relative(installRoot,file),device:String(observed.dev),inode:String(observed.ino)});
   }
  };
  walk(installRoot);if(!executableInodes.length)fail('gateway_process_quiescence_unknown');
  for(const entry of filesystem.readdirSync(procRoot)){
   if(!/^\d+$/.test(entry))continue;
   const proc=path.join(procRoot,entry);
   try{
    if(filesystem.statSync(proc).uid!==process.getuid())continue;
    const before=startIdentity(filesystem.readFileSync(path.join(proc,'stat'),'utf8'));
    const raw=filesystem.readFileSync(path.join(proc,'cmdline'));
    if(!raw.length){if(['Z','X'].includes(before.state)&&filesystem.readdirSync(path.join(proc,'task')).length===1)continue;fail('gateway_process_quiescence_unknown')}
    if(raw.length>1024*1024||raw[raw.length-1]!==0)fail('gateway_process_quiescence_unknown');
    const args=raw.toString().split('\0').slice(0,-1);
    if(!args[0])fail('gateway_process_quiescence_unknown');
    if(Number(entry)!==process.pid&&args.some(arg=>arg===stateDir||arg.startsWith(stateDir+path.sep)||arg===installRoot||arg.startsWith(installRoot+path.sep)))fail('gateway_runtime_process_still_running');
    let inaccessible=false;
    try{
     const executable=filesystem.readlinkSync(path.join(proc,'exe')).replace(/ \(deleted\)$/,'');
     if(executable.startsWith(installRoot+path.sep))fail('gateway_runtime_process_still_running');
    }catch(error){
     if(!['EACCES','EPERM'].includes(error.code))throw error;
     // Only a complete, unrelated argv plus the held kernel exclusions can
     // resolve an inaccessible executable. argv alone is never enough.
     inaccessible=true;
    }
    const after=startIdentity(filesystem.readFileSync(path.join(proc,'stat'),'utf8'));
    if(after.startTicks!==before.startTicks||!raw.equals(filesystem.readFileSync(path.join(proc,'cmdline'))))fail('gateway_process_quiescence_unknown');
    if(inaccessible)inaccessibleExecutablePids.push(Number(entry));
   }catch(error){
    if(['ENOENT','ESRCH'].includes(error.code)){
     // A missing exe/cmdline on a still-present process is not proof of death
     // (for example, an exited thread-group leader with live worker threads).
     try{filesystem.statSync(proc)}catch(gone){if(['ENOENT','ESRCH'].includes(gone.code))continue}
    }
    if(error.message==='gateway_runtime_process_still_running')throw error;
    fail('gateway_process_quiescence_unknown');
   }
  }
  // Verify path identities once more before releasing the non-writing probes.
  for(let index=0;index<held.length;index++)if(!same(fs.fstatSync(held[index]),fs.lstatSync(path.join(installRoot,executableInodes[index].file))))fail('gateway_process_quiescence_unknown');
  return {method:'linux_kernel_current_executable_inodes_and_complete_argv',executableInodes,inaccessibleExecutablePids,scope:'current_installed_inodes_and_supported_fixed_argument_entrypoints',continuousExclusion:false};
 }catch(error){if(error.message==='gateway_runtime_process_still_running')throw error;fail('gateway_process_quiescence_unknown')}
 finally{for(const fd of held)fs.closeSync(fd)}
}
