// A stopped, disabled user unit participates in the existing payload transaction.
// This module never starts/stops services or creates a separate migration journal.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {knownLinuxUserUnit} from '../host/linux-service.mjs';
import {requirePrivateFile} from '../host/private-storage.mjs';
const fail=code=>{throw Error(code)};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fields=text=>Object.fromEntries(String(text).trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)]}));
export function linuxHostPayloadUnitPath(service,{home=os.homedir()}={}){
 const name=service.id??service.unitName;
 if(!/^styx-(?:vnext-)?[a-z0-9][a-z0-9-]{0,48}\.service$/.test(name??'')||!path.isAbsolute(home)||path.normalize(home)!==home)fail('host_payload_linux_unit_scope_invalid');
 return path.join(home,'.config/systemd/user',name);
}
function observe(service,{home=os.homedir(),run=execFileSync}={}){
 const unit=service.id??service.unitName,file=linuxHostPayloadUnitPath(service,{home});
 const row=fields(run('/usr/bin/systemctl',['--user','show',unit,'--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,DropInPaths,Restart,Type','--no-pager'],{encoding:'utf8',timeout:10000,maxBuffer:32768,stdio:['ignore','pipe','pipe']}));
 if(row.LoadState!=='loaded'||!['inactive','failed'].includes(row.ActiveState)||!['dead','failed'].includes(row.SubState)||row.UnitFileState!=='disabled'||row.MainPID!=='0'||row.FragmentPath!==file||row.DropInPaths!==''||row.Restart!=='on-failure'||!['exec','simple'].includes(row.Type))fail('host_payload_linux_unit_not_stopped_disabled');
 return row;
}
export function inspectLinuxHostPayloadUnit(service,options={}){
 const file=linuxHostPayloadUnitPath(service,options);
 if(!fs.existsSync(file))return null;
 for(let parent=path.dirname(file);parent!==path.dirname(options.home??os.homedir());parent=path.dirname(parent))if(fs.lstatSync(parent).isSymbolicLink())fail('host_payload_linux_unit_redirected');
 if(requirePrivateFile(file).size>32768)fail('host_payload_linux_unit_too_large');const before=fs.readFileSync(file),unitName=service.id??service.unitName;
 if(!knownLinuxUserUnit(before.toString(),{...service,unitName}))fail('host_payload_linux_unit_definition_changed');
 const prior='ExecStart='+service.nodeBinary+' ',replacement='ExecStart='+path.join(service.installRoot,'node')+' ';
 if(!before.toString().includes('\n'+prior))fail('host_payload_linux_unit_definition_changed');
 const after=Buffer.from(before.toString().replace('\n'+prior,'\n'+replacement)),observation=observe(service,options);
 return {name:'linuxHostUnit',path:file,before,after,mode:fs.statSync(file).mode&0o777,afterMode:0o600,binding:{schema:1,unitName,path:file,beforeSha256:sha(before),afterSha256:sha(after),observation}};
}
export function observeLinuxHostPayloadUnit(service,binding,options={}){
 const file=linuxHostPayloadUnitPath(service,options);
 if(binding?.schema!==1||binding.path!==file||binding.unitName!==(service.id??service.unitName)||!['beforeSha256','afterSha256'].every(key=>/^[a-f0-9]{64}$/.test(binding[key]??'')))fail('host_payload_linux_unit_binding_invalid');
 requirePrivateFile(file);if(![binding.beforeSha256,binding.afterSha256].includes(sha(fs.readFileSync(file))))fail('host_payload_linux_unit_definition_changed');
 const state=observe(service,options);
 if(JSON.stringify(state)!==JSON.stringify(binding.observation))fail('host_payload_linux_unit_observation_changed');
 return true;
}
export function reconcileLinuxHostPayloadUnit(service,binding,options={}){
 observeLinuxHostPayloadUnit(service,binding,options);
 (options.run??execFileSync)('/usr/bin/systemctl',['--user','daemon-reload'],{encoding:'utf8',timeout:10000,maxBuffer:32768,stdio:['ignore','pipe','pipe']});
 observeLinuxHostPayloadUnit(service,binding,options);return true;
}

export function writeLinuxHostPayloadUnit(service,binding,data,{expectedSha256,mode=0o600,...options}={}){
 if(!Number.isInteger(mode)||mode<0||mode>0o700||(mode&0o077)!==0)fail('host_payload_linux_unit_mode_invalid');
 const file=linuxHostPayloadUnitPath(service,options),home=options.home??os.homedir();
 if(binding?.path!==file||![binding.beforeSha256,binding.afterSha256].includes(sha(data)))fail('host_payload_linux_unit_binding_invalid');
 const parents=[home,path.join(home,'.config'),path.join(home,'.config/systemd'),path.dirname(file)];
 const observed=parents.map(parent=>{const st=fs.lstatSync(parent);if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o022)!==0)fail('host_payload_linux_unit_directory_unsafe');return {path:parent,ino:st.ino,dev:st.dev}});
 observeLinuxHostPayloadUnit(service,binding,options);const prior=requirePrivateFile(file);
 if(sha(fs.readFileSync(file))!==expectedSha256)fail('host_payload_linux_unit_definition_changed');
 const temp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,mode);
 try{fs.writeFileSync(fd,data);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 try{
  for(const parent of observed){const st=fs.lstatSync(parent.path);if(st.ino!==parent.ino||st.dev!==parent.dev||st.isSymbolicLink()||(st.mode&0o022)!==0)fail('host_payload_linux_unit_directory_changed')}
  const now=requirePrivateFile(file);if(now.ino!==prior.ino||now.dev!==prior.dev||sha(fs.readFileSync(file))!==expectedSha256)fail('host_payload_linux_unit_definition_changed');
  fs.renameSync(temp,file);const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}
 }finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}
}
