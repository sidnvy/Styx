// Fixed Linux owner adapter. These operations are never supplied by a model.
// macOS/Windows need their own observed inhibited candidate-start contracts.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {knownLinuxUserUnit} from '../host/linux-service.mjs';
import {observeLinuxGatewayProcesses} from '../host/linux-gateway-quiescence.mjs';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';
import {gatewayFetch} from './connection.mjs';
import {ownerCommand} from '../gateway/enroll-admin.mjs';
import {stdioClient,ExecConnection} from '../packages/styx-exec-adapter/rpc.mjs';
import {ExecAdapter} from '../packages/styx-exec-adapter/adapter.mjs';
const fail=code=>{throw Error(code)};
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const read=file=>{requirePrivateFile(file);return JSON.parse(fs.readFileSync(file,'utf8'))};
const DROPIN='# Managed by Styx reviewed Host update\n[Service]\nRestart=no\n';
function fileHash(file){requirePrivateFile(file);return hash(fs.readFileSync(file))}
function sync(dir){const fd=fs.openSync(dir,'r');try{fs.fsyncSync(fd)}finally{fs.closeSync(fd)}}
function processIdentity(pid,ctx,version,{allowJournalIdentity=false}={}){
 if(!Number.isSafeInteger(pid)||pid<2)fail('host_update_native_pid_unavailable');
 const proc='/proc/'+pid;
 if(fs.statSync(proc).uid!==process.getuid())fail('host_update_native_owner_changed');
 const argv=fs.readFileSync(proc+'/cmdline','utf8').split('\0').filter(Boolean);let exe;
 // systemd exposes its forked pre-exec stub before the signed Node has execed.
 if(argv.length===1&&argv[0]==='(node)')fail('host_update_candidate_generation_unobserved');
 try{exe=fs.readlinkSync(proc+'/exe')}catch(error){if(!allowJournalIdentity||!['EACCES','EPERM'].includes(error.code))throw error;exe=argv[0]}
 if(exe!==fs.realpathSync(ctx.service.nodeBinary)||JSON.stringify(argv.slice(1))!==JSON.stringify([path.join(ctx.installRoot,'launch.mjs'),ctx.installRoot,ctx.service.hostConfigFile,ctx.service.publisherKeyFile]))fail('host_update_service_process_changed');
 const children=fs.readFileSync(proc+'/task/'+pid+'/children','utf8').trim().split(/\s+/).filter(Boolean).map(Number);
 const script=path.join(ctx.installRoot,'releases',version,'host/connect.mjs');
 const candidates=children.filter(child=>{
  try{const args=fs.readFileSync('/proc/'+child+'/cmdline','utf8').split('\0').filter(Boolean);let executable;try{executable=fs.readlinkSync('/proc/'+child+'/exe')}catch(error){if(!allowJournalIdentity||!['EACCES','EPERM'].includes(error.code))throw error;executable=args[0]}return fs.statSync('/proc/'+child).uid===process.getuid()&&executable===path.join(ctx.installRoot,'releases',version,'bin/node')&&JSON.stringify(args.slice(1))===JSON.stringify([script,'--stdin-config'])}catch{return false}
 });
 if(candidates.length!==1)fail('host_update_candidate_generation_unobserved');
 const ticks=id=>{const raw=fs.readFileSync('/proc/'+id+'/stat','utf8');const value=raw.slice(raw.lastIndexOf(')')+2).split(' ')[19];if(!/^[0-9]+$/.test(value??''))fail('host_update_service_process_changed');return value};
 return {pid,connectorPid:candidates[0],serviceStart:ticks(pid),connectorStart:ticks(candidates[0])};
}
// Only trusted journal fields can substitute for a restricted /proc executable
// read. The current systemd PID/parent/start identity is checked around health.
export function observeCandidateConnection({unit,invocationId,connectorPid,hostId,expectedExecutable,uid=process.getuid()}, {run=execFileSync}={}){
 if(!/^[a-f0-9]{32}$/.test(invocationId??'')||!Number.isSafeInteger(connectorPid)||connectorPid<2||!Number.isInteger(uid)||typeof expectedExecutable!=='string'||!path.isAbsolute(expectedExecutable))fail('host_update_connection_observation_unavailable');
 const raw=String(run('/usr/bin/journalctl',['--user','--no-pager','--output=json','--lines=64',
  '_SYSTEMD_USER_UNIT='+unit,'_SYSTEMD_INVOCATION_ID='+invocationId,'_PID='+connectorPid,'_UID='+uid,'_TRANSPORT=stdout'],
 {encoding:'utf8',timeout:5000,maxBuffer:256*1024,stdio:['ignore','pipe','pipe']}));
 let latest=null;
 for(const line of raw.trim().split('\n').filter(Boolean)){
  let record,message;try{record=JSON.parse(line);message=JSON.parse(record.MESSAGE)}catch{fail('host_update_connection_observation_unavailable')}
  if(record._SYSTEMD_USER_UNIT!==unit||record._SYSTEMD_INVOCATION_ID!==invocationId||record._PID!==String(connectorPid)||record._UID!==String(uid)||record._TRANSPORT!=='stdout'||record._EXE!==expectedExecutable)fail('host_update_connection_observation_unavailable');
  if(message.host!==hostId||message.lane!=='exec')continue;
  if(!['connected','disconnected','connection_failed'].includes(message.status))fail('host_update_connection_observation_unavailable');
  latest=message.status;
 }
 return latest===null?'unknown':latest==='connected'?'connected':'disconnected';
}
export async function probeSignedLocalExec({binary,signal},{factory=stdioClient}={}){
 if(signal.aborted)fail('host_update_cancelled');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'styx-update-exec-'));fs.chmodSync(temp,0o700);
 let runtime,client;
 const abort=()=>{client?.close().catch(()=>{})};signal.addEventListener('abort',abort,{once:true});
 try{
  // No deployment credentials, shell startup files, login profile or user Codex
  // configuration enter this fixed local probe. Only its own process is closed.
  runtime=new ExecConnection(async()=>{client=await factory({binary,cwd:temp,env:{PATH:'/usr/bin:/bin',HOME:temp,CODEX_HOME:temp},timeoutMs:5000});if(signal.aborted){await client.close();fail('host_update_cancelled')}return client});
  await runtime.initialize();
  const adapter=new ExecAdapter({resolve:async()=>({id:'local-update-probe',generation:'candidate',runtime,platform:'linux',cwd:temp,shell:'/bin/sh',shells:['/bin/sh'],env:{}})}),nonce=randomBytes(24).toString('hex');
  let result=await adapter.execCommand({cmd:'printf '+nonce,login:false,yield_time_ms:1000},'local-update-probe'),output=result.output;
  while(result.session_id){if(signal.aborted)fail('host_update_cancelled');result=await adapter.writeStdin({session_id:result.session_id,chars:'',yield_time_ms:1000},'local-update-probe');output+=result.output;if(output.length>128)fail('host_update_local_exec_failed')}
  if(signal.aborted||result.exit_code!==0||output!==nonce)fail('host_update_local_exec_failed');return true;
 }finally{signal.removeEventListener('abort',abort);await runtime?.close().catch(()=>{});fs.rmSync(temp,{recursive:true,force:true})}
}
export function createHostUpdateRuntime(ctx,{home=os.homedir(),run=execFileSync,observeProcess=processIdentity,observeConnection,observeQuiescence,observeJournal=observeCandidateConnection,probeExec=probeSignedLocalExec}={}){
 if(process.platform!=='linux'||!['create-local','join-existing'].includes(ctx.config.mode))fail('host_update_native_adapter_not_supported');
 const unit=ctx.service.id,unitFile=path.join(home,'.config/systemd/user',unit),dropDir=unitFile+'.d',dropFile=path.join(dropDir,'90-styx-reviewed-update.conf');
 let receipt,healthEvidence;
 const hostOnly=ctx.config.mode==='join-existing';
 const candidateProcess=(pid,ctx,version)=>observeProcess(pid,ctx,version,{allowJournalIdentity:hostOnly});
 const command=(...args)=>String(run('/usr/bin/systemctl',['--user',...args],{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']}));
 function observe(){
  const raw=command('show',unit,'--property=LoadState,ActiveState,UnitFileState,MainPID,FragmentPath,DropInPaths,Restart,InvocationID,StandardOutput','--no-pager');
  const row=Object.fromEntries(raw.trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)]}));
  if(row.LoadState!=='loaded'||row.FragmentPath!==unitFile||!['enabled','disabled'].includes(row.UnitFileState)||!/^\d+$/.test(row.MainPID??''))fail('host_update_service_observation_unavailable');
  const expectedDrops=receipt?.dropInstalled?dropFile:'';
  if((row.DropInPaths??'')!==expectedDrops||row.Restart!==(receipt?.dropInstalled?'no':'on-failure'))fail('host_update_service_override_changed');
  if(receipt&&fileHash(unitFile)!==receipt.unitSha256)fail('host_update_service_definition_changed');
  if(receipt?.dropInstalled&&fileHash(dropFile)!==hash(DROPIN))fail('host_update_inhibition_changed');
  if(hostOnly&&row.StandardOutput!=='journal')fail('host_update_connection_log_destination_unavailable');
  return {state:row.ActiveState,pid:Number(row.MainPID),enabled:row.UnitFileState,invocationId:row.InvocationID};
 }
 function bindGateway(){
  const owner=read(path.join(ctx.stateDir,'gateway/owner.json'));
  if(owner.gateway_url!==ctx.config.gateway.url||owner.gateway_ca_file!==path.join(ctx.stateDir,'gateway/certificate.pem')||owner.admin_token_file!==path.join(ctx.stateDir,'gateway/admin.token'))fail('host_update_gateway_identity_changed');
  return owner;
 }
 async function connection(){
  if(observeConnection){const result=await observeConnection();if(typeof result!=='boolean')fail('host_update_connection_observation_invalid');return result;}
  if(hostOnly){const s=observe();if(['inactive','failed'].includes(s.state)&&s.pid===0)return false;const version=read(path.join(ctx.installRoot,'active.json')).version,identity=candidateProcess(s.pid,ctx,version);return observeJournal({unit,invocationId:s.invocationId,connectorPid:identity.connectorPid,hostId:ctx.host.host_id,expectedExecutable:path.join(ctx.installRoot,'releases',version,'bin/node')},{run})==='connected';}
  const identity=read(path.join(ctx.base,'device/identity.json')),rows=await ownerCommand(bindGateway(),'devices');
  const row=rows.find(x=>x.device_id===identity.device_id&&x.fingerprint===identity.fingerprint&&x.status==='approved');
  if(!row||typeof row.online!=='boolean')fail('host_update_gateway_host_identity_unobserved');
  return row.online;
 }
 async function until(predicate,signal){
  const end=Date.now()+8000;
  do{if(signal?.aborted)fail('host_update_cancelled');if(await predicate())return true;await sleep(100)}while(Date.now()<end);
  fail('host_update_native_observation_timeout');
 }
 function noOtherHostProcesses(){
  if(observeQuiescence){if(observeQuiescence()!==true)fail('host_update_process_quiescence_unknown');return;}
  // Reuse the offline migration's kernel executable exclusion. A legitimate
  // nondumpable user manager may deny /proc/PID/exe; do not ignore that process
  // or mistake the OS policy for a live Host. Complete argv is still required.
  try{observeLinuxGatewayProcesses({stateDir:ctx.base,installRoot:ctx.installRoot})}
  catch(error){fail(error.message==='gateway_runtime_process_still_running'?'host_update_unowned_host_process':'host_update_process_quiescence_unknown')}
 }

 return {
  healthEvidence(){return healthEvidence??null},
  async prepare(save,existing){
   if(existing){
    if(existing.schema!==1||existing.unitFile!==unitFile||existing.dropFile!==dropFile||!['enabled','disabled'].includes(existing.initialEnabled)||typeof existing.unitSha256!=='string'||typeof existing.initialActive!=='boolean')fail('host_update_native_receipt_invalid');
    receipt={...existing};
    // A crash may happen after writing the drop-in but before recording it.
    if(fs.existsSync(dropFile)){if(fileHash(dropFile)!==hash(DROPIN))fail('host_update_inhibition_changed');receipt.dropInstalled=true;}
    else{
     // Finalization may have unlinked our drop-in before saving its receipt.
     // Only an empty, private directory recorded as ours may be reconciled.
     if(fs.existsSync(dropDir)){requirePrivateDirectory(dropDir);if(!existing.dropInstalled||fs.readdirSync(dropDir).length)fail('host_update_service_override_changed');fs.rmdirSync(dropDir);sync(path.dirname(dropDir));}
     receipt.dropInstalled=false;
    }
    await save(receipt);return;
   }
   const options={unitName:unit,installRoot:ctx.installRoot,hostConfigFile:ctx.service.hostConfigFile,trustPublicKeyFile:ctx.service.publisherKeyFile,nodeBinary:ctx.service.nodeBinary,...(ctx.service.restartSec!==undefined?{restartSec:ctx.service.restartSec}:{})};
   requirePrivateFile(unitFile);const expected=fs.readFileSync(unitFile,'utf8');
   if(!knownLinuxUserUnit(expected,options)||fs.existsSync(dropDir))fail('host_update_service_definition_changed');
   const state=observe();if(!['active','inactive','failed'].includes(state.state))fail('host_update_service_transitioning');
   // Admission/drain must be atomic with the Gateway before live tasks may be
   // interrupted. Until that contract exists, only an already stopped Host is
   // admitted; explicit update permission alone is not a task-drain receipt.
   if(state.state==='active')fail('host_update_active_work_drain_required');
   noOtherHostProcesses();
   receipt={schema:1,unitFile,dropFile,unitSha256:hash(expected),initialEnabled:state.enabled,initialActive:state.state==='active',dropInstalled:false};
   await save(receipt);
  },
  async stop({signal},save){
   if(!receipt)fail('host_update_native_receipt_required');
   if(fileHash(unitFile)!==receipt.unitSha256)fail('host_update_service_definition_changed');
   // First remove automatic login activation, then explicitly stop the exact unit.
   command('disable',unit);command('stop',unit);
   if(!receipt.dropInstalled){
    if(fs.existsSync(dropDir))fail('host_update_service_override_changed');
    fs.mkdirSync(dropDir,{mode:0o700});requirePrivateDirectory(dropDir);
    const fd=openPrivateFile(dropFile);try{fs.writeFileSync(fd,DROPIN);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}sync(dropDir);sync(path.dirname(dropDir));
    receipt.dropInstalled=true;await save(receipt);
   }
   command('daemon-reload');
   return until(async()=>{const s=observe();if(s.enabled!=='disabled')fail('host_update_restart_not_inhibited');if(!['inactive','failed'].includes(s.state)||s.pid!==0)return false;noOtherHostProcesses();return !(await connection())},signal);
  },
  async start({version,signal}){
   if(signal.aborted)fail('host_update_cancelled');const before=observe();
   if(before.enabled!=='disabled'||before.pid!==0||!['inactive','failed'].includes(before.state))fail('host_update_candidate_start_precondition');
   command('start',unit);
   return until(()=>{const s=observe();if(s.enabled!=='disabled')fail('host_update_restart_not_inhibited');if(s.state!=='active'||!s.pid)return false;try{candidateProcess(s.pid,ctx,version);return true}catch(error){if(error.message==='host_update_candidate_generation_unobserved'||['ENOENT','ESRCH'].includes(error.code))return false;throw error}},signal);
  },
  async health({version,signal}){
   healthEvidence=null;
   await until(()=>connection(),signal);
   const before=observe();if(before.enabled!=='disabled'||before.state!=='active')fail('host_update_candidate_not_inhibited');
   if(hostOnly){
    const identity=candidateProcess(before.pid,ctx,version);
    if(!(await probeExec({binary:path.join(ctx.installRoot,'releases',version,'bin/codex'),signal})))fail('host_update_local_exec_failed');
    const after=observe();if(after.state!=='active'||after.enabled!=='disabled'||after.invocationId!==before.invocationId||JSON.stringify(candidateProcess(after.pid,ctx,version))!==JSON.stringify(identity)||!(await connection()))fail('host_update_health_identity_changed');
    healthEvidence={method:'local_exec_probe_and_systemd_candidate_connection',serviceConnector:'signed_executable_observed_by_current_journal',serviceExecProcess:'not_independently_observed',localExec:'fixed_command_passed_independent_probe',hostConnection:'authenticated_transport_observed_in_current_invocation',remoteMcp:'NOT RUN',accountAcceptance:'NOT RUN'};return true;
   }
   const identity=candidateProcess(before.pid,ctx,version),endpoint=new URL('/mcp',ctx.config.gateway.url),tokenFile=path.join(ctx.stateDir,'gateway/model.token');
   requirePrivateFile(tokenFile);const token=fs.readFileSync(tokenFile,'utf8').trim();if(!/^[A-Za-z0-9_-]{32,}$/.test(token))fail('host_update_invalid_model_credential');
   const client=new Client({name:'styx-host-update-health',version:'1'}),transport=new StreamableHTTPClientTransport(endpoint,{requestInit:{headers:{Authorization:'Bearer '+token}},fetch:gatewayFetch(endpoint.href,{ca:fs.readFileSync(bindGateway().gateway_ca_file)}),reconnectionOptions:{maxRetries:0}});
   const nonce=randomBytes(24).toString('hex');
   // The command executes once. Its process ancestry must include the exact
   // observed candidate connector and service, not merely the same device ID.
   const cmd="printf '"+nonce+":'; p=$$; while [ \"$p\" -gt 1 ]; do printf '%s,' \"$p\"; p=$(awk '/^PPid:/{print $2}' /proc/\"$p\"/status) || exit 1; done";
   try{
    await client.connect(transport,{timeout:5000,signal});if(client.getServerVersion()?.name!=='styx-vnext')fail('host_update_wrong_gateway');
    let result=await client.callTool({name:'exec_command',arguments:{environment_id:ctx.host.host_id,cmd,login:false,yield_time_ms:250}},undefined,{timeout:5000,signal}),output=result.structuredContent?.output??'';
    while(!result.isError&&result.structuredContent?.session_id){
     result=await client.callTool({name:'write_stdin',arguments:{session_id:result.structuredContent.session_id,chars:'',yield_time_ms:250}},undefined,{timeout:5000,signal});output+=result.structuredContent?.output??'';
     if(output.length>4096)fail('host_update_health_response_invalid');
    }
    if(result.isError||result.structuredContent?.exit_code!==0||!output.startsWith(nonce+':')||!/^([0-9]+,)+$/.test(output.slice(nonce.length+1)))fail('host_update_exec_health_failed');
    const ancestors=output.slice(nonce.length+1).split(',').map(Number);
    if(!ancestors.includes(identity.pid)||!ancestors.includes(identity.connectorPid))fail('host_update_exec_wrong_generation');
    if(JSON.stringify(candidateProcess(observe().pid,ctx,version))!==JSON.stringify(identity)||!(await connection()))fail('host_update_health_identity_changed');
    healthEvidence={method:'mcp_exec_candidate_process_ancestry_and_authenticated_host_connection',remoteMcp:'verified',accountAcceptance:'NOT RUN'};return true;
   }finally{try{await transport.terminateSession()}catch{}try{await client.close()}catch{}}
  },
  async confirmStopped(){noOtherHostProcesses();const s=observe();return s.enabled==='disabled'&&s.pid===0&&['inactive','failed'].includes(s.state)&&!(await connection())},
  async finish(save,{restoreEnabled=true}={}){
   let s=observe();if(s.enabled!=='disabled')fail('host_update_restart_not_inhibited');
   if(restoreEnabled){
    if(s.state!=='active'||s.pid<2)fail('host_update_healthy_candidate_exited');
    candidateProcess(s.pid,ctx,read(path.join(ctx.installRoot,'active.json')).version);
    if(!receipt.initialActive){command('stop',unit);await until(()=>{const current=observe();return ['inactive','failed'].includes(current.state)&&current.pid===0},undefined);s=observe();}
   }else if(!['inactive','failed'].includes(s.state)||s.pid!==0)fail('host_update_recovery_requires_stopped');
   if(fileHash(dropFile)!==hash(DROPIN))fail('host_update_inhibition_changed');
   fs.unlinkSync(dropFile);fs.rmdirSync(dropDir);sync(path.dirname(dropDir));receipt.dropInstalled=false;await save(receipt);command('daemon-reload');
   if(restoreEnabled&&receipt.initialEnabled==='enabled')command('enable',unit);
   return {startup:restoreEnabled?receipt.initialEnabled:'disabled',state:restoreEnabled&&receipt.initialActive?'running':'stopped',restartPolicy:'restored'};
  }
 };
}
