// Explicit, isolated native acceptance. The production quiescence observer is
// never replaced. Same payload / different signed generations tests transaction
// mechanics, not an upgrade to another Node binary or application revision.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {buildGatewayRelease} from '../onboarding/gateway-release.mjs';
import {createDeployment,advanceDeployment,stopDeploymentGateway,readDeployment} from '../onboarding/core.mjs';
import {readGatewayRuntime,verifyGatewayRuntimeRelease} from '../onboarding/gateway-runtime.mjs';
import {planGatewayRuntimeChange,applyGatewayRuntimeChange,recoverGatewayRuntimeChange,readGatewayRuntimeChange,observeGatewayRuntimeQuiescence} from '../onboarding/gateway-runtime-update.mjs';
import {gatewayFetch} from '../onboarding/connection.mjs';
import {gatewayServiceIdentity} from '../onboarding/gateway-service.mjs';
import {ensurePrivateDirectory,writePrivateFile} from './private-storage.mjs';
const assert=(condition,code)=>{if(!condition)throw Error(code)};
const sha=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const here=fileURLToPath(import.meta.url);
export function linuxGatewayUpdatePaths(options={},platform=process.platform,arch=process.arch){
 assert(platform==='linux'&&arch==='x64','linux_x64_acceptance_required');
 const {directory,nodeBinary,nodeLicenseFile,nodeProvenanceFile,sourceRoot,dependenciesRoot}=options;
 for(const value of [directory,nodeBinary,nodeLicenseFile,nodeProvenanceFile,sourceRoot,dependenciesRoot])assert(typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value,'absolute_acceptance_paths_required');
 assert(/^linux-update-20261021(?:-[A-Za-z0-9_-]+)?$/.test(path.basename(directory)),'scoped_linux_update_directory_required');
 for(const input of [nodeBinary,nodeLicenseFile,nodeProvenanceFile,sourceRoot,dependenciesRoot])assert(input!==directory&&!input.startsWith(directory+path.sep),'independent_acceptance_inputs_required');
 return {directory,nodeBinary,nodeLicenseFile,nodeProvenanceFile,sourceRoot,dependenciesRoot};
}
export function linuxGatewayPreservedInventory(stateDir){
 const result={'deployment.json':sha(path.join(stateDir,'deployment.json'))};
 const walk=(dir,relative)=>{for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
  const name=relative+'/'+entry.name,file=path.join(dir,entry.name);assert(!entry.isSymbolicLink(),'unexpected_preserved_symlink');
  if(entry.isDirectory())walk(file,name);else {assert(entry.isFile(),'unexpected_preserved_file');result[name]=sha(file);}
 }};
 walk(path.join(stateDir,'gateway'),'gateway');return result;
}
function ownedIdentity(pid){
 const stat=fs.readFileSync('/proc/'+pid+'/stat','utf8');return {pid,startTicks:stat.slice(stat.lastIndexOf(')')+2).split(' ')[19]};
}
function alive(record){try{return ownedIdentity(record.pid).startTicks===record.startTicks;}catch{return false;}}
// Explain a refusal using only numeric PID / operation / errno. Never expose
// unrelated command lines, executable names, environment, or process contents.
function inaccessibleProcesses(){
 const errors=[];
 for(const entry of fs.readdirSync('/proc').filter(x=>/^\d+$/.test(x))){let operation='stat';
  try{const proc='/proc/'+entry;if(fs.statSync(proc).uid!==process.getuid())continue;
   operation='cmdline';const args=fs.readFileSync(proc+'/cmdline');if(args.length===0)continue;
   operation='exe';fs.readlinkSync(proc+'/exe');
  }catch(error){if(!['ENOENT','ESRCH'].includes(error.code))errors.push({pid:Number(entry),operation,code:error.code??'unknown'});}
 }
 return errors;
}
async function stop(child){
 if(!child||child.exitCode!==null||child.signalCode!==null)return;
 child.kill('SIGTERM');for(let i=0;i<60&&child.exitCode===null&&child.signalCode===null;i++)await pause(100);
 assert(child.exitCode!==null||child.signalCode!==null,'owned_gateway_shutdown_unconfirmed');
}
async function waitForReady(child){
 for(let i=0;i<200;i++){if(child.ready)return;assert(child.exitCode===null&&child.signalCode===null,'signed_gateway_runner_exited');await pause(50);}
 throw Error('signed_gateway_runner_ready_timeout');
}
export async function runLinuxGatewayUpdateAcceptance(options){
 assert(process.env.STYX_RUN_LINUX_GATEWAY_UPDATE_ACCEPTANCE==='1','explicit_linux_gateway_update_acceptance_required');
 const cfg=linuxGatewayUpdatePaths(options);assert(!fs.existsSync(cfg.directory),'fresh_linux_update_directory_required');
 ensurePrivateDirectory(cfg.directory,{exclusive:true});
 const privateRoot=path.join(cfg.directory,'private');ensurePrivateDirectory(privateRoot,{exclusive:true});
 const receipt={schema:1,kind:'linux-native-signed-gateway-offline-generation-update-rollback',status:'RUNNING',startedAt:new Date().toISOString(),gates:{},boundaries:{binaryUpgrade:'NOT RUN; identical official Node and application payload in two differently versioned signed manifests',publisher:'ephemeral test publisher, not official release trust',services:'no installation, only real systemd read-only observation',execCuaBrowser:'NOT INSTALLED',realRebootPowerLoss:'NOT RUN',productionMutation:'NOT RUN',chatgptAccount:'NOT RUN'}};
 const save=()=>fs.writeFileSync(path.join(cfg.directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
 const record=(name,evidence={})=>{receipt.gates[name]={status:'PASS',...evidence};save();};
 const stateDir=path.join(privateRoot,'deployment');let currentChild,phase='verify_inputs',owned=[],gatewayPrepared=false;
 let runtime;
 try{
  const provenance=JSON.parse(fs.readFileSync(cfg.nodeProvenanceFile,'utf8'));
  assert(provenance.version==='22.23.3'&&provenance.platform==='linux'&&provenance.arch==='x64'&&provenance.url==='https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-x64.tar.xz','official_node_provenance_required');
  assert(sha(cfg.nodeBinary)===provenance.binary_sha256&&sha(cfg.nodeLicenseFile)===provenance.license_sha256,'official_node_payload_hash_mismatch');
  assert(execFileSync(cfg.nodeBinary,['--version'],{encoding:'utf8',timeout:10000}).trim()==='v22.23.3','official_node_version_mismatch');
  receipt.nodeProvenance={...provenance};receipt.acceptanceSourceSha256=sha(here);
  phase='build_signed_generations';const key=generateKeyPairSync('ed25519'),privateKeyFile=path.join(privateRoot,'publisher-private.pem'),publisherKeyFile=path.join(privateRoot,'publisher.pem');
  writePrivateFile(privateKeyFile,key.privateKey.export({type:'pkcs8',format:'pem'}));writePrivateFile(publisherKeyFile,key.publicKey.export({type:'spki',format:'pem'}));
  const bundles=['update-old.20261021','update-new.20261021'].map(version=>({version,bundle:path.join(privateRoot,version)}));
  const builds=bundles.map(({bundle:destination,version})=>buildGatewayRelease({...cfg,destination,version,privateKeyFile}));
  const pem=fs.readFileSync(publisherKeyFile),verified=bundles.map(x=>verifyGatewayRuntimeRelease(x.bundle,pem));
  assert(JSON.stringify(verified[0].manifest.files)===JSON.stringify(verified[1].manifest.files),'generation_payloads_differ');
  assert(builds[0].manifestSha256!==builds[1].manifestSha256,'generation_manifests_not_distinct');
  fs.rmSync(privateKeyFile);record('two_complete_signed_generations_identical_payload',{generations:builds.map(({version,manifestSha256,files,dependencies})=>({version,manifestSha256,files,dependencies})),nodeSha256:sha(cfg.nodeBinary),privateSigningKeyDeleted:true});
  const probe=createServer();await new Promise(resolve=>probe.listen(0,'127.0.0.1',resolve));const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));
  runtime={bundle:bundles[0].bundle,publisherKeyFile,publisherSha256:builds[0].publisherSha256,baseDir:path.join(privateRoot,'gateway-runtime')};
  const input=path.join(privateRoot,'input.json'),config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl',runtime}};writePrivateFile(input,JSON.stringify(config));
  phase='prepare_gateway_only_core';createDeployment(input,{stateDir});gatewayPrepared=true;
  await advanceDeployment(stateDir,{authorize:['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify']});
  await stopDeploymentGateway(stateDir);
  assert(readDeployment(stateDir).steps.every(step=>!step.id.startsWith('host.'))&&!fs.existsSync(path.join(stateDir,'host')),'gateway_only_prepared_host');
  const before=linuxGatewayPreservedInventory(stateDir);record('real_core_gateway_only_prepare_no_host',{preservedFiles:before});
  const scope={stateDir,installRoot:path.join(runtime.baseDir,'install')};
  const quiet=()=>observeGatewayRuntimeQuiescence(scope);
  const start=async(label)=>{
   const active=readGatewayRuntime(runtime),log=fs.openSync(path.join(cfg.directory,label+'-runner.log'),'wx',0o600);
   currentChild=spawn(active.nodeBinary,[active.runnerBinary,stateDir],{stdio:['ignore','pipe',log]});fs.closeSync(log);
   currentChild.ready=false;let stdout='';currentChild.stdout.on('data',data=>{stdout+=data;currentChild.ready=stdout.includes('Styx signed Gateway running.');});currentChild.on('error',()=>{});
   owned.push(ownedIdentity(currentChild.pid));await waitForReady(currentChild);
   const exe=fs.readlinkSync('/proc/'+currentChild.pid+'/exe'),args=fs.readFileSync('/proc/'+currentChild.pid+'/cmdline').toString().split('\0').filter(Boolean);
   assert(exe===active.nodeBinary&&args[1]===active.runnerBinary,'actual_signed_process_binding_mismatch');
   const client=new Client({name:'styx-linux-update-owned',version:'1'}),endpoint=config.gateway.url+'/mcp';
   const transport=new StreamableHTTPClientTransport(new URL(endpoint),{requestInit:{headers:{Authorization:'Bearer '+fs.readFileSync(path.join(stateDir,'gateway/model.token'),'utf8').trim()}},fetch:gatewayFetch(endpoint,{ca:fs.readFileSync(path.join(stateDir,'gateway/certificate.pem'))})});
   try{await client.connect(transport);const tools=await client.listTools();assert(tools.tools.some(x=>x.name==='exec_command'),'tls_mcp_tools_missing');return {version:active.version,manifestSha256:active.manifestSha256,nodeSha256:sha(active.nodeBinary),runnerSha256:sha(active.runnerBinary),pid:currentChild.pid,tools:tools.tools.map(x=>x.name)};}
   finally{await transport.terminateSession().catch(()=>{});await client.close().catch(()=>{});await stop(currentChild);currentChild=undefined;}
  };
  phase='old_signed_runner_tls_mcp';record('old_generation_actual_signed_runner_tls_mcp',await start('old'));
  assert(JSON.stringify(linuxGatewayPreservedInventory(stateDir))===JSON.stringify(before),'old_runner_changed_preserved_configuration');
  phase='review_update_apply';const plan=planGatewayRuntimeChange({stateDir,bundle:bundles[1].bundle});
  writePrivateFile(path.join(cfg.directory,'update-plan.json'),JSON.stringify(plan,null,2)+'\n');
  receipt.realServiceObservation={name:gatewayServiceIdentity(stateDir),output:execFileSync('/usr/bin/systemctl',['--user','show',gatewayServiceIdentity(stateDir),'--property=LoadState,ActiveState,MainPID'],{encoding:'utf8',timeout:10000}).trim().split('\n')};save();
  const updated=applyGatewayRuntimeChange({stateDir,plan,authorize:true});assert(updated.version===bundles[1].version,'updated_generation_wrong');
  assert(JSON.stringify(linuxGatewayPreservedInventory(stateDir))===JSON.stringify(before),'update_changed_preserved_configuration');record('real_observer_review_bound_update_preserves_exact_configuration',{...updated,quiescence:quiet()});
  phase='new_signed_runner_tls_mcp';record('new_generation_actual_signed_runner_tls_mcp',await start('new'));
  phase='offline_signed_rollback';const rollback=planGatewayRuntimeChange({stateDir,rollback:true});writePrivateFile(path.join(cfg.directory,'rollback-plan.json'),JSON.stringify(rollback,null,2)+'\n');
  const rolledBack=applyGatewayRuntimeChange({stateDir,plan:rollback,authorize:true});assert(rolledBack.version===bundles[0].version,'rollback_generation_wrong');
  assert(JSON.stringify(linuxGatewayPreservedInventory(stateDir))===JSON.stringify(before),'rollback_changed_preserved_configuration');record('real_observer_offline_signed_rollback_preserves_exact_configuration',{...rolledBack,quiescence:quiet()});
  record('rollback_old_generation_actual_signed_runner_tls_mcp',await start('rollback'));
  phase='actual_installer_process_interruption';const interruptedInput=path.join(privateRoot,'interrupted-change.json'),interruptedPlan=planGatewayRuntimeChange({stateDir,bundle:bundles[1].bundle});writePrivateFile(interruptedInput,JSON.stringify({stateDir,plan:interruptedPlan,authorize:true}));
  const worker=spawn(cfg.nodeBinary,[here,'--interrupt-own-update',interruptedInput],{stdio:['ignore','ignore','pipe'],env:{...process.env,STYX_RUN_LINUX_GATEWAY_UPDATE_ACCEPTANCE:'1'}});owned.push(ownedIdentity(worker.pid));
  const death=await new Promise((resolve,reject)=>{worker.once('error',reject);worker.once('close',(code,signal)=>resolve({code,signal}));});
  assert(death.signal==='SIGKILL','installer_did_not_die_at_committed_pointer');const interrupted=readGatewayRuntimeChange({stateDir});assert(interrupted.status==='recovery_required'&&interrupted.phase==='committing','interrupted_journal_not_recoverable');
  const recovered=recoverGatewayRuntimeChange({stateDir,transactionId:interrupted.transactionId,authorize:true});assert(recovered.version===bundles[0].version,'recovery_generation_wrong');
  assert(JSON.stringify(linuxGatewayPreservedInventory(stateDir))===JSON.stringify(before),'recovery_changed_preserved_configuration');record('actual_sigkill_after_pointer_switch_real_observer_recovery',{death,...recovered,quiescence:quiet()});
  record('recovered_old_generation_actual_signed_runner_tls_mcp',await start('recovered'));
  assert(JSON.stringify(linuxGatewayPreservedInventory(stateDir))===JSON.stringify(before),'final_preserved_configuration_changed');receipt.preservedFilesAfter=linuxGatewayPreservedInventory(stateDir);receipt.status='PASS';
 }catch(error){
  receipt.status='BLOCKED';receipt.failedPhase=phase;receipt.reason=/^[A-Za-z0-9_]+$/.test(error.message??'')?error.message:'native_update_acceptance_operation_failed';
  if(error.message==='gateway_process_quiescence_unknown'){
   receipt.quiescenceBlocker={inaccessibleCurrentUserProcesses:inaccessibleProcesses(),policyChanges:'NOT RUN',observerOverride:'NOT USED'};
   const unchanged=readGatewayRuntime(runtime),current=linuxGatewayPreservedInventory(stateDir);
   const baseline=receipt.gates.real_core_gateway_only_prepare_no_host.preservedFiles;
   assert(unchanged.version==='update-old.20261021'&&JSON.stringify(current)===JSON.stringify(baseline),'blocked_update_changed_preserved_configuration');
   assert(readGatewayRuntimeChange({stateDir}).status==='none'&&!fs.existsSync(path.join(stateDir,'advance.lock')),'blocked_update_left_transaction_or_lock');
   record('blocked_update_preserves_original_generation_exact_configuration_no_journal_or_lock',{version:unchanged.version,manifestSha256:unchanged.manifestSha256,preservedFiles:current});
  }
 }
 finally{
  try{await stop(currentChild);if(gatewayPrepared)await stopDeploymentGateway(stateDir);}catch{receipt.status='BLOCKED';receipt.cleanup='owned_gateway_shutdown_unconfirmed';}
  receipt.remainingOwnedProcesses=owned.filter(alive).map(x=>x.pid);
  const signingKey=path.join(privateRoot,'publisher-private.pem');fs.rmSync(signingKey,{force:true});
  if(receipt.remainingOwnedProcesses.length===0&&!receipt.cleanup){fs.rmSync(privateRoot,{recursive:true,force:true});receipt.cleanup='own_processes_stopped_private_state_and_signing_key_removed_no_service_changes';}
  else {receipt.status='BLOCKED';receipt.cleanup??='own_process_shutdown_unconfirmed_private_state_preserved';}
  receipt.completedAt=new Date().toISOString();save();
 }
 return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===here){
 try{
  if(process.argv[2]==='--interrupt-own-update'){
   assert(process.env.STYX_RUN_LINUX_GATEWAY_UPDATE_ACCEPTANCE==='1','explicit_linux_gateway_update_acceptance_required');
   const input=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
   assert(path.basename(path.dirname(path.dirname(input.stateDir))).startsWith('linux-update-20261021'),'scoped_linux_update_directory_required');
   applyGatewayRuntimeChange(input,{afterCheckpoint(stage){if(stage==='pointer_switched')process.kill(process.pid,'SIGKILL');}});
   throw Error('interruption_checkpoint_not_reached');
  }
  const result=await runLinuxGatewayUpdateAcceptance(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));
  console.log(JSON.stringify(result));process.exitCode=result.status==='PASS'?0:2;
 }catch(error){console.log(JSON.stringify({status:'BLOCKED',reason:/^[A-Za-z0-9_]+$/.test(error.message??'')?error.message:'native_update_acceptance_setup_failed'}));process.exitCode=2;}
}
