// Opt-in native CLI acceptance: real signed Host, real pairing, isolated installed user service.
// Upgrade health has no access to Gateway credentials. The separate acceptance client does.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,generateKeyPairSync,createPublicKey} from 'node:crypto';
import {createServer} from 'node:http';
import {spawn,execFileSync} from 'node:child_process';
import os from 'node:os';
import {installLinuxService,removeLinuxService,systemdUser,statusUserService} from './linux-service.mjs';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import * as api from '../onboarding/core.mjs';
import {gatewayFetch} from '../onboarding/connection.mjs';
import {buildHostRelease} from './build-host-release.mjs';
import {activeRelease} from './installer.mjs';
import {ensurePrivateDirectory,writePrivateFile} from './private-storage.mjs';
const assert=(ok,why)=>{if(!ok)throw Error(why)};
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function wait(check,why){for(let n=0;n<100;n++){if(await check())return;await pause(200)}throw Error(why)}
export async function runLinuxHostServiceAcceptance(options){
 assert(process.env.STYX_RUN_LINUX_HOST_SERVICE_ACCEPTANCE==='1'&&process.platform==='linux','explicit_native_linux_acceptance_required');
 const {directory,distribution,nodeBinary,codexBinary,cuaBinary,listenHost,unitName}=options;
 assert(/^styx-rc[0-9]{8}-owned-[a-z0-9]{1,12}\.service$/.test(unitName??''),'explicit_owned_unit_required');
 const unitFile=path.join(os.homedir(),'.config/systemd/user',unitName);assert(!fs.existsSync(unitFile)&&!fs.existsSync(unitFile+'.d'),'fresh_unit_required');
 const initial=String(execFileSync('/usr/bin/systemctl',['--user','show',unitName,'--property=LoadState','--value'],{encoding:'utf8'})).trim();assert(initial==='not-found','fresh_unloaded_unit_required');
 for(const p of [directory,distribution,nodeBinary,codexBinary,cuaBinary])assert(path.isAbsolute(p)&&path.normalize(p)===p,'absolute_paths_required');
 assert(!fs.existsSync(directory)&&options.authorizeExactInterface===true,'fresh_authorized_scope_required');
 ensurePrivateDirectory(directory,{exclusive:true});
 const privateRoot=path.join(directory,'private');ensurePrivateDirectory(privateRoot,{exclusive:true});
 const receipt={schema:1,kind:'linux-native-host-only-core-cli-installed-service-update',status:'RUNNING',startedAt:new Date().toISOString(),gates:{},boundaries:{serviceInstall:unitName,realAccount:'NOT RUN',physicalRestart:'NOT RUN',publisher:'ephemeral acceptance publisher'}};
 const save=()=>fs.writeFileSync(path.join(directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600}),record=(name,details={})=>{receipt.gates[name]={status:'PASS',...details};save()};
 const owner=path.join(privateRoot,'owner'),joined=path.join(privateRoot,'joined'),base=path.join(privateRoot,'host');
 const previousHome=process.env.CODEX_HOME;process.env.CODEX_HOME=path.join(privateRoot,'codex-home');ensurePrivateDirectory(process.env.CODEX_HOME,{exclusive:true});
 let phase='build',client,transport,installed=false;
 const cli=async args=>{
  const child=spawn(nodeBinary,[fileURLToPath(new URL('../onboarding/cli.mjs',import.meta.url)),...args],{env:process.env,stdio:['ignore','pipe','pipe']});let out='',error='';child.stdout.on('data',x=>out+=x);child.stderr.on('data',x=>error+=x);
  const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve)});
  if(error.trim()){receipt.nativeDiagnostic=error.trim().slice(0,1800);save()}if(code!==0){receipt.cliFailure={command:args[0],exitCode:code,error:error.trim().slice(0,1800),blockers:(()=>{try{return JSON.parse(out).blockers}catch{return undefined}})()};save();throw Error('real_cli_failed_'+args[0])}return JSON.parse(out);
 };
 const stop=async()=>{if(transport)await transport.terminateSession().catch(()=>{});await client?.close().catch(()=>{});transport=null;client=null;if(installed)systemdUser(unitName,'stop');};
 try{
  const keys=generateKeyPairSync('ed25519'),pem=keys.publicKey.export({type:'spki',format:'pem'}),publicKeyFile=path.join(privateRoot,'publisher.pem'),privateKeyFile=path.join(privateRoot,'publisher-private.pem');
  writePrivateFile(publicKeyFile,pem);writePrivateFile(privateKeyFile,keys.privateKey.export({type:'pkcs8',format:'pem'}));
  const publisherSha256=createHash('sha256').update(createPublicKey(pem).export({type:'spki',format:'der'})).digest('hex');
  const versions=['0.1.0-linux-offline-old','0.2.0-linux-offline-next'],bundles=versions.map(v=>path.join(privateRoot,v));
  for(let n=0;n<2;n++)buildHostRelease({destination:bundles[n],version:versions[n],privateKeyFile,nodeBinary,codexBinary,cuaBinary});
  record('native_signed_host_generations',{versions});
  phase='gateway_only_prepare';const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
  const build=JSON.parse(fs.readFileSync(path.join(distribution,'build-receipt.json'))),gatewayUrl='https://127.0.0.1:'+port;
  const ownerConfig={schema:1,mode:'create-local',gateway:{url:gatewayUrl,openssl:'/usr/bin/openssl',runtime:{bundle:path.join(distribution,'gateway-bundle'),publisherKeyFile:path.join(distribution,'publisher.pem'),publisherSha256:build.publisherSha256,baseDir:path.join(privateRoot,'gateway-runtime')}}};
  const ownerInput=path.join(privateRoot,'owner.json');writePrivateFile(ownerInput,JSON.stringify(ownerConfig));api.createDeployment(ownerInput,{stateDir:owner});await api.advanceDeployment(owner,{authorize:['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify']});
  phase='host_only_real_pairing';const invitation=await api.createDeploymentPairingLink(owner,{authorize:true,listenHost}),inspected=api.inspectPairingLink(invitation.link),material=path.join(privateRoot,'join-material');api.acceptPairingLink(invitation.link,{stateDir:material,approvedGatewayOrigin:inspected.origin,approvedCaSha256:inspected.caSha256});const pairing=JSON.parse(fs.readFileSync(path.join(material,'pairing.json')));
  const joinInput=path.join(privateRoot,'join.json');writePrivateFile(joinInput,JSON.stringify({schema:1,mode:'join-existing',gateway:{url:pairing.gatewayOrigin,caFile:pairing.gatewayCaFile},host:{bundle:bundles[0],publisherKeyFile:publicKeyFile,publisherSha256,baseDir:base,label:'Owned Linux offline Host',computer:false},invitationFile:pairing.invitationFile}));api.createDeployment(joinInput,{stateDir:joined});await api.advanceDeployment(joined,{authorize:['host.prepare','host.request']});
  const requested=api.readDeployment(joined).steps.find(s=>s.id==='host.request').evidence,pending=(await api.listDeploymentPending(owner,{authorize:true})).find(s=>s.request_id===requested.request_id);assert(requested.fingerprint===pending.fingerprint&&requested.comparison_code===pending.comparison_code,'pairing_identity_mismatch');await api.approveDeploymentPending(owner,{authorize:true,requestId:pending.request_id,fingerprint:pending.fingerprint});await api.advanceDeployment(joined,{authorize:['host.claim','host.doctor']});
  for(const id of ['host.prepare','host.request','host.claim','host.doctor'])assert(api.readDeployment(joined).steps.some(s=>s.id===id&&s.status==='succeeded'),'host_step_failed_'+id.replaceAll('.','_'));
  assert(!fs.existsSync(path.join(joined,'gateway')),'host_only_created_local_gateway');record('real_host_only_invitation_approval_and_claim_without_local_gateway');
  const identityFiles=['identity.json','identity.pem','host.token'].map(n=>path.join(base,'device',n)),identityBefore=identityFiles.map(hash),deviceId=requested.device_id;
  const serviceFile=path.join(base,'service.json');let service=JSON.parse(fs.readFileSync(serviceFile));service.unitName=unitName;fs.writeFileSync(serviceFile,JSON.stringify(service),{mode:0o600});assert(service.nodeBinary===path.join(base,'install/node'),'fresh_stable_bootstrap_required');installLinuxService(service);installed=true;record('isolated_systemd_user_service_installed_stopped',{unitName});
  const runExec=async marker=>{systemdUser(unitName,'start');await wait(async()=>{const d=(await api.readDeploymentDevices(owner)).find(x=>x.device_id===deviceId);return d?.connections.exec},'host_exec_not_connected');
   const endpoint=gatewayUrl+'/mcp';client=new Client({name:'owned-linux-offline-migration',version:'1'});transport=new StreamableHTTPClientTransport(new URL(endpoint),{requestInit:{headers:{Authorization:'Bearer '+fs.readFileSync(path.join(owner,'gateway/model.token'),'utf8').trim()}},fetch:gatewayFetch(endpoint,{ca:fs.readFileSync(path.join(owner,'gateway/certificate.pem'))})});await client.connect(transport);
   let result=await client.callTool({name:'exec_command',arguments:{environment_id:deviceId,cmd:'printf '+marker,login:false,yield_time_ms:1000}}),output=result.structuredContent?.output??'';
   while(result.structuredContent?.session_id){result=await client.callTool({name:'write_stdin',arguments:{session_id:result.structuredContent.session_id,chars:'',yield_time_ms:1000}});output+=result.structuredContent?.output??'';}
   assert(!result.isError&&output===marker&&result.structuredContent?.exit_code===0,'real_exec_output_failed');await stop();
  };
  phase='baseline_exec';await runExec('STYX_LINUX_OLD_EXEC');record('old_native_exec_before_migration');
  phase='cli_service_plan';const plan=await cli(['host-update-plan',joined,bundles[1]]);assert(plan.status==='ready','native_service_plan_unavailable');
  const planFile=path.join(privateRoot,'plan.json');writePrivateFile(planFile,JSON.stringify(plan));record('real_cli_host_only_service_plan_no_gateway_credentials',{localGatewayDirectory:fs.existsSync(path.join(joined,'gateway'))});
  phase='cli_service_apply';const applied=await cli(['host-update-apply',joined,planFile,'--authorize']);fs.writeFileSync(path.join(directory,'apply.json'),JSON.stringify(applied,null,2)+'\n',{mode:0o600});assert(applied.status==='activated','service_apply_wrong_result');assert(applied.nativeHealth.method==='local_exec_probe_and_systemd_candidate_connection'&&applied.nativeHealth.remoteMcp==='NOT RUN','service_health_scope_wrong');assert(activeRelease(path.join(base,'install'),pem).version===versions[1],'candidate_not_active');assert(identityFiles.every((f,n)=>hash(f)===identityBefore[n]),'identity_changed');record('real_cli_apply_signed_generation_preserves_identity',{activeVersion:versions[1],health:applied.nativeHealth});
  phase='candidate_exec';await runExec('STYX_LINUX_NEXT_EXEC');record('candidate_remote_mcp_exec_separate_from_upgrade_health');
  phase='cli_service_rollback';const rollback=await cli(['host-rollback-plan',joined]);assert(rollback.status==='ready','rollback_plan_blocked');const rollbackFile=path.join(privateRoot,'rollback.json');writePrivateFile(rollbackFile,JSON.stringify(rollback));const rolled=await cli(['host-update-apply',joined,rollbackFile,'--authorize']);assert(rolled.status==='activated','rollback_wrong_result');assert(activeRelease(path.join(base,'install'),pem).version===versions[0],'old_generation_not_restored');assert(identityFiles.every((f,n)=>hash(f)===identityBefore[n]),'rollback_identity_changed');record('real_cli_rollback_restores_generation_and_identity',{activeVersion:versions[0]});
  phase='rollback_exec';await runExec('STYX_LINUX_RESTORED_EXEC');record('restored_remote_mcp_exec_separate_from_upgrade_health');receipt.status='PASS';
 }catch(e){try{receipt.update=api.readHostUpdate({stateDir:joined})}catch{}receipt.status='BLOCKED';receipt.failedPhase=phase;receipt.reason=/^[\w.-]+$/.test(e.message??'')?e.message:'native_acceptance_failed';}
 finally{
  try{if(fs.existsSync(joined))await stop();if(installed){removeLinuxService(unitName);installed=false;const drop=path.join(unitFile+'.d','90-styx-reviewed-update.conf');if(fs.existsSync(drop)){assert(fs.readFileSync(drop,'utf8')==='# Managed by Styx reviewed Host update\n[Service]\nRestart=no\n','owned_drop_changed');fs.unlinkSync(drop);fs.rmdirSync(unitFile+'.d');systemdUser(unitName,'daemon-reload');}}if(fs.existsSync(owner))await api.stopDeploymentGateway(owner);receipt.cleanup='owned_service_removed_gateway_stopped_private_state_removed';fs.rmSync(privateRoot,{recursive:true,force:true});}catch{receipt.status='BLOCKED';receipt.cleanup='shutdown_unconfirmed_private_state_preserved'}
  if(previousHome===undefined)delete process.env.CODEX_HOME;else process.env.CODEX_HOME=previousHome;
  receipt.completedAt=new Date().toISOString();save();
 }
 return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const result=await runLinuxHostServiceAcceptance(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));console.log(JSON.stringify(result,null,2));if(result.status!=='PASS')process.exitCode=2;
}
