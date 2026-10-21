// Explicit native acceptance of a packaged Core. No fixture identity injection,
// service installation, public endpoint, daily profile, or account login.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {ensurePrivateDirectory,writePrivateFile} from './private-storage.mjs';
import {verifySignedRelease} from './installer.mjs';
const assert=(condition,code)=>{if(!condition)throw Error(code)};
const sha=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const text=result=>(result.content??[]).filter(x=>x.type==='text').map(x=>x.text).join('\n');
async function wait(check,code){for(let i=0;i<160;i++){if(await check())return;await pause(250);}throw Error(code);}
export function linuxAcceptanceReference(result,label){
 const escaped=label.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 const match=new RegExp('"'+escaped+'"[^\\n]*\\[ref=(styx-[a-f0-9]+)\\]').exec(text(result));
 assert(match,'owned_browser_reference_missing');return match[1];
}
export function linuxAcceptancePaths({directory,distribution}={},platform=process.platform,arch=process.arch){
 assert(platform==='linux'&&arch==='x64','linux_x64_acceptance_required');
 for(const p of [directory,distribution])assert(typeof p==='string'&&path.isAbsolute(p)&&path.normalize(p)===p,'absolute_acceptance_paths_required');
 assert(directory!==distribution&&!directory.startsWith(distribution+path.sep)&&!distribution.startsWith(directory+path.sep),'independent_acceptance_directory_required');
 return {directory,distribution};
}
function descendants(pid=process.pid){
 const children=fs.readFileSync('/proc/'+pid+'/task/'+pid+'/children','utf8').trim().split(/\s+/).filter(Boolean).map(Number),result=[];
 for(const id of children){try{const stat=fs.readFileSync('/proc/'+id+'/stat','utf8'),tail=stat.slice(stat.lastIndexOf(')')+2).split(' '),name=path.basename(fs.readlinkSync('/proc/'+id+'/exe'));result.push({pid:id,name,startTicks:tail[19]},...descendants(id));}catch{}}
 return result;
}
function alive(record){try{const stat=fs.readFileSync('/proc/'+record.pid+'/stat','utf8');return stat.slice(stat.lastIndexOf(')')+2).split(' ')[19]===record.startTicks;}catch{return false;}}
export async function runLinuxCliAcceptance(options){
 assert(process.env.STYX_RUN_LINUX_CLI_ACCEPTANCE==='1','explicit_linux_cli_acceptance_required');
 const {directory,distribution}=linuxAcceptancePaths(options);
 assert(!fs.existsSync(directory),'fresh_linux_acceptance_directory_required');
 ensurePrivateDirectory(directory,{exclusive:true});
 const receipt={schema:1,kind:'linux-packaged-core-real-tls-exec-browser-and-join',status:'RUNNING',startedAt:new Date().toISOString(),gates:{},boundaries:{publisher:'ephemeral test publisher; not official distribution trust',desktop:'disabled; no Cua acceptance claimed',serviceMutation:'NOT RUN',productionMutation:'NOT RUN',realAccountLogin:'NOT RUN',chatgptAcceptance:'NOT RUN'}};
 const output=path.join(directory,'receipt.json'),save=()=>fs.writeFileSync(output,JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
 const record=(gate,evidence={})=>{receipt.gates[gate]={status:'PASS',...evidence};save();};
 let api,site,combined,joined,phase='verify_distribution',clients=[],owned=[];
 const privateRoot=path.join(directory,'private');ensurePrivateDirectory(privateRoot,{exclusive:true});
 const originalCodexHome=process.env.CODEX_HOME,ownerCodexHome=path.join(privateRoot,'owner-codex-home');ensurePrivateDirectory(ownerCodexHome,{exclusive:true});process.env.CODEX_HOME=ownerCodexHome;
 const closeClient=async item=>{if(item.closed)return;await item.transport.terminateSession().catch(()=>{});await item.client.close().catch(()=>{});item.closed=true;};
 try{
  const build=JSON.parse(fs.readFileSync(path.join(distribution,'build-receipt.json'))),pem=fs.readFileSync(path.join(distribution,'publisher.pem'));
  assert(build.hostBundleIncluded===true,'signed_host_distribution_required');
  const verified=verifySignedRelease(path.join(distribution,'host-bundle'),pem,{platform:'linux',arch:'x64'});
  verifySignedRelease(path.join(distribution,'gateway-bundle'),pem,{platform:'linux',arch:'x64'});
  receipt.distribution={version:build.version,publisherSha256:build.publisherSha256,hostManifestSha256:verified.sha256,nodeSha256:sha(path.join(distribution,'runtime/node')),sourceAcceptanceSha256:sha(fileURLToPath(import.meta.url))};record('signed_host_and_gateway_distribution_verified');
  api=await import(pathToFileURL(path.join(distribution,'app/onboarding/core.mjs')));
  const {gatewayFetch}=await import(pathToFileURL(path.join(distribution,'app/onboarding/connection.mjs')));
  const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
  const publicKeyFile=path.join(distribution,'publisher.pem'),hostBundle=path.join(distribution,'host-bundle');
  const hostConfig=baseDir=>({bundle:hostBundle,publisherKeyFile:publicKeyFile,publisherSha256:build.publisherSha256,baseDir,label:path.basename(baseDir),computer:false,browser:{enabled:true,headless:true,channel:'chrome',persistLogin:true}});
  const config={schema:1,mode:'create-local',gateway:{url:'https://127.0.0.1:'+port,openssl:'/usr/bin/openssl',runtime:{bundle:path.join(distribution,'gateway-bundle'),publisherKeyFile:publicKeyFile,publisherSha256:build.publisherSha256,baseDir:path.join(privateRoot,'gateway-runtime')}},host:hostConfig(path.join(privateRoot,'combined-host'))};
  combined=path.join(privateRoot,'combined');const input=path.join(privateRoot,'combined.json');writePrivateFile(input,JSON.stringify(config));api.createDeployment(input,{stateDir:combined});
  phase='core_combined_prepare_pair_doctor';
  await api.advanceDeployment(combined,{authorize:['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify','host.prepare']});
  await api.advanceDeployment(combined,{authorize:['host.pair','host.doctor'],ownerApproval:{approve:true,...api.planDeployment(combined).ownerPairingScope}});
  const prepared=api.readDeployment(combined);for(const id of ['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.doctor'])assert(prepared.steps.some(x=>x.id===id&&x.status==='succeeded'),'combined_core_preparation_failed_'+id.replaceAll('.','_'));
  const identity=host=>['identity.json','identity.pem','host.token','host.json'].map(n=>[n,sha(path.join(host,'device',n))]);
  const before=identity(config.host.baseDir),hostId=JSON.parse(fs.readFileSync(path.join(config.host.baseDir,'device/identity.json'))).device_id;
  assert(prepared.roles.computer==='disabled'&&prepared.accountAcceptance==='NOT RUN','headless_or_account_projection_false');record('core_combined_tls_prepare_explicit_local_identity_approval_and_doctor',{deviceId:hostId,accountAcceptance:prepared.accountAcceptance});
  let stores=0;site=createServer((req,res)=>{if(req.url==='/store'){stores++;res.end('ok');return;}res.setHeader('content-type','text/html');res.end('<!doctype html><title>Owned Linux fixture</title><h1>Owned Linux fixture</h1><label>Name<input id="name"></label><button onclick="document.querySelector(\'#saved\').textContent=\'Saved \'+document.querySelector(\'#name\').value;fetch(\'/store\')">Store</button><p id="saved">Saved none</p>');});await new Promise(r=>site.listen(0,'127.0.0.1',r));const siteUrl='http://127.0.0.1:'+site.address().port;
  const newClient=async()=>{const endpoint=config.gateway.url+'/mcp',client=new Client({name:'styx-linux-core-owned',version:'1'}),transport=new StreamableHTTPClientTransport(new URL(endpoint),{requestInit:{headers:{Authorization:'Bearer '+fs.readFileSync(path.join(combined,'gateway/model.token'),'utf8').trim()}},fetch:gatewayFetch(endpoint,{ca:fs.readFileSync(path.join(combined,'gateway/certificate.pem'))})});await client.connect(transport);const item={client,transport,closed:false};clients.push(item);return item;};
  const call=async(item,name,args={})=>{const result=await item.client.callTool({name,arguments:args},undefined,{timeout:60000});assert(!result.isError,'native_mcp_tool_failed_'+name);return result;};
  const exec=async(item,id,marker)=>{let r=await call(item,'exec_command',{environment_id:id,cmd:"printf '%s' "+marker,login:false,yield_time_ms:1000}),output=r.structuredContent?.output??'';while(r.structuredContent?.session_id){r=await call(item,'write_stdin',{session_id:r.structuredContent.session_id,chars:'',yield_time_ms:1000});output+=r.structuredContent?.output??'';}assert(output===marker&&r.structuredContent?.exit_code===0,'native_exec_marker_or_exit_failed');};
  phase='combined_foreground_exec_browser';await api.startDeploymentForeground(combined,{authorize:true});
  await wait(async()=>{const d=(await api.readDeploymentDevices(combined)).find(x=>x.device_id===hostId);return d?.connections.exec&&d.connections.browser;},'combined_outbound_not_connected');
  let a=await newClient();await exec(a,hostId,'STYX_LINUX_CORE_COMBINED_EXEC');record('real_tls_mcp_core_host_outbound_codex_exec_marker_and_exit');
  await call(a,'browser_navigate',{environment_id:hostId,url:siteUrl});let snap=await call(a,'browser_snapshot',{environment_id:hostId});assert(text(snap).includes('Owned Linux fixture'),'real_chrome_snapshot_missing');
  await call(a,'browser_type',{environment_id:hostId,target:linuxAcceptanceReference(snap,'Name'),text:'Linux'});snap=await call(a,'browser_snapshot',{environment_id:hostId});await call(a,'browser_click',{environment_id:hostId,target:linuxAcceptanceReference(snap,'Store')});await wait(()=>stores===1,'real_chrome_click_not_observed');assert(text(await call(a,'browser_snapshot',{environment_id:hostId})).includes('Saved Linux'),'real_chrome_readback_failed');
  await call(a,'browser_evaluate',{environment_id:hostId,function:"()=>{document.cookie='styx_linux_core=retained; path=/; max-age=3600';localStorage.setItem('styx_linux_core','retained');return 'stored synthetic fixture';}"});record('real_installed_chrome_observe_type_click_independent_server_readback',{exactActionCount:stores});
  const processes=descendants();assert(processes.some(x=>x.name==='codex'),'owned_codex_process_missing');assert(!processes.some(x=>x.name==='cua-driver'),'headless_cua_process_started');assert((await api.readDeploymentForeground(combined)).desktopConnection==='not_requested','headless_desktop_state_false');owned.push(...processes);record('headless_foreground_does_not_start_cua',{ownedProcessNames:[...new Set(processes.map(x=>x.name))].sort(),desktopConnection:'not_requested'});
  phase='combined_same_identity_reconnect';await closeClient(a);await api.stopDeploymentForeground(combined);assert(JSON.stringify(identity(config.host.baseDir))===JSON.stringify(before),'stop_changed_identity');await api.startDeploymentForeground(combined,{authorize:true});
  await wait(async()=>{const d=(await api.readDeploymentDevices(combined)).find(x=>x.device_id===hostId);return d?.connections.exec&&d.connections.browser;},'combined_reconnect_failed');a=await newClient();await exec(a,hostId,'STYX_LINUX_CORE_RECONNECTED_EXEC');await call(a,'browser_navigate',{environment_id:hostId,url:siteUrl});assert(text(await call(a,'browser_evaluate',{environment_id:hostId,function:'()=>({cookie:document.cookie,state:localStorage.getItem("styx_linux_core")})'})).includes('styx_linux_core=retained'),'synthetic_login_not_restored');assert(JSON.stringify(identity(config.host.baseDir))===JSON.stringify(before),'restart_changed_identity');assert(stores===1,'user_action_replayed');record('real_host_foreground_restart_same_identity_no_repair_login_restore_no_action_replay');
  phase='join_existing_product_invitation';const invitation=await api.createDeploymentPairingLink(combined,{authorize:true}),inspected=api.inspectPairingLink(invitation.link),material=path.join(privateRoot,'join-material');api.acceptPairingLink(invitation.link,{stateDir:material,approvedGatewayOrigin:inspected.origin,approvedCaSha256:inspected.caSha256});const pairing=JSON.parse(fs.readFileSync(path.join(material,'pairing.json')));
  joined=path.join(privateRoot,'joined');const joinConfig={schema:1,mode:'join-existing',gateway:{url:pairing.gatewayOrigin,caFile:pairing.gatewayCaFile},host:hostConfig(path.join(privateRoot,'joined-host')),invitationFile:pairing.invitationFile},joinInput=path.join(privateRoot,'join.json');writePrivateFile(joinInput,JSON.stringify(joinConfig));api.createDeployment(joinInput,{stateDir:joined});assert(api.planDeployment(joined).steps.every(x=>!x.id.startsWith('gateway.')),'join_planned_second_gateway');await api.advanceDeployment(joined,{authorize:['host.prepare','host.request']});
  const requested=api.readDeployment(joined).steps.find(x=>x.id==='host.request').evidence,pending=(await api.listDeploymentPending(combined,{authorize:true})).find(x=>x.request_id===requested.request_id);assert(pending?.fingerprint===requested.fingerprint,'join_pending_identity_mismatch');
  let wrongRejected=false;try{await api.approveDeploymentPending(combined,{authorize:true,requestId:pending.request_id,fingerprint:'0'.repeat(64),enableComputer:false,enableBrowser:true});}catch{wrongRejected=true;}assert(wrongRejected,'wrong_join_identity_approved');await api.approveDeploymentPending(combined,{authorize:true,requestId:pending.request_id,fingerprint:pending.fingerprint,enableComputer:false,enableBrowser:true});
  await api.advanceDeployment(joined,{authorize:['host.claim','host.doctor']});for(const id of ['host.prepare','host.request','host.claim','host.doctor'])assert(api.readDeployment(joined).steps.some(x=>x.id===id&&x.status==='succeeded'),'joined_core_preparation_failed');await api.startDeploymentForeground(joined,{authorize:true});
  await wait(async()=>{const d=(await api.readDeploymentDevices(combined)).find(x=>x.device_id===requested.device_id);return d?.connections.exec&&d.connections.browser;},'joined_outbound_not_connected');await exec(a,requested.device_id,'STYX_LINUX_CORE_JOINED_EXEC');await call(a,'browser_navigate',{environment_id:requested.device_id,url:siteUrl});assert(text(await call(a,'browser_snapshot',{environment_id:requested.device_id})).includes('Owned Linux fixture'),'joined_browser_observation_failed');assert(!fs.existsSync(path.join(joined,'gateway'))&&(await api.readDeploymentForeground(joined)).gateway==='external','join_created_second_gateway');assert((await api.readDeploymentDevices(combined)).filter(x=>x.online).length===2,'two_host_connections_not_observed');record('second_host_real_invitation_tls_identity_approval_claim_exec_browser_without_second_gateway',{deviceId:requested.device_id,wrongFingerprintRejected:true,deviceTopology:'two independent real Core Host installations on one physical Linux host; not cross-machine routing acceptance'});
  owned.push(...descendants());receipt.status='PASS';
 }catch(error){receipt.status='BLOCKED';receipt.failedPhase=phase;receipt.reason=/^[A-Za-z0-9_]+$/.test(error.message??'')?error.message:'native_acceptance_operation_failed';}
 finally{
  for(const item of clients)await closeClient(item).catch(()=>{});
  for(const state of [joined,combined].filter(Boolean))try{await api?.stopDeploymentForeground(state);}catch{receipt.status='BLOCKED';receipt.cleanup='foreground_shutdown_unconfirmed';}
  if(combined)try{await api?.stopDeploymentGateway(combined);}catch{receipt.status='BLOCKED';receipt.cleanup='gateway_shutdown_unconfirmed';}
  if(site)await new Promise(r=>site.close(r));await pause(200);
  receipt.remainingOwnedProcesses=owned.filter(alive).map(({pid,name})=>({pid,name}));
  if(!receipt.cleanup&&receipt.remainingOwnedProcesses.length===0){fs.rmSync(privateRoot,{recursive:true,force:true});receipt.cleanup='own_foreground_hosts_gateway_browser_processes_stopped_private_state_removed_no_service_changes';}else{receipt.status='BLOCKED';receipt.cleanup??='owned_process_shutdown_unconfirmed_private_state_preserved';}
  if(originalCodexHome===undefined)delete process.env.CODEX_HOME;else process.env.CODEX_HOME=originalCodexHome;
  receipt.completedAt=new Date().toISOString();save();
 }
 return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=await runLinuxCliAcceptance(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));console.log(JSON.stringify({status:result.status,failedPhase:result.failedPhase,reason:result.reason,gates:result.gates,cleanup:result.cleanup,remainingOwnedProcesses:result.remainingOwnedProcesses}));process.exitCode=result.status==='PASS'?0:2;}catch(error){console.log(JSON.stringify({status:'BLOCKED',reason:/^[A-Za-z0-9_]+$/.test(error.message??'')?error.message:'native_acceptance_setup_failed'}));process.exitCode=2;}
}
