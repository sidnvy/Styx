// Explicit isolated native test actors. Private file IPC is transported by the
// operator over SSH; device enrollment and tools use direct verified TLS only.
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import {createServer} from 'node:http';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {gatewayFetch} from '../onboarding/connection.mjs';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile,writePrivateFile} from './private-storage.mjs';
import {buildHostRelease} from './build-host-release.mjs';
const sourceRoot=fileURLToPath(new URL('../',import.meta.url));
const assert=(ok,code)=>{if(!ok)throw Error(code)};
const sha=p=>createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const text=r=>(r.content??[]).filter(x=>x.type==='text').map(x=>x.text).join('\n');
export function publishCrossFile(filename,data,{replace=false}={}){
 const tmp=filename+'.'+randomBytes(12).toString('hex')+'.tmp';
 if(fs.existsSync(filename)){assert(replace,'fresh_cross_publication_required');requirePrivateFile(filename);}
 writePrivateFile(tmp,data);
 try{fs.renameSync(tmp,filename);}finally{fs.rmSync(tmp,{force:true});}
}
export const saveCrossReceipt=(filename,data)=>publishCrossFile(filename,JSON.stringify(data,null,2)+'\n',{replace:true});
export function crossScope(options,role,platform=process.platform){
 assert(process.env.STYX_RUN_CROSS_PLATFORM_ACCEPTANCE==='1','explicit_cross_platform_acceptance_required');
 assert(role==='gateway'?platform==='linux':role==='host'&&platform==='win32','cross_native_role_platform_required');
 for(const key of ['directory'])assert(typeof options?.[key]==='string'&&path.isAbsolute(options[key])&&path.normalize(options[key])===options[key],'absolute_cross_scope_required');
 if(role==='gateway')assert(net.isIPv4(options.listenHost)&&options.listenHost!=='0.0.0.0'&&options.listenHost!=='127.0.0.1'&&options.authorizeExactInterface===true,'explicit_exact_cross_interface_required');
 return options;
}
export function observedCrossReference(result,label){
 const labelPattern=label.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),match=new RegExp('"'+labelPattern+'"[^\\n]*\\[ref=(styx-[a-f0-9]+)\\]').exec(text(result));
 assert(match,'cross_owned_observed_reference_missing');return match[1];
}
function fixtureState(directory,role){
 assert(!fs.existsSync(directory),'fresh_cross_directory_required');ensurePrivateDirectory(directory,{exclusive:true});
 for(const name of ['requests','responses','private'])ensurePrivateDirectory(path.join(directory,name),{exclusive:true});
 const receipt={schema:1,role,status:'RUNNING',startedAt:new Date().toISOString(),gates:{},attempts:[],boundaries:{productionMutation:'NOT RUN',servicesTasksFirewallMutation:'NOT RUN',sshTunnel:'NOT USED',chatgptAccountAcceptance:'NOT RUN',cua:'disabled'},source:{actor:sha(fileURLToPath(import.meta.url)),connection:sha(path.join(sourceRoot,'onboarding/connection.mjs'))}};
 const save=()=>saveCrossReceipt(path.join(directory,'receipt.json'),receipt);
 const record=(name,evidence={})=>{receipt.gates[name]={status:'PASS',...evidence};save();};
 save();return {receipt,save,record};
}
export function requireCrossGates(receipt,names){receipt.missingRequiredGates=names.filter(name=>receipt.gates[name]?.status!=='PASS');assert(receipt.missingRequiredGates.length===0,'cross_required_gates_incomplete');}
async function commandLoop(directory,handlers,onAttempt=()=>{}){
 for(;;){
  for(const name of fs.readdirSync(path.join(directory,'requests')).sort()){
   if(!/^[a-f0-9]{32}\.json$/.test(name)||fs.existsSync(path.join(directory,'responses',name)))continue;
   const file=path.join(directory,'requests',name);assert(fs.statSync(file).size<65536,'cross_command_too_large');const {operation,payload={}}=JSON.parse(fs.readFileSync(file,'utf8'));
   let answer;try{assert(typeof handlers[operation]==='function','cross_command_not_allowed');answer={status:'PASS',...await handlers[operation](payload)};}catch(e){answer={status:'BLOCKED',reason:/^[A-Za-z0-9_]+$/.test(e.message??'')?e.message:'cross_operation_failed'};}
   onAttempt({operation,status:answer.status,...(answer.reason?{reason:answer.reason}:{}),at:new Date().toISOString()});
   publishCrossFile(path.join(directory,'responses',name),JSON.stringify(answer)+'\n');
   if(operation==='abort'||operation==='stop'&&answer.status==='PASS')return answer;
  }
  await pause(100);
 }
}
export async function sendCrossCommand({directory,operation,payload={},responseFile}={}){
 requirePrivateDirectory(directory);assert(typeof operation==='string'&&/^[a-z-]+$/.test(operation),'fixed_cross_operation_required');assert(path.isAbsolute(responseFile)&&!fs.existsSync(responseFile),'fresh_cross_response_file_required');
 const nonce=randomBytes(16).toString('hex')+'.json',request=JSON.stringify({operation,payload});assert(Buffer.byteLength(request)<65536,'cross_command_too_large');
 publishCrossFile(path.join(directory,'requests',nonce),request);
 for(let n=0;n<2400;n++){const file=path.join(directory,'responses',nonce);if(fs.existsSync(file)){publishCrossFile(responseFile,fs.readFileSync(file));const result=JSON.parse(fs.readFileSync(file));return {status:result.status,responseFile,...(result.reason?{reason:result.reason}:{})};}await pause(100);}
 throw Error('cross_actor_response_timeout');
}
export async function runCrossGateway(options){
 const {directory,distribution,listenHost}=crossScope(options,'gateway');const {receipt,save,record}=fixtureState(directory,'linux-gateway');
 let api,client,transport;const state=path.join(directory,'private/deployment'),peerIds=new Set();
 try{
  api=await import(pathToFileURL(path.join(distribution,'app/onboarding/core.mjs')));
  const probe=net.createServer();await new Promise(r=>probe.listen(0,listenHost,r));const port=probe.address().port;await new Promise(r=>probe.close(r));
  const build=JSON.parse(fs.readFileSync(path.join(distribution,'build-receipt.json'))),gateway={url:'https://'+listenHost+':'+port,listenHost,allowRemoteHosts:true,openssl:'/usr/bin/openssl',runtime:{bundle:path.join(distribution,'gateway-bundle'),publisherKeyFile:path.join(distribution,'publisher.pem'),publisherSha256:build.publisherSha256,baseDir:path.join(directory,'private/runtime')}};
  const input=path.join(directory,'private/input.json');writePrivateFile(input,JSON.stringify({schema:1,mode:'create-local',gateway}));api.createDeployment(input,{stateDir:state});await api.advanceDeployment(state,{authorize:['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify']});assert(api.readDeployment(state).steps.every(x=>x.status==='succeeded'),'cross_gateway_core_setup_failed');
  const ingress=api.planDeviceIngress(state);assert(ingress.networkExposureAuthorized===true&&ingress.listenHost===listenHost,'cross_exact_interface_not_authorized');const cert=fs.readFileSync(path.join(state,'gateway/certificate.pem'),'utf8');const {X509Certificate}=await import('node:crypto');const fingerprint=createHash('sha256').update(new X509Certificate(cert).raw).digest('hex');
  publishCrossFile(path.join(directory,'ready.json'),JSON.stringify({origin:gateway.url,caSha256:fingerprint,certificatePem:cert,listenHost,port,pid:process.pid})+'\n');record('gateway_core_tls_on_exact_owned_authorized_interface',{origin:gateway.url,listenHost,certificateSha256:fingerprint,hostRole:'disabled'});
  const endpoint=gateway.url+'/mcp';client=new Client({name:'styx-cross-physical-native',version:'1'});transport=new StreamableHTTPClientTransport(new URL(endpoint),{requestInit:{headers:{Authorization:'Bearer '+fs.readFileSync(path.join(state,'gateway/model.token'),'utf8').trim()}},fetch:gatewayFetch(endpoint,{ca:cert})});await client.connect(transport);
  const call=async(name,args)=>{const result=await client.callTool({name,arguments:args},undefined,{timeout:60000});assert(!result.isError,'cross_native_tool_failed_'+name);return result;};
  await commandLoop(directory,{
   async invite(){const invitation=await api.createDeploymentPairingLink(state,{authorize:true});record('one_use_product_invitation_created');return {link:invitation.link,origin:gateway.url,caSha256:fingerprint,expiresAt:invitation.expiresAt};},
   async approve({requestId,deviceId,fingerprint:deviceFingerprint}){const pending=(await api.listDeploymentPending(state,{authorize:true})).find(x=>x.request_id===requestId);assert(pending?.device_id===deviceId&&pending.fingerprint===deviceFingerprint,'cross_both_device_identity_mismatch');let wrong=false;try{await api.approveDeploymentPending(state,{authorize:true,requestId,fingerprint:'0'.repeat(64),enableComputer:false,enableBrowser:true});}catch{wrong=true;}assert(wrong,'cross_wrong_fingerprint_accepted');await api.approveDeploymentPending(state,{authorize:true,requestId,fingerprint:deviceFingerprint,enableComputer:false,enableBrowser:true});peerIds.add(deviceId);record('exact_peer_identity_approved_wrong_fingerprint_rejected',{deviceId,fingerprint:deviceFingerprint});return {deviceId};},
   async verify({deviceId,siteUrl,longCommand=false,expectedStoredCount}){assert(peerIds.has(deviceId),'cross_unknown_peer');assert(/^http:\/\/127\.0\.0\.1:\d+\/$/.test(siteUrl),'cross_owned_loopback_site_required');for(let n=0;n<160;n++){const d=(await api.readDeploymentDevices(state)).find(x=>x.device_id===deviceId);if(d?.connections.exec&&d.connections.browser)break;if(n===159)throw Error('cross_peer_outbound_not_connected');await pause(250);}
    const start=Date.now(),marker=longCommand?'STYX_CROSS_LONG_EXEC':'STYX_CROSS_EXEC';let result=await call('exec_command',{environment_id:deviceId,cmd:(longCommand?'Start-Sleep -Seconds 12; ':'')+"[Console]::Write('"+marker+"')",login:false,yield_time_ms:longCommand?15000:1000}),output=result.structuredContent?.output??'';while(result.structuredContent?.session_id){result=await call('write_stdin',{session_id:result.structuredContent.session_id,chars:'',yield_time_ms:1000});output+=result.structuredContent?.output??'';}assert(result.structuredContent?.exit_code===0&&output===marker,'cross_actual_exec_readback_failed');const durationMs=Date.now()-start;if(longCommand)assert(durationMs>=11000,'cross_long_exec_not_delayed');record(longCommand?'windows_real_exec_exceeds_ten_second_tls_idle':'windows_real_exec_after_reconnect',{deviceId,exitCode:0,durationMs});
    await call('browser_navigate',{environment_id:deviceId,url:siteUrl});let snap=await call('browser_snapshot',{environment_id:deviceId});assert(text(snap).includes('Owned NAB cross fixture'),'cross_edge_snapshot_missing');if(expectedStoredCount===0){await call('browser_type',{environment_id:deviceId,target:observedCrossReference(snap,'Name'),text:'Cross'});snap=await call('browser_snapshot',{environment_id:deviceId});await call('browser_click',{environment_id:deviceId,target:observedCrossReference(snap,'Store')});assert(text(await call('browser_snapshot',{environment_id:deviceId})).includes('Saved Cross'),'cross_edge_click_readback_failed');}
    record(expectedStoredCount===0?'windows_edge_observe_type_click':'windows_edge_after_reconnect',{deviceId});return {deviceId,exitCode:0,durationMs};},
   async status(){return {devices:await api.readDeploymentDevices(state)};},
   async stop(){requireCrossGates(receipt,['gateway_core_tls_on_exact_owned_authorized_interface','one_use_product_invitation_created','exact_peer_identity_approved_wrong_fingerprint_rejected','windows_real_exec_exceeds_ten_second_tls_idle','windows_edge_observe_type_click','windows_real_exec_after_reconnect','windows_edge_after_reconnect']);receipt.status='PASS';return {};},
   async abort(){receipt.status='BLOCKED';receipt.reason='operator_aborted_cross_acceptance';return {};}
  },attempt=>{receipt.attempts.push(attempt);save();});
 }catch(e){receipt.status='BLOCKED';receipt.reason=/^[A-Za-z0-9_]+$/.test(e.message??'')?e.message:'cross_gateway_failed';}
 finally{await transport?.terminateSession().catch(()=>{});await client?.close().catch(()=>{});if(api)await api.stopDeploymentGateway(state).catch(()=>{receipt.status='BLOCKED';receipt.cleanup='gateway_shutdown_unconfirmed';});if(!receipt.cleanup){for(const name of ['private','requests','responses'])fs.rmSync(path.join(directory,name),{recursive:true,force:true});receipt.cleanup='own_gateway_closed_private_credentials_and_invitation_ipc_removed_no_service_firewall_changes';}receipt.completedAt=new Date().toISOString();save();}
 return receipt;
}
function windowsProcessRows(){const script='$ProgressPreference="SilentlyContinue";@(Get-CimInstance Win32_Process | Where-Object {$_.ProcessId -ne $PID} | ForEach-Object {@{pid=[int]$_.ProcessId;parentPid=[int]$_.ParentProcessId;name=$_.Name;path=$_.ExecutablePath;created=[string]$_.CreationDate.ToUniversalTime().Ticks}})|ConvertTo-Json -Compress';const raw=execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{encoding:'utf8',timeout:15000,maxBuffer:2*1024*1024,windowsHide:true,stdio:['ignore','pipe','ignore']}).trim();return raw?[JSON.parse(raw)].flat():[];}
function windowsOwnedProcesses(){const rows=windowsProcessRows(),ids=new Set([process.pid]),owned=[];for(let pass=0;pass<20;pass++){let added=0;for(const row of rows)if(ids.has(row.parentPid)&&!ids.has(row.pid)){ids.add(row.pid);owned.push(row);added++;}if(!added)break;}return owned;}
function windowsOwnedCodex(){return windowsOwnedProcesses().find(row=>row.parentPid===process.pid&&row.name.toLowerCase()==='codex.exe');}
export async function runCrossWindowsHost(options){
 const {directory,nodeBinary,codexBinary,cuaBinary,nodeLicenseFile}=crossScope(options,'host');const {receipt,save,record}=fixtureState(directory,'windows-host');const api=await import('../onboarding/core.mjs');
 const privateRoot=path.join(directory,'private'),state=path.join(privateRoot,'deployment'),hostRoot=path.join(privateRoot,'host');let site,stores=0,before,deviceId,siteUrl,crashedPid;const trackedProcesses=new Map();const census=()=>{const rows=windowsOwnedProcesses();for(const row of rows)trackedProcesses.set(row.pid+':'+row.created,row);return rows;};
 const oldCodexHome=process.env.CODEX_HOME;process.env.CODEX_HOME=path.join(privateRoot,'owner-codex-home');ensurePrivateDirectory(process.env.CODEX_HOME,{exclusive:true});
 const identity=()=>Object.fromEntries(['identity.json','identity.pem','host.token','host.json'].map(n=>[n,sha(path.join(hostRoot,'device',n))]));
 try{
  const pins={node:'9c9245166b4a8e182e0b797da9c20136117ff24368eaff1fec8343a123c8db0e',codex:'2692c8c7bb2cf8b0aefe638741fc90236f4b824c59578ce84994f9de58200993',cua:'99291d8d6a4851d9df96da5813a1ef2761f2c9d3a59d2a7036c0bf4d09652f4f'};for(const [name,file]of [['node',nodeBinary],['codex',codexBinary],['cua',cuaBinary]])assert(sha(file)===pins[name],'cross_public_runtime_pin_mismatch');
  const runtime=path.join(privateRoot,'runtime');ensurePrivateDirectory(runtime,{exclusive:true});for(const [file,name]of [[nodeBinary,'node.exe'],[nodeLicenseFile,'LICENSE']])fs.copyFileSync(file,path.join(runtime,name));writePrivateFile(path.join(runtime,'node-provenance.json'),JSON.stringify({schema:1,component:'node',version:'22.23.3',platform:'win32',arch:'x64',binary_sha256:pins.node,license_sha256:sha(path.join(runtime,'LICENSE')),verification:'previously recorded public binary digest; not new upstream attestation'}));
  const {privateKey,publicKey}=generateKeyPairSync('ed25519'),key=path.join(privateRoot,'test-private.pem'),pub=path.join(privateRoot,'publisher.pem');writePrivateFile(key,privateKey.export({format:'pem',type:'pkcs8'}));writePrivateFile(pub,publicKey.export({format:'pem',type:'spki'}));
  const bundle=path.join(privateRoot,'signed-host');let built;try{built=buildHostRelease({destination:bundle,version:'0.3.0-cross-windows-owned',privateKeyFile:key,nodeBinary:path.join(runtime,'node.exe'),codexBinary,cuaBinary,browserRuntime:true});}finally{fs.rmSync(key,{force:true});}record('previously_verified_public_runtime_pins_and_test_signed_host',{binarySha256:pins,publisherTrust:'ephemeral test only, private key deleted'});
  site=createServer((req,res)=>{if(req.url==='/store'){stores++;res.end('ok');return;}res.setHeader('content-type','text/html');res.end('<!doctype html><title>Owned NAB cross fixture</title><h1>Owned NAB cross fixture</h1><label>Name<input id="name"></label><button onclick="document.querySelector(\'#saved\').textContent=\'Saved \'+document.querySelector(\'#name\').value;fetch(\'/store\')">Store</button><p id="saved">Saved none</p>');});await new Promise(r=>site.listen(0,'127.0.0.1',r));siteUrl='http://127.0.0.1:'+site.address().port+'/';
  publishCrossFile(path.join(directory,'ready.json'),JSON.stringify({pid:process.pid,siteUrl})+'\n');
  await commandLoop(directory,{
   async join({link,approvedOrigin,approvedCaSha256}){const inspection=api.inspectPairingLink(link);assert(inspection.origin===approvedOrigin&&inspection.caSha256===approvedCaSha256,'cross_expected_gateway_identity_mismatch');const material=path.join(privateRoot,'material');api.acceptPairingLink(link,{stateDir:material,approvedGatewayOrigin:approvedOrigin,approvedCaSha256});const pairing=JSON.parse(fs.readFileSync(path.join(material,'pairing.json'))),config={schema:1,mode:'join-existing',gateway:{url:pairing.gatewayOrigin,caFile:pairing.gatewayCaFile},host:{bundle,publisherKeyFile:pub,publisherSha256:built.publisher_spki_sha256,baseDir:hostRoot,label:'NAB cross physical isolated',computer:false,browser:{enabled:true,headless:true,channel:'msedge',persistLogin:true}},invitationFile:pairing.invitationFile};const input=path.join(privateRoot,'join.json');writePrivateFile(input,JSON.stringify(config));api.createDeployment(input,{stateDir:state});assert(api.planDeployment(state).steps.every(x=>!x.id.startsWith('gateway.')),'cross_join_planned_gateway');const ingress=await api.verifyDeviceIngress(state,{url:approvedOrigin,expectedCertificateSha256:approvedCaSha256});assert(ingress.status==='ingress_endpoint_verified'&&ingress.tls?.status==='verified'&&ingress.tls.certificate.sha256===approvedCaSha256,'cross_remote_tls_ingress_unverified');record('actual_windows_to_linux_tls_reachability_and_explicit_ca_confirmation',{origin:approvedOrigin,certificateSha256:approvedCaSha256,ingress});await api.advanceDeployment(state,{authorize:['host.prepare','host.request']});const requested=api.readDeployment(state).steps.find(x=>x.id==='host.request');assert(requested.status==='succeeded','cross_host_request_failed');const own=JSON.parse(fs.readFileSync(path.join(hostRoot,'device/identity.json')));assert(own.fingerprint===requested.evidence.fingerprint&&own.device_id===requested.evidence.device_id,'cross_local_identity_request_mismatch');deviceId=own.device_id;record('windows_core_join_request_own_identity',{deviceId,fingerprint:own.fingerprint});return {...requested.evidence,siteUrl};},
   async claim(){await api.advanceDeployment(state,{authorize:['host.claim','host.doctor']});for(const id of ['host.claim','host.doctor'])assert(api.readDeployment(state).steps.some(x=>x.id===id&&x.status==='succeeded'),'cross_claim_doctor_failed');before=identity();await api.startDeploymentForeground(state,{authorize:true});assert((await api.readDeploymentForeground(state)).gateway==='external'&&!fs.existsSync(path.join(state,'gateway')),'cross_host_created_gateway');record('windows_core_claim_doctor_foreground_no_second_gateway',{deviceId});return {deviceId,siteUrl};},
   async status(){assert(!before||JSON.stringify(identity())===JSON.stringify(before),'cross_host_identity_changed');return {deviceId,siteUrl,stores,...(before?{foreground:await api.readDeploymentForeground(state)}:{})};},
   async crash(){census();const child=windowsOwnedCodex();assert(child&&Number.isSafeInteger(child.pid)&&typeof child.path==='string'&&child.path.toLowerCase().startsWith((path.join(hostRoot,'install','releases')+path.sep).toLowerCase())&&path.basename(child.path).toLowerCase()==='codex.exe','cross_owned_codex_scope_unverified');crashedPid=child.pid;process.kill(child.pid,'SIGTERM');record('only_owned_exec_child_terminated_for_automatic_reconnect',{pid:child.pid});return {oldPid:child.pid};},
   async confirm(){assert(stores===1,'cross_edge_action_count_wrong');assert(JSON.stringify(identity())===JSON.stringify(before),'cross_reconnect_regenerated_identity');const child=windowsOwnedCodex();assert(child&&Number.isSafeInteger(child.pid)&&crashedPid&&child.pid!==crashedPid,'cross_reconnected_codex_missing_or_same_pid');census();record('windows_actual_edge_click_server_readback_identity_stable_after_reconnect',{stores,deviceId,oldPid:crashedPid,pid:child.pid});return {stores,oldPid:crashedPid,pid:child.pid};},
   async stop(){requireCrossGates(receipt,['previously_verified_public_runtime_pins_and_test_signed_host','actual_windows_to_linux_tls_reachability_and_explicit_ca_confirmation','windows_core_join_request_own_identity','windows_core_claim_doctor_foreground_no_second_gateway','only_owned_exec_child_terminated_for_automatic_reconnect','windows_actual_edge_click_server_readback_identity_stable_after_reconnect']);receipt.status='PASS';return {};},
   async abort(){receipt.status='BLOCKED';receipt.reason='operator_aborted_cross_acceptance';return {};}
  },attempt=>{receipt.attempts.push(attempt);census();save();});
 }catch(e){receipt.status='BLOCKED';receipt.reason=/^[A-Za-z0-9_]+$/.test(e.message??'')?e.message:'cross_windows_host_failed';}
 finally{try{census();receipt.ownedProcessCensus=[...trackedProcesses.values()];await api.stopDeploymentForeground(state);}catch{receipt.status='BLOCKED';receipt.cleanup='windows_foreground_shutdown_unconfirmed';}if(site)await new Promise(r=>site.close(r));await pause(500);try{const current=new Map(windowsProcessRows().map(row=>[row.pid+':'+row.created,row]));receipt.remainingOwnedProcesses=[...trackedProcesses].filter(([id])=>current.has(id)).map(([,row])=>row);assert(receipt.remainingOwnedProcesses.length===0,'cross_owned_processes_still_running');}catch{receipt.status='BLOCKED';receipt.cleanup='windows_owned_process_cleanup_unconfirmed';}if(!receipt.cleanup){for(const name of ['private','requests','responses'])fs.rmSync(path.join(directory,name),{recursive:true,force:true});receipt.cleanup='own_windows_foreground_and_site_stopped_private_state_key_invitation_ipc_removed_no_task_changes';}if(oldCodexHome===undefined)delete process.env.CODEX_HOME;else process.env.CODEX_HOME=oldCodexHome;receipt.completedAt=new Date().toISOString();save();}
 return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const role=process.argv[2],input=role==='send'?JSON.parse(fs.readFileSync(0,'utf8')):JSON.parse(fs.readFileSync(process.argv[3],'utf8'));const result=role==='send'?await sendCrossCommand(input):role==='gateway'?await runCrossGateway(input):await runCrossWindowsHost(input);console.log(JSON.stringify(role==='send'?result:{status:result.status,reason:result.reason,cleanup:result.cleanup}));process.exitCode=result.status==='PASS'?0:2;}catch(e){console.log(JSON.stringify({status:'BLOCKED',reason:/^[A-Za-z0-9_]+$/.test(e.message??'')?e.message:'cross_actor_setup_failed'}));process.exitCode=2;}
}
