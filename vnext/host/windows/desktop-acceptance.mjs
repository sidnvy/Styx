// Explicit own-window native Cua acceptance. No personal app enumeration or input.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn,execFileSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {runHostConnector} from '../connect.mjs';
import {runComputerConnectors} from '../computer.mjs';
import {ensurePrivateDirectory,writePrivateFile} from '../private-storage.mjs';
const sha=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const assert=(yes,code)=>{if(!yes)throw Error(code)};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(check,reason,timeout=30000){const end=Date.now()+timeout;while(Date.now()<end){if(await check())return;await sleep(200);}throw Error(reason);}
function ownedProcessCount(pids){if(!pids.size)return 0;const script='$ErrorActionPreference="Stop";$ids=ConvertFrom-Json $env:STYX_OWNED_UI_PIDS;@($ids | ForEach-Object {Get-Process -Id $_ -ErrorAction SilentlyContinue}).Count';return Number(execFileSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{env:{...process.env,STYX_OWNED_UI_PIDS:JSON.stringify([...pids])},encoding:'utf8',timeout:10000,windowsHide:true,stdio:['ignore','pipe','ignore']}).trim());}
export async function runOwnedDesktopAcceptance(config){
 assert(process.platform==='win32'&&config.authorizeOwnedDesktop===true,'explicit_native_owned_desktop_required');
 for(const file of [config.receiptFile,config.directory,config.nodeBinary,config.codexBinary,config.cuaBinary,config.desktopProbeFile])assert(typeof file==='string'&&path.isAbsolute(file),'absolute_owned_paths_required');
 const receipt={schema:1,kind:'windows-own-window-cua-acceptance',status:'RUNNING',startedAt:new Date().toISOString(),sourceSha256:sha(fileURLToPath(import.meta.url)),gates:{},boundaries:{task:'fresh Limited InteractiveToken manual task only',ui:'existing self-expiring physical-cua-windows own WinForms fixture only',screenshots:'own exact PID/window only, image payload not persisted',personalApps:'NOT RUN',loginLogoutReboot:'NOT RUN',osPermissionMutation:'NOT RUN'}};
 const save=()=>fs.writeFileSync(config.receiptFile,JSON.stringify(receipt,null,2)+'\n');save();
 let gateway,http,physical,abort,tasks=[],phase='native_session_preflight',uiPids=new Set(),started=false;
 try{
  assert(sha(config.desktopProbeFile)==='3793651f796361ec81a9085494fca19f8e34fce7894575e57d93728757320dfd','owned_session_probe_pin_mismatch');
  const probe=JSON.parse(execFileSync(config.desktopProbeFile,[],{encoding:'utf8',timeout:5000,maxBuffer:4096,windowsHide:true,stdio:['ignore','pipe','ignore']}));receipt.session={status:probe.status,sessionId:probe.sessionId,interactive:probe.interactive,windowStation:probe.windowStation,inputDesktop:probe.inputDesktop};save();
  assert(probe.schema===1&&probe.status==='available'&&probe.sessionId>0&&probe.interactive===true&&probe.windowStation==='WinSta0'&&probe.inputDesktop==='Default','interactive_default_desktop_unavailable');receipt.gates.current_native_input_desktop={status:'PASS'};
  if(config.probeOnly){receipt.status='PASS';return receipt;}
  phase='pinned_public_runtime';for(const [file,pin] of [[config.nodeBinary,'9c9245166b4a8e182e0b797da9c20136117ff24368eaff1fec8343a123c8db0e'],[config.codexBinary,'2692c8c7bb2cf8b0aefe638741fc90236f4b824c59578ce84994f9de58200993'],[config.cuaBinary,'99291d8d6a4851d9df96da5813a1ef2761f2c9d3a59d2a7036c0bf4d09652f4f']])assert(sha(file)===pin,'public_native_runtime_pin_mismatch');receipt.gates.pinned_native_inputs={status:'PASS'};
  assert(!fs.existsSync(config.directory),'fresh_owned_desktop_private_state_required');ensurePrivateDirectory(config.directory,{exclusive:true});started=true;
  const scratch=path.join(config.directory,'workspace'),home=path.join(config.directory,'codex-home');ensurePrivateDirectory(scratch,{exclusive:true});ensurePrivateDirectory(home,{exclusive:true});
  const hostToken=randomBytes(32).toString('hex'),modelToken=randomBytes(32).toString('hex'),hostTokenFile=path.join(config.directory,'host.token'),modelTokenFile=path.join(config.directory,'model.token');writePrivateFile(hostTokenFile,hostToken);writePrivateFile(modelTokenFile,modelToken);
  const id='windows-owned-desktop',shell=path.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
  const observed=({name,result})=>{if(['exec_command','write_stdin'].includes(name)){const text=result.structuredContent?.output??'';for(const match of text.matchAll(/STYX_PID=(\d+)/g))uiPids.add(Number(match[1]));}if(['list_windows','get_window_state','click'].includes(name)&&!result.isError){receipt.gates['mcp_'+name]={status:'PASS',...(name==='get_window_state'?{ownWindowPng:result.content?.some(x=>x.type==='image'&&x.mimeType==='image/png')===true}:{})};save();}};
  gateway=createStyxGateway({catalog:{version:1,default_environment_id:id,targets:[{id,kind:'host',platform:'win32',generation:'owned-desktop-g1',allowed:true,cwd:scratch,shell,shells:[shell],exec:{transport:'outbound',token_file:hostTokenFile},computer:{enabled:true,transport:'outbound',max_connections:1}}]},onToolResult:observed});const hosts=[];http=await createGatewayHttp(gateway,{token:modelToken,host:'127.0.0.1',port:0,allowedHosts:hosts});hosts.push('127.0.0.1:'+http.address.port);
  const hostConfig={host_id:id,gateway_ws_url:'ws://'+hosts[0],token_file:hostTokenFile,exec:{binary:config.codexBinary,cwd:scratch,env:{CODEX_HOME:home}},computer:{enabled:true,binary:config.cuaBinary,connections:1}};
  abort=new AbortController();tasks=[runHostConnector(hostConfig,{signal:abort.signal,retryMinMs:200,retryMaxMs:1000}),runComputerConnectors(hostConfig,{signal:abort.signal,retryMinMs:200,retryMaxMs:1000})];for(const task of tasks)task.catch(()=>{});phase='native_cua_outbound_readiness';await wait(()=>gateway.relay.connected(id)&&gateway.relay.computerConnected(id)===1,'native_cua_outbound_not_connected',45000);receipt.gates.native_codex_cua_outbound_connected={status:'PASS'};save();
  phase='existing_owned_winforms_mcp_acceptance';const script=fileURLToPath(new URL('../physical-cua-windows.mjs',import.meta.url));receipt.ownedFixtureSha256=sha(script);
  const result=await new Promise((resolve,reject)=>{physical=spawn(config.nodeBinary,[script],{windowsHide:true,cwd:scratch,env:{...process.env,STYX_PILOT_MCP_URL:'http://'+hosts[0]+'/mcp',STYX_PILOT_MCP_TOKEN_FILE:modelTokenFile,STYX_PILOT_ENVIRONMENT_ID:id,STYX_PILOT_SCRATCH_DIR:scratch},stdio:['ignore','pipe','pipe']});let output='';const timer=setTimeout(()=>{physical.kill();reject(Error('own_window_acceptance_deadline'));},90000);physical.stdout.on('data',data=>{if(output.length<65536)output+=data;});physical.stderr.resume();physical.on('error',error=>{clearTimeout(timer);reject(error);});physical.on('exit',code=>{clearTimeout(timer);try{const last=JSON.parse(output.trim().split('\n').at(-1));if(code!==0||last.result!=='PASS'){receipt.fixtureFailure={phase:last.phase,error:last.error};reject(Error('owned_native_ui_assertion_failed'));}else resolve(last);}catch(error){reject(error);}});});
  assert(result.observedExactOwnedPid&&result.png&&result.clickedOwnedButton&&result.independentExitCode===0,'owned_cua_evidence_incomplete');receipt.gates.own_window_screenshot_ax_click_independent_readback={status:'PASS',...result};receipt.status='PASS';
 }catch(error){receipt.status='BLOCKED';receipt.failedPhase=phase;receipt.reason=/^[a-z0-9_]+$/.test(error.message??'')?error.message:'owned_desktop_acceptance_failed';}
 finally{
  abort?.abort();await Promise.allSettled(tasks);await http?.close().catch(()=>{receipt.status='BLOCKED';receipt.cleanup='gateway_shutdown_unconfirmed';});
  if(started){try{await wait(()=>ownedProcessCount(uiPids)===0,'owned_winforms_did_not_exit',35000);receipt.ownedUiPids=[...uiPids];receipt.remainingOwnedUiProcesses=0;if(!receipt.cleanup){fs.rmSync(config.directory,{recursive:true,force:true});receipt.cleanup='own_connectors_closed_ui_exited_private_state_removed';}}catch{receipt.status='BLOCKED';receipt.cleanup='owned_process_or_state_cleanup_unconfirmed';}}
  receipt.completedAt=new Date().toISOString();save();
 }
 return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{assert(process.argv[3]==='--authorize-owned-desktop','explicit_native_owned_desktop_required');const result=await runOwnedDesktopAcceptance(JSON.parse(fs.readFileSync(process.argv[2],'utf8')));console.log(JSON.stringify({status:result.status,reason:result.reason}));process.exitCode=result.status==='PASS'?0:2;}catch{process.exitCode=2;}}
