// Explicitly opted-in, bounded native user-service acceptance. No ordinary CI
// imports mutate systemd. Only a fresh, named Styx-owned unit is ever controlled.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import {Readable} from 'node:stream';
import {execFileSync} from 'node:child_process';
import {createHash,generateKeyPairSync,randomBytes,X509Certificate} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {buildHostRelease} from './build-host-release.mjs';
import {stageSignedRelease,activateRelease,rollbackRelease,refreshVerifiedBootstrap,activeRelease} from './installer.mjs';
import {installLinuxService,removeLinuxService,systemdUser,statusUserService} from './linux-service.mjs';
import {createStyxGateway} from '../gateway/index.mjs';
import {createGatewayHttp} from '../gateway/http.mjs';

const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const sha=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const assert=(ok,why)=>{if(!ok)throw Error(why)};
const root=fileURLToPath(new URL('../',import.meta.url));
const GRAPHICAL=['WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','DISPLAY','HYPRLAND_INSTANCE_SIGNATURE'];
const PINNED={node:'fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48',
  codex:'399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215',
  cua:'d09deb163d5c505493c865c0882ccf261d460c515afe9df1ad1e5d4173f2a4f9'};
const native=(args)=>execFileSync('/usr/bin/systemctl',['--user',...args],{
  encoding:'utf8',timeout:25000,stdio:['ignore','pipe','pipe']}).trim();
export function pilotOptions({directory,unitName,nodeBinary,codexBinary,cuaBinary}={}){
  assert(typeof directory==='string'&&path.isAbsolute(directory)&&/^\/[A-Za-z0-9._/+@-]+$/.test(directory),'absolute_safe_fresh_pilot_directory_required');
  assert(/^styx-rc[0-9]{8}-owned(?:-[a-z0-9]{1,12})?\.service$/.test(unitName??''),'explicit_owned_pilot_unit_required');
  for(const p of [nodeBinary,codexBinary,cuaBinary])assert(typeof p==='string'&&path.isAbsolute(p),'absolute_pinned_binary_required');
  return {directory,unitName,nodeBinary,codexBinary,cuaBinary};
}
// Unknown manager/load/enablement states never attest an offline boundary.
export function confirmedInactiveDisabled(state={}){
  return state.status==='reported'&&state.load==='loaded'&&
    ['inactive','failed'].includes(state.active)&&state.pid===0&&state.enabled==='disabled';
}
export function graphicalEnvironment(text){
  const values={};
  for(const line of String(text).split('\n')){
    const i=line.indexOf('=');if(i<1)continue;
    const name=line.slice(0,i);
    if(GRAPHICAL.includes(name))values[name]=line.slice(i+1);
  }
  return values;
}
async function until(check,why,timeout=18000){
  const end=Date.now()+timeout;
  while(Date.now()<end){if(await check())return;await sleep(100)}
  throw Error(why);
}
function save(file,value){
  const temporary=file+'.new',fd=fs.openSync(temporary,'w',0o600);
  try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(temporary,file);
  const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}
}
// Per-client CA trust and origin pinning; never disable certificate checks or
// alter global trust. SDK uses JSON requests and streamed SSE responses.
function caFetch(origin,ca){
  return async (input,init={})=>{
    const url=new URL(String(input));assert(url.origin===origin,'pilot_fetch_origin_mismatch');
    return new Promise((resolve,reject)=>{
      const req=https.request(url,{method:init.method??'GET',
        headers:Object.fromEntries(new Headers(init.headers)),ca,signal:init.signal},res=>{
        const headers=new Headers();
        for(const [k,v] of Object.entries(res.headers))if(v!==undefined)
          headers.set(k,Array.isArray(v)?v.join(', '):v);
        resolve(new Response([204,205,304].includes(res.statusCode)?null:Readable.toWeb(res),
          {status:res.statusCode,headers}));
      });
      req.once('error',reject);req.end(init.body??undefined);
    });
  };
}
export async function runManagedLinuxPilot(raw,{optIn=process.env.STYX_RUN_MANAGED_LINUX_PILOT,
  buildRelease=buildHostRelease,updateAcceptance,signal,tlsDays=1}={}){
  assert(optIn==='1','managed_linux_pilot_requires_explicit_opt_in');
  if(signal?.aborted)throw Error('managed_pilot_aborted');
  assert(Number.isInteger(tlsDays)&&tlsDays>=1&&tlsDays<=7,'bounded_pilot_tls_validity_required');
  assert(process.platform==='linux'&&process.arch==='x64','native_linux_x64_required');
  const options=pilotOptions(raw);
  const {directory,unitName,nodeBinary,codexBinary,cuaBinary}=options;
  assert(!fs.existsSync(directory),'pilot_directory_must_be_fresh');
  for(const [name,binary] of Object.entries({node:nodeBinary,codex:codexBinary,cua:cuaBinary})){
    const st=fs.lstatSync(binary);
    assert(st.isFile()&&!st.isSymbolicLink()&&sha(binary)===PINNED[name],'pinned_'+name+'_binary_mismatch');
  }
  // Refuse pre-existing units, including ones registered outside this home.
  const unitFile=path.join(os.homedir(),'.config/systemd/user',unitName);
  assert(!fs.existsSync(unitFile),'pilot_unit_already_exists');
  const before=statusUserService(unitName);
  assert(before.status==='reported','user_manager_unreachable');
  assert(before.load==='not-found','pilot_unit_already_registered');
  const graphical=graphicalEnvironment(native(['show-environment']));
  assert(graphical.WAYLAND_DISPLAY&&graphical.XDG_RUNTIME_DIR,'native_graphical_session_unavailable');
  fs.mkdirSync(directory,{mode:0o700});
  const state=path.join(directory,'private');fs.mkdirSync(state,{mode:0o700});
  const receiptFile=path.join(directory,'receipt.json');
  const receipt={schema:1,kind:'linux-owned-managed-host-pilot',status:'NOT RUN',
    revision:execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),
    runtime:{node:'22.23.3',codex:'0.163.0',cua:'0.36.0'},binary_sha256:PINNED,
    evidence:{signed_build:'NOT RUN',signed_install:'NOT RUN',managed_start_ready:'NOT RUN',
      managed_restart:'NOT RUN',managed_sigkill_recovery:'NOT RUN',signed_upgrade:'NOT RUN',
      signed_rollback:'NOT RUN',owned_gui_screenshot_ax_action_readback:'NOT RUN',
      managed_uninstall:'NOT RUN',secret_cleanup:'NOT RUN',cold_install:'NOT RUN',
      publisher_trust_distribution:'NOT RUN',full_platform_24h_soak:'NOT RUN'},
    boundaries:{gateway:'private loopback HTTPS/WSS with per-client test CA',
      service:'one explicitly named user systemd unit; no sudo, lingering or session changes',
      publisher:'ephemeral pilot Ed25519 key, not established distribution trust',
      gui:'self-expiring exact-title/pid owned scratch only; no screenshot bytes persisted'},
    samples:[]};
  save(receiptFile,receipt);
  let installed=false,server,gateway,client,transport,phase='setup',cleanupOK=false;
  const clients=[];
  const installRoot=path.join(state,'installed');
  const note=(name)=>{receipt.evidence[name]='PASS';save(receiptFile,receipt)};
  const command=(args)=>{native(args)};
  async function closeClient(){
    if(transport)await transport.terminateSession().catch(()=>{});
    await client?.close().catch(()=>{});client=null;transport=null;
  }
  try{
    phase='signed_build';
    const publisher=generateKeyPairSync('ed25519',{
      publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
    const privateKeyFile=path.join(state,'publisher-private.pem');
    const publicKeyFile=path.join(state,'publisher-public.pem');
    fs.writeFileSync(privateKeyFile,publisher.privateKey,{mode:0o600});
    fs.writeFileSync(publicKeyFile,publisher.publicKey,{mode:0o600});
    const release1='0.1.0-managed-pilot-1',release2='0.1.0-managed-pilot-2';
    for(const version of [release1,release2]){
      const destination=path.join(state,version);
      buildRelease({destination,version,privateKeyFile,codexBinary,cuaBinary,nodeBinary});
      stageSignedRelease({sourceDir:destination,installRoot,publicKeyPem:publisher.publicKey});
    }
    note('signed_build');
    activateRelease(installRoot,release1,publisher.publicKey);
    refreshVerifiedBootstrap(installRoot,publisher.publicKey,release1);note('signed_install');
    const token=randomBytes(32).toString('hex'),modelToken=randomBytes(32).toString('hex');
    const tokenFile=path.join(state,'host.token');fs.writeFileSync(tokenFile,token,{mode:0o600});
    const keyFile=path.join(state,'gateway-key.pem'),certFile=path.join(state,'gateway-cert.pem');
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days',String(tlsDays),
      '-keyout',keyFile,'-out',certFile,'-subj','/CN=styx-managed-owned',
      '-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',timeout:10000});
    const certificateNotAfter=Date.parse(new X509Certificate(fs.readFileSync(certFile)).validTo);
    receipt.tls={validity_days:tlsDays,certificate_not_after:new Date(certificateNotAfter).toISOString(),
      trust_scope:'per-client private test CA only; no global trust change'};
    const target='managed-owned-host';
    gateway=createStyxGateway({catalog:{version:1,default_environment_id:target,targets:[{
      id:target,kind:'host',platform:'linux',generation:'owned-managed-pilot-g1',
      allowed:true,cwd:state,shell:'/bin/sh',shells:['/bin/sh'],
      exec:{transport:'outbound',token_file:tokenFile},
      computer:{enabled:true,transport:'outbound',max_connections:1}}]}});
    const allowedHosts=[];
    server=await createGatewayHttp(gateway,{token:modelToken,port:0,allowedHosts,
      tlsCertificateFile:certFile,tlsPrivateKeyFile:keyFile});
    const host='127.0.0.1:'+server.address.port;allowedHosts.push(host);
    const origin='https://'+host,ca=fs.readFileSync(certFile);
    const codexHome=path.join(state,'codex-home');fs.mkdirSync(codexHome,{mode:0o700});
    const config={host_id:target,gateway_ws_url:'wss://'+host,token_file:tokenFile,
      gateway_ca_file:certFile,exec:{binary:codexBinary,cwd:state,
        env:{...graphical,PATH:'/usr/bin:/bin',HOME:state,CODEX_HOME:codexHome}},
      computer:{enabled:true,binary:cuaBinary,connections:1,
        env:{...graphical,CUA_DRIVER_RS_ENABLE_WAYLAND:'1'}}};
    const configFile=path.join(state,'host.json');fs.writeFileSync(configFile,JSON.stringify(config),{mode:0o600});
    if(signal?.aborted)throw Error('managed_pilot_aborted');
    phase='managed_start_ready';
    try { installLinuxService({unitName,installRoot,hostConfigFile:configFile,trustPublicKeyFile:publicKeyFile,restartSec:1}) }
    finally { installed=fs.existsSync(unitFile) }
    systemdUser(unitName,'enable');systemdUser(unitName,'start');
    let lastExecPeer,lastComputerPeer;
    function ownsGeneration(status,version){
      try {
        if(fs.realpathSync('/proc/'+status.pid+'/exe')!==path.join(installRoot,'node'))return false;
        const children=fs.readFileSync('/proc/'+status.pid+'/task/'+status.pid+'/children','utf8').trim().split(/\s+/).filter(Boolean);
        const script=path.join(installRoot,'releases',version,'host/connect.mjs');
        return children.some(pid=>fs.readFileSync('/proc/'+pid+'/cmdline','utf8').split('\0').includes(script));
      }catch{return false}
    }
    async function sampleExec(marker){
      assert(/^[A-Z0-9_]{1,100}$/.test(marker),'invalid_owned_exec_marker');
      if(signal?.aborted)throw Error('managed_pilot_aborted');
      let result,output='';
      try{
        const requestOptions={timeout:10000,...(signal?{signal}:{})};
        result=await client.callTool({name:'exec_command',arguments:{environment_id:target,
          cmd:'printf '+marker,login:false,yield_time_ms:250}},undefined,requestOptions);
        output=result.structuredContent?.output??'';
        const deadline=Date.now()+10000;
        while(!result.isError&&result.structuredContent?.session_id&&Date.now()<deadline){
          result=await client.callTool({name:'write_stdin',arguments:{session_id:result.structuredContent.session_id,
            chars:'',yield_time_ms:250}},undefined,requestOptions);
          output+=result.structuredContent?.output??'';
        }
      }catch(error){if(signal?.aborted)throw Error('managed_pilot_aborted');throw error}
      assert(!result.isError&&result.structuredContent?.exit_code===0&&output===marker,'managed_native_exec_readback_failed');
      return true;
    }
    async function ready(version){
      await until(()=>{
        if(signal?.aborted)throw Error('managed_pilot_aborted');
        const s=statusUserService(unitName);
        return s.active==='active'&&s.pid>1&&ownsGeneration(s,version)&&
          gateway.relay.connected(target)&&gateway.relay.sessions.get(target)!==lastExecPeer&&
          gateway.relay.computerConnected(target)===1&&
          [...gateway.relay.computerPeers.get(target)][0]!==lastComputerPeer;
      },'managed_host_readiness_timeout');
      const status=statusUserService(unitName);
      assert(activeRelease(installRoot,publisher.publicKey).version===version,'active_release_mismatch');
      lastExecPeer=gateway.relay.sessions.get(target);
      lastComputerPeer=[...gateway.relay.computerPeers.get(target)][0];
      await closeClient();
      transport=new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{
        requestInit:{headers:{Authorization:'Bearer '+modelToken}},fetch:caFetch(origin,ca)});
      client=new Client({name:'styx-owned-managed-pilot',version:'0.1.0'});
      await client.connect(transport);clients.push({client,transport});
      await sampleExec('STYX_MANAGED_'+receipt.samples.length);
      receipt.samples.push({phase,version,status:'PASS',service_active:true,exec_wss_connected:true,
        computer_wss_slots:1,systemd_restarts:status.restarts,signed_stable_node:true,signed_connector_generation:true});
      save(receiptFile,receipt);return status;
    }
    let previous=await ready(release1);note(phase);
    phase='managed_restart';await closeClient();systemdUser(unitName,'restart');
    await until(()=>statusUserService(unitName).pid!==previous.pid,'managed_restart_pid_unchanged');
    previous=await ready(release1);note(phase);
    phase='managed_sigkill_recovery';await closeClient();
    command(['kill','--signal=SIGKILL','--kill-whom=all',unitName]);
    await until(()=>{const s=statusUserService(unitName);return s.pid>1&&s.pid!==previous.pid&&s.restarts>previous.restarts},'managed_crash_not_restarted');
    previous=await ready(release1);note(phase);
    if(updateAcceptance){
      // Trusted local acceptance code only: these hooks are never loaded from
      // Host configuration, an agent tool argument, or a remote document.
      phase='update_transaction_acceptance';
      await updateAcceptance({installRoot,unitName,directory,signal,sampleExec,certificateNotAfter,publicKeyPem:publisher.publicKey,
        publicKeyFile,release1,release2,ready,closeClient,gateway,target,receipt,
        setPhase:value=>{phase=value},saveReceipt:()=>save(receiptFile,receipt)});
    }else{
      phase='signed_upgrade';await closeClient();systemdUser(unitName,'stop');
      await until(()=>!gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===0,'managed_stop_not_disconnected');
      activateRelease(installRoot,release2,publisher.publicKey);
      refreshVerifiedBootstrap(installRoot,publisher.publicKey,release2);
      systemdUser(unitName,'start');previous=await ready(release2);note(phase);
      phase='signed_rollback';await closeClient();systemdUser(unitName,'stop');
      await until(()=>!gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===0,'managed_stop_not_disconnected');
      rollbackRelease(installRoot,publisher.publicKey);
      refreshVerifiedBootstrap(installRoot,publisher.publicKey,release1);
      systemdUser(unitName,'start');await ready(release1);note(phase);
    }
    if(signal?.aborted)throw Error('managed_pilot_aborted');
    phase='owned_gui_screenshot_ax_action_readback';
    async function tool(name,args){
      const res=await client.callTool({name,arguments:args});
      assert(!res.isError,name+'_native_refusal');return res;
    }
    const title='STYX_MANAGED_OWNED_'+randomBytes(6).toString('hex');
    const cmd="GDK_BACKEND=wayland /usr/bin/zenity --question --timeout=25 --title='"+title+
      "' --text='Owned managed Styx pilot' --ok-label='Styx Verify Click' --cancel-label=Cancel & "+
      "pid=$!; printf 'STYX_PID=%s\\n' \"$pid\"; wait \"$pid\"; rc=$?; printf 'STYX_EXIT=%s\\n' \"$rc\"; exit \"$rc\"";
    const started=await tool('exec_command',{environment_id:target,cmd,login:false,yield_time_ms:500});
    const output=started.structuredContent?.output??'';
    const match=/STYX_PID=(\d+)/.exec(output),session=started.structuredContent?.session_id;
    assert(match&&session,'owned_scratch_pid_and_session_required');const pid=Number(match[1]);
    let window;
    await until(async()=>{
      const res=await tool('list_windows',{environment_id:target,pid,on_screen_only:false});
      window=res.structuredContent?.windows?.find(w=>w.pid===pid&&w.title===title);return Boolean(window);
    },'owned_scratch_window_not_found',6000);
    const window_id=Number(window.window_id);assert(Number.isSafeInteger(window_id),'invalid_owned_window');
    const stateResult=await tool('get_window_state',{environment_id:target,pid,window_id,
      tree_format:'elements',max_elements:80,include_screenshot:true});
    const elements=stateResult.structuredContent?.elements;
    assert(Array.isArray(elements),'owned_accessibility_elements_missing');
    const image=stateResult.content?.find(c=>c.type==='image'&&c.mimeType==='image/png');
    assert(image?.data,'owned_screenshot_missing');
    const button=elements.find(e=>String(e.label??'').includes('Styx Verify Click'));
    assert(button?.element_token,'owned_observed_button_missing');
    await tool('click',{environment_id:target,pid,window_id,element_token:button.element_token});
    let finished,readback=output;
    const end=Date.now()+10000;
    do{
      finished=await tool('write_stdin',{session_id:session,chars:'',yield_time_ms:250});
      readback+=finished.structuredContent?.output??'';
    }while(finished.structuredContent?.session_id&&Date.now()<end);
    assert(finished.structuredContent?.exit_code===0&&readback.includes('STYX_EXIT=0'),'independent_owned_click_readback_failed');
    receipt.gui={owned_window:true,pid_and_exact_title_scoped:true,screenshot:true,
      accessibility_elements:elements.length,observed_button_clicked:true,independent_exit_code:0};
    note(phase);receipt.status='PASS';
  }catch(error){
    receipt.status=error.message==='managed_pilot_aborted'?'BLOCKED':'FAIL';receipt.failed_phase=phase;
    receipt.reason=String(error.message).replaceAll(directory,'<private-pilot>').slice(0,150);
    if(phase in receipt.evidence)receipt.evidence[phase]=receipt.status;
  }finally{
    await closeClient();
    for(const pair of clients){await pair.transport.terminateSession().catch(()=>{});await pair.client.close().catch(()=>{})}
    if(installed){
      try{
        removeLinuxService(unitName);installed=false;
        const after=statusUserService(unitName);
        assert(!fs.existsSync(unitFile)&&after.load==='not-found'&&after.active!=='active','owned_unit_not_removed');
        receipt.evidence.managed_uninstall='PASS';cleanupOK=true;
      }catch{receipt.evidence.managed_uninstall='FAIL';receipt.status='FAIL';receipt.cleanup_reason='owned_unit_cleanup_requires_attention'}
    }else cleanupOK=true;
    await server?.close().catch(()=>{});
    if(cleanupOK){fs.rmSync(state,{recursive:true,force:true});receipt.evidence.secret_cleanup='PASS'}
    receipt.completed_at=new Date().toISOString();save(receiptFile,receipt);
  }
  return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [configFile]=process.argv.slice(2);
  try{
    assert(configFile&&path.isAbsolute(configFile),'absolute_pilot_config_required');
    const receipt=await runManagedLinuxPilot(JSON.parse(fs.readFileSync(configFile,'utf8')));
    console.log(JSON.stringify(receipt));process.exitCode=receipt.status==='PASS'?0:1;
  }catch(error){console.log(JSON.stringify({status:'BLOCKED',reason:String(error.message).slice(0,120)}));process.exitCode=2}
}
