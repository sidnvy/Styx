// Opt-in, bounded, isolated real native Mac Gateway -> outbound Host -> app Cua.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import {Readable} from 'node:stream';
import {spawn,execFileSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
const assert=(ok,code)=>{if(!ok)throw Error(code)};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const sha=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const quote=text=>"'"+text.replaceAll("'","'\\''")+"'";
async function until(check,code,ms=15000){const end=Date.now()+ms;while(Date.now()<end){if(await check())return;await sleep(100)}throw Error(code)}
function caFetch(origin,ca){return async(input,init={})=>{
 const url=new URL(String(input));assert(url.origin===origin,'test_origin_mismatch');
 return new Promise((resolve,reject)=>{const req=https.request(url,{method:init.method??'GET',headers:Object.fromEntries(new Headers(init.headers)),ca,signal:init.signal},res=>{
  const headers=new Headers();for(const[k,v]of Object.entries(res.headers))if(v!==undefined)headers.set(k,Array.isArray(v)?v.join(', '):v);
  resolve(new Response([204,205,304].includes(res.statusCode)?null:Readable.toWeb(res),{status:res.statusCode,headers}));
 });req.once('error',reject);req.end(init.body??undefined)});
}}
export async function runMacGatewayAcceptance(directory){
 assert(process.platform==='darwin'&&process.env.STYX_MAC_GATEWAY_ACCEPTANCE==='1','explicit_native_mac_optin_required');
 const root=fs.realpathSync(directory),stat=fs.lstatSync(root);
 assert(stat.isDirectory()&&stat.uid===process.getuid()&&!(stat.mode&0o077)&&path.basename(root).startsWith('styx-local-dev-'),'private_owned_scratch_required');
 assert(JSON.parse(fs.readFileSync(path.join(root,'.styx-local-owner.json'))).kind==='styx-local-development-app-pilot','owned_marker_required');
 const state=path.join(root,'gateway-private');assert(!fs.existsSync(state),'fresh_gateway_state_required');fs.mkdirSync(state,{mode:0o700});
 const codex='/private/tmp/styx-local-dev-20261019-0743bc4c/runtimes/codex/codex';
 assert(sha(codex)==='8813367285524ac798dd96d1b071aea30d58708c7226fd236cd275cf1cfdee31','pinned_mac_codex_required');
 const driver='/Applications/Styx.app/Contents/MacOS/cua-driver',socket=`/tmp/styx-cua-${process.getuid()}/cua.sock`;
 const descriptor=JSON.parse(fs.readFileSync(`/tmp/styx-cua-${process.getuid()}/connection.json`));
 assert(execFileSync('/bin/ps',['-p',String(descriptor.owner_pid),'-o','comm='],{encoding:'utf8'}).trim()==='/Applications/Styx.app/Contents/MacOS/Styx','installed_app_owner_required');
 const permissions=JSON.parse(execFileSync(driver,['call','check_permissions',JSON.stringify({prompt:false,probe_direct_capture:false}),'--socket',socket],{encoding:'utf8',timeout:10000}));
 assert(permissions.accessibility&&permissions.screen_recording,'actual_host_grants_required');
 const receipt={schema:1,status:'NOT RUN',source_revision:'32791a1',scope:'native macOS SDK -> private HTTPS Gateway -> outbound WSS Host -> installed Styx.app embedded Cua; same Gateway native Exec',
  chatgpt_connector:'NOT RUN',production_endpoint:'NOT RUN',service_install:'NOT RUN',signing_mutation:'NOT RUN',tcc_mutation:'NOT RUN',node:process.version,
  evidence:{outbound_exec_connected:'NOT RUN',outbound_computer_connected:'NOT RUN',native_exec:'NOT RUN',owned_gui:'NOT RUN',cleanup:'NOT RUN'},installed_app_owner:descriptor.owner_pid};
 let gateway,server,host,transport,client,phase='setup';
 const hostToken=randomBytes(32).toString('hex'),modelToken=randomBytes(32).toString('hex');
 try{
  const tokenFile=path.join(state,'host.token');fs.writeFileSync(tokenFile,hostToken,{mode:0o600});
  const keyFile=path.join(state,'key.pem'),certFile=path.join(state,'cert.pem');
  execFileSync('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2','-keyout',keyFile,'-out',certFile,'-subj','/CN=styx-mac-owned','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore',timeout:15000});
  fs.chmodSync(keyFile,0o600);const target='mac-owned-gateway';
  gateway=createStyxGateway({catalog:{version:1,default_environment_id:target,targets:[{id:target,kind:'host',platform:'darwin',generation:'mac-owned-g1',allowed:true,cwd:state,shell:'/bin/sh',shells:['/bin/sh'],exec:{transport:'outbound',token_file:tokenFile},computer:{enabled:true,transport:'outbound',max_connections:1}}]}});
  const allowedHosts=[];server=await createGatewayHttp(gateway,{token:modelToken,port:0,allowedHosts,tlsCertificateFile:certFile,tlsPrivateKeyFile:keyFile});
  const address='127.0.0.1:'+server.address.port;allowedHosts.push(address);const origin='https://'+address;
  const home=path.join(state,'codex-home');fs.mkdirSync(home,{mode:0o700});
  const config={host_id:target,gateway_ws_url:'wss://'+address,token_file:tokenFile,gateway_ca_file:certFile,
   exec:{binary:codex,cwd:state,env:{PATH:'/usr/bin:/bin',HOME:state,CODEX_HOME:home,LANG:'en_US.UTF-8'}},computer:{enabled:true,binary:driver,socket,connections:1}};
  host=spawn(process.execPath,[path.join(root,'vnext/host/connect.mjs'),'--stdin-config'],{env:{PATH:'/usr/bin:/bin',HOME:state},stdio:['pipe','ignore','ignore']});
  host.stdin.on('error',()=>{});host.stdin.end(JSON.stringify(config));
  phase='outbound_ready';await until(()=>gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===1,'native_outbound_ready_timeout');
  receipt.evidence.outbound_exec_connected='PASS';receipt.evidence.outbound_computer_connected='PASS';
  transport=new StreamableHTTPClientTransport(new URL(origin+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+modelToken}},fetch:caFetch(origin,fs.readFileSync(certFile))});
  client=new Client({name:'styx-native-macos-gateway-acceptance',version:'0.1.0'});await client.connect(transport);
  async function tool(name,args){const r=await client.callTool({name,arguments:args},undefined,{timeout:15000});assert(!r.isError,'gateway_tool_'+name+'_refused');return r}
  async function complete(result){let output=result.structuredContent?.output??'';const end=Date.now()+12000;
   while(result.structuredContent?.session_id&&Date.now()<end){result=await tool('write_stdin',{session_id:result.structuredContent.session_id,chars:'',yield_time_ms:250});output+=result.structuredContent?.output??''}
   assert(!result.structuredContent?.session_id,'native_exec_incomplete');return{...result.structuredContent,output};}
  phase='native_exec';const execResult=await complete(await tool('exec_command',{environment_id:target,cmd:'printf STYX_MAC_GATEWAY_EXEC',login:false,yield_time_ms:250}));
  assert(execResult.exit_code===0&&execResult.output==='STYX_MAC_GATEWAY_EXEC','native_gateway_exec_readback_mismatch');receipt.evidence.native_exec='PASS';
  phase='owned_gui';const title='STYX_OWNED_GUI_'+randomBytes(6).toString('hex'),readback=path.join(state,'gui-readback.json');
  const fixture=path.join(root,'OwnedGuiFixture');assert(fs.lstatSync(fixture).isFile()&&!fs.lstatSync(fixture).isSymbolicLink(),'owned_fixture_required');
  const cmd=quote(fixture)+' '+quote(title)+' '+quote(readback)+' & pid=$!; printf "STYX_PID=%s\\n" "$pid"; wait "$pid"; rc=$?; printf "STYX_EXIT=%s\\n" "$rc"; exit "$rc"';
  const started=await tool('exec_command',{environment_id:target,cmd,login:false,yield_time_ms:250}),out=started.structuredContent?.output??'';
  const match=/STYX_PID=(\d+)/.exec(out),session=started.structuredContent?.session_id;assert(match&&session,'owned_fixture_pid_session_required');const pid=Number(match[1]);
  let window;await until(async()=>{const r=await tool('list_windows',{environment_id:target,pid,on_screen_only:false});window=r.structuredContent?.windows?.find(w=>w.pid===pid&&w.title===title);return !!window},'owned_window_timeout',8000);
  const window_id=Number(window.window_id);assert(Number.isSafeInteger(window_id),'owned_window_id_required');
  const snapshot=await tool('get_window_state',{environment_id:target,pid,window_id,tree_format:'elements',max_elements:80,include_screenshot:true});
  const elements=snapshot.structuredContent?.elements,image=snapshot.content?.find(c=>c.type==='image'&&c.mimeType==='image/png');
  assert(Array.isArray(elements)&&image?.data,'owned_observation_missing');
  const button=elements.find(e=>e.label==='Styx Verify Click'&&e.element_token);assert(button,'owned_button_missing');
  await tool('click',{environment_id:target,pid,window_id,element_token:button.element_token});
  const finished=await complete(await tool('write_stdin',{session_id:session,chars:'',yield_time_ms:250}));assert(finished.exit_code===0&&finished.output.includes('STYX_EXIT=0'),'owned_fixture_exit_readback_failed');
  const read=await complete(await tool('exec_command',{environment_id:target,cmd:'cat '+quote(readback),login:false,yield_time_ms:250}));assert(read.exit_code===0,'independent_gateway_read_failed');
  const independent=JSON.parse(read.output);assert(independent.status==='PASS'&&independent.pid===pid&&independent.title===title,'independent_gateway_readback_mismatch');
  receipt.evidence.owned_gui='PASS';receipt.gui={screenshot:'PASS',screenshot_sha256:createHash('sha256').update(Buffer.from(image.data,'base64')).digest('hex'),accessibility_elements:elements.length,observed_click:'PASS',independent_readback:'PASS',fixture_exit_code:0};receipt.status='PASS';
 }catch(error){receipt.status='FAIL';receipt.failed_phase=phase;receipt.error_code=/^[a-z_]+$/.test(error.message)?error.message:'native_gateway_acceptance_failed'}
 finally{
  await transport?.terminateSession().catch(()=>{});await client?.close().catch(()=>{});
  if(server)await server.close().catch(()=>{});else await gateway?.close().catch(()=>{});
  if(host&&host.exitCode===null&&host.signalCode===null){host.kill('SIGTERM');await Promise.race([new Promise(r=>host.once('close',r)),sleep(7000)]);if(host.exitCode===null&&host.signalCode===null){host.kill('SIGKILL');await new Promise(r=>host.once('close',r))}}
  fs.rmSync(state,{recursive:true,force:true});receipt.evidence.cleanup='PASS';
  fs.writeFileSync(path.join(root,'gateway-acceptance.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
 }
 return receipt;
}
if(process.argv[1]&&fs.realpathSync(process.argv[1])===fs.realpathSync(new URL(import.meta.url))){const result=await runMacGatewayAcceptance(process.argv[2]);console.log(JSON.stringify(result));process.exitCode=result.status==='PASS'?0:1}
