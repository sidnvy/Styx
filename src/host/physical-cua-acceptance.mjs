// Reproducible, unattended cross-host acceptance over Styx's own MCP tools.
// Only a self-expiring, exact-title Zenity scratch dialog is ever targeted.
// Never reads other windows, user documents or clipboard contents.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const url=process.env.STYX_PILOT_MCP_URL;
const tokenFile=process.env.STYX_PILOT_MCP_TOKEN_FILE;
const target=process.env.STYX_PILOT_ENVIRONMENT_ID;
let safeEndpoint=false;
try {
  const endpoint=new URL(url);
  safeEndpoint=endpoint.pathname==='/mcp' &&
    !endpoint.username && !endpoint.password && !endpoint.search &&
    !endpoint.hash &&
    (endpoint.protocol==='https:' ||
      (endpoint.protocol==='http:' &&
        ['127.0.0.1','localhost','[::1]'].includes(endpoint.hostname)));
}catch{}
if(!safeEndpoint || !tokenFile || !path.isAbsolute(tokenFile) ||
   !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(target??'')) {
  console.log(JSON.stringify({status:'BLOCKED',reason:'private_gateway_not_configured'}));
  process.exit(2);
}
const token=fs.readFileSync(tokenFile,'utf8').trim();
const title='STYX_CUA_REMOTE_ACCEPT_'+randomBytes(6).toString('hex');
const transport=new StreamableHTTPClientTransport(new URL(url),{
  requestInit:{headers:{Authorization:'Bearer '+token}}
});
const client=new Client({name:'styx-own-window-acceptance',version:'0.1.0'});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let initialized=false,phase='initialize',pid=null;
async function tool(name,args){
  phase=name;
  const r=await client.callTool({name,arguments:args});
  if(r.isError)throw Error(name+'_'+(r.structuredContent?.error||'native_refusal'));
  return r;
}
try {
  await client.connect(transport);initialized=true;
  // A scoped terminal timeout makes this test self-cleaning if an action fails.
  const cmd="GDK_BACKEND=wayland /usr/bin/zenity --question --timeout=30 "+
    "--title='"+title+"' --text='Styx owned unattended pilot' "+
    "--ok-label='Styx Verify Click' --cancel-label=Cancel & "+
    "pid=$!; printf 'STYX_PID=%s\n' \"$pid\"; "+
    "wait \"$pid\"; rc=$?; printf 'STYX_EXIT=%s\n' \"$rc\"; exit \"$rc\"";
  const started=await tool('exec_command',{environment_id:target,cmd,
    login:false,yield_time_ms:1000});
  const output=started.structuredContent?.output??'';
  const match=/STYX_PID=(\d+)/.exec(output);
  if(!match)throw Error('fixture_pid_not_confirmed');
  pid=Number(match[1]);
  const shellSession=started.structuredContent?.session_id;
  if(!shellSession)throw Error('fixture_session_unavailable');
  let window;
  for(let n=0;n<28;n++) {
    const discovered=await tool('list_windows',{environment_id:target,
      pid,on_screen_only:false});
    const windows=discovered.structuredContent?.windows??[];
    window=windows.find(w=>w.pid===pid&&w.title===title);
    if(window)break;
    await sleep(200);
  }
  if(!window)throw Error('owned_window_not_found');
  const windowId=Number(window.window_id);
  if(!Number.isSafeInteger(windowId))throw Error('invalid_owned_window_id');
  const state=await tool('get_window_state',{environment_id:target,pid,
    window_id:windowId,tree_format:'elements',max_elements:80,
    include_screenshot:true});
  const elements=state.structuredContent?.elements??[];
  const image=state.content?.find(c=>c.type==='image'&&c.mimeType==='image/png');
  if(!image?.data || !Array.isArray(elements))throw Error('observation_incomplete');
  const button=elements.find(e=>String(e.label||'').includes('Styx Verify Click'));
  if(!button?.element_token)throw Error('observed_button_not_found');
  await tool('click',{environment_id:target,pid,window_id:windowId,
    element_token:button.element_token});
  let result=await tool('write_stdin',{session_id:shellSession,chars:'',
    yield_time_ms:500});
  let collected=output+(result.structuredContent?.output??'');
  for(let i=0;result.structuredContent?.session_id && i<22;i++) {
    result=await tool('write_stdin',{session_id:shellSession,chars:'',
      yield_time_ms:500});
    collected+=result.structuredContent?.output??'';
  }
  if(result.structuredContent?.exit_code!==0 ||
     !collected.includes('STYX_EXIT=0'))throw Error('independent_readback_failed');
  console.log(JSON.stringify({pilot:'styx-physical-cua-unattended',
    status:'PASS',physicalHost:true,
    connection:'Gateway MCP + authenticated Host Outbound WSS',
    driver:'cua-driver 0.36.0',
    ownWindow:true,screenshot:true,accessibilityElements:elements.length,
    clickedObservedButton:true,independentExitCode:0,
    externalControlPlane:'none'}));
}catch(e){
  console.log(JSON.stringify({pilot:'styx-physical-cua-unattended',
    status:'FAIL',phase,error:String(e.message).slice(0,120),
    automaticScratchTimeoutSeconds:30}));
  process.exitCode=1;
}finally{
  if(initialized)await transport.terminateSession().catch(()=>{});
  await client.close().catch(()=>{});
}
