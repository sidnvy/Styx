// Unattended Windows UIA acceptance through Styx-only tool calls.
// Creates and controls only a self-expiring WinForms test window. No OOB
// fixture copy, personal UI enumeration or screenshot payload persistence.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {requirePrivateFile,requirePrivateDirectory} from '../shared/private-file.mjs';

const endpoint=process.env.STYX_PILOT_MCP_URL;
const tokenFile=process.env.STYX_PILOT_MCP_TOKEN_FILE;
const host=process.env.STYX_PILOT_ENVIRONMENT_ID;
const literal=value=>"'"+String(value).replaceAll("'","''")+"'";
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let url,valid=false;
try{
  url=new URL(endpoint);
  valid=url.pathname==='/mcp'&&!url.search&&!url.hash&&
    !url.username&&!url.password&&(url.protocol==='https:'||
      (url.protocol==='http:'&&
        ['127.0.0.1','localhost','[::1]'].includes(url.hostname)));
}catch{}
if(process.platform!=='win32'||!valid||
  typeof tokenFile!=='string'||!path.isAbsolute(tokenFile)||
  !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(host??'')||
  !process.env.LOCALAPPDATA){
  console.log(JSON.stringify({pilot:'styx-owned-windows-ui',
    result:'BLOCKED',reason:'windows_interactive_pilot_configuration_required'}));
  process.exit(2);
}
requirePrivateFile(tokenFile);
const token=fs.readFileSync(tokenFile,'utf8').trim();
const ownerRoot=process.env.STYX_PILOT_SCRATCH_DIR;
requirePrivateDirectory(ownerRoot);
const nonce=randomBytes(6).toString('hex');
const title='STYX_OWNED_WINDOWS_'+nonce;
const receipt=path.join(ownerRoot,'receipt-'+nonce+'.txt');
const client=new Client({name:'styx-owns-its-windows-scratch',version:'0.1.0'});
const transport=new StreamableHTTPClientTransport(url,{
  requestInit:{headers:{Authorization:'Bearer '+token}}
});
let phase='connect',connected=false,pid;
async function call(name,args){
  phase=name;
  const result=await client.callTool({name,arguments:args},undefined,{timeout:10000});
  if(result.isError)throw Error('native_tool_refusal');
  return result;
}
try{
  await client.connect(transport);
  connected=true;
  // Entire scratch GUI is defined locally in the test; only its own window
  // title, receipt path, and short-lived test program are sent via Styx Exec.
  const child=[
    "$ErrorActionPreference='Stop'",
    'Add-Type -AssemblyName System.Windows.Forms',
    'Add-Type -AssemblyName System.Drawing',
    '[System.Windows.Forms.Application]::EnableVisualStyles()',
    '$receipt='+literal(receipt),
    '$form=New-Object System.Windows.Forms.Form',
    '$form.Text='+literal(title),
    '$form.Width=480;$form.Height=190',
    "$form.StartPosition='Manual';$form.Left=160;$form.Top=150",
    '$form.ShowInTaskbar=$true',
    '$button=New-Object System.Windows.Forms.Button',
    "$button.Text='Styx Verify Click'",
    "$button.Name='styx_verify_click'",
    "$button.AccessibleName='Styx Verify Click'",
    '$button.Left=24;$button.Top=48;$button.Width=215;$button.Height=45',
    "$button.Add_Click({[System.IO.File]::WriteAllText($receipt,'clicked');$form.Close()})",
    '$form.Controls.Add($button)',
    '$timer=New-Object System.Windows.Forms.Timer',
    '$timer.Interval=28000',
    '$timer.Add_Tick({$timer.Stop();$form.Close()})',
    '$timer.Start()',
    '[System.Windows.Forms.Application]::Run($form)'
  ].join('\n');
  const encoded=Buffer.from(child,'utf16le').toString('base64');
  const command=[
    "$exe=Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'",
    "$p=Start-Process -FilePath $exe -ArgumentList @("+
      "'-NoProfile','-STA','-EncodedCommand',"+
      literal(encoded)+") -PassThru",
    "Write-Output ('STYX_PID='+$p.Id)",
    'Wait-Process -Id $p.Id -Timeout 34',
    'if ((Test-Path -LiteralPath '+literal(receipt)+') -and '+
      '([IO.File]::ReadAllText('+literal(receipt)+") -eq 'clicked')) {"+
      "Remove-Item -LiteralPath "+literal(receipt)+" -Force;"+
      "Write-Output 'STYX_CLICK_RECEIPT_OK';exit 0} else {"+
      "Write-Output 'STYX_CLICK_RECEIPT_MISSING';exit 2}"
  ].join(';');
  let result=await call('exec_command',{environment_id:host,cmd:command,
    login:false,yield_time_ms:1000});
  let output=result.structuredContent?.output??'';
  let sessionId=result.structuredContent?.session_id;
  let pidMatch=/STYX_PID=(\d+)/.exec(output);
  for(let i=0;!pidMatch && sessionId && i<18;i++){
    result=await call('write_stdin',{session_id:sessionId,chars:'',
      yield_time_ms:250});
    output+=result.structuredContent?.output??'';
    sessionId=result.structuredContent?.session_id;
    pidMatch=/STYX_PID=(\d+)/.exec(output);
  }
  if(!pidMatch||!sessionId)throw Error('owned_gui_process_not_started');
  pid=Number(pidMatch[1]);
  if(!Number.isSafeInteger(pid)||pid<1)throw Error('invalid_own_process_id');
  let window;
  for(let i=0;i<26;i++){
    const r=await call('list_windows',{environment_id:host,pid,
      on_screen_only:false});
    const windows=r.structuredContent?.windows??[];
    window=windows.find(w=>Number(w.pid)===pid&&String(w.title||'')===title);
    if(window)break;
    await pause(180);
  }
  if(!window)throw Error('exact_owned_window_not_found');
  const windowId=Number(window.window_id);
  if(!Number.isSafeInteger(windowId)||windowId<1)
    throw Error('owned_window_id_invalid');
  const state=await call('get_window_state',{environment_id:host,pid,
    window_id:windowId,tree_format:'elements',max_elements:100,
    include_screenshot:true});
  const elements=state.structuredContent?.elements??[];
  const png=state.content?.find(x=>x.type==='image'&&x.mimeType==='image/png');
  if(!png?.data||png.data.length<128)
    throw Error('owned_window_screenshot_unavailable');
  const button=elements.find(x=>String(x.label||x.name||'')
    .includes('Styx Verify Click'));
  if(!button?.element_token)throw Error('owned_button_not_observed');
  await call('click',{environment_id:host,pid,window_id:windowId,
    element_token:button.element_token});
  let r=await call('write_stdin',{session_id:sessionId,chars:'',
    yield_time_ms:500});
  output+=r.structuredContent?.output??'';
  for(let i=0;i<30&&r.structuredContent?.session_id;i++){
    r=await call('write_stdin',{session_id:sessionId,chars:'',
      yield_time_ms:500});
    output+=r.structuredContent?.output??'';
  }
  if(r.structuredContent?.exit_code!==0||
    !output.includes('STYX_CLICK_RECEIPT_OK'))
    throw Error('independent_winforms_readback_failed');
  console.log(JSON.stringify({
    pilot:'styx-windows-fully-selfcontained-cua',
    result:'PASS',platform:'win32',nativeUi:'WinForms/UIA',
    observedExactOwnedPid:true,png:true,
    accessibilityElements:elements.length,clickedOwnedButton:true,
    independentExitCode:0,externalControlPlane:'none'
  }));
}catch(e){
  console.log(JSON.stringify({
    pilot:'styx-windows-fully-selfcontained-cua',
    result:'BLOCKED',phase,error:'owned_windows_ui_acceptance_failed',
    ownedWindowAutoTimeoutSeconds:28
  }));
  process.exitCode=2;
}finally{
  if(connected)await transport.terminateSession().catch(()=>{});
  await client.close().catch(()=>{});
}
