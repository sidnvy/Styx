import WebSocket from 'ws';
import {resolveInstalledBrowser} from '../packages/styx-browser-provider/installed.mjs';
import {browserFailure} from '../packages/styx-browser-provider/contract.mjs';
import {hostAuthentication,normalizeConnector} from './connect.mjs';
import {normalizeBrowserConfig} from '../packages/styx-browser-provider/config.mjs';
const MAX_FRAME=8*1024*1024;
export function browserConfig(config){const c=normalizeConnector(config);const browser=normalizeBrowserConfig(c.browser);if(!browser)return null;const endpoint=new URL(c.endpoint);endpoint.pathname=endpoint.pathname.replace(/\/exec$/,'/browser');return {...c,browser,browserEndpoint:endpoint.href};}
export async function connectBrowserOnce(config,{supervisor,signal,onReady,workAdmission}={}){
  const c=browserConfig(config);if(!c)throw Error('browser_not_configured');if(signal?.aborted)throw Error('connector_cancelled');
  const workPeer=workAdmission?.openPeer('browser');
  let ws,server,closed=false;const terminate=()=>{if(closed)return;closed=true;ws?.terminate();transport.onclose?.();};
  const transport={onmessage:null,onerror:null,onclose:null,async start(){},async send(message){try{workPeer?.response(message)}catch(error){workAdmission?.markUnknown();terminate();throw error}if(closed||ws?.readyState!==WebSocket.OPEN)throw Error('browser_disconnected');let data=JSON.stringify(message);if(Buffer.byteLength(data)>MAX_FRAME){if(message.id!==undefined&&!message.method)data=JSON.stringify({jsonrpc:'2.0',id:message.id,result:browserFailure('browser_frame_limit')});else{terminate();throw Error('browser_frame_limit');}}await new Promise((resolve,reject)=>ws.send(data,{binary:false},error=>{if(error){terminate();reject(error)}else resolve()}));},async close(){terminate();}};
  signal?.addEventListener('abort',terminate,{once:true});
  try{
    server=supervisor.createServer();await server.connect(transport);
    ws=new WebSocket(c.browserEndpoint,{...hostAuthentication(c),maxPayload:MAX_FRAME,handshakeTimeout:5000,followRedirects:false,perMessageDeflate:false});
    ws.on('message',(data,isBinary)=>{if(isBinary||data.length>MAX_FRAME){terminate();return;}try{const message=JSON.parse(String(data));if(!message||Array.isArray(message)||typeof message!=='object')throw Error();try{workPeer?.request(message)}catch(error){if(error.message==='device_in_maintenance'){ws.send(JSON.stringify({jsonrpc:'2.0',id:message.id,error:{code:-32001,message:'device_in_maintenance'}}));return}throw error}transport.onmessage?.(message);}catch{terminate();}});
    await new Promise((resolve,reject)=>{const open=()=>{resolve();};const fail=()=>reject(Error('browser_websocket_unavailable'));ws.once('open',open);ws.once('error',fail);ws.once('close',fail);});
    if(signal?.aborted)throw Error('connector_cancelled');onReady?.({host_id:c.host_id,lane:'browser'});
    await new Promise(resolve=>{ws.once('close',resolve);ws.once('error',resolve);if(closed)resolve();});
  }finally{workPeer?.close();terminate();signal?.removeEventListener('abort',terminate);await server?.close().catch(()=>{});}
}
export async function runBrowserConnector(config,{signal,once=false,onReady,onStatus,retryMinMs=500,retryMaxMs=15000,workAdmission}={}){
  const c=browserConfig(config);if(!c)return;
  let supervisor,failures=0;
  try{while(!signal?.aborted){
    try{
      if(!supervisor){
        let browser=c.browser;
        const installed=resolveInstalledBrowser(browser);if(installed)browser={...browser,executablePath:installed.executablePath};
        if(!browser.executablePath){onStatus?.('preparing',{lane:'browser'});const {prepareManagedBrowser}=await import('../packages/styx-browser-provider/prepare.mjs');const runtime=await prepareManagedBrowser({profileRoot:browser.profileRoot,authorize:true,signal});browser={...browser,executablePath:runtime.executablePath};}
        const {HostBrowserSupervisor}=await import('../packages/styx-browser-provider/host.mjs');supervisor=new HostBrowserSupervisor({browser,cwd:c.exec.cwd});
      }
      await connectBrowserOnce(c,{supervisor,signal,onReady,workAdmission});failures=0;onStatus?.('disconnected',{lane:'browser'});
    }catch{failures++;onStatus?.(supervisor?'connection_failed':'preparation_failed',{lane:'browser'});}
    if(once)break;
    const retryMs=Math.min(retryMaxMs,retryMinMs*2**Math.min(failures,8));
    await new Promise(resolve=>{const done=()=>{clearTimeout(timer);signal?.removeEventListener('abort',done);resolve();};const timer=setTimeout(done,retryMs);signal?.addEventListener('abort',done,{once:true});if(signal?.aborted)done();});
  }}finally{await supervisor?.close();}
}
