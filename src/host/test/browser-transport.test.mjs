import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {CallToolRequestSchema,ListToolsRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {browserTools,BROWSER_VERSION} from '../../packages/styx-browser-provider/contract.mjs';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {connectBrowserOnce} from '../browser.mjs';

test('oversized native result gets an immediate compact error over the authenticated Browser lane',{timeout:10000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-browser-frame-'));fs.chmodSync(root,0o700);
 const tokenFile=path.join(root,'host.token');fs.writeFileSync(tokenFile,randomBytes(48).toString('hex'),{mode:0o600});
 const target={id:'frame-host',allowed:true,kind:'host',platform:process.platform,generation:'g1',cwd:root,shell:'/bin/sh',shells:['/bin/sh'],exec:{transport:'outbound',token_file:tokenFile},browser:{enabled:true,transport:'outbound'}};
 const gateway=createStyxGateway({catalog:{version:1,default_environment_id:target.id,targets:[target]},computer:null});
 const hosts=[],http=await createGatewayHttp(gateway,{token:randomBytes(48).toString('hex'),host:'127.0.0.1',port:0,allowedHosts:hosts});hosts.push('127.0.0.1:'+http.address.port);
 let ready;const connected=new Promise(r=>{ready=r});const abort=new AbortController();let calls=0;
 const supervisor={createServer(){const server=new Server({name:'styx-browser-host',version:BROWSER_VERSION},{capabilities:{tools:{}}});server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:browserTools}));server.setRequestHandler(CallToolRequestSchema,async()=>{calls++;return {content:[{type:'image',mimeType:'image/png',data:'a'.repeat(9*1024*1024)}]}});return server;}};
 const task=connectBrowserOnce({host_id:target.id,gateway_ws_url:'ws://'+hosts[0],token_file:tokenFile,exec:{binary:process.execPath,cwd:root},browser:{enabled:true,profileRoot:path.join(root,'profiles')}},{supervisor,signal:abort.signal,onReady:ready});task.catch(()=>{});
 t.after(async()=>{abort.abort();await task.catch(()=>{});await http.close();fs.rmSync(root,{recursive:true,force:true})});
 await connected;
 const result=await gateway.browser.callTool('browser_take_screenshot',{scale:'css'},'owner');assert.equal(calls,1);assert.equal(result.structuredContent.error,'browser_frame_limit');assert.equal(result.structuredContent.uncertain,undefined);
});
