import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {runHostConnector} from '../connect.mjs';
import {createHostWorkAdmission} from '../../shared/work-admission.mjs';
const live=process.env.STYX_NATIVE_WORK_ADMISSION==='1',tick=()=>new Promise(r=>setTimeout(r,20));
test('native Host-only and Gateway-wide fences retain waiting command, allow input/drain, and resume admission',{skip:!live,timeout:30000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-native-work-admission-')),token=randomBytes(32).toString('hex'),tokenFile=path.join(root,'token');fs.chmodSync(root,0o700);fs.writeFileSync(tokenFile,token,{mode:0o600});const codexHome=path.join(root,'codex-home');fs.mkdirSync(codexHome,{mode:0o700});
 const gateway=createStyxGateway({catalog:{version:1,default_environment_id:'owned',targets:[{id:'owned',kind:'host',platform:process.platform,generation:'one',allowed:true,cwd:root,shell:'/bin/sh',shells:['/bin/sh'],exec:{transport:'outbound',token_file:tokenFile}}]}}),allowedHosts=[],model=randomBytes(32).toString('hex'),http=await createGatewayHttp(gateway,{token:model,port:0,allowedHosts}),origin='127.0.0.1:'+http.address.port;allowedHosts.push(origin);
 const abort=new AbortController(),host=createHostWorkAdmission('owned');let connected=false;
 const connector=runHostConnector({host_id:'owned',gateway_ws_url:'ws://'+origin,token_file:tokenFile,exec:{binary:process.env.STYX_NATIVE_CODEX,cwd:root,env:{CODEX_HOME:codexHome}}},{signal:abort.signal,workAdmission:host,onReady:()=>{connected=true}});
 const client=new Client({name:'owned-native-work-admission',version:'1'}),transport=new StreamableHTTPClientTransport(new URL('http://'+origin+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+model}}});await client.connect(transport);
 t.after(async()=>{await transport.terminateSession().catch(()=>{});await client.close();abort.abort();await connector;await http.close();fs.rmSync(root,{recursive:true,force:true})});while(!connected)await tick();
 const call=(name,args)=>client.callTool({name,arguments:args});
 for(const [label,controller]of [['host-only',host],['gateway-all',gateway.workAdmission]]){
  const initial=await call('exec_command',{cmd:'read answer; printf "%s" "$answer"',login:false,yield_time_ms:0});assert.equal(initial.isError,undefined);const id=initial.structuredContent.session_id;assert.ok(id);
  const ticket=randomBytes(16).toString('hex');assert.equal(controller.begin({ticketId:ticket,scope:'all'}).status,'waiting',label);assert.throws(()=>controller.commit(ticket),/not_settled/);
  const rejected=await call('exec_command',{cmd:'printf MUST_NOT_RUN',login:false,yield_time_ms:0});assert.equal(rejected.isError,true);assert.match(rejected.structuredContent.error,/maintenance|executor_rejected/);
  let result=await call('write_stdin',{session_id:id,chars:'retained-command\n',yield_time_ms:250}),output=result.structuredContent.output??'';
  for(let n=0;result.structuredContent.session_id&&n<30;n++){result=await call('write_stdin',{session_id:id,chars:'',yield_time_ms:250});output+=result.structuredContent.output??''}
  assert.equal(result.structuredContent.exit_code,0);assert.equal(output,'retained-command');assert.equal(controller.commit(ticket).status,'ready');controller.cancel(ticket);
 }
 // The process may finish after the last MCP poll. Its authenticated terminal
 // notifications must unblock Quit without consuming the owner's later output.
 let pending=await call('exec_command',{cmd:'read answer; sleep 0.1; printf preserved-result',login:false,yield_time_ms:0});
 const completedId=pending.structuredContent.session_id;assert.ok(completedId);
 pending=await call('write_stdin',{session_id:completedId,chars:'continue\n',yield_time_ms:0});
 let preserved=pending.structuredContent.output??'';assert.equal(pending.structuredContent.session_id,completedId);
 const settledTicket=randomBytes(16).toString('hex');host.begin({ticketId:settledTicket});gateway.workAdmission.begin({ticketId:settledTicket});
 for(let n=0;n<100&&(host.status(settledTicket).status!=='ready'||gateway.workAdmission.status(settledTicket).status!=='ready');n++)await tick();
 assert.equal(host.status(settledTicket).status,'ready');assert.equal(gateway.workAdmission.status(settledTicket).status,'ready');assert(gateway.exec.sessions.has(completedId));
 pending=await call('write_stdin',{session_id:completedId,chars:'',yield_time_ms:1000});preserved+=pending.structuredContent.output??'';
 assert.equal(preserved,'preserved-result');assert.equal(pending.structuredContent.exit_code,0);assert(!gateway.exec.sessions.has(completedId));
 host.cancel(settledTicket);gateway.workAdmission.cancel(settledTicket);
 let next=await call('exec_command',{cmd:'printf resumed',login:false,yield_time_ms:1000}),resumed=next.structuredContent.output??'';while(next.structuredContent.session_id){next=await call('write_stdin',{session_id:next.structuredContent.session_id,chars:'',yield_time_ms:250});resumed+=next.structuredContent.output??''}assert.equal(resumed,'resumed');assert.equal(next.structuredContent.exit_code,0);
});
