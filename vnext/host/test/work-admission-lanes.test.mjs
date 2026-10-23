import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {once} from 'node:events';
import {WebSocketServer} from 'ws';
import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {connectComputerOnce} from '../computer.mjs';
import {connectBrowserOnce} from '../browser.mjs';
import {createHostWorkAdmission} from '../../shared/work-admission.mjs';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
for(const lane of ['computer','browser'])test(`${lane} actual Host transport fences incoming work while its admitted reply settles`,{skip:lane==='computer'&&process.platform!=='linux',timeout:8000},async t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-lane-admission-')),token=path.join(root,'token'),binary=path.join(root,'driver');fs.chmodSync(root,0o700);fs.writeFileSync(token,'a'.repeat(48),{mode:0o600});
 fs.writeFileSync(binary,'#!'+process.execPath+'\n'+`import readline from 'node:readline';readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);setTimeout(()=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{content:[{type:'text',text:'completed'}]}})+'\\n'),200)});`,{mode:0o700});
 const server=new WebSocketServer({host:'127.0.0.1',port:0});await once(server,'listening');let socket;const connected=new Promise(r=>server.once('connection',s=>{socket=s;r()})),abort=new AbortController(),admission=createHostWorkAdmission('host',{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'b'.repeat(32),lanes:['exec','computer','browser']});admission.openPeer('exec').ready();
 const config={host_id:'host',gateway_ws_url:'ws://127.0.0.1:'+server.address().port,token_file:token,exec:{binary:process.execPath,cwd:root},computer:{enabled:true,binary},browser:{enabled:true,profileRoot:path.join(root,'profiles')}};
 const supervisor={createServer(){const s=new Server({name:'test',version:'1'},{capabilities:{tools:{}}});s.setRequestHandler(CallToolRequestSchema,async()=>{await sleep(200);return{content:[{type:'text',text:'completed'}]}});return s}};
 const running=(lane==='computer'?connectComputerOnce:connectBrowserOnce)(config,{signal:abort.signal,workAdmission:admission,supervisor});running.catch(()=>{});await connected;
 const replies=new Map();socket.on('message',data=>{const m=JSON.parse(String(data));replies.set(m.id,m)});const send=(id,method,params)=>socket.send(JSON.stringify({jsonrpc:'2.0',id,method,params}));
 const reply=async id=>{for(let n=0;n<200;n++){if(replies.has(id))return replies.get(id);await sleep(5)}throw Error('fixture_reply_missing')};
 t.after(async()=>{abort.abort();await running;for(const c of server.clients)c.terminate();await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true})});
 if(lane==='browser'){send(90,'initialize',{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'fixture',version:'1'}});await reply(90);socket.send(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'}));}
 send(1,'tools/call',{name:'fixture',arguments:{}});for(let n=0;!admission.active.size&&n<100;n++)await sleep(2);assert.ok(admission.active.size);
 const ticket='a'.repeat(32);assert.equal(admission.begin({ticketId:ticket}).status,'waiting');send(2,'tools/call',{name:'fixture',arguments:{}});assert.equal((await reply(2)).error.message,'device_in_maintenance');assert.equal((await reply(1)).result.content[0].text,'completed');assert.equal(admission.commit(ticket).status,'ready');admission.cancel(ticket);send(3,'tools/call',{name:'fixture',arguments:{}});assert.equal((await reply(3)).result.content[0].text,'completed');
});

for(const lane of ['computer','browser'])for(const outcome of ['send_failure','disconnect_before_terminal'])test(`${lane} local dispatch settlement: ${outcome}`,{skip:lane==='computer'&&process.platform!=='linux',timeout:8000},async t=>{
 const {default:WebSocket}=await import('ws');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-terminal-send-'));fs.chmodSync(root,0o700);const token=path.join(root,'token');fs.writeFileSync(token,'a'.repeat(48),{mode:0o600});
 const binary=path.join(root,'driver');fs.writeFileSync(binary,'#!'+process.execPath+'\n'+`import readline from 'node:readline';readline.createInterface({input:process.stdin}).on('line',line=>{const m=JSON.parse(line);setTimeout(()=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result:{content:[]}})+'\\n'),200)});`,{mode:0o700});
 const server=new WebSocketServer({host:'127.0.0.1',port:0});await once(server,'listening');let socket;const connected=new Promise(r=>server.once('connection',s=>{socket=s;r()}));
 const admission=createHostWorkAdmission('host',{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'b'.repeat(32),lanes:['exec','computer','browser']});let release,started;const begun=new Promise(r=>started=r),hold=new Promise(r=>release=r);let injected=false;
 const original=WebSocket.prototype.send;WebSocket.prototype.send=function(data,options,callback){let message;try{message=JSON.parse(String(data))}catch{}if(!this._isServer&&message?.id===1&&message.result&&outcome==='send_failure'){injected=true;queueMicrotask(()=>callback(Error('fixture_delivery_failure')));return}return original.call(this,data,options,callback)};
 const supervisor={createServer(){const s=new Server({name:'test',version:'1'},{capabilities:{tools:{}}});s.setRequestHandler(CallToolRequestSchema,async()=>{started();await hold;return{content:[{type:'text',text:'done'}]}});return s}};
 const abort=new AbortController(),config={host_id:'host',gateway_ws_url:'ws://127.0.0.1:'+server.address().port,token_file:token,exec:{binary:process.execPath,cwd:root},computer:{enabled:true,binary},browser:{enabled:true,profileRoot:path.join(root,'profiles')}};
 const running=(lane==='computer'?connectComputerOnce:connectBrowserOnce)(config,{signal:abort.signal,workAdmission:admission,supervisor});running.catch(()=>{});
 t.after(async()=>{release();abort.abort();await running.catch(()=>{});WebSocket.prototype.send=original;for(const c of server.clients)c.terminate();await new Promise(r=>server.close(r));fs.rmSync(root,{recursive:true,force:true})});
 await connected;const replies=new Map();socket.on('message',data=>{const m=JSON.parse(String(data));replies.set(m.id,m)});
 socket.send(JSON.stringify({jsonrpc:'2.0',id:90,method:'initialize',params:{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'fixture',version:'1'}}}));for(let n=0;!replies.has(90)&&n<100;n++)await sleep(10);assert.ok(replies.has(90));
 socket.send(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'}));socket.send(JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'fixture',arguments:{}}}));if(lane==='browser')await begun;else{for(let n=0;!admission.active.size&&n<100;n++)await sleep(5);assert.ok(admission.active.size)}
 if(outcome==='send_failure')release();else socket.terminate();await running;
 assert.equal(injected,outcome==='send_failure');assert.equal(admission.begin({ticketId:'c'.repeat(32)}).status,outcome==='send_failure'?'ready':'unknown');
});
