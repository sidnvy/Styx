import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,mkdir,rm} from 'node:fs/promises';import path from 'node:path';import os from 'node:os';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';
import {ExecAdapter} from '../../styx-exec-adapter/adapter.mjs';
import {ExecConnection,stdioClient} from '../../styx-exec-adapter/rpc.mjs';
import {GuiBroker} from '../broker.mjs';import {createUnifiedServer} from '../mcp.mjs';
test('unified MCP routes actual Exec Server sessions and fixture GUI scopes independently',async t=>{
 const owner='principal/chat',root=await mkdtemp(path.join(os.tmpdir(),'styx-unified-'));
 await mkdir(path.join(root,'codex-home'));
 const binary=fileURLToPath(new URL('../../styx-exec-adapter/.runtime/codex',import.meta.url));
 const runtime=await new ExecConnection(()=>stdioClient({binary,cwd:root,env:{PATH:'/usr/bin:/bin',HOME:root,CODEX_HOME:path.join(root,'codex-home')}})).initialize();
 const exec=new ExecAdapter({resolve:async(id,who)=>{
  assert.equal(who,owner);assert.ok(id===undefined||id==='pilot');
  return {id:'pilot',generation:'exec-1',runtime,cwd:root,platform:'linux',shell:'/bin/sh',shells:['/bin/sh'],env:{PATH:'/usr/bin:/bin'}};
 }});
 let value='initial',snap=0,mutationCount=0;
 const gui=new GuiBroker({resolve:async(id,who)=>{
  assert.equal(who,owner);assert.ok(id===undefined||id==='pilot');
  return {id:'pilot',host:'pilot',osUser:'fixture-user',sessionGeneration:'login',appGeneration:'app',runtimeGeneration:'cua',ready:true};
 },verifyTarget:async()=>({generation:'fixture-process'}),connect:async()=>{
  const client={closed:false,onClose(fn){this.notify=fn;},async close(){this.closed=true;this.notify?.();},
   async call(name,args){
    if(name==='get_window_state')return {structuredContent:{pid:12,window_id:34,snapshot_id:'s'+(++snap),elements_complete:false,
     elements:[{element_token:'s'+snap+':0',role:'AXTextField',value}]}};
    mutationCount++;value=args.value;return {structuredContent:{effect:'confirmed',evidence:[{kind:'value_readback'}],route:'accessibility'}};
   }};return client;
 }});
 const server=createUnifiedServer({exec,gui,owner});
 const client=new Client({name:'test',version:'0'}),[ct,st]=InMemoryTransport.createLinkedPair();
 await server.connect(st);await client.connect(ct);
 t.after(async()=>{await client.close();await server.close();await gui.close();assert.ok((await exec.cleanup()).every(x=>x.confirmed));await runtime.close();await rm(root,{recursive:true,force:true});});
 const tools=await client.listTools();assert.deepEqual(tools.tools.map(x=>x.name),['exec_command','write_stdin','get_window_state','click','set_value']);
 const initial=await client.callTool({name:'exec_command',arguments:{cmd:'read line; printf "shell:%s" "$line"',environment_id:'pilot',yield_time_ms:0,login:false}});
 const session=initial.structuredContent.session_id;assert.ok(session);
 const observed=await client.callTool({name:'get_window_state',arguments:{environment_id:'pilot',pid:12,window_id:34}});
 const old=observed.structuredContent.elements[0].element_token;
 await gui.reconnect('pilot',owner);
 const refused=await client.callTool({name:'set_value',arguments:{element_token:old,value:'wrong'}});
 assert.equal(refused.isError,true);assert.equal(mutationCount,0);
 const fresh=await client.callTool({name:'get_window_state',arguments:{environment_id:'pilot',pid:12,window_id:34}});
 const changed=await client.callTool({name:'set_value',arguments:{element_token:fresh.structuredContent.elements[0].element_token,value:'GUI验证'}});
 assert.equal(changed.structuredContent.effect,'confirmed');
 const readback=await client.callTool({name:'get_window_state',arguments:{pid:12,window_id:34}});
 assert.equal(readback.structuredContent.elements[0].value,'GUI验证');assert.equal(mutationCount,1);
 let result=await client.callTool({name:'write_stdin',arguments:{session_id:session,chars:'unaffected\n',yield_time_ms:250}});
 let output=result.structuredContent.output;
 for(let i=0;result.structuredContent.session_id&&i<10;i++){
  result=await client.callTool({name:'write_stdin',arguments:{session_id:session,yield_time_ms:250}});
  output+=result.structuredContent.output;
 }
 assert.equal(result.structuredContent.exit_code,0);assert.equal(output,'shell:unaffected');
});
