// Actual official legacy MCP client; a private token file is read only here.
// JSON-lines control is an acceptance harness, not another product protocol.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import readline from 'node:readline';
const [legacyRoot,endpoint,tokenFile] = process.argv.slice(2);
const sdk=path.join(legacyRoot,'node_modules/@modelcontextprotocol/sdk/dist/esm');
const {Client}=await import(pathToFileURL(path.join(sdk,'client/index.js')));
const {StreamableHTTPClientTransport}=await import(pathToFileURL(path.join(sdk,'client/streamableHttp.js')));
const info=fs.lstatSync(tokenFile);
if(!info.isFile()||info.isSymbolicLink()||info.nlink!==1||(info.mode&0o077)!==0)throw Error('private token required');
const token=fs.readFileSync(tokenFile,'utf8').trim();
const clients=new Map();
function emit(value){process.stdout.write(JSON.stringify(value)+'\n')}
for await(const line of readline.createInterface({input:process.stdin,crlfDelay:Infinity})) {
 let request;
 try {
  request=JSON.parse(line);
  const {id,operation,owner}=request;
  if(operation==='open'){
   if(clients.has(owner))throw Error('duplicate owner');
   const client=new Client({name:'styx-legacy-interop-owned',version:'1.0.0'},{capabilities:{}});
   const transport=new StreamableHTTPClientTransport(new URL(endpoint),{requestInit:{headers:{Authorization:'Bearer '+token}}});
   await client.connect(transport);clients.set(owner,{client,transport});emit({id,ok:true,data:{connected:true}});
  }else if(operation==='list'){
   emit({id,ok:true,data:await clients.get(owner).client.listTools()});
  }else if(operation==='call'){
   emit({id,ok:true,data:await clients.get(owner).client.callTool({name:request.name,arguments:request.arguments??{}})});
  }else if(operation==='close'){
   const current=clients.get(owner);if(!current)throw Error('unknown owner');
   await current.transport.terminateSession();await current.client.close();clients.delete(owner);
   emit({id,ok:true,data:{closed:true}});
  }else if(operation==='stop'){
   for(const {client,transport} of clients.values()){await transport.terminateSession().catch(()=>{});await client.close().catch(()=>{})}
   clients.clear();emit({id,ok:true,data:{stopped:true}});break;
  }else throw Error('unsupported harness operation');
 }catch{
  // Never print upstream request headers, raw errors, credentials or payloads.
  emit({id:request?.id??null,ok:false,error:'client_operation_failed'});
 }
}
