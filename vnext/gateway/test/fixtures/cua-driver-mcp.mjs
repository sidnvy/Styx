#!/usr/bin/env node
// Test-only MCP stdio server; simulates the public Cua MCP protocol, not GUI.
import readline from 'node:readline';
import {randomUUID} from 'node:crypto';

const lease=randomUUID();
const tools=[
  {name:'list_apps',description:'read-only synthetic app fixture',
    inputSchema:{type:'object',properties:{session:{type:'string'}},additionalProperties:false}},
  {name:'click',description:'synthetic acknowledged action',
    inputSchema:{type:'object',properties:{element_token:{type:'string'},session:{type:'string'}},
      additionalProperties:false}}
];
const input=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
function send(message){process.stdout.write(JSON.stringify({jsonrpc:'2.0',...message})+'\n')}
input.on('line',line=>{
  let r;
  try{r=JSON.parse(line)}catch{return}
  if(!r || typeof r!=='object' || r.id===undefined)return;
  if(r.method==='initialize') {
    send({id:r.id,result:{protocolVersion:'2025-06-18',capabilities:{tools:{}},
      serverInfo:{name:'cua-driver',version:'0.36.0'}}});return;
  }
  if(r.method==='tools/list') {send({id:r.id,result:{tools}});return}
  if(r.method==='tools/call') {
    const {name,arguments:args={}}=r.params||{};
    if(name==='click' && args.element_token==='simulate-unknown')return;
    if(name==='list_apps' || name==='click') {
      const result={lease,name,args};
      send({id:r.id,result:{isError:false,structuredContent:result,
        content:[{type:'text',text:JSON.stringify(result)}]}});
      return;
    }
  }
  send({id:r.id,error:{code:-32601,message:'unsupported fixture method'}});
});
