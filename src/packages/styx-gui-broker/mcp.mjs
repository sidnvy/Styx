import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {ListToolsRequestSchema,CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {tools as execTools} from '../styx-exec-adapter/schema.mjs';
const string={type:'string'},number={type:'number'};
export const guiTools=[
 {name:'get_window_state',description:'Observe an admitted exact window and issue scoped element references.',
 inputSchema:{type:'object',additionalProperties:false,required:['pid','window_id'],properties:{
 environment_id:string,pid:number,window_id:number,include_screenshot:{type:'boolean'},tree_format:{type:'string',enum:['elements']}}}},
 {name:'click',description:'Dispatch one observed element action; effect and verification remain separate.',
 inputSchema:{type:'object',additionalProperties:false,required:['element_token'],properties:{element_token:string}}},
 {name:'set_value',description:'Set an observed element value; preserve native effect evidence.',
 inputSchema:{type:'object',additionalProperties:false,required:['element_token','value'],properties:{element_token:string,value:string}}}
];
export function createUnifiedServer({exec,gui,owner}) {
 if(typeof owner!=='string'||!owner)throw TypeError('Authenticated principal and conversation required');
 const server=new Server({name:'styx-isolated-broker',version:'0.0.0'},{capabilities:{tools:{}}});
 server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:[...execTools,...guiTools]}));
 server.setRequestHandler(CallToolRequestSchema,async req=>{
  const {name,arguments:args={}}=req.params;
  return (execTools.some(t=>t.name===name)?exec:gui).callTool(name,args,owner);
 });
 return server;
}
