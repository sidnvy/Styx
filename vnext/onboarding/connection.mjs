// Owner-side transport verification. Never establishes account-side acceptance.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import {Readable} from 'node:stream';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {requirePrivateFile} from '../host/private-storage.mjs';

const required=['list_execution_environments','get_execution_environment_status','exec_command','write_stdin'];
function secureEndpoint(value) {
  const u=new URL(value);
  if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error('invalid_gateway_endpoint');
  return u;
}
// A TLS-verifying streaming Fetch adapter supports private Gateway CAs without
// changing process-wide trust. Never follows redirects or forwards bearer elsewhere.
export function gatewayFetch(endpoint,{ca}={}) {
  const expected=secureEndpoint(endpoint);
  return async (input,init={})=>{
    const u=secureEndpoint(input instanceof Request?input.url:String(input));
    if(u.href!==expected.href)throw Error('gateway_endpoint_changed');
    if(input instanceof Request)throw Error('request_object_not_supported');
    if(init.body!=null&&typeof init.body!=='string'&&!(init.body instanceof Uint8Array))throw Error('unsupported_request_body');
    return new Promise((resolve,reject)=>{
      const req=https.request(u,{method:init.method??'GET',headers:Object.fromEntries(new Headers(init.headers)),
        ca,rejectUnauthorized:true,signal:init.signal},res=>{
        if(res.statusCode>=300&&res.statusCode<400){res.resume();reject(Error('gateway_redirect_refused'));return;}
        const headers=new Headers();for(const [k,v] of Object.entries(res.headers))if(v!==undefined)headers.set(k,Array.isArray(v)?v.join(', '):v);
        const body=[204,205,304].includes(res.statusCode)?null:Readable.toWeb(res);
        if(body===null)res.resume();
        resolve(new Response(body,{status:res.statusCode,headers}));
      });
      req.setTimeout(10000,()=>req.destroy(Error('gateway_request_timeout')));
      req.on('error',reject);req.end(init.body);
    });
  };
}
export async function verifyGatewayConnection(config) {
  if(!config||Object.keys(config).some(k=>!['url','tokenFile','caFile','independentStyx','freshConnection'].includes(k)))throw Error('invalid_connection_config');
  const endpoint=secureEndpoint(config.url);
  if(config.independentStyx!==true||config.freshConnection!==true)throw Error('owner_connection_attestation_required');
  requirePrivateFile(config.tokenFile);
  const token=fs.readFileSync(config.tokenFile,'utf8').trim();
  if(token.length<32||/\s/.test(token))throw Error('invalid_model_credential');
  let ca;
  if(config.caFile!==undefined){
    if(!path.isAbsolute(config.caFile))throw Error('absolute_ca_file_required');
    const st=fs.lstatSync(config.caFile);if(!st.isFile()||st.isSymbolicLink()||st.size>1024*1024)throw Error('invalid_ca_file');
    ca=fs.readFileSync(config.caFile);
  }
  const client=new Client({name:'styx-onboarding-verifier',version:'0.1.0'});
  const transport=new StreamableHTTPClientTransport(endpoint,{
    requestInit:{headers:{Authorization:'Bearer '+token}},fetch:gatewayFetch(endpoint.href,{ca}),reconnectionOptions:{maxRetries:0}
  });
  try {
    await client.connect(transport,{timeout:10000});
    const server=client.getServerVersion();
    if(server?.name!=='styx-vnext')throw Error('wrong_gateway_identity');
    const names=[];let cursor;
    for(let page=0;page<10;page++){
      const result=await client.listTools(cursor?{cursor}:{},{timeout:10000});
      names.push(...result.tools.map(x=>x.name));cursor=result.nextCursor;if(!cursor)break;
    }
    if(cursor||new Set(names).size!==names.length||required.some(n=>!names.includes(n))||names.some(n=>/^(env_|project_|service_|cas_)/.test(n)))throw Error('wrong_gateway_contract');
    return {scope:'sdk_gateway',account_acceptance:'NOT RUN',status:'gateway_verified',
      receipt:{version:1,connection:{url:endpoint.href},independentStyx:true,freshConnection:true,
        verifiedAt:new Date().toISOString(),serverName:server.name,tools:names,method:'authenticated-mcp-discovery'}};
  }catch{
    // SDK/server errors may include response text. Never surface it to chat/UI.
    throw Error('gateway_verification_failed');
  }finally{
    try{await transport.terminateSession();}catch{}
    try{await client.close();}catch{}
  }
}
