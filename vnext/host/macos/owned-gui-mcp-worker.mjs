// Official MCP SDK transport to an existing embedded Styx socket only.
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {createInterface} from 'node:readline';
const client=new Client({name:'styx-owned-macos-gui',version:'0.1.0'});
const transport=new StdioClientTransport({command:'/Applications/Styx.app/Contents/MacOS/cua-driver',
  args:['mcp','--socket',process.argv[2]],stderr:'ignore'});
try{
  await client.connect(transport);
  for await(const line of createInterface({input:process.stdin})){
    const req=JSON.parse(line);
    try{const result=await client.callTool({name:req.name,arguments:req.arguments});
      process.stdout.write(JSON.stringify({result})+'\n');}
    catch{process.stdout.write(JSON.stringify({error:'native_mcp_request_failed'})+'\n');}
  }
}finally{await client.close();}
