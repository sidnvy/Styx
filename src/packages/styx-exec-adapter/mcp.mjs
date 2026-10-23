import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {ListToolsRequestSchema, CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {tools} from './schema.mjs';

// The gateway supplies principal+conversation identity out of band.
// No network listener, account discovery, model API or second reasoning loop.
export function createMcpServer(adapter, owner) {
  if (typeof owner !== 'string' || !owner) throw new TypeError('Authenticated owner required');
  const server = new Server({name: 'styx-exec-adapter-prototype', version: '0.0.0'},
    {capabilities: {tools: {}}});
  server.setRequestHandler(ListToolsRequestSchema, async () => ({tools}));
  server.setRequestHandler(CallToolRequestSchema, async request =>
    adapter.callTool(request.params.name, request.params.arguments ?? {}, owner));
  return server;
}
