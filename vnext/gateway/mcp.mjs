import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {ListToolsRequestSchema, CallToolRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {tools as execTools} from '../packages/styx-exec-adapter/schema.mjs';
import {guiTools} from '../packages/styx-gui-broker/mcp.mjs';

const targetsTool = {
  name: 'list_execution_environments',
  description: 'List allowed execution contexts and their available capabilities.',
  inputSchema: {type: 'object', properties: {}, additionalProperties: false},
  annotations: {readOnlyHint: true, destructiveHint: false, idempotentHint: true}
};

export function createGatewayMcp({exec, computer, gui, registry, owner}) {
  if (typeof owner !== 'string' || !owner) throw new TypeError('Authenticated session required');
  const server = new Server({name: 'styx-vnext', version: '0.1.0'}, {capabilities: {tools: {}}});
  const computerAllowed=()=>registry.list().some(t=>t.capabilities.includes('computer'));
  async function definitions() {
    const computerTools = computer && computerAllowed()
      ? await computer.listTools() : [];
    return [...execTools, ...computerTools,
      ...(gui && !computer && computerAllowed() ? guiTools : []), targetsTool];
  }
  server.setRequestHandler(ListToolsRequestSchema, async () => ({tools: await definitions()}));
  server.setRequestHandler(CallToolRequestSchema, async ({params}) => {
    const {name, arguments: args = {}} = params;
    if (name === targetsTool.name) {
      if (Object.keys(args).length) {
        return {isError: true, content: [{type: 'text', text: 'invalid_arguments'}]};
      }
      const result = {environments: registry.list()};
      return {structuredContent: result, content: [{type: 'text', text: JSON.stringify(result)}]};
    }
    if (execTools.some(t => t.name === name)) return exec.callTool(name, args, owner);
    if (computer && computerAllowed() &&
      (await computer.listTools()).some(t => t.name === name)) {
      return computer.callTool(name,args,owner);
    }
    if (gui && !computer && computerAllowed() && guiTools.some(t => t.name === name)) {
      return gui.callTool(name, args, owner);
    }
    return {isError: true, content: [{type: 'text', text: 'unknown_tool'}]};
  });
  return server;
}
