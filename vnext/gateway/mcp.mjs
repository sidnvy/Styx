import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {ListToolsRequestSchema, CallToolRequestSchema,
  ListResourcesRequestSchema, ReadResourceRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {tools as execTools} from '../packages/styx-exec-adapter/schema.mjs';
import {guiTools} from '../packages/styx-gui-broker/mcp.mjs';
import {CAS_TOOLS, CAS_APP_URI, casCall, casResourceList, casResourceRead} from './cas/mcp.mjs';

const targetsTool = {
  name: 'list_execution_environments',
  description: 'List allowed execution contexts and their available capabilities.',
  inputSchema: {type: 'object', properties: {}, additionalProperties: false},
  annotations: {readOnlyHint: true, destructiveHint: false, idempotentHint: true}
};

export function createGatewayMcp({exec, computer, gui, registry, owner, cas = null, casOnly = false}) {
  if (typeof owner !== 'string' || !owner) throw new TypeError('Authenticated session required');
  if (casOnly && !cas) throw Error('cas_lab_requires_explicit_experiment_ledger');
  const server = new Server({name: 'styx-vnext', version: '0.1.0'},
    {capabilities: {tools: {}, ...(cas ? {resources: {}} : {})}});
  const computerAllowed=()=>registry.list().some(t=>t.capabilities.includes('computer'));
  async function definitions() {
    if (casOnly) return CAS_TOOLS;
    const computerTools = computer && computerAllowed()
      ? await computer.listTools() : [];
    return [...execTools, ...computerTools,
      ...(gui && !computer && computerAllowed() ? guiTools : []),
      ...(cas ? CAS_TOOLS : []), targetsTool];
  }
  if (cas) {
    server.setRequestHandler(ListResourcesRequestSchema, async () => casResourceList());
    server.setRequestHandler(ReadResourceRequestSchema, async ({params}) => {
      if (params.uri !== CAS_APP_URI) throw Error('Unknown CAS resource');
      return casResourceRead(params.uri);
    });
  }
  server.setRequestHandler(ListToolsRequestSchema, async () => ({tools: await definitions()}));
  server.setRequestHandler(CallToolRequestSchema, async ({params}) => {
    const {name, arguments: args = {}} = params;
    if (cas && CAS_TOOLS.some(tool => tool.name === name))
      return casCall(cas, name, args);
    // Lab-only credentials must never unlock production Exec or native Cua.
    if (casOnly) return {isError: true, content: [{type: 'text', text: 'unknown_tool'}]};
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
