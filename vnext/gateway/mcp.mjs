import {Server} from '@modelcontextprotocol/sdk/server/index.js';
import {randomUUID} from 'node:crypto';
import {ListToolsRequestSchema, CallToolRequestSchema,
  ListResourcesRequestSchema, ReadResourceRequestSchema} from '@modelcontextprotocol/sdk/types.js';
import {tools as execTools} from '../packages/styx-exec-adapter/schema.mjs';
import {guiTools} from '../packages/styx-gui-broker/mcp.mjs';
import {CAS_TOOLS, CAS_APP_URI, casCall, casResourceList, casResourceRead} from './cas/mcp.mjs';

const EXEC_ROUTING_GUIDANCE = 'Default to exec_command for Git/GitHub clone, downloads (curl/wget), file operations, builds, tests and other CLI/development work. Interactive foreground or TTY sessions managed by exec_command/write_stdin are Exec sessions. Do not open Terminal or another desktop terminal through Spotlight, launchers or computer tools to paste these commands. If Exec fails, is disconnected, or reports authentication, permission or sandbox errors, check get_execution_environment_status, resolve the specific Exec issue or report the blocker; never use a desktop terminal to bypass it.';
const COMPUTER_ROUTING_GUIDANCE = 'Use Styx computer tools when GUI observation/interaction is necessary or the user explicitly requests a GUI workflow. Git/GitHub clone, downloads, file operations, builds, tests and CLI work default to exec_command, including foreground/TTY sessions. Do not open Terminal through Spotlight or another launcher to paste commands, including as a fallback for Exec failure, authentication, sandbox restrictions or disconnection; check get_execution_environment_status and recover the Exec connection or report the blocker. For genuine GUI tasks observe first and act with fresh references; after a desktop error refresh stale observations or report the missing permission/connection, not osascript/System Events or shell-driven input.';
export const DESKTOP_ROUTING_INSTRUCTIONS = `${EXEC_ROUTING_GUIDANCE} For genuine GUI tasks, use Styx computer tools first: discover apps/windows, observe with get_window_state or get_desktop_state, then act using fresh references. Use the app bundle identifier or observed PID when localized app names do not match. An explicitly requested GUI workflow may use computer tools; this does not authorize bypassing an Exec restriction. Do not replace desktop tools with osascript, AppleScript/System Events, JXA or shell-driven input automation, including when a computer tool fails. Those paths have separate macOS permissions and can expose a node authorization prompt. For computer_snapshot_required or stale element references, observe again and use the new references; never reuse another conversation's references. For a permission or connection error, check get_execution_environment_status and report the specific missing permission or connection. Do not reset permissions or request additional Node/System Events access as a desktop fallback. Only use application scripting when the user explicitly requests that scripting workflow, explain its separate Automation permission before the first invocation, and let the user grant it through macOS. Styx desktop permission does not authorize that separate path.`;
const guidedExecTools = execTools.map(tool => ({...tool, description: tool.description +
  ' ' + EXEC_ROUTING_GUIDANCE + ' For GUI reading or interaction use Styx computer tools, not osascript/System Events or shell-driven input. Do not fall back to scripting after a desktop error; refresh stale observations or report the missing permission. Explicit user-requested application scripting needs separate macOS Automation consent.'}));
const guideComputerTools = tools => tools.map(tool => ({...tool,
  description: (tool.description ? tool.description + ' ' : '') + COMPUTER_ROUTING_GUIDANCE}));

const targetsTool = {
  name: 'list_execution_environments',
  description: 'List allowed execution contexts and their available capabilities.',
  inputSchema: {type: 'object', properties: {}, additionalProperties: false},
  annotations: {readOnlyHint: true, destructiveHint: false, idempotentHint: true}
};

const statusTool = {
  name: 'get_execution_environment_status',
  description: 'Read an explicitly selected allowed environment status without connecting or running native tools. Connection does not imply permission or readiness.',
  inputSchema: {type: 'object', properties: {environment_id: {type: 'string', minLength: 1}},
    required: ['environment_id'], additionalProperties: false},
  annotations: {readOnlyHint: true, destructiveHint: false, idempotentHint: true}
};

export function createGatewayMcp({exec, computer, gui, registry, owner, relay = null, cas = null, casOnly = false, onToolResult = null}) {
  if (typeof owner !== 'string' || !owner) throw new TypeError('Authenticated session required');
  if (casOnly && !cas) throw Error('cas_lab_requires_explicit_experiment_ledger');
  const server = new Server({name: 'styx-vnext', version: '0.1.0'},
    {capabilities: {tools: {}, ...(cas ? {resources: {}} : {})},
      instructions: DESKTOP_ROUTING_INSTRUCTIONS});
  const computerAllowed=()=>registry.list().some(t=>t.capabilities.includes('computer'));
  async function definitions() {
    if (casOnly) return CAS_TOOLS;
    const computerTools = computer && computerAllowed()
      ? await computer.listTools() : [];
    return [...guidedExecTools, ...guideComputerTools(computerTools),
      ...(gui && !computer && computerAllowed() ? guideComputerTools(guiTools) : []),
      ...(cas ? CAS_TOOLS : []), targetsTool, statusTool];
  }
  if (cas) {
    server.setRequestHandler(ListResourcesRequestSchema, async () => casResourceList());
    server.setRequestHandler(ReadResourceRequestSchema, async ({params}) => {
      if (params.uri !== CAS_APP_URI) throw Error('Unknown CAS resource');
      return casResourceRead(params.uri);
    });
  }
  server.setRequestHandler(ListToolsRequestSchema, async () => ({tools: await definitions()}));
  async function observed(name,args,operation){
    let target=null;
    try{const execution=name==='write_stdin'?exec.sessions?.get(args.session_id):null;target=registry.resolve(execution?.environment??args.environment_id);}catch{}
    const operationId=randomUUID();
    if(target&&typeof onToolResult?.before==='function')try{await onToolResult.before({name,args,owner,target,operationId})}catch{}
    const result=await operation();
    if(onToolResult&&target)try{const current=registry.resolve(target.id);if(current.generation===target.generation)await onToolResult({name,args,result,owner,target:current,operationId});}catch{/* Observation never changes/replays an executed request. */}
    return result;
  }

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
    if (name === statusTool.name) {
      if (!args || typeof args !== 'object' || Array.isArray(args) ||
          Object.keys(args).length !== 1 || typeof args.environment_id !== 'string' ||
          !args.environment_id.length)
        return {isError: true, content: [{type: 'text', text: 'invalid_arguments'}]};
      let target;
      try { target = registry.resolve(args.environment_id); }
      catch { return {isError: true, content: [{type: 'text', text: 'environment_unavailable'}]}; }
      const connection = relay?.status(target) ?? {exec: 'unknown', computer: 'unknown'};
      const result = {
        environment_id: target.id, kind: target.kind, platform: target.platform,
        access: 'allowed',
        exec: {configured: true, connection: connection.exec,
          readiness: 'unknown', version: 'unknown'},
        computer: {configured: target.computer?.enabled === true,
          connection: target.computer?.enabled ? connection.computer : 'not_configured',
          permission: 'unknown', readiness: 'unknown', version: 'unknown'}
      };
      return {structuredContent: result, content: [{type: 'text', text: JSON.stringify(result)}]};
    }
    if (execTools.some(t => t.name === name)) return observed(name,args,()=>exec.callTool(name, args, owner));
    if (computer && computerAllowed() &&
      (await computer.listTools()).some(t => t.name === name)) {
      return observed(name,args,()=>computer.callTool(name,args,owner));
    }
    if (gui && !computer && computerAllowed() && guiTools.some(t => t.name === name)) {
      return gui.callTool(name, args, owner);
    }
    return {isError: true, content: [{type: 'text', text: 'unknown_tool'}]};
  });
  return server;
}
