// External Browser executor only. The Rust Host owns all authorization, owner /
// profile binding, URL/ref policy, request serialization and Unknown history.
import { pathToFileURL } from 'node:url';
import { createConnection } from '@playwright/mcp';
import { chromium } from 'playwright';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { CallToolRequestSchema, ListToolsRequestSchema, ListRootsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { readConfiguration } from './config.mjs';

// Hints are coalesced/dropped under pressure; they are not an audit authority.
let factBytesRemaining = 64 * 1024, factsBlocked = false;
function fact(event) {
  if (factsBlocked) return;
  const line = `${JSON.stringify({ schema: 1, event, headless: true })}\n`;
  const bytes = Buffer.byteLength(line);
  if (bytes > factBytesRemaining) return;
  factBytesRemaining -= bytes;
  if (!process.stderr.write(line)) {
    factsBlocked = true;
    process.stderr.once('drain', () => { factsBlocked = false; });
  }
}
const NATIVE_META = 'app.styx/browser-native';
const STATE_TOOL = 'styx_browser_state';
const stateTool = {
  name: STATE_TOOL,
  description: 'Read factual native Browser epoch/state without launching a context.',
  inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};
let macProcess, macProcessClose;
let nativeEpoch = 1, nativeClosed = false, epochExhausted = false;
let contextPromise, context, backend, client, server, startupPromise, closing = false, cleanupPromise;
// Fixed Playwright 1.64 adapter only: reuse its existing in-process bridge,
// never a new BrowserServer/listener or a process selected by remote input.
function retainMacBrowserProcess(value, executable) {
  if (process.platform !== 'darwin') return;
  const implementation = value?._connection?.toImpl?.(value);
  const child = implementation?._browser?.options?.browserProcess?.process;
  if (!child || !Number.isInteger(child.pid) || child.pid <= 0 || child.pid > 0x7fffffff
      || child.spawnfile !== executable || child.exitCode !== null || child.signalCode !== null
      || macProcess) throw new Error('browser_original_process_unconfirmed');
  macProcess = { schema: 1, pid: child.pid, original_child_closed: false };
  // The closure retains the original ChildProcess until its actual close event;
  // it is not inferred from a later PID census or an MCP close acknowledgement.
  macProcessClose = new Promise(resolve => child.once('close', () => {
    macProcess.original_child_closed = true;
    resolve();
  }));
}
function advanceEpoch() {
  if (epochExhausted) return false;
  if (nativeEpoch === Number.MAX_SAFE_INTEGER) {
    epochExhausted = true;
    closing = true;
    fail();
    return false;
  }
  nativeEpoch += 1;
  return true;
}
function withNativeMeta(result, before, dispatched, reason) {
  const factual = { schema: 1, before, after: nativeEpoch, dispatched };
  if (reason) factual.reason = reason;
  return { ...result, _meta: { ...result._meta, [NATIVE_META]: factual } };
}
function refused(reason) {
  return withNativeMeta({ isError: true, content: [{ type: 'text', text: `browser_native_${reason}` }] }, nativeEpoch, false, reason);
}
function expectedEpoch(params) {
  if (!Object.hasOwn(params._meta ?? {}, NATIVE_META)) return undefined;
  const expected = params._meta[NATIVE_META];
  if (!expected || typeof expected !== 'object' || Array.isArray(expected)
      || Object.keys(expected).length !== 2 || !Object.hasOwn(expected, 'schema') || expected.schema !== 1
      || !Object.hasOwn(expected, 'expected_epoch')
      || !Number.isSafeInteger(expected.expected_epoch) || expected.expected_epoch < 1) return null;
  return expected.expected_epoch;
}
async function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  closing = true;
  cleanupPromise = (async () => {
    await startupPromise?.catch(() => {});
    await contextPromise?.catch(() => {});
    await context?.close();
    await macProcessClose;
    await client?.close();
    await backend?.close();
    await server?.close();
  })();
  return cleanupPromise;
}
function fail() {
  process.exitCode = 2;
  fact('browser_worker_failed');
  void cleanup().catch(() => { process.exitCode = 2; fact('browser_worker_cleanup_unconfirmed'); });
}
async function main() {
  if (process.versions.node.split('.')[0] !== '22' || process.argv.length !== 4 || process.argv[2] !== '--config') throw new Error('browser_worker_start_rejected');
  const config = readConfiguration(process.argv[3]);
  // No browser download, headed mode, debug takeover, or arbitrary launch args.
  delete process.env.PWDEBUG;
  process.env.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = '1';
  const getOwnedContext = () => {
    if (closing) throw new Error('browser_worker_closing');
    // Cache the one launch promise even after closure/failure. No action, launch
    // or context recovery is replayed after transport errors or browser_close.
    contextPromise ??= chromium.launchPersistentContext(config.profile_dir, {
      headless: true, chromiumSandbox: true, executablePath: config.browser_executable,
      // Headless Chrome has no desktop-portal/session-bus responsibility. Recent
      // Chromium can ask the user manager to move its main PID to another scope,
      // outside the Rust-owned resource/cleanup boundary. Keep the supervisor's
      // real bus, but give only this native child an explicit non-socket address.
      // An absent address could trigger libdbus auto-discovery instead.
      ...(process.platform === 'linux' ? {
        env: { ...process.env, DBUS_SESSION_BUS_ADDRESS: 'unix:path=/dev/null' },
      } : {}),
      acceptDownloads: true, downloadsPath: config.output_dir,
      viewport: { width: 1280, height: 800 },
    }).then(async value => {
      context = value;
      retainMacBrowserProcess(value, config.browser_executable);
      if (closing) { await value.close(); throw new Error('browser_worker_closing'); }
      const pageObserved = page => {
        advanceEpoch();
        fact('browser_native_page');
        page.on('framenavigated', () => { advanceEpoch(); fact('browser_native_navigation'); });
        page.once('close', () => { advanceEpoch(); fact('browser_native_page_closed'); });
      };
      for (const page of value.pages()) pageObserved(page);
      value.on('page', pageObserved);
      value.once('close', () => {
        nativeClosed = true;
        advanceEpoch();
        fact('browser_native_context_closed');
      });
      fact('browser_native_context_open');
      return value;
    });
    return contextPromise;
  };
  backend = await createConnection({
    browser: { browserName: 'chromium', isolated: false },
    capabilities: ['core'], webmcp: false, outputDir: config.output_dir,
    filePaths: 'absolute', snapshot: { mode: 'none' }, imageResponses: 'allow',
    timeouts: { idle: 0 },
  }, getOwnedContext);
  client = new Client({ name: 'styx-browser-native-backend', version: '0.1.0' }, { capabilities: { roots: { listChanged: false } } });
  client.setRequestHandler(ListRootsRequestSchema, async () => ({ roots: [
    { uri: pathToFileURL(config.workspace_dir).href, name: 'workspace' },
    { uri: pathToFileURL(config.output_dir).href, name: 'browser-output' },
  ] }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await backend.connect(a);
  await client.connect(b);
  server = new Server({ name: 'styx-browser-native-worker', version: '0.2.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const listed = await client.listTools();
    return { ...listed, tools: [...listed.tools, stateTool] };
  });
  server.setRequestHandler(CallToolRequestSchema, async ({ params }, extra) => {
    const expected = expectedEpoch(params);
    if (expected === null) return refused('invalid');
    if (params.name === STATE_TOOL) {
      if (Object.keys(params.arguments ?? {}).length !== 0) return refused('invalid');
      // Read-only factual query: no context getter, backend RPC or policy.
      return withNativeMeta({ content: [], structuredContent: {
        schema: 1, epoch: nativeEpoch,
        ready: !!context && !nativeClosed && !closing && !epochExhausted,
        closed: nativeClosed || epochExhausted,
        ...(process.platform === 'darwin' ? { mac_process: macProcess ?? null } : {}),
      } }, nativeEpoch, false);
    }
    // Reject known-invalid/stale calls before any avoidable native launch.
    if (closing || nativeClosed || epochExhausted
        || (expected !== undefined && expected !== nativeEpoch)) return refused('stale');
    // Use the exact same cached promise as upstream's context getter. Record
    // before only after its initial page/lifecycle observations are installed;
    // never retry a tool/snapshot or create a replacement context on failure.
    try { await getOwnedContext(); }
    catch { throw new Error('browser_native_context_unconfirmed'); }
    // Initialization can change the factual epoch or close the context. This
    // final guard and backend invocation have no intervening await.
    if (closing || nativeClosed || epochExhausted
        || (expected !== undefined && expected !== nativeEpoch)) return refused('stale');
    const before = nativeEpoch;
    if (params.name === 'browser_tabs'
        && ['new', 'close', 'select'].includes(params.arguments?.action)
        && !advanceEpoch()) return refused('stale');
    let result;
    try {
      result = await client.callTool({ name: params.name, arguments: params.arguments ?? {} }, undefined, { signal: extra.signal });
      if (params.name === 'browser_close') {
        // Context closure is not Node exit/physical process-tree cleanup.
        closing = true;
        const ownedContext = await contextPromise;
        if (!ownedContext) throw new Error('browser_worker_close_unconfirmed');
        await ownedContext.close();
        await macProcessClose;
        result = { ...result, structuredContent: { ...result.structuredContent, styx_context_closed: true } };
      }
    } catch {
      // Bytes may already have reached the native backend: never call this
      // NotSent, replay it, or disclose upstream exception/private arguments.
      result = { isError: true, content: [{ type: 'text', text: 'browser_native_result_unconfirmed' }] };
    }
    // Upstream cannot spoof this wrapper's dispatch/epoch facts.
    return withNativeMeta(result, before, true);
  });
  server.onclose = () => { void cleanup().catch(fail); };
  server.onerror = fail;
  await server.connect(new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 256 * 1024 }));
}
process.stdin.once('end', () => { void cleanup().catch(fail); });
process.stdin.once('error', fail);
process.once('SIGTERM', () => { void cleanup().catch(fail); });
process.once('SIGINT', () => { void cleanup().catch(fail); });
startupPromise = main();
startupPromise.catch(fail);
