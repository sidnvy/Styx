// External Browser executor only. The Rust Host owns all authorization, owner /
// extension-bridge binding, URL/ref policy, request serialization and Unknown history.
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
  const line = `${JSON.stringify({ schema: 1, event, headless: false })}\n`;
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
let nativeEpoch = 1, nativeClosed = false, epochExhausted = false;
let closeRequestId;
let attachedBrowser;
let contextPromise, context, backend, client, server, startupPromise, closing = false, cleanupPromise;
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
async function closeCdpAttachment() {
  const browser = attachedBrowser;
  attachedBrowser = undefined;
  context = undefined;
  if (browser) await browser.close();
}
async function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  closing = true;
  cleanupPromise = (async () => {
    await startupPromise?.catch(() => {});
    await contextPromise?.catch(() => {});
    await closeCdpAttachment().catch(() => {});
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
  // Use the Host-owned Extension Bridge WS endpoint; no debug takeover or download.
  delete process.env.PWDEBUG;
  process.env.PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = '1';
  const observeContext = (value, browser) => {
    const pageObserved = page => {
      advanceEpoch();
      fact('browser_native_page');
      page.on('framenavigated', frame => {
        if (frame === page.mainFrame()) {
          advanceEpoch();
          fact('browser_native_navigation');
        }
      });
      page.once('close', () => {
        advanceEpoch();
        fact('browser_native_page_closed');
      });
    };
    for (const page of value.pages()) pageObserved(page);
    value.on('page', pageObserved);
    let closedFactEmitted = false;
    const onClosed = () => {
      nativeClosed = true;
      advanceEpoch();
      if (!closedFactEmitted) {
        closedFactEmitted = true;
        fact('browser_native_context_closed');
      }
      if (!closing && closeRequestId === undefined) fail();
    };
    value.once('close', onClosed);
    browser?.once('disconnected', onClosed);
  };
  const getOwnedContext = () => {
    if (closing) throw new Error('browser_worker_closing');
    // Extension-Bridge mode resets pre-attach connection failures so retries stay NotDispatched.
    contextPromise ??= chromium.connectOverCDP(config.cdp_endpoint, {
      noDefaults: true,
      timeout: 25000,
    }).then(async browser => {
      const value = browser.contexts()[0];
      if (!value) {
        await browser.close().catch(() => {});
        throw new Error('browser_cdp_unavailable');
      }
      attachedBrowser = browser;
      context = value;
      if (closing) {
        await closeCdpAttachment();
        throw new Error('browser_worker_closing');
      }
      observeContext(value, browser);
      fact('browser_native_context_open');
      return value;
    }, err => {
      if (!attachedBrowser && !closing) contextPromise = undefined;
      const wrapped = new Error('browser_cdp_unavailable');
      wrapped.cause = err;
      throw wrapped;
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
      } }, nativeEpoch, false);
    }
    // Reject known-invalid/stale calls before any avoidable attach.
    if (closing || nativeClosed || epochExhausted
        || (expected !== undefined && expected !== nativeEpoch)) return refused('stale');
    // Use the exact same cached promise as upstream's context getter. Record
    // before only after its initial page/lifecycle observations are installed;
    // never retry a tool/snapshot or create a replacement context on failure.
    try { await getOwnedContext(); }
    catch (error) {
      if (!attachedBrowser && error?.message === 'browser_cdp_unavailable') {
        return refused('cdp_unavailable');
      }
      throw new Error('browser_native_context_unconfirmed');
    }
    // Initialization can change the factual epoch or close the context. This
    // final guard and backend invocation have no intervening await.
    if (closing || nativeClosed || epochExhausted
        || (expected !== undefined && expected !== nativeEpoch)) return refused('stale');
    const before = nativeEpoch;
    if (params.name === 'browser_tabs'
        && ['new', 'close', 'select'].includes(params.arguments?.action)
        && !advanceEpoch()) return refused('stale');
    let result;
    if (params.name === 'browser_close'
        || (params.name === 'browser_tabs' && params.arguments?.action === 'close')) closeRequestId = extra.requestId;
    try {
      result = await client.callTool({ name: params.name, arguments: params.arguments ?? {} }, undefined, { signal: extra.signal });
      if (params.name === 'browser_close' || nativeClosed) {
        // Context detach is not Node exit/physical process-tree cleanup.
        closing = true;
        await contextPromise?.catch(() => {});
        await closeCdpAttachment();
        result = { ...result, structuredContent: { ...result.structuredContent, styx_context_closed: true } };
      }
    } catch {
      // Bytes may already have reached the native backend: never call this
      // NotSent, replay it, or disclose upstream exception/private arguments.
      return withNativeMeta(
        { isError: true, content: [{ type: 'text', text: 'browser_native_result_unconfirmed' }] },
        before,
        true,
        'result_unconfirmed',
      );
    }
    // Upstream cannot spoof this wrapper's dispatch/epoch facts.
    return withNativeMeta(result, before, true);
  });
  server.onclose = () => { void cleanup().catch(fail); };
  server.onerror = fail;
  const transport = new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 256 * 1024 });
  const send = transport.send.bind(transport);
  transport.send = async message => {
    await send(message);
    if (closeRequestId !== undefined && message.id === closeRequestId) {
      closeRequestId = undefined;
      if (nativeClosed) void cleanup().catch(fail);
    }
  };
  await server.connect(transport);
}
process.stdin.once('end', () => { void cleanup().catch(fail); });
process.stdin.once('error', fail);
process.once('SIGTERM', () => { void cleanup().catch(fail); });
process.once('SIGINT', () => { void cleanup().catch(fail); });
startupPromise = main();
startupPromise.catch(fail);
