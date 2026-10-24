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
let contextPromise, context, backend, client, server, startupPromise, closing = false, cleanupPromise;
async function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  closing = true;
  cleanupPromise = (async () => {
    await startupPromise?.catch(() => {});
    await contextPromise?.catch(() => {});
    await context?.close();
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
  backend = await createConnection({
    browser: { browserName: 'chromium', isolated: false },
    capabilities: ['core'], webmcp: false, outputDir: config.output_dir,
    filePaths: 'absolute', snapshot: { mode: 'none' }, imageResponses: 'allow',
    timeouts: { idle: 0 },
  }, () => {
    if (closing) throw new Error('browser_worker_closing');
    // Cache the one launch promise even after closure/failure. No action, launch
    // or context recovery is replayed after transport errors or browser_close.
    contextPromise ??= chromium.launchPersistentContext(config.profile_dir, {
      headless: true, chromiumSandbox: true, executablePath: config.browser_executable,
      acceptDownloads: true, downloadsPath: config.output_dir,
      viewport: { width: 1280, height: 800 },
    }).then(async value => {
      context = value;
      if (closing) { await value.close(); throw new Error('browser_worker_closing'); }
      const pageObserved = page => {
        fact('browser_native_page');
        page.on('framenavigated', () => fact('browser_native_navigation'));
      };
      for (const page of value.pages()) pageObserved(page);
      value.on('page', pageObserved);
      value.once('close', () => fact('browser_native_context_closed'));
      fact('browser_native_context_open');
      return value;
    });
    return contextPromise;
  });
  client = new Client({ name: 'styx-browser-native-backend', version: '0.1.0' }, { capabilities: { roots: { listChanged: false } } });
  client.setRequestHandler(ListRootsRequestSchema, async () => ({ roots: [
    { uri: pathToFileURL(config.workspace_dir).href, name: 'workspace' },
    { uri: pathToFileURL(config.output_dir).href, name: 'browser-output' },
  ] }));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await backend.connect(a);
  await client.connect(b);
  server = new Server({ name: 'styx-browser-native-worker', version: '0.1.0' }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, () => client.listTools());
  server.setRequestHandler(CallToolRequestSchema, async ({ params }, extra) => {
    if (closing) throw new Error('browser_worker_closing');
    const result = await client.callTool({ name: params.name, arguments: params.arguments ?? {} }, undefined, { signal: extra.signal });
    if (params.name !== 'browser_close') return result;
    // Upstream browser_close disposes tabs, not the supplied persistent context.
    // This is a native backend lifecycle fact, never an owner/policy decision.
    closing = true;
    const ownedContext = await contextPromise;
    if (!ownedContext) throw new Error('browser_worker_close_unconfirmed');
    await ownedContext.close();
    return { ...result, structuredContent: { ...result.structuredContent, styx_context_closed: true } };
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
