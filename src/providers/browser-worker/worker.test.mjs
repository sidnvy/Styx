import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const executable = process.env.STYX_BROWSER_EXECUTABLE;
const text = result => result.content.filter(item => item.type === 'text').map(item => item.text).join('\n');
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
async function bounded(promise, label) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), 10000);
    })]);
  } finally { clearTimeout(timer); }
}

test('extension-bridge WS worker attaches to browser, reuses cookies/tabs, and detaches without closing chrome', {
  skip: !executable && 'set STYX_BROWSER_EXECUTABLE to run the real installed browser',
  timeout: 120000,
}, async t => {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
  const { randomUUID } = await import('node:crypto');
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-ws-e2e-')));
  fs.chmodSync(root, 0o700);
  let chrome, server, worker;
  t.after(async () => {
    if (worker) await worker.client.close().catch(() => {});
    if (chrome) {
      if (chrome.exitCode === null) {
        if (process.platform === 'win32') {
          chrome.kill();
        } else {
          try { process.kill(-chrome.pid, 'SIGTERM'); } catch {}
        }
        await new Promise(resolve => chrome.once('exit', resolve));
      }
      if (process.platform !== 'win32') {
        try { process.kill(-chrome.pid, 'SIGKILL'); } catch {}
      }
    }
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
    for (let attempt = 0; attempt < 20; attempt += 1) {
      try {
        fs.rmSync(root, { recursive: true, force: true });
        break;
      } catch (err) {
        if (attempt === 19 || !['ENOTEMPTY', 'EBUSY', 'EPERM'].includes(err?.code)) throw err;
        await new Promise(resolve => setTimeout(resolve, 50));
      }
    }
  });

  const nonce = randomUUID();
  const seenProbe = deferred();
  server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    response.setHeader('cache-control', 'no-store');
    if (url.pathname === '/initial') {
      response.setHeader('set-cookie', `styx_ws_auth=${nonce}; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax`);
      response.setHeader('content-type', 'text/html');
      response.end(`<!doctype html><title>Existing Tab ${nonce}</title><h1>Existing Browser Session</h1><p>Marker ${nonce}</p>`);
    } else if (url.pathname === '/probe') {
      const cookie = request.headers.cookie ?? '';
      seenProbe.resolve(cookie);
      response.setHeader('content-type', 'text/html');
      response.end(`<!doctype html><title>Probe ${nonce}</title><p id="cookie-len">${cookie.length}</p>`);
    } else {
      response.statusCode = 204;
      response.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  const chromeUserDir = path.join(root, 'external-chrome-profile');
  fs.mkdirSync(chromeUserDir, { mode: 0o700 });
  chrome = spawn(fs.realpathSync(executable), [
    `--user-data-dir=${chromeUserDir}`,
    '--remote-debugging-port=0',
    '--no-first-run',
    '--no-default-browser-check',
    `${base}/initial`,
  ], { detached: process.platform !== 'win32', stdio: ['ignore', 'ignore', 'pipe'] });

  const devToolsFile = path.join(chromeUserDir, 'DevToolsActivePort');
  const startedAt = Date.now();
  let cdpPort, cdpWsPath;
  while (Date.now() - startedAt < 20000) {
    assert.equal(chrome.exitCode, null, 'external browser exited prematurely');
    if (fs.existsSync(devToolsFile)) {
      const lines = fs.readFileSync(devToolsFile, 'utf8').trim().split(/\r?\n/).filter(Boolean);
      if (lines.length >= 1 && /^[1-9][0-9]*$/.test(lines[0])) {
        cdpPort = Number(lines[0]);
        cdpWsPath = lines[1] || '/devtools/browser';
        break;
      }
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.ok(cdpPort, 'DevToolsActivePort was not written in time');
  const cdpEndpoint = `ws://127.0.0.1:${cdpPort}${cdpWsPath}`;

  const outputDir = path.join(root, 'output');
  const workspaceDir = path.join(root, 'workspace');
  fs.mkdirSync(outputDir, { mode: 0o700 });
  fs.mkdirSync(workspaceDir, { mode: 0o700 });
  const configFile = path.join(root, 'cdp-worker.json');
  fs.writeFileSync(configFile, JSON.stringify({
    schema: 1,
    output_dir: outputDir,
    workspace_dir: workspaceDir,
    cdp_endpoint: cdpEndpoint,
  }), { mode: 0o600 });

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('./worker.mjs', import.meta.url)), '--config', configFile],
    env: { ...process.env, DEBUG: 'pw:browser,pw:api' },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'styx-ws-worker-test', version: '1.0.0' });
  const closed = deferred();
  let stderr = '';
  client.onclose = closed.resolve;
  transport.stderr.on('data', chunk => { stderr += chunk.toString(); });
  worker = { client, transport, closed: closed.promise, facts: () => stderr };
  await client.connect(transport);

  async function callWs(name, args = {}) {
    const result = await worker.client.callTool({ name, arguments: args }, undefined, { timeout: 35000 });
    assert.notEqual(result.isError, true, `${name}: ${text(result)}\n${worker.facts()}`);
    return result;
  }

  const tabsResult = text(await callWs('browser_tabs', { action: 'list' }));
  assert.match(tabsResult, /Existing Tab/);
  const snapshotResult = text(await callWs('browser_snapshot'));
  assert.match(snapshotResult, new RegExp(`Marker ${nonce}`));

  await callWs('browser_tabs', { action: 'new' });
  await callWs('browser_navigate', { url: `${base}/probe` });
  const probeCookie = await bounded(seenProbe.promise, 'probe did not send HTTP request');
  assert.ok(probeCookie.split(';').some(item => item.trim() === `styx_ws_auth=${nonce}`));

  const closeResult = await callWs('browser_close');
  assert.equal(closeResult.structuredContent?.styx_context_closed, true);
  await bounded(worker.closed, 'worker did not exit after browser_close');
  assert.equal(worker.transport.pid, null);
  assert.doesNotMatch(worker.facts(), /browser_worker_failed/);
  assert.equal(chrome.exitCode, null, 'external Chrome must remain alive after detach');
});

test('extension-bridge worker returns browser_native_cdp_unavailable with dispatched=false when endpoint refuses connection', {
  timeout: 30000,
}, async t => {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
  const net = await import('node:net');
  const probe = net.createServer();
  await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const deadPort = probe.address().port;
  await new Promise(resolve => probe.close(resolve));

  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-cdp-unavailable-')));
  fs.chmodSync(root, 0o700);
  let client;
  t.after(async () => {
    if (client) await client.close().catch(() => {});
    fs.rmSync(root, { recursive: true, force: true });
  });
  const outputDir = path.join(root, 'output');
  const workspaceDir = path.join(root, 'workspace');
  fs.mkdirSync(outputDir, { mode: 0o700 });
  fs.mkdirSync(workspaceDir, { mode: 0o700 });
  const configFile = path.join(root, 'cdp-dead.json');
  fs.writeFileSync(configFile, JSON.stringify({
    schema: 1,
    output_dir: outputDir,
    workspace_dir: workspaceDir,
    cdp_endpoint: `ws://127.0.0.1:${deadPort}/devtools/browser/test`,
  }), { mode: 0o600 });

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('./worker.mjs', import.meta.url)), '--config', configFile],
    stderr: 'pipe',
  });
  client = new Client({ name: 'styx-cdp-unavailable-test', version: '1.0.0' });
  await client.connect(transport);
  const res = await client.callTool({ name: 'browser_tabs', arguments: { action: 'list' } }, undefined, { timeout: 10000 });
  assert.equal(res.isError, true);
  assert.equal(text(res), 'browser_native_cdp_unavailable');
  assert.equal(res._meta?.['app.styx/browser-native']?.dispatched, false);
  assert.equal(res._meta?.['app.styx/browser-native']?.reason, 'cdp_unavailable');
  t.diagnostic('unreachable CDP endpoint cleanly reported not-dispatched cdp_unavailable');
});
