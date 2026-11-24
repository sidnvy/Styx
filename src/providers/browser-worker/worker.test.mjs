import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
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
function reference(snapshot, label) {
  const line = snapshot.split('\n').find(value => value.includes(label));
  const ref = line?.match(/\[ref=([^\]]+)\]/)?.[1];
  assert.ok(ref, `missing snapshot reference for ${label}`);
  return ref;
}

test('headed worker shares a live page with external changes and settles each close path', {
  skip: !executable && 'set STYX_BROWSER_EXECUTABLE to run the real installed browser',
  timeout: 120000,
}, async t => {
  // Keep ordinary contract tests independent of the optional native dependency
  // closure. CI sets the executable and installs these already pinned packages.
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-headed-')));
  fs.chmodSync(root, 0o700);
  const workers = [];
  let server;
  t.after(async () => {
    await Promise.all(workers.map(worker => worker.client.close()));
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  async function start(name) {
    const config = { schema: 1, browser_executable: fs.realpathSync(executable) };
    for (const key of ['profile_dir', 'output_dir', 'workspace_dir']) {
      config[key] = path.join(root, `${name}-${key}`);
      fs.mkdirSync(config[key], { mode: 0o700 });
    }
    const configFile = path.join(root, `${name}.json`);
    fs.writeFileSync(configFile, JSON.stringify(config), { mode: 0o600 });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL('./worker.mjs', import.meta.url)), '--config', configFile],
      env: { ...process.env, DEBUG: 'pw:browser,pw:api' },
      stderr: 'pipe',
    });
    const client = new Client({ name: 'styx-headed-worker-test', version: '1.0.0' });
    const closed = deferred();
    let stderr = '';
    client.onclose = closed.resolve;
    transport.stderr.on('data', chunk => { stderr += chunk.toString(); });
    const worker = { client, transport, closed: closed.promise, facts: () => stderr };
    workers.push(worker);
    await client.connect(transport);
    return worker;
  }
  async function tool(worker, name, args = {}) {
    const started = Date.now();
    try {
      const result = await worker.client.callTool({ name, arguments: args }, undefined, { timeout: 35000 });
      assert.notEqual(result.isError, true, `${name}: ${text(result)}`);
      t.diagnostic(`${name} completed in ${Date.now() - started} ms`);
      return result;
    } catch (cause) {
      throw new Error(`${name} failed after ${Date.now() - started} ms\n${cause.stack ?? cause}\n${worker.facts()}`, { cause });
    }
  }
  const nonce = randomUUID(), humanValue = `human-${nonce}`, agentValue = `agent-${nonce}`;
  const ready = deferred(), changed = deferred(), effect = deferred();
  const documents = [];
  let phase = 'idle';
  const page = `<!doctype html><title>Styx interactive ${nonce}</title>
    <label>Shared value<input id="value" aria-label="Shared value" value="initial"></label>
    <button id="commit">Commit shared value</button><p id="status">Ready</p>
    <script>
      const documentId = crypto.randomUUID();
      fetch('/ready', {method:'POST', body:documentId});
      document.querySelector('#commit').onclick = async () => {
        const value = document.querySelector('#value').value;
        await fetch('/effect', {method:'POST', body:JSON.stringify({value, documentId})});
        document.querySelector('#status').textContent = 'Saved: ' + value;
      };
      let previous = 'idle';
      setInterval(async () => {
        const phase = await (await fetch('/phase')).text();
        if (phase === previous) return;
        previous = phase;
        if (phase === 'human') {
          await fetch('/login', {method:'POST', body:documentId});
          const input = document.querySelector('#value');
          input.value = ${JSON.stringify(humanValue)};
          input.dispatchEvent(new Event('input', {bubbles:true}));
          document.querySelector('#status').textContent = 'Human completed';
          await fetch('/changed', {method:'POST', body:documentId});
        }
        if (phase === 'close') window.close();
      }, 100);
    </script>`;
  server = http.createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    response.setHeader('cache-control', 'no-store');
    switch (request.url) {
      case '/launch':
        response.setHeader('content-type', 'text/html');
        response.end('<button id="open" onclick="window.open(\'/interactive\', \'_blank\', \'popup,width=900,height=700\')">Open shared window</button>');
        break;
      case '/interactive':
        response.setHeader('content-type', 'text/html'); response.end(page); break;
      case '/phase': response.end(phase); break;
      case '/ready': documents.push(body); ready.resolve(body); response.end('ready'); break;
      case '/login':
        response.setHeader('set-cookie', `styx_handoff_auth=${nonce}; Path=/; HttpOnly; SameSite=Lax`);
        response.end('signed in'); break;
      case '/changed': changed.resolve(body); response.end('changed'); break;
      case '/effect':
        effect.resolve({ ...JSON.parse(body), cookie: request.headers.cookie ?? '' });
        response.end('saved'); break;
      default: response.statusCode = 204; response.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const shared = await start('shared');
  await tool(shared, 'browser_navigate', { url: 'chrome://version' });
  const launch = text(await tool(shared, 'browser_evaluate', {
    function: "() => document.querySelector('#command_line').textContent",
  }));
  assert.match(launch, /--user-data-dir/);
  assert.doesNotMatch(launch, /(?:^|\s)--headless(?:[=\s"]|$)/);
  await tool(shared, 'browser_navigate', { url: `${base}/launch` });
  await tool(shared, 'browser_click', { target: '#open' });
  await tool(shared, 'browser_tabs', { action: 'select', index: 1 });
  await tool(shared, 'browser_tabs', { action: 'close', index: 0 });
  const documentId = await bounded(ready.promise, 'shared page did not load');
  const before = text(await tool(shared, 'browser_snapshot'));
  assert.match(before, /Shared value/);
  assert.match(before, /initial/);

  // This independent page event simulates a person changing the live page. It
  // does not claim OS keyboard/mouse acceptance, and no Browser tool runs here.
  phase = 'human';
  assert.equal(await bounded(changed.promise, 'external page change did not finish'), documentId);
  const fresh = text(await tool(shared, 'browser_snapshot'));
  assert.ok(fresh.includes(humanValue));
  await tool(shared, 'browser_type', { target: reference(fresh, 'textbox'), text: agentValue });
  const afterType = text(await tool(shared, 'browser_snapshot'));
  await tool(shared, 'browser_click', { target: reference(afterType, 'Commit shared value') });
  const recorded = await bounded(effect.promise, 'agent submission had no HTTP effect');
  assert.equal(recorded.value, agentValue);
  assert.equal(recorded.documentId, documentId);
  assert.ok(recorded.cookie.split(';').some(value => value.trim() === `styx_handoff_auth=${nonce}`));
  await tool(shared, 'browser_wait_for', { text: `Saved: ${agentValue}` });
  assert.ok(text(await tool(shared, 'browser_snapshot')).includes(`Saved: ${agentValue}`));
  assert.deepEqual(documents, [documentId]);

  // A real script-opened window may close itself. This happens outside MCP and
  // must settle the worker even on macOS, where Chrome keeps no-window apps alive.
  phase = 'close';
  await bounded(shared.closed, 'closing the last window left the worker running');
  assert.equal(shared.transport.pid, null);
  assert.equal(shared.facts().match(/browser_native_context_open/g)?.length, 1);
  assert.match(shared.facts(), /browser_native_context_closed/);
  assert.doesNotMatch(shared.facts(), /browser_worker_failed/);

  // Explicit closure must deliver its result before ending the same worker.
  for (const name of ['browser_close', 'last_tab']) {
    const worker = await start(name);
    await tool(worker, 'browser_snapshot');
    const result = name === 'browser_close'
      ? await tool(worker, 'browser_close')
      : await tool(worker, 'browser_tabs', { action: 'close', index: 0 });
    assert.equal(result.structuredContent?.styx_context_closed, true);
    await bounded(worker.closed, `${name} left the worker running`);
    assert.equal(worker.transport.pid, null);
    assert.doesNotMatch(worker.facts(), /browser_worker_failed/);
  }
});


test('headed workers retain a complete login profile after restart and isolate parallel profiles', {
  skip: !executable && 'set STYX_BROWSER_EXECUTABLE to run the real installed browser',
  timeout: 120000,
}, async t => {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-profile-')));
  fs.chmodSync(root, 0o700);
  const workers = [], reports = new Map();
  let server;
  t.after(async () => {
    await Promise.allSettled(workers.map(worker => worker.client.close()));
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
    fs.rmSync(root, { recursive: true, force: true });
  });
  async function start(name, profile) {
    const config = { schema: 1, browser_executable: fs.realpathSync(executable), profile_dir: profile };
    fs.mkdirSync(profile, { recursive: true, mode: 0o700 });
    for (const key of ['output_dir', 'workspace_dir']) {
      config[key] = path.join(root, `${name}-${key}`);
      fs.mkdirSync(config[key], { mode: 0o700 });
    }
    const configFile = path.join(root, `${name}.json`);
    fs.writeFileSync(configFile, JSON.stringify(config), { mode: 0o600 });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL('./worker.mjs', import.meta.url)), '--config', configFile],
      env: { ...process.env, DEBUG: 'pw:browser,pw:api' },
      stderr: 'pipe',
    });
    const client = new Client({ name: 'styx-profile-worker-test', version: '1.0.0' });
    const closed = deferred();
    let stderr = '';
    client.onclose = closed.resolve;
    transport.stderr.on('data', chunk => { stderr += chunk.toString(); });
    const worker = { client, transport, closed: closed.promise, facts: () => stderr };
    workers.push(worker);
    await client.connect(transport);
    return worker;
  }
  async function tool(worker, name, args = {}) {
    try {
      const result = await worker.client.callTool({ name, arguments: args }, undefined, { timeout: 35000 });
      assert.notEqual(result.isError, true, `${name}: ${text(result)}`);
      return result;
    } catch (cause) {
      throw new Error(`${name}: ${cause.stack ?? cause}\n${worker.facts()}`, { cause });
    }
  }
  const tokens = { a: `a-${randomUUID()}`, b: `b-${randomUUID()}` };
  const cookieName = 'styx_profile_auth';
  const page = (seed, label) => `<!doctype html><title>Styx profile fixture</title>
    <p>Profile storage fixture</p><script type="module">
      const documentId = crypto.randomUUID();
      const database = await new Promise((resolve, reject) => {
        const request = indexedDB.open('styx-login', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('auth');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const seed = ${JSON.stringify(seed)};
      if (seed !== null) {
        localStorage.setItem('styx-auth', seed);
        await new Promise((resolve, reject) => {
          const transaction = database.transaction('auth', 'readwrite');
          transaction.objectStore('auth').put(seed, 'token');
          transaction.oncomplete = resolve;
          transaction.onerror = () => reject(transaction.error);
          transaction.onabort = () => reject(transaction.error);
        });
      }
      window.reportState = async label => {
        const indexedDBValue = await new Promise((resolve, reject) => {
          const request = database.transaction('auth', 'readonly').objectStore('auth').get('token');
          request.onsuccess = () => resolve(request.result ?? null);
          request.onerror = () => reject(request.error);
        });
        await fetch('/report?case=' + encodeURIComponent(label), {
          method: 'POST',
          body: JSON.stringify({
            documentId, localStorageValue: localStorage.getItem('styx-auth'),
            indexedDBValue, documentCookie: document.cookie
          })
        });
      };
      await window.reportState(${JSON.stringify(label)});
    </script>`;
  server = http.createServer(async (request, response) => {
    const url = new URL(request.url, 'http://fixture');
    let body = '';
    for await (const chunk of request) body += chunk;
    response.setHeader('cache-control', 'no-store');
    const label = url.searchParams.get('case');
    if (url.pathname === '/report') {
      // Cookie evidence comes from this independent HTTP observer, never from
      // document.cookie or the Browser tool's own claim about its storage.
      reports.get(label)?.resolve({ ...JSON.parse(body), cookie: request.headers.cookie ?? '' });
      response.end('observed');
    } else if (url.pathname === '/seed' || url.pathname === '/probe') {
      const seed = url.pathname === '/seed' ? tokens[url.searchParams.get('actor')] : null;
      if (seed) {
        // The fixture deliberately issues a persistent HttpOnly login cookie.
        // Session-cookie expiry is never rewritten by the worker or the test.
        response.setHeader('set-cookie',
          `${cookieName}=${seed}; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax`);
      }
      response.setHeader('content-type', 'text/html');
      response.end(page(seed, label));
    } else {
      response.statusCode = 204;
      response.end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  async function observe(label, action) {
    const report = deferred();
    reports.set(label, report);
    await action();
    return bounded(report.promise, `HTTP profile report missing: ${label}`);
  }
  function assertLogin(report, token) {
    assert.equal(report.cookie, `${cookieName}=${token}`);
    assert.equal(report.documentCookie, '', 'HttpOnly login cookie must remain unreadable to page scripts');
    assert.equal(report.localStorageValue, token);
    assert.equal(report.indexedDBValue, token);
  }

  const profileA = path.join(root, 'profile-a'), profileB = path.join(root, 'profile-b');
  const [a, b] = await Promise.all([start('a-first', profileA), start('b-live', profileB)]);
  const bPid = b.transport.pid;
  const [aSeeded, bEmpty] = await Promise.all([
    observe('a-seeded', () => tool(a, 'browser_navigate', { url: `${base}/seed?actor=a&case=a-seeded` })),
    observe('b-empty', () => tool(b, 'browser_navigate', { url: `${base}/probe?case=b-empty` })),
  ]);
  assertLogin(aSeeded, tokens.a);
  assert.equal(bEmpty.cookie, '');
  assert.equal(bEmpty.localStorageValue, null);
  assert.equal(bEmpty.indexedDBValue, null);
  const bSeeded = await observe('b-seeded',
    () => tool(b, 'browser_navigate', { url: `${base}/seed?actor=b&case=b-seeded` }));
  assertLogin(bSeeded, tokens.b);

  const closed = await tool(a, 'browser_close');
  assert.equal(closed.structuredContent?.styx_context_closed, true);
  await bounded(a.closed, 'first profile worker did not close');
  assert.equal(a.transport.pid, null);
  assert.match(a.facts(), /browser_native_context_closed/);
  const bAfterClose = await observe('b-after-a-close', () => tool(b, 'browser_evaluate', {
    function: "() => window.reportState('b-after-a-close')",
  }));
  assertLogin(bAfterClose, tokens.b);
  assert.equal(bAfterClose.documentId, bSeeded.documentId, 'closing A must preserve B\'s live document');
  assert.equal(b.transport.pid, bPid);

  // A completely new worker and Chromium context reuse A's full profile directory.
  // No storageState export/import, cookie injection or second login occurs.
  const reopened = await start('a-reopened', profileA);
  const [aRestored, bAfterReopen] = await Promise.all([
    observe('a-reopened', () => tool(reopened, 'browser_navigate', { url: `${base}/probe?case=a-reopened` })),
    observe('b-after-a-reopened', () => tool(b, 'browser_evaluate', {
      function: "() => window.reportState('b-after-a-reopened')",
    })),
  ]);
  assertLogin(aRestored, tokens.a);
  assert.notEqual(aRestored.documentId, aSeeded.documentId, 'reopened A must be a new document');
  assertLogin(bAfterReopen, tokens.b);
  assert.equal(bAfterReopen.documentId, bSeeded.documentId);
  assert.equal(b.transport.pid, bPid);
  for (const worker of [reopened, b]) {
    await tool(worker, 'browser_close');
    await bounded(worker.closed, 'profile worker remained after browser_close');
    assert.equal(worker.transport.pid, null);
    assert.doesNotMatch(worker.facts(), /browser_worker_failed/);
  }
  t.diagnostic('HTTP observed persistent HttpOnly auth, localStorage and IndexedDB after A restart; B stayed isolated and live');
});

test('cdp worker attaches to existing browser, reuses cookies/tabs, and detaches without closing chrome', {
  skip: !executable && 'set STYX_BROWSER_EXECUTABLE to run the real installed browser',
  timeout: 120000,
}, async t => {
  const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-cdp-e2e-')));
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
      response.setHeader('set-cookie', `styx_cdp_auth=${nonce}; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax`);
      response.setHeader('content-type', 'text/html');
      response.end(`<!doctype html><title>Existing Tab ${nonce}</title><h1>Existing CDP Session</h1><p>Marker ${nonce}</p>`);
    } else if (url.pathname === '/probe') {
      const cookie = request.headers.cookie ?? '';
      seenProbe.resolve(cookie);
      response.setHeader('content-type', 'text/html');
      response.end(`<!doctype html><title>CDP Probe ${nonce}</title><p id="cookie-len">${cookie.length}</p>`);
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
  t.diagnostic(`spawned external browser pid=${chrome.pid}`);

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
  t.diagnostic(`resolved external CDP endpoint ${cdpEndpoint}`);

  // Confirm initial tab settled and set the HttpOnly cookie before Styx attaches.
  const tabPollStart = Date.now();
  let initialTabReady = false;
  while (Date.now() - tabPollStart < 15000) {
    const res = await fetch(`http://127.0.0.1:${cdpPort}/json/list`).catch(() => null);
    if (res?.ok) {
      const targets = await res.json();
      if (targets.some(item => item.type === 'page' && item.url?.includes('/initial'))) {
        initialTabReady = true;
        break;
      }
    }
    await new Promise(resolve => setTimeout(resolve, 150));
  }
  assert.ok(initialTabReady, 'external browser did not open initial tab');

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
  const client = new Client({ name: 'styx-cdp-worker-test', version: '1.0.0' });
  const closed = deferred();
  let stderr = '';
  client.onclose = closed.resolve;
  transport.stderr.on('data', chunk => { stderr += chunk.toString(); });
  worker = { client, transport, closed: closed.promise, facts: () => stderr };
  await client.connect(transport);

  async function callCdp(name, args = {}) {
    const result = await worker.client.callTool({ name, arguments: args }, undefined, { timeout: 35000 });
    assert.notEqual(result.isError, true, `${name}: ${text(result)}\n${worker.facts()}`);
    return result;
  }

  const tabsResult = text(await callCdp('browser_tabs', { action: 'list' }));
  assert.match(tabsResult, /Existing Tab/);
  const snapshotResult = text(await callCdp('browser_snapshot'));
  assert.match(snapshotResult, new RegExp(`Marker ${nonce}`));

  // Open a second tab inside the existing browser and verify the HttpOnly cookie is shared.
  await callCdp('browser_tabs', { action: 'new' });
  await callCdp('browser_navigate', { url: `${base}/probe` });
  const probeCookie = await bounded(seenProbe.promise, 'CDP probe did not send HTTP request');
  assert.ok(probeCookie.split(';').some(item => item.trim() === `styx_cdp_auth=${nonce}`));

  // Explicit browser_close MUST only detach WebSocket and MUST NOT close external Chrome or its original tab.
  const closeResult = await callCdp('browser_close');
  assert.equal(closeResult.structuredContent?.styx_context_closed, true);
  await bounded(worker.closed, 'CDP worker did not exit after browser_close');
  assert.equal(worker.transport.pid, null);
  assert.doesNotMatch(worker.facts(), /browser_worker_failed/);

  // Verify external Chrome process is still alive and its initial tab is still present.
  assert.equal(chrome.exitCode, null, 'external Chrome must remain alive after CDP detach');
  process.kill(chrome.pid, 0);
  const postCloseTargets = await (await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();
  assert.ok(
    postCloseTargets.some(item => item.type === 'page' && item.url?.includes('/initial')),
    'external Chrome pre-existing tab must still be open after browser_close'
  );
  assert.ok(
    postCloseTargets.some(item => item.type === 'page' && item.url?.includes('/probe')),
    'CDP-opened tab also remains non-destructively intact on detach'
  );
});

test('cdp worker returns browser_native_cdp_unavailable with dispatched=false when endpoint refuses connection', {
  skip: !executable && 'set STYX_BROWSER_EXECUTABLE to run the real installed browser',
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
    cdp_endpoint: `http://127.0.0.1:${deadPort}`,
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
