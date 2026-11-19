import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
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
  timeout: 60000,
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
      env: { ...process.env },
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
    const result = await worker.client.callTool({ name, arguments: args }, undefined, { timeout: 10000 });
    assert.notEqual(result.isError, true, `${name}: ${text(result)}`);
    return result;
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
