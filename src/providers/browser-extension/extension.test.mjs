import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const EXPECTED_EXTENSION_ID = 'cncjpfhbbnibdjkcheeimdfklfiknibl';

function computeExtensionIdFromKey(keyB64) {
  const der = Buffer.from(keyB64, 'base64');
  const hash = crypto.createHash('sha256').update(der).digest().subarray(0, 16);
  let id = '';
  for (const byte of hash) {
    id += String.fromCharCode(97 + (byte >> 4));
    id += String.fromCharCode(97 + (byte & 0x0f));
  }
  return id;
}

function createFakeChrome(tabsList) {
  const listeners = {
    debuggerEvent: [],
    debuggerDetach: [],
    tabCreated: [],
    tabUpdated: [],
    tabRemoved: [],
    runtimeMessage: [],
    alarm: [],
    portMessage: [],
    portDisconnect: [],
  };
  const posted = [];
  const attached = new Set();
  const sentCommands = [];
  const windowUpdates = [];
  const tabUpdates = [];
  const groupUpdates = [];
  let nextTabId = 99;
  let nextGroupId = 500;
  let failOnDisconnect = null;

  const port = {
    postMessage(msg) {
      posted.push(msg);
    },
    disconnect() {
      for (const cb of listeners.portDisconnect) cb();
    },
    onMessage: { addListener: cb => listeners.portMessage.push(cb) },
    onDisconnect: { addListener: cb => listeners.portDisconnect.push(cb) },
  };

  const chrome = {
    runtime: {
      id: EXPECTED_EXTENSION_ID,
      lastError: null,
      connectNative(name) {
        assert.equal(name, 'com.styx.browser_bridge');
        return port;
      },
      onMessage: { addListener: cb => listeners.runtimeMessage.push(cb) },
      onInstalled: { addListener() {} },
      onStartup: { addListener() {} },
    },
    tabs: {
      async query() {
        return tabsList;
      },
      async create(opts) {
        const created = {
          id: nextTabId++,
          url: opts.url,
          title: 'New',
          active: opts.active === true,
          windowId: 1,
          groupId: -1,
        };
        tabsList.push(created);
        return created;
      },
      async remove(tabId) {
        const idx = tabsList.findIndex(t => t.id === tabId);
        if (idx >= 0) tabsList.splice(idx, 1);
      },
      async update(tabId, props) {
        tabUpdates.push({ tabId, props });
        const tab = tabsList.find(t => t.id === tabId);
        if (tab) Object.assign(tab, props);
        return tab;
      },
      async group(opts) {
        const groupId = typeof opts.groupId === 'number' ? opts.groupId : nextGroupId++;
        for (const tabId of opts.tabIds || []) {
          const tab = tabsList.find(t => t.id === tabId);
          if (tab) tab.groupId = groupId;
        }
        return groupId;
      },
      onCreated: { addListener: cb => listeners.tabCreated.push(cb) },
      onUpdated: { addListener: cb => listeners.tabUpdated.push(cb) },
      onRemoved: { addListener: cb => listeners.tabRemoved.push(cb) },
      onActivated: { addListener() {} },
    },
    tabGroups: {
      async update(groupId, props) {
        groupUpdates.push({ groupId, props });
        return { id: groupId, ...props };
      },
    },
    windows: {
      async update(windowId, props) {
        windowUpdates.push({ windowId, props });
        return {};
      },
    },
    debugger: {
      async attach(target, version) {
        assert.equal(version, '1.3');
        attached.add(target.tabId);
      },
      async detach(target) {
        if (!attached.has(target.tabId)) {
          throw new Error('Debugger is not attached to the tab with id: ' + target.tabId);
        }
        attached.delete(target.tabId);
      },
      async sendCommand(target, method, params) {
        sentCommands.push({ target, method, params });
        return { ok: true, method };
      },
      onEvent: { addListener: cb => listeners.debuggerEvent.push(cb) },
      onDetach: { addListener: cb => listeners.debuggerDetach.push(cb) },
    },
    alarms: {
      create() {},
      onAlarm: { addListener: cb => listeners.alarm.push(cb) },
    },
  };

  return {
    chrome,
    posted,
    attached,
    sentCommands,
    windowUpdates,
    tabUpdates,
    groupUpdates,
    listeners,
    emitPort(msg) {
      for (const cb of listeners.portMessage) cb(msg);
    },
    emitDisconnect(errMsg) {
      chrome.runtime.lastError = errMsg ? { message: errMsg } : null;
      for (const cb of listeners.portDisconnect) cb();
      chrome.runtime.lastError = null;
    },
    setFailOnDisconnect(val) { failOnDisconnect = val; },
  };
}

test('manifest has deterministic extension ID, minimal permissions, and icons exist', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.equal(computeExtensionIdFromKey(manifest.key), EXPECTED_EXTENSION_ID);
  assert.deepEqual(manifest.permissions, ['debugger', 'tabs', 'tabGroups', 'nativeMessaging', 'alarms']);
  for (const rel of ['icons/icon16.png', 'icons/icon48.png', 'icons/icon128.png', 'popup.html', 'popup.js', 'background.js']) {
    assert.ok(fs.existsSync(path.join(dir, rel)), `missing ${rel}`);
  }
});

test('background controller connects, filters chrome:// tabs, forwards RPCs/events, and cleans up on host disconnect', async () => {
  const code = fs.readFileSync(path.join(dir, 'background.js'), 'utf8');
  const fake = createFakeChrome([
    { id: 1, url: 'chrome://extensions/', title: 'Extensions', active: false, windowId: 1 },
    { id: 2, url: 'https://dash.cloudflare.com/', title: 'Cloudflare', active: true, windowId: 1 },
    { id: 3, url: 'chrome-extension://other/index.html', title: 'Other', active: false, windowId: 1 },
  ]);
  const sandbox = {
    globalThis: null,
    chrome: undefined,
    navigator: { userAgent: 'Mozilla/5.0 Chrome/158.0.0.0 Safari/537.36' },
    setTimeout,
    clearTimeout,
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(code, sandbox);

  const tools = sandbox.__styxExtensionTools;
  assert.equal(tools.isAttachableUrl('chrome://settings'), false);
  assert.equal(tools.isAttachableUrl('https://example.com'), true);
  assert.equal(tools.parseBrowserVersion('Mozilla/5.0 Chrome/158.0.8127.88 Safari/537.36'), 'Chrome/158.0.8127.88');

  const controller = tools.createExtensionController(fake.chrome, {
    userAgent: sandbox.navigator.userAgent,
    setTimeout: () => 1,
    clearTimeout() {},
  });
  controller.registerListeners();
  assert.equal(controller.ensureConnected(), true);

  // Bridge reports Host connected -> controller emits extension.hello with only attachable tabs.
  fake.emitPort({ type: 'bridge.status', hostConnected: true });
  await new Promise(r => setImmediate(r));
  const hello = fake.posted.find(m => m.event === 'extension.hello');
  assert.ok(hello);
  assert.equal(hello.params.browser, 'Chrome/158.0.0.0');
  assert.deepEqual(hello.params.tabs.map(t => t.id), [2]);

  // Attach tab 2 and send a CDP command (including child sessionId forwarding).
  fake.emitPort({ id: 10, method: 'debugger.attach', params: { tabId: 2 } });
  await new Promise(r => setImmediate(r));
  assert.ok(fake.attached.has(2));
  assert.deepEqual(JSON.parse(JSON.stringify(fake.posted.at(-1))), { id: 10, result: { ok: true } });

  fake.emitPort({
    id: 11,
    method: 'debugger.sendCommand',
    params: { tabId: 2, sessionId: 'child-1', method: 'Page.bringToFront', params: {} },
  });
  await new Promise(r => setImmediate(r));
  assert.deepEqual(JSON.parse(JSON.stringify(fake.sentCommands.at(-1))), {
    target: { tabId: 2, sessionId: 'child-1' },
    method: 'Page.bringToFront',
    params: {},
  });
  assert.equal(fake.tabUpdates.length, 0);
  assert.equal(fake.windowUpdates.length, 0);

  // Background Tab Group creation defaults to active:false, assigns group title/color, and excludes isolated tabs from excludeIsolated queries.
  fake.emitPort({
    id: 12,
    method: 'tabs.create',
    params: {
      url: 'https://example.org/bg',
      isolated: true,
      groupTitle: 'Styx · 1',
      groupColor: 'blue',
    },
  });
  await new Promise(r => setImmediate(r));
  const createReply = JSON.parse(JSON.stringify(fake.posted.at(-1)));
  assert.equal(createReply.id, 12);
  assert.equal(createReply.result.tab.active, false);
  assert.equal(createReply.result.tab.isolated, true);
  assert.equal(createReply.result.groupId, 500);
  assert.deepEqual(JSON.parse(JSON.stringify(fake.groupUpdates.at(-1))), {
    groupId: 500,
    props: { title: 'Styx · 1', color: 'blue' },
  });

  fake.emitPort({ id: 13, method: 'tabs.list', params: { excludeIsolated: true } });
  await new Promise(r => setImmediate(r));
  const listFiltered = JSON.parse(JSON.stringify(fake.posted.at(-1)));
  assert.deepEqual(listFiltered.result.tabs.map(t => t.id), [2]);

  fake.emitPort({ id: 14, method: 'tabs.activate', params: { tabId: 2 } });
  await new Promise(r => setImmediate(r));
  assert.equal(fake.windowUpdates.length, 0);
  assert.equal(fake.tabUpdates.length, 0);

  // Extension events forward to bridge while Host is connected.
  for (const cb of fake.listeners.debuggerEvent) cb({ tabId: 2 }, 'Page.loadEventFired', { timestamp: 1 });
  assert.equal(fake.posted.at(-1).event, 'chrome.debugger.onEvent');

  // Host disconnect detaches attached tabs cleanly.
  fake.emitPort({ type: 'bridge.status', hostConnected: false });
  await new Promise(r => setImmediate(r));
  assert.equal(fake.attached.size, 0);
  assert.equal(controller.getStatus().hostConnected, false);
});
