import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import {randomUUID} from 'node:crypto';
import {CasExperimentLedger} from '../cas/ledger.mjs';
import {casCall} from '../cas/mcp.mjs';

async function setup(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'styx-cas-view-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  const clock = {value: Date.parse('2026-10-18T12:00:00Z')};
  const ledger = await new CasExperimentLedger({directory, now: () => clock.value}).init();
  const source = await fs.readFile(new URL('../cas/controller.html', import.meta.url), 'utf8');
  const script = /<script>([\s\S]*?)<\/script>/.exec(source)[1];
  return {clock, ledger, script};
}

function createHostView({clock, ledger, script, rejectUiMessage = false}) {
  const handlers = new Map(), tasks = new Map(), sent = [];
  const elements = new Map();
  let counter = 0, inFlight = 0, timerSeq = 0, closed = false;
  const listen = (type, cb) => handlers.set(type, cb);
  const parent = {
    postMessage: message => {
      if (message.method === 'ui/notifications/initialized') return;
      if (!Object.hasOwn(message, 'id')) return;
      inFlight++;
      Promise.resolve().then(async () => {
        if (message.method === 'ui/initialize')
          return {jsonrpc: '2.0', id: message.id, result: {}};
        if (message.method === 'tools/call') {
          const result = await casCall(ledger, message.params.name, message.params.arguments);
          return {jsonrpc: '2.0', id: message.id, result};
        }
        if (message.method === 'ui/message') {
          sent.push(message.params.content[0].text);
          return rejectUiMessage
            ? {jsonrpc: '2.0', id: message.id, error: {code: -32000, message: 'host_refused'}}
            : {jsonrpc: '2.0', id: message.id, result: {}};
        }
        throw Error('Unexpected Host message: ' + message.method);
      }).then(result => {
        handlers.get('message')?.({source: parent, data: result});
      }).finally(() => { inFlight--; });
    }
  };
  const fakeWindow = {parent, addEventListener: listen};
  const button = {disabled: true, addEventListener: (_event, fn) => {button.onclick = fn;}};
  elements.set('stop', button);
  elements.set('state', {textContent: ''});
  elements.set('detail', {textContent: ''});
  const document = {
    visibilityState: 'visible',
    getElementById: id => elements.get(id)
  };
  const FakeDate = class extends Date {static now() {return clock.value;}};
  const context = {
    window: fakeWindow, document, Date: FakeDate, crypto: {randomUUID},
    setTimeout(fn, delay) {
      const id = ++timerSeq;
      tasks.set(id, {at: clock.value + delay, fn});
      return id;
    },
    clearTimeout(id) { tasks.delete(id); },
    console
  };
  vm.runInNewContext(script, context, {timeout: 1500});
  return {
    sent, elements, document, get inFlight() {return inFlight;},
    async settle() {
      for (let i = 0; i < 20; i++) {
        await new Promise(resolve => setTimeout(resolve, 2));
        if (!inFlight) break;
      }
      await new Promise(resolve => setTimeout(resolve, 15));
    },
    giveRun(run_id) {
      handlers.get('message')({source: parent, data: {
        jsonrpc: '2.0', method: 'ui/notifications/tool-input',
        params: {arguments: {run_id}}
      }});
    },
    async advanceTo(until) {
      let steps = 0;
      while (!closed && steps++ < 100) {
        const next = [...tasks.entries()].sort((a, b) => a[1].at - b[1].at)[0];
        if (!next || next[1].at > until) break;
        tasks.delete(next[0]);
        clock.value = next[1].at;
        next[1].fn();
        await this.settle();
      }
      assert.ok(steps < 100, 'bounded browser timers');
      clock.value = until;
    },
    close() { closed = true; handlers.get('pagehide')?.(); tasks.clear(); }
  };
}

test('mounted MCP App requests exactly two Host messages and never equates ACK with consume', async t => {
  const f = await setup(t);
  const start = await f.ledger.start({objective: 'harmless app wake', rounds: 2, delay_ms: 15000});
  const view = createHostView({...f, rejectUiMessage: false});
  t.after(() => view.close());
  await view.settle();
  view.giveRun(start.run_id);
  await view.advanceTo(f.clock.value + 28000);
  assert.equal(view.sent.length, 1);
  assert.equal((await f.ledger.read(start.run_id)).completed_rounds, 0);
  assert.equal((await f.ledger.read(start.run_id)).wake.phase, 'dispatch_accepted');
  const payload = JSON.parse(view.sent[0].match(/with exactly (\{.*?\})\./)[1]);
  assert.equal((await f.ledger.consume(payload)).completed_rounds, 1);
  await view.advanceTo(f.clock.value + 24000);
  assert.equal(view.sent.length, 2);
  const second = JSON.parse(view.sent[1].match(/with exactly (\{.*?\})\./)[1]);
  assert.equal((await f.ledger.consume(second)).status, 'completed');
  await view.advanceTo(f.clock.value + 30000);
  assert.equal(view.sent.length, 2);
});

test('Host ui/message refusal becomes delivery_unknown with no automatic resend', async t => {
  const f = await setup(t);
  const start = await f.ledger.start({objective: 'refusal', delay_ms: 15000});
  const view = createHostView({...f, rejectUiMessage: true});
  t.after(() => view.close());
  await view.settle();
  view.giveRun(start.run_id);
  await view.advanceTo(f.clock.value + 45000);
  assert.equal(view.sent.length, 1);
  assert.equal((await f.ledger.read(start.run_id)).wake.phase, 'delivery_unknown');
  await view.advanceTo(f.clock.value + 150000);
  assert.equal(view.sent.length, 1);
});
