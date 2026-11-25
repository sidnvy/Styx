import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readConfiguration } from './config.mjs';

test('trusted startup scope accepts canonical extension-bridge WS configs and rejects managed/http/unsafe fields', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-config-')));
  fs.chmodSync(root, 0o700);
  try {
    const outputDir = path.join(root, 'output');
    const workspaceDir = path.join(root, 'workspace');
    fs.mkdirSync(outputDir, { mode: 0o700 });
    fs.mkdirSync(workspaceDir, { mode: 0o700 });
    const file = path.join(root, 'startup.json');
    const write = value => fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 });

    const base = {
      schema: 1,
      output_dir: outputDir,
      workspace_dir: workspaceDir,
    };

    for (const valid of [
      'ws://127.0.0.1:9333/devtools/browser',
      'ws://localhost:9222/devtools/browser/abc-123_4.5',
      'ws://[::1]:9222/devtools/browser/session-1',
    ]) {
      const cfg = { ...base, cdp_endpoint: valid };
      write(cfg);
      assert.deepEqual(readConfiguration(file), cfg);
      if (process.platform === 'linux') {
        const fd = fs.openSync(file, 'r');
        try {
          assert.notEqual(process.pid, process.ppid);
          assert.deepEqual(readConfiguration(`/proc/${process.pid}/fd/${fd}`), cfg);
        } finally {
          fs.closeSync(fd);
        }
      }
    }

    const validCfg = { ...base, cdp_endpoint: 'ws://127.0.0.1:9222/devtools/browser/test' };
    write({ ...validCfg, owner: 'forged-authority' }); assert.throws(() => readConfiguration(file));
    write({ ...validCfg, output_dir: workspaceDir }); assert.throws(() => readConfiguration(file));
    const alias = path.join(root, 'alias');
    fs.symlinkSync(outputDir, alias, 'dir');
    write({ ...validCfg, output_dir: alias }); assert.throws(() => readConfiguration(file));
    write(validCfg);
    const linked = path.join(root, 'linked.json');
    fs.linkSync(file, linked);
    assert.throws(() => readConfiguration(file));
    fs.unlinkSync(linked);
    fs.writeFileSync(file, 'x'.repeat(16385)); assert.throws(() => readConfiguration(file));
    if (process.platform !== 'win32') {
      write(validCfg);
      fs.chmodSync(outputDir, 0o755);
      assert.throws(() => readConfiguration(file));
      fs.chmodSync(outputDir, 0o700);
    }

    // Legacy managed and http:// direct-CDP shapes are rejected.
    write({ ...validCfg, profile_dir: path.join(root, 'profile') });
    assert.throws(() => readConfiguration(file));
    write({ ...validCfg, browser_executable: '/usr/bin/true' });
    assert.throws(() => readConfiguration(file));
    write({ ...base, profile_dir: outputDir, browser_executable: '/usr/bin/true' });
    assert.throws(() => readConfiguration(file));

    for (const invalid of [
      '',
      'http://127.0.0.1:9222',
      'http://localhost:9222/',
      'https://127.0.0.1:9222',
      'wss://127.0.0.1:9222/devtools/browser',
      'ws://192.168.1.5:9222/devtools/browser',
      'ws://example.com:9222/devtools/browser',
      'ws://user@127.0.0.1:9222/devtools/browser',
      'ws://127.0.0.1:9222/devtools/browser?token=abc',
      'ws://127.0.0.1:9222/devtools/browser#frag',
      'ws://127.0.0.1/devtools/browser',
      'ws://127.0.0.1:9222/other',
      'ws://127.0.0.1:9222/devtools/browser/..',
      'ws://127.0.0.1:9222/devtools/browser/../secret',
    ]) {
      write({ ...base, cdp_endpoint: invalid });
      assert.throws(() => readConfiguration(file), `expected rejection for ${invalid}`);
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
