import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readConfiguration } from './config.mjs';

test('trusted startup scope accepts exact private directories and rejects aliases, extra authorities and shared profile', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-config-')));
  fs.chmodSync(root, 0o700);
  try {
    const config = { schema: 1 };
    for (const [key, folder] of [['profile_dir', 'profile'], ['output_dir', 'output'], ['workspace_dir', 'workspace']]) {
      config[key] = path.join(root, folder); fs.mkdirSync(config[key], { mode: 0o700 });
    }
    // Executable validation only. No shell or native browser is run by this test.
    const executable = path.join(root, 'browser-placeholder'); fs.writeFileSync(executable, 'not executed', { mode: 0o700 });
    config.browser_executable = executable;
    const file = path.join(root, 'startup.json');
    const write = value => fs.writeFileSync(file, JSON.stringify(value), { mode: 0o600 });
    write(config); assert.deepEqual(readConfiguration(file), config);
    if (process.platform === 'linux') {
      // Owned kernel FD from a non-parent PID: the scope launcher may reparent
      // Node. Source authority is Rust's fixed factory, not worker PPID guesses.
      const fd = fs.openSync(file, 'r');
      const executableFd = fs.openSync(executable, 'r');
      try {
        assert.notEqual(process.pid, process.ppid);
        assert.deepEqual(readConfiguration(`/proc/${process.pid}/fd/${fd}`), config);
        write({ ...config, browser_executable: `/proc/${process.pid}/fd/${executableFd}` });
        assert.equal(readConfiguration(file).browser_executable, `/proc/${process.pid}/fd/${executableFd}`);
      } finally { fs.closeSync(fd); fs.closeSync(executableFd); }
    }

    write({ ...config, owner: 'forged-authority' }); assert.throws(() => readConfiguration(file));
    write({ ...config, profile_dir: config.workspace_dir }); assert.throws(() => readConfiguration(file));
    write({ ...config, browser_executable: 'relative-browser' }); assert.throws(() => readConfiguration(file));
    const alias = path.join(root, 'alias'); fs.symlinkSync(config.profile_dir, alias, 'dir');
    write({ ...config, profile_dir: alias }); assert.throws(() => readConfiguration(file));
    write(config); const linked = path.join(root, 'linked.json'); fs.linkSync(file, linked);
    assert.throws(() => readConfiguration(file)); fs.unlinkSync(linked);
    fs.writeFileSync(file, 'x'.repeat(16385)); assert.throws(() => readConfiguration(file));
    if (process.platform !== 'win32') {
      write(config); fs.chmodSync(config.profile_dir, 0o755); assert.throws(() => readConfiguration(file));
    }

    // Opt-in CDP configuration validates strict loopback URLs and forbids mixed managed fields.
    const cdpBase = {
      schema: 1,
      output_dir: config.output_dir,
      workspace_dir: config.workspace_dir,
    };
    for (const valid of [
      'http://127.0.0.1:9222',
      'http://localhost:9222/',
      'ws://[::1]:9222/devtools/browser/abc-123_4.5',
      'ws://127.0.0.1:9333/devtools/browser',
    ]) {
      const cdpConfig = { ...cdpBase, cdp_endpoint: valid };
      write(cdpConfig);
      assert.deepEqual(readConfiguration(file), cdpConfig);
    }
    for (const invalid of [
      '',
      'https://127.0.0.1:9222',
      'http://192.168.1.5:9222',
      'http://example.com:9222',
      'http://user@127.0.0.1:9222',
      'http://127.0.0.1:9222?token=abc',
      'http://127.0.0.1:9222#frag',
      'http://127.0.0.1',
      'http://127.0.0.1:9222/json/version',
      'ws://127.0.0.1:9222/other',
      'ws://127.0.0.1:9222/devtools/browser/../secret',
    ]) {
      write({ ...cdpBase, cdp_endpoint: invalid });
      assert.throws(() => readConfiguration(file), `expected rejection for ${invalid}`);
    }
    write({ ...cdpBase, cdp_endpoint: 'http://127.0.0.1:9222', profile_dir: config.profile_dir });
    assert.throws(() => readConfiguration(file));
    write({ ...cdpBase, cdp_endpoint: 'http://127.0.0.1:9222', browser_executable: executable });
    assert.throws(() => readConfiguration(file));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
