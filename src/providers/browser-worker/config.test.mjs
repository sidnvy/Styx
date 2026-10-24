import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readConfiguration } from './config.mjs';

test('trusted startup scope accepts exact private directories and rejects aliases, extra authorities and shared profile', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'styx-browser-config-'));
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
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
