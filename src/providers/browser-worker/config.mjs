import fs from 'node:fs';
import path from 'node:path';

const CONFIG_LIMIT = 16 * 1024;
const fields = ['schema', 'profile_dir', 'output_dir', 'workspace_dir', 'browser_executable'];
const fail = () => { throw new Error('browser_worker_configuration_rejected'); };
function pinnedKernelFile(value) {
  return typeof value === 'string' && /^\/proc\/[1-9][0-9]*\/fd\/[0-9]+$/.test(value);
}
function canonical(value) {
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\0\r\n]/.test(value) || !path.isAbsolute(value)) fail();
  const absolute = path.resolve(value);
  if (value !== absolute || fs.realpathSync(value) !== absolute) fail();
  return value;
}
function privateEntry(stats) {
  if (process.platform !== 'win32' && (stats.uid !== process.getuid() || (stats.mode & 0o077) !== 0)) fail();
}
function directory(value) {
  canonical(value);
  const stats = fs.lstatSync(value);
  if (!stats.isDirectory() || stats.isSymbolicLink()) fail();
  privateEntry(stats);
}
function within(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}
// Defensive shape/filesystem checks only. Rust supplies the authorized scope;
// this function does not choose a profile, owner, URL policy or credentials.
export function readConfiguration(file) {
  const pinned = pinnedKernelFile(file);
  if (!pinned) canonical(file);
  const before = pinned ? fs.statSync(file) : fs.lstatSync(file);
  if (!before.isFile() || (!pinned && before.isSymbolicLink()) || before.nlink !== 1 || before.size > CONFIG_LIMIT) fail();
  privateEntry(before);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (pinned ? 0 : (fs.constants.O_NOFOLLOW ?? 0)));
  let config;
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) fail();
    privateEntry(opened);
    const buffer = Buffer.alloc(CONFIG_LIMIT + 1);
    const count = fs.readSync(fd, buffer, 0, buffer.length, 0);
    if (count > CONFIG_LIMIT) fail();
    config = JSON.parse(buffer.subarray(0, count).toString('utf8'));
    const after = fs.fstatSync(fd);
    if (after.size !== count || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) fail();
  } finally { fs.closeSync(fd); }
  if (!config || typeof config !== 'object' || Array.isArray(config) || config.schema !== 1 || Object.keys(config).length !== fields.length || fields.some(key => !Object.hasOwn(config, key))) fail();
  for (const key of ['profile_dir', 'output_dir', 'workspace_dir']) directory(config[key]);
  const executablePinned = pinnedKernelFile(config.browser_executable);
  if (!executablePinned) canonical(config.browser_executable);
  const executable = executablePinned ? fs.statSync(config.browser_executable) : fs.lstatSync(config.browser_executable);
  if (!executable.isFile() || (!executablePinned && executable.isSymbolicLink()) || (process.platform !== 'win32' && !(executable.mode & 0o111))) fail();
  for (const other of [config.output_dir, config.workspace_dir]) {
    if (within(config.profile_dir, other) || within(other, config.profile_dir)) fail();
  }
  return Object.freeze(config);
}
