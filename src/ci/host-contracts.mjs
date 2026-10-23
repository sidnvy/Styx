// Native Host contracts: platform-specific fixtures stay with their OS. New
// unclassified files default to shared, so adding a test cannot silently drop it.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {summarizeTap} from './acceptance.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const platforms = ['linux', 'darwin', 'win32'];
const specific = {
  linux: ['linux-build', 'linux-cli-acceptance', 'linux-cli-build', 'linux-desktop',
    'linux-gateway-quiescence', 'linux-gateway-update-acceptance', 'linux-payload-absence',
    'linux-service', 'managed-linux-pilot', 'managed-service-soak', 'managed-update-pilot'],
  darwin: ['macos-app', 'macos-launchagent', 'macos-local-signing',
    'macos-native-launcher', 'macos-platform-update', 'macos-preview'],
  win32: ['managed-windows-pilot', 'windows-stage-fast-path', 'windows-task-private'],
};
const owner = new Map(Object.entries(specific).flatMap(([platform, names]) =>
  names.map(name => [`host/test/${name}.test.mjs`, [platform]])));
// This fixture runs Python fcntl/flock, but never invokes codesign or Keychain.
// Keep its real POSIX lock coverage on Linux as well as macOS.
owner.set('host/test/macos-signing-session.test.mjs', ['linux', 'darwin']);

export function hostContractSelection(platform, {sourceRoot = root} = {}) {
  if (!platforms.includes(platform)) throw Error('unsupported_host_contract_platform');
  const files = ['host/test', 'host/windows'].flatMap(directory =>
    fs.readdirSync(path.join(sourceRoot, directory)).filter(name => name.endsWith('.test.mjs'))
      .map(name => `${directory}/${name}`));
  files.push('host/windows/platform-update/product.test.mjs');
  for (const file of owner.keys()) {
    if (!files.includes(file)) throw Error(`stale_host_contract_classification: ${file}`);
  }
  const inventory = files.sort().map(file => {
    const applicablePlatforms = owner.get(file) ?? (file.startsWith('host/windows/') ? ['win32'] : null);
    return {file, platforms: applicablePlatforms ?? platforms,
      reason: applicablePlatforms ? `${applicablePlatforms.join('/')} implementation/fixture contract` : 'shared Host contract'};
  });
  return {schema: 1, platform, inventory,
    selected: inventory.filter(entry => entry.platforms.includes(platform)).map(entry => entry.file),
    notApplicable: inventory.filter(entry => !entry.platforms.includes(platform))};
}

export function runHostContracts(directory, {sourceRoot = root, platform = process.platform, run = spawnSync} = {}) {
  if (platform !== process.platform) throw Error('host_contract_native_platform_required');
  const selection = hostContractSelection(platform, {sourceRoot});
  fs.mkdirSync(directory, {recursive: true});
  const receiptFile = path.join(directory, 'receipt.json');
  // Each file runs in a separate Node process with its own temporary fixtures.
  // Keep tests within a file serial; native build/smoke remains once per OS job.
  const args = ['--test', '--test-concurrency=4', '--test-reporter=tap', ...selection.selected];
  const receipt = {...selection, status: 'RUNNING', node: process.version,
    revision: process.env.GITHUB_SHA ?? null, fileConcurrency: 4, command: [process.execPath, ...args]};
  fs.writeFileSync(receiptFile, JSON.stringify(receipt, null, 2) + '\n');
  const fd = fs.openSync(path.join(directory, 'contracts.tap'), 'w');
  const start = Date.now();
  let result;
  try { result = run(process.execPath, args, {cwd: sourceRoot, stdio: ['ignore', fd, fd]}); }
  catch { result = {status: null, error: true}; }
  finally { fs.closeSync(fd); }
  const output = fs.readFileSync(path.join(directory, 'contracts.tap'), 'utf8');
  const summary = summarizeTap(output, result.error ? 1 : result.status);
  Object.assign(receipt, {status: summary.status, summary,
    exitCode: result.status, signal: result.signal ?? null, elapsedMs: Date.now() - start,
    log: 'contracts.tap'});
  fs.writeFileSync(receiptFile, JSON.stringify(receipt, null, 2) + '\n');
  process.stdout.write(output);
  return receipt;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === 'list') {
    console.log(JSON.stringify(hostContractSelection(process.argv[3] ?? process.platform), null, 2));
  } else {
    const directory = path.resolve(process.argv[2] ?? 'acceptance/host-contracts');
    process.exitCode = runHostContracts(directory).status === 'PASS' ? 0 : 1;
  }
}
