// Owner-reviewed, offline config migration only. Native jobs are never changed.
// Every managed file is replaced atomically, but the multi-file transaction is
// journaled: interrupted work requires explicit rollback, never automatic replay.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createHash, randomBytes} from 'node:crypto';
import {requirePrivateDirectory, requirePrivateFile, ensurePrivateDirectory} from '../host/private-storage.mjs';
import {macNativeAppRequirement, verifiedMacNativeLauncher} from '../host/macos-native-launcher.mjs';
import {statusMacLaunchAgent} from '../host/macos-launchagent.mjs';
import {validateDeployment} from './deployment-config.mjs';

const kind = 'mac-native-supervisor-v1';
const fail = code => { throw Error(code); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = value => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value;
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const lockNames = ['advance.lock', 'background.lock', 'capabilities.lock'];
const processOwnerToken = randomBytes(32).toString('hex');
function keys(value, allowed) {
  if (!object(value) || Object.keys(value).some(key => !allowed.includes(key))) fail('migration_invalid_options');
}
function bytes(file) {
  if (requirePrivateFile(file).size > 1024 * 1024) fail('migration_file_too_large');
  return fs.readFileSync(file);
}
const read = file => JSON.parse(bytes(file).toString('utf8'));
function syncDirectory(directory) {
  if (process.platform === 'win32') return;
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function atomic(file, data) {
  const temp = file + '.' + randomBytes(8).toString('hex') + '.tmp';
  const fd = fs.openSync(temp, 'wx', 0o600);
  try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try {
    requirePrivateFile(temp); fs.renameSync(temp, file);
    syncDirectory(path.dirname(file));
  } finally { if (fs.existsSync(temp)) fs.unlinkSync(temp); }
}
function maybeProtected(file, result) {
  if (fs.existsSync(file)) result.push({path: file, sha256: sha(bytes(file))});
}
function protectedTree(directory, result) {
  if (!fs.existsSync(directory)) return;
  requirePrivateDirectory(directory);
  for (const item of fs.readdirSync(directory).sort()) {
    const file = path.join(directory, item), info = fs.lstatSync(file);
    if (info.isSymbolicLink()) fail('migration_preserved_path_redirected');
    if (info.isDirectory()) protectedTree(file, result); else maybeProtected(file, result);
    if (result.length > 512) fail('migration_preserved_state_too_large');
  }
}
function snapshot(stateDir, nativeApp) {
  if (!absolute(stateDir)) fail('migration_absolute_state_required');
  requirePrivateDirectory(stateDir); macNativeAppRequirement(nativeApp);
  const configFile = path.join(stateDir, 'deployment.json'), stateFile = path.join(stateDir, 'state.json');
  const configBytes = bytes(configFile), stateBytes = bytes(stateFile);
  const config = JSON.parse(configBytes), state = JSON.parse(stateBytes);
  validateDeployment(config, {checkNetwork: false});
  if (config.schema !== 1 || !['create-local', 'join-existing'].includes(config.mode) ||
      state.schema !== 1 || state.mode !== config.mode || state.configSha256 !== sha(configBytes) ||
      !Array.isArray(state.steps)) fail('migration_deployment_binding_changed');
  if (!config.host || !absolute(config.host.baseDir)) fail('migration_local_host_required');
  requirePrivateDirectory(config.host.baseDir);
  const serviceFile = path.join(config.host.baseDir, 'service.json'), serviceBytes = bytes(serviceFile), service = JSON.parse(serviceBytes);
  keys(service, ['label', 'installRoot', 'hostConfigFile', 'trustPublicKeyFile', 'nodeBinary', 'logDir', 'nativeApp']);
  if (!/^app\.styx\.(?:connector|host(?:-pilot)?(?:\.[a-z0-9][a-z0-9-]{0,32})?)$/.test(service.label ?? '') ||
      service.installRoot !== path.join(config.host.baseDir, 'install') ||
      service.hostConfigFile !== path.join(config.host.baseDir, 'device', 'host.json') ||
      service.trustPublicKeyFile !== path.join(config.host.baseDir, 'publisher.pem') ||
      service.logDir !== path.join(config.host.baseDir, 'logs') || !absolute(service.nodeBinary) ||
      !service.nodeBinary.startsWith(service.installRoot + path.sep)) fail('migration_legacy_mac_service_binding_required');
  if (config.host.macPreviewApp !== undefined) fail('migration_preview_app_not_supported');
  if (config.host.macTeamID !== undefined && config.host.macTeamID !== nativeApp.teamID)
    fail('migration_existing_team_identity_mismatch');
  const prepared = state.steps.find(step => step.id === 'host.prepare' && step.status === 'succeeded');
  if (prepared?.evidence?.serviceConfiguration?.path !== serviceFile || prepared.evidence.serviceConfiguration.sha256 !== sha(serviceBytes))
    fail('migration_host_preparation_evidence_required');
  // All existing completed file evidence must still be intact before it can be
  // incorporated into a new authoritative config/state pair.
  for (const step of state.steps.filter(step => step.status === 'succeeded')) {
    for (const value of Object.values(step.evidence ?? {})) {
      if (object(value) && absolute(value.path) && /^[a-f0-9]{64}$/.test(value.sha256 ?? '') && sha(bytes(value.path)) !== value.sha256)
        fail('migration_completed_evidence_changed');
    }
  }
  const preserved = [];
  protectedTree(path.join(config.host.baseDir, 'device'), preserved);
  protectedTree(path.join(stateDir, 'gateway'), preserved);
  for (const name of ['enrollment.json', 'gateway-ca.pem', 'publisher.pem', 'setup-receipt.json', 'setup-state.json'])
    maybeProtected(path.join(config.host.baseDir, name), preserved);
  const auxiliary = [];
  for (const name of ['background', 'capabilities']) {
    const file = path.join(stateDir, name + '.json');
    if (!fs.existsSync(file)) continue;
    const before = bytes(file), value = JSON.parse(before);
    if (value.schema !== 1 || value.configSha256 !== sha(configBytes)) fail('migration_auxiliary_config_binding_changed');
    if (['running', 'uncertain', 'configuring'].includes(value.status) && name === 'capabilities' ||
        name === 'background' && (value.status === 'configuring' || !Array.isArray(value.operations) ||
          value.operations.some(entry => ['running', 'uncertain'].includes(entry.status))))
      fail('migration_auxiliary_operation_requires_reconciliation');
    auxiliary.push({name, path: file, before, value});
  }
  return {config, state, service, preserved, auxiliary,
    files: [{name: 'deployment', path: configFile, before: configBytes},
      {name: 'service', path: serviceFile, before: serviceBytes}, {name: 'state', path: stateFile, before: stateBytes}, ...auxiliary]};
}
function proposed(s, nativeApp, planId) {
  const config = {...s.config, host: {...s.config.host, macTeamID: nativeApp.teamID}};
  const service = {...s.service, nativeApp};
  const configAfter = encode(config), serviceAfter = encode(service);
  const state = structuredClone(s.state);
  state.configSha256 = sha(configAfter);
  state.steps.find(step => step.id === 'host.prepare').evidence.serviceConfiguration.sha256 = sha(serviceAfter);
  // Preserve historical evidence in the private before-state backup, then let
  // Core install the explicitly selected launcher through its normal workflow.
  // No installed job is ever replaced by this transaction.
  const resetSteps = [];
  state.steps = state.steps.map(step => {
    if (!step.id.startsWith('host.service.')) return step;
    resetSteps.push(step.id); return {id: step.id, status: 'pending'};
  });
  state.configMigrations = [...(state.configMigrations ?? []), {transactionId: planId, kind, status: 'applied_configuration_only'}];
  const after = [configAfter, serviceAfter, encode(state), ...(s.auxiliary ?? []).map(file => encode({...file.value, configSha256: sha(configAfter)}))];
  return {after, resetSteps};
}
function bindingId(s, nativeApp, reviewNonce) {
  return sha(JSON.stringify({kind, nativeApp, reviewNonce,
    files: s.files.map(file => ({path: file.path, beforeSha256: sha(file.before)})), preserved: s.preserved}));
}
function build(stateDir, nativeApp, reviewNonce, platform) {
  nativeApp = structuredClone(nativeApp);
  const s = snapshot(stateDir, nativeApp), blockers = [];
  if (platform !== 'darwin') blockers.push('native_mac_service_observation_unavailable_on_current_platform');
  if (s.state.steps.some(step => ['running', 'uncertain'].includes(step.status)) ||
      [...(s.state.maintenance ?? []), ...(s.state.gatewayMaintenance ?? [])].some(entry => ['running', 'uncertain'].includes(entry.status)))
    blockers.push('existing_uncertain_operation_requires_reconciliation');
  if (s.service.nativeApp !== undefined) blockers.push('native_supervisor_already_configured_or_requires_separate_identity_review');
  const planId = bindingId(s, nativeApp, reviewNonce);
  const {after, resetSteps} = proposed(s, nativeApp, planId);
  const changes = s.files.map((file, i) => ({name: file.name, path: file.path, beforeSha256: sha(file.before), afterSha256: sha(after[i])}));
  const plan = {schema: 1, kind, planId, reviewNonce, nativeApp, status: blockers.length ? 'blocked' : 'reviewable',
    blockers, changes, resetSteps, preserved: s.preserved,
    requires: ['fresh_host_service_absent_and_stopped_observation', 'signed_native_app_team_verification', 'explicit_exact_plan_authorization'],
    serviceMutation: 'NONE', nativeCompile: 'NOT RUN', tccAttribution: 'NOT RUN', systemPermissions: 'UNCHANGED', accountAcceptance: 'NOT RUN'};
  return {plan, snapshot: s, after};
}

export function planNativeSupervisorMigration(stateDir, options = {}, adapters = {}) {
  keys(options, ['nativeApp']);
  return build(stateDir, options.nativeApp, randomBytes(16).toString('hex'), adapters.platform ?? process.platform).plan;
}
function transactionDirectory(stateDir, transactionId) {
  if (!/^[a-f0-9]{64}$/.test(transactionId ?? '')) fail('migration_invalid_transaction_id');
  return path.join(stateDir, 'migrations', transactionId);
}
function ownerAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return true;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
}
function lock(stateDir, transactionId, existing, name, adapters) {
  const file = path.join(stateDir, name);
  let fd, value;
  if (existing && fs.existsSync(file)) {
    value = read(file);
    if (value.kind !== kind || value.transactionId !== transactionId || value.token !== existing.token)
      fail('migration_foreign_or_interrupted_lock');
    fd = fs.openSync(file, 'r+');
    const info = fs.fstatSync(fd);
    if (String(info.ino) !== existing.ino || String(info.dev) !== existing.dev) {
      fs.closeSync(fd); fail('migration_lock_identity_changed');
    }
    if (!Number.isSafeInteger(value.ownerPid) || !/^[a-f0-9]{64}$/.test(value.ownerToken ?? '') ||
        (adapters.ownerAlive ?? ownerAlive)(value.ownerPid)) {
      fs.closeSync(fd); fail('migration_live_or_unknown_lock_owner');
    }
    // The exclusive recovery guard spans all three adoptions and every await.
    // Keep the creation token/inode, but identify the new process before writes.
    value.ownerPid = process.pid; value.ownerToken = processOwnerToken;
    fs.ftruncateSync(fd, 0); fs.writeFileSync(fd, encode(value)); fs.fsyncSync(fd);
  } else {
    try { fd = fs.openSync(file, 'wx', 0o600); } catch { fail('onboarding_busy_or_interrupted_lock'); }
    value = {kind, transactionId, token: randomBytes(32).toString('hex'), ownerPid: process.pid, ownerToken: processOwnerToken};
    try { fs.writeFileSync(fd, encode(value)); fs.fsyncSync(fd); } catch (error) { fs.closeSync(fd); throw error; }
  }
  const info = fs.fstatSync(fd);
  const identity = {token: value.token, ino: String(info.ino), dev: String(info.dev), ownerPid: value.ownerPid, ownerToken: value.ownerToken};
  let closed = false;
  return {identity, close(retain = false) {
    if (closed) return; closed = true;
    try {
      const actual = fs.lstatSync(file);
      if (!retain && String(actual.ino) === identity.ino && String(actual.dev) === identity.dev && read(file).token === identity.token)
        fs.unlinkSync(file);
    } finally { fs.closeSync(fd); }
  }};
}
function locks(stateDir, transactionId, existing = {}, adapters = {}) {
  const acquired = [];
  try {
    // All acquisitions are nonblocking. Existing background/capability flows
    // may acquire their lock before advance.lock; a conflict releases ours.
    for (const name of lockNames) {
      const wasPresent = fs.existsSync(path.join(stateDir, name));
      const handle = lock(stateDir, transactionId, existing[name], name, adapters);
      acquired.push({name, handle, wasPresent});
    }
    syncDirectory(stateDir);
  } catch (error) {
    for (const item of acquired.reverse()) item.handle.close(item.wasPresent);
    throw error;
  }
  return {identity: Object.fromEntries(acquired.map(item => [item.name, item.handle.identity])),
    close(retain = false) { for (const item of acquired.reverse()) item.handle.close(retain); }};
}
function recoveryGuard(directory) {
  const file = path.join(directory, 'recovery.lock'); let fd;
  // Never steal a recovery guard. A process crash here requires explicit owner
  // inspection of this private transaction; automatic stale-guard removal has
  // a read/unlink race and could admit two recoveries.
  try { fd = fs.openSync(file, 'wx', 0o600); } catch { fail('migration_recovery_in_progress_or_guard_requires_inspection'); }
  const token = randomBytes(32).toString('hex');
  fs.writeFileSync(fd, encode({ownerPid: process.pid, ownerToken: processOwnerToken, token})); fs.fsyncSync(fd); syncDirectory(directory);
  const info = fs.fstatSync(fd);
  return {close() {
    try {
      const actual = fs.lstatSync(file);
      if (actual.ino === info.ino && actual.dev === info.dev && read(file).token === token) {
        fs.unlinkSync(file); syncDirectory(directory);
      }
    } finally { fs.closeSync(fd); }
  }};
}
export function observeNativeSupervisorServiceAbsence(serviceFile, adapters = {}) {
  // Absence depends on launchd and the exact plist path, not whether a newly
  // selected App exists or passes codesign. This keeps offline rollback usable.
  const service = read(serviceFile), label = service.label;
  if (!/^app\.styx\.(?:connector|host(?:-pilot)?(?:\.[a-z0-9][a-z0-9-]{0,32})?)$/.test(label ?? ''))
    fail('migration_invalid_service_label');
  const home = adapters.home ?? os.homedir();
  if (!absolute(home)) fail('migration_absolute_native_home_required');
  const plist = path.join(home, 'Library', 'LaunchAgents', label + '.plist');
  let installed;
  try { fs.lstatSync(plist); installed = true; } catch (error) { if (error.code !== 'ENOENT') throw error; installed = false; }
  const native = (adapters.statusAgent ?? statusMacLaunchAgent)(label);
  return {status: native.status === 'not_loaded' && native.loaded === false ? 'reported' : 'unavailable',
    installed, state: native.status === 'not_loaded' && native.loaded === false ? 'stopped' : 'unknown',
    role: 'host', action: 'status', manager: 'launchd-user'};
}
async function absent(serviceFile, adapters) {
  if ((adapters.platform ?? process.platform) !== 'darwin') fail('migration_native_mac_observation_required');
  const result = await (adapters.observeService ?? (file => observeNativeSupervisorServiceAbsence(file, adapters)))(serviceFile);
  if (result?.status !== 'reported' || result.installed !== false || !['stopped', 'not_installed'].includes(result.state) ||
      result.role !== 'host' || result.action !== 'status' || result.manager !== 'launchd-user')
    fail('migration_host_service_must_be_observed_absent_and_stopped');
}
function checkPreserved(preserved) {
  for (const file of preserved) if (sha(bytes(file.path)) !== file.sha256) fail('migration_preserved_identity_or_credentials_changed');
}
function journalResult(journal) {
  return {schema: 1, transactionId: journal.transactionId, kind, status: journal.status,
    files: journal.files.map(({path: file, beforeSha256, afterSha256}) => ({path: file, beforeSha256, afterSha256})),
    identityAndCredentials: 'preserved', serviceMutation: 'NONE', nativeCompile: 'NOT RUN', tccAttribution: 'NOT RUN', accountAcceptance: 'NOT RUN'};
}

export async function applyNativeSupervisorMigration(stateDir, options = {}, adapters = {}) {
  keys(options, ['plan', 'authorize']);
  if (options.authorize !== true || !object(options.plan) || !/^[a-f0-9]{32}$/.test(options.plan.reviewNonce ?? ''))
    fail('migration_explicit_reviewed_plan_required');
  const reviewed = structuredClone(options.plan);
  const expected = build(stateDir, reviewed.nativeApp, reviewed.reviewNonce, adapters.platform ?? process.platform);
  if (JSON.stringify(expected.plan) !== JSON.stringify(reviewed)) fail('migration_reviewed_plan_changed');
  if (expected.plan.blockers.length) fail('migration_plan_blocked');
  const transactionId = expected.plan.planId, directory = transactionDirectory(stateDir, transactionId);
  const ownership = locks(stateDir, transactionId, {}, adapters);
  let attempted = false, journal;
  try {
    if (fs.existsSync(directory)) fail('migration_transaction_exists_no_replay');
    const serviceFile = expected.snapshot.files.find(file => file.name === 'service').path;
    await absent(serviceFile, adapters);
    (adapters.verifyLauncher ?? verifiedMacNativeLauncher)(expected.plan.nativeApp);
    // Native observation and codesign may yield; authorize only the exact still
    // current plan after both complete, under the shared deployment lock.
    const current = build(stateDir, reviewed.nativeApp, reviewed.reviewNonce, adapters.platform ?? process.platform);
    if (JSON.stringify(current.plan) !== JSON.stringify(expected.plan)) fail('migration_reviewed_plan_changed');
    const parent = path.dirname(directory);
    ensurePrivateDirectory(parent); ensurePrivateDirectory(directory);
    syncDirectory(stateDir); syncDirectory(parent);
    const files = current.snapshot.files.map((file, i) => ({...current.plan.changes[i],
      beforeFile: file.name + '.before', afterFile: file.name + '.after'}));
    for (let i = 0; i < files.length; i++) {
      fs.writeFileSync(path.join(directory, files[i].beforeFile), current.snapshot.files[i].before, {flag: 'wx', mode: 0o600});
      fs.writeFileSync(path.join(directory, files[i].afterFile), current.after[i], {flag: 'wx', mode: 0o600});
      for (const name of [files[i].beforeFile, files[i].afterFile]) {
        const fd = fs.openSync(path.join(directory, name), 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      }
    }
    journal = {schema: 1, kind, transactionId, status: 'prepared', createdAt: new Date().toISOString(),
      nativeApp: current.plan.nativeApp, reviewNonce: current.plan.reviewNonce, files, preserved: current.snapshot.preserved, lock: ownership.identity};
    const journalFile = path.join(directory, 'journal.json'); atomic(journalFile, encode(journal));
    checkPreserved(journal.preserved);
    for (let i = 0; i < files.length; i++) {
      if (sha(bytes(files[i].path)) !== files[i].beforeSha256) fail('migration_managed_file_changed');
      journal.status = 'applying'; journal.activeFile = files[i].name; atomic(journalFile, encode(journal));
      attempted = true;
      (adapters.replaceManagedFile ?? atomic)(files[i].path, current.after[i]);
      if (sha(bytes(files[i].path)) !== files[i].afterSha256) fail('migration_write_verification_failed');
    }
    checkPreserved(journal.preserved);
    journal.status = 'applied'; delete journal.activeFile; journal.completedAt = new Date().toISOString();
    atomic(journalFile, encode(journal));
    return journalResult(journal);
  } catch (error) {
    if (attempted && journal) {
      journal.status = 'uncertain';
      try { atomic(path.join(directory, 'journal.json'), encode(journal)); } catch {}
      fail('migration_uncertain_explicit_rollback_required');
    }
    throw error;
  } finally { ownership.close(attempted && journal?.status !== 'applied'); }
}

function rollbackJournal(stateDir, transactionId) {
  requirePrivateDirectory(stateDir);
  const directory = transactionDirectory(stateDir, transactionId); requirePrivateDirectory(directory);
  const journal = read(path.join(directory, 'journal.json'));
  if (journal.schema !== 1 || journal.kind !== kind || journal.transactionId !== transactionId ||
      !['applied', 'applying', 'uncertain', 'rolling_back'].includes(journal.status) || !Array.isArray(journal.files) ||
      journal.files.length < 3 || journal.files.length > 5)
    fail('migration_transaction_not_rollbackable');
  macNativeAppRequirement(journal.nativeApp);
  if (!/^[a-f0-9]{32}$/.test(journal.reviewNonce ?? '')) fail('migration_invalid_rollback_scope');
  const original = JSON.parse(bytes(path.join(directory, 'deployment.before')));
  validateDeployment(original, {checkNetwork: false});
  const expected = {deployment: path.join(stateDir, 'deployment.json'), state: path.join(stateDir, 'state.json'),
    service: path.join(original.host?.baseDir ?? '', 'service.json'), background: path.join(stateDir, 'background.json'), capabilities: path.join(stateDir, 'capabilities.json')};
  const names = journal.files.map(file => file.name);
  if (!absolute(original.host?.baseDir) || new Set(names).size !== names.length || !Array.isArray(journal.preserved) ||
      JSON.stringify(names) !== JSON.stringify(['deployment', 'service', 'state', ...['background', 'capabilities'].filter(name => names.includes(name))]))
    fail('migration_invalid_rollback_scope');
  for (const name of ['background', 'capabilities']) {
    if (!names.includes(name) && fs.existsSync(expected[name])) fail('migration_new_auxiliary_state_refuse_rollback');
  }
  for (const file of journal.files) {
    if (file.path !== expected[file.name] || file.beforeFile !== file.name + '.before' || file.afterFile !== file.name + '.after' ||
        sha(bytes(path.join(directory, file.beforeFile))) !== file.beforeSha256 || sha(bytes(path.join(directory, file.afterFile))) !== file.afterSha256)
      fail('migration_backup_or_scope_changed');
    if (![file.beforeSha256, file.afterSha256].includes(sha(bytes(file.path)))) fail('migration_foreign_changes_refuse_rollback');
  }
  // Reconstruct the reviewed transaction from its original bytes. The journal
  // cannot silently broaden the write scope or substitute different backups.
  const s = {config: original, state: JSON.parse(bytes(path.join(directory, 'state.before'))),
    service: JSON.parse(bytes(path.join(directory, 'service.before'))), preserved: journal.preserved,
    files: journal.files.map(file => ({path: file.path, before: bytes(path.join(directory, file.beforeFile))})),
    auxiliary: journal.files.filter(file => ['background', 'capabilities'].includes(file.name)).map(file => ({value: JSON.parse(bytes(path.join(directory, file.beforeFile)))}))};
  if (bindingId(s, journal.nativeApp, journal.reviewNonce) !== transactionId) fail('migration_journal_binding_changed');
  const {after} = proposed(s, journal.nativeApp, transactionId);
  if (journal.files.some((file, i) => sha(after[i]) !== file.afterSha256)) fail('migration_backup_or_scope_changed');
  return {directory, journal};
}

export async function rollbackNativeSupervisorMigration(stateDir, options = {}, adapters = {}) {
  keys(options, ['transactionId', 'authorize']);
  if (options.authorize !== true || !absolute(stateDir)) fail('migration_explicit_rollback_authorization_required');
  let {directory, journal} = rollbackJournal(stateDir, options.transactionId);
  const guard = recoveryGuard(directory);
  let ownership;
  const recoveringInterruptedLock = lockNames.some(name => fs.existsSync(path.join(stateDir, name)));
  let attempted = false;
  try {
    ownership = locks(stateDir, options.transactionId, journal.lock, adapters);
    await absent(journal.files.find(file => file.name === 'service').path, adapters);
    ({directory, journal} = rollbackJournal(stateDir, options.transactionId));
    checkPreserved(journal.preserved);
    journal.lock = ownership.identity; journal.status = 'rolling_back';
    atomic(path.join(directory, 'journal.json'), encode(journal));
    for (const file of [...journal.files].reverse()) {
      if (sha(bytes(file.path)) === file.beforeSha256) continue;
      journal.activeFile = file.name; atomic(path.join(directory, 'journal.json'), encode(journal));
      attempted = true;
      (adapters.replaceManagedFile ?? atomic)(file.path, bytes(path.join(directory, file.beforeFile)));
      if (sha(bytes(file.path)) !== file.beforeSha256) fail('migration_rollback_write_verification_failed');
    }
    checkPreserved(journal.preserved);
    journal.status = 'rolled_back'; delete journal.activeFile; journal.completedAt = new Date().toISOString();
    atomic(path.join(directory, 'journal.json'), encode(journal));
    return journalResult(journal);
  } catch (error) {
    if (attempted) {
      journal.status = 'uncertain';
      try { atomic(path.join(directory, 'journal.json'), encode(journal)); } catch {}
      fail('migration_rollback_uncertain_preserve_state');
    }
    throw error;
  } finally {
    try { ownership?.close((attempted || recoveringInterruptedLock) && journal.status !== 'rolled_back'); }
    finally { guard.close(); }
  }
}
