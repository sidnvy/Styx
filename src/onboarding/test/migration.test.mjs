import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
import {planNativeSupervisorMigration, applyNativeSupervisorMigration, rollbackNativeSupervisorMigration, observeNativeSupervisorServiceAbsence} from '../migration.mjs';
import {spawn} from 'node:child_process';
import {once} from 'node:events';

const nativeApp = {path: '/Applications/Styx.app', teamID: 'ABCDEFGHIJ'};
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const write = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', {mode: 0o600});
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
// These injected observations exercise transaction logic only. They are not
// evidence that launchd, a compiled App or TCC has been tested on macOS.
const observedAbsent = {status: 'reported', installed: false, state: 'stopped', role: 'host', action: 'status', manager: 'launchd-user'};
const adapters = () => ({platform: 'darwin', observeService: async () => observedAbsent, verifyLauncher() {}, ownerAlive: () => false});
const lockNames = ['advance.lock', 'background.lock', 'capabilities.lock'];
function fixture(t, mode = 'create-local') {
  const root = path.join(os.tmpdir(), 'styx-migration-' + randomUUID()); ensurePrivateDirectory(root);
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const d = path.join(root, 'deployment'), baseDir = path.join(root, 'host'); ensurePrivateDirectory(d); ensurePrivateDirectory(baseDir);
  for (const folder of ['device', 'logs', 'install']) ensurePrivateDirectory(path.join(baseDir, folder));
  const deviceDir = path.join(baseDir, 'device');
  for (const [name, value] of Object.entries({'identity.json': '{"identity":"EXISTING_IDENTITY"}', 'host.json': '{"host_id":"existing-host"}',
    'host.token': 'EXISTING_HOST_CREDENTIAL', 'private-key.pem': 'EXISTING_HOST_PRIVATE_KEY'}))
    fs.writeFileSync(path.join(deviceDir, name), value, {mode: 0o600});
  for (const [name, value] of Object.entries({'publisher.pem': 'EXISTING_PUBLISHER', 'enrollment.json': '{"label":"Existing host"}',
    'gateway-ca.pem': 'EXISTING_CA', 'setup-receipt.json': '{"status":"prepared_not_paired"}', 'setup-state.json': '{"status":"prepared"}'}))
    fs.writeFileSync(path.join(baseDir, name), value, {mode: 0o600});
  if (mode === 'create-local') {
    const gateway = path.join(d, 'gateway'); ensurePrivateDirectory(gateway);
    for (const name of ['certificate.pem', 'private-key.pem', 'admin.token', 'model.token', 'enrollment.json'])
      fs.writeFileSync(path.join(gateway, name), 'EXISTING_GATEWAY_' + name, {mode: 0o600});
  }
  const configFile = path.join(d, 'deployment.json'), stateFile = path.join(d, 'state.json'), serviceFile = path.join(baseDir, 'service.json');
  const config = {schema: 1, mode, gateway: {url: 'https://127.0.0.1:8795', ...(mode === 'create-local' ? {openssl: process.execPath} : {})},
    host: {baseDir, bundle: path.join(root, 'bundle'), publisherKeyFile: path.join(baseDir, 'publisher.pem'), publisherSha256: 'a'.repeat(64), computer: false, label: 'Existing host'}};
  const service = {label: 'app.styx.connector', installRoot: path.join(baseDir, 'install'), hostConfigFile: path.join(deviceDir, 'host.json'),
    trustPublicKeyFile: path.join(baseDir, 'publisher.pem'), nodeBinary: path.join(baseDir, 'install', 'releases', 'v1', 'bin', 'node'), logDir: path.join(baseDir, 'logs')};
  write(configFile, config); write(serviceFile, service);
  const state = {schema: 1, mode, configSha256: sha(fs.readFileSync(configFile)), steps: [
    {id: 'host.prepare', status: 'succeeded', evidence: {serviceConfiguration: {path: serviceFile, sha256: sha(fs.readFileSync(serviceFile))},
      enrollmentConfiguration: {path: path.join(baseDir, 'enrollment.json'), sha256: sha(fs.readFileSync(path.join(baseDir, 'enrollment.json')))}}},
    {id: 'host.pair', status: 'succeeded', evidence: {device_id: 'existing-device'}},
    {id: 'host.doctor', status: 'succeeded', evidence: {status: 'ready_for_exec'}},
    {id: 'host.service.install', status: 'succeeded'}, {id: 'host.service.start', status: 'succeeded'}, {id: 'host.service.status', status: 'succeeded'}]};
  write(stateFile, state);
  return {root, d, baseDir, configFile, stateFile, serviceFile, config, state, service,
    plan: () => planNativeSupervisorMigration(d, {nativeApp}, adapters())};
}

test('offline review plan identifies exact files, preservation and unavailable native evidence without changing bytes', t => {
  const f = fixture(t), before = [f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file, 'utf8'));
  const plan = f.plan();
  assert.equal(plan.status, 'reviewable'); assert.equal(plan.changes.length, 3); assert.equal(plan.resetSteps.length, 3);
  assert.equal(plan.nativeCompile, 'NOT RUN'); assert.equal(plan.tccAttribution, 'NOT RUN'); assert.equal(plan.serviceMutation, 'NONE');
  assert.ok(plan.preserved.some(file => file.path.endsWith('host.token')));
  assert.ok(plan.preserved.some(file => file.path.endsWith('gateway/private-key.pem')));
  assert.ok(!JSON.stringify(plan).includes('EXISTING_HOST_CREDENTIAL'));
  assert.deepEqual([f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file, 'utf8')), before);
  if (process.platform !== 'darwin') assert.equal(planNativeSupervisorMigration(f.d, {nativeApp}).status, 'blocked');
});

test('reviewed config-only apply and byte-exact rollback preserve both identities and pairing, using injected native observations', async t => {
  const f = fixture(t), original = [f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file));
  const plan = f.plan(), preserved = plan.preserved.map(file => [file.path, fs.readFileSync(file.path)]);
  let observations = 0, verifications = 0;
  const dependencies = {...adapters(), observeService: async () => { observations++; return observedAbsent; }, verifyLauncher: app => { verifications++; assert.deepEqual(app, nativeApp); }};
  const result = await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, dependencies);
  assert.equal(result.status, 'applied'); assert.equal(observations, 1); assert.equal(verifications, 1);
  assert.deepEqual(read(f.serviceFile).nativeApp, nativeApp); assert.equal(read(f.configFile).host.macTeamID, nativeApp.teamID);
  const state = read(f.stateFile); assert.equal(state.configSha256, sha(fs.readFileSync(f.configFile)));
  assert.equal(state.steps[0].evidence.serviceConfiguration.sha256, sha(fs.readFileSync(f.serviceFile)));
  assert.equal(state.steps[1].status, 'succeeded'); assert.equal(state.steps[3].status, 'pending');
  assert.equal(state.configMigrations[0].transactionId, result.transactionId);
  assert.equal(fs.existsSync(path.join(f.d, 'advance.lock')), false);
  const rolled = await rollbackNativeSupervisorMigration(f.d, {transactionId: result.transactionId, authorize: true}, dependencies);
  assert.equal(rolled.status, 'rolled_back'); assert.equal(observations, 2);
  assert.deepEqual([f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file)), original);
  for (const [file, contents] of preserved) assert.deepEqual(fs.readFileSync(file), contents);
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: result.transactionId, authorize: true}, dependencies), /not_rollbackable/);
});

test('join-existing migration never creates Gateway identity or runtime material', async t => {
  const f = fixture(t, 'join-existing'), plan = f.plan();
  await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
  assert.equal(fs.existsSync(path.join(f.d, 'gateway')), false);
  assert.equal(read(f.configFile).mode, 'join-existing');
  assert.equal(read(f.stateFile).steps.find(step => step.id === 'host.pair').evidence.device_id, 'existing-device');
});

test('installed, loaded, running, unknown or unobserved service always blocks before any managed file writes', async t => {
  for (const observation of [undefined, {...observedAbsent, installed: true}, {...observedAbsent, state: 'running'},
    {...observedAbsent, state: 'loaded'}, {...observedAbsent, status: 'blocked'}, {...observedAbsent, state: 'unknown'},
    {...observedAbsent, manager: 'systemd-user'}]) {
    const f = fixture(t), plan = f.plan(), before = fs.readFileSync(f.serviceFile);
    await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, {...adapters(), observeService: async () => observation}), /must_be_observed_absent/);
    assert.deepEqual(fs.readFileSync(f.serviceFile), before); assert.equal(fs.existsSync(path.join(f.d, 'advance.lock')), false);
    assert.equal(fs.existsSync(path.join(f.d, 'migrations')), false);
  }
});

test('missing authorization, modified plan, existing Core lock and code signing failure refuse mutation', async t => {
  const f = fixture(t), plan = f.plan();
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan}, adapters()), /explicit_reviewed_plan/);
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan: {...plan, blockers: ['tampered']}, authorize: true}, adapters()), /reviewed_plan_changed/);
  fs.writeFileSync(path.join(f.d, 'advance.lock'), 'CORE_OWNS_THIS_LOCK', {mode: 0o600});
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters()), /busy_or_interrupted_lock/);
  assert.equal(fs.readFileSync(path.join(f.d, 'advance.lock'), 'utf8'), 'CORE_OWNS_THIS_LOCK');
  fs.unlinkSync(path.join(f.d, 'advance.lock'));
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, {...adapters(), verifyLauncher() { throw Error('native_app_signature_invalid'); }}), /signature_invalid/);
  assert.equal(fs.existsSync(path.join(f.d, 'migrations')), false);
});

test('configuration/evidence drift and identity/credential changes invalidate a reviewed plan', async t => {
  const f = fixture(t), plan = f.plan();
  fs.appendFileSync(path.join(f.baseDir, 'device', 'host.token'), '_CHANGED');
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters()), /reviewed_plan_changed/);
  fs.appendFileSync(f.serviceFile, ' ');
  assert.throws(f.plan, /preparation_evidence_required/);
});

test('team changes, preview apps, foreign service bindings and uncertain Core work are never silently adopted', t => {
  const f = fixture(t);
  f.config.host.macTeamID = 'ZYXWVUTSRQ'; write(f.configFile, f.config); f.state.configSha256 = sha(fs.readFileSync(f.configFile)); write(f.stateFile, f.state);
  assert.throws(f.plan, /existing_team_identity_mismatch/);
  delete f.config.host.macTeamID; f.config.host.macPreviewApp = {path: '/tmp/Styx.app'}; write(f.configFile, f.config);
  f.state.configSha256 = sha(fs.readFileSync(f.configFile)); write(f.stateFile, f.state);
  assert.throws(f.plan, /preview_app_not_supported/);
  delete f.config.host.macPreviewApp; write(f.configFile, f.config); f.state.configSha256 = sha(fs.readFileSync(f.configFile));
  f.state.maintenance = [{action: 'start', status: 'uncertain'}]; write(f.stateFile, f.state);
  assert.equal(f.plan().status, 'blocked');
  f.service.hostConfigFile = '/tmp/foreign-host.json'; write(f.serviceFile, f.service);
  assert.throws(f.plan, /legacy_mac_service_binding_required/);
});

test('partial file replacement retains token-bound Core lock and explicit rollback recovers original bytes', async t => {
  const f = fixture(t), plan = f.plan(), original = [f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file));
  let writes = 0;
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, {...adapters(), replaceManagedFile(file, contents) {
    writes++; if (writes === 2) throw Error('injected disk failure'); fs.writeFileSync(file, contents);
  }}), /uncertain_explicit_rollback_required/);
  const lockFile = path.join(f.d, 'advance.lock'); assert.equal(fs.existsSync(lockFile), true);
  const journalFile = path.join(f.d, 'migrations', plan.planId, 'journal.json');
  assert.equal(read(journalFile).status, 'uncertain');
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters()));
  const result = await rollbackNativeSupervisorMigration(f.d, {transactionId: plan.planId, authorize: true}, adapters());
  assert.equal(result.status, 'rolled_back'); assert.equal(fs.existsSync(lockFile), false);
  assert.deepEqual([f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file)), original);
});

test('rollback refuses foreign changed files and modified backups', async t => {
  const f = fixture(t), plan = f.plan();
  const result = await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
  const original = fs.readFileSync(f.serviceFile); fs.appendFileSync(f.serviceFile, ' ');
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: result.transactionId, authorize: true}, adapters()), /foreign_changes_refuse_rollback/);
  fs.writeFileSync(f.serviceFile, original);
  const backup = path.join(f.d, 'migrations', result.transactionId, 'service.before'); fs.appendFileSync(backup, ' ');
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: result.transactionId, authorize: true}, adapters()), /backup_or_scope_changed/);
});

test('state changes during native observation invalidate apply after await', async t => {
  const f = fixture(t), plan = f.plan();
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, {...adapters(), observeService: async () => {
    fs.appendFileSync(path.join(f.baseDir, 'device', 'host.token'), '_NEW'); return observedAbsent;
  }}), /reviewed_plan_changed/);
  assert.equal(fs.existsSync(path.join(f.d, 'migrations')), false);
});

test('existing background/capability journals preserve history while rebinding authority, then rollback exact bytes', async t => {
  const f = fixture(t), digest = sha(fs.readFileSync(f.configFile));
  const background = path.join(f.d, 'background.json'), capabilities = path.join(f.d, 'capabilities.json');
  const bg = {schema: 1, configSha256: digest, status: 'running', operations: [{id: 'host.start', status: 'succeeded'}], gateway: 'running', updatedAt: '2026-10-19T01:00:00Z'};
  const cap = {schema: 1, configSha256: digest, status: 'updated', requestedComputer: true, computer: true, phase: 'complete'};
  write(background, bg); write(capabilities, cap);
  const originals = [background, capabilities].map(file => fs.readFileSync(file));
  const plan = f.plan(); assert.equal(plan.changes.length, 5);
  const result = await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
  const nextHash = sha(fs.readFileSync(f.configFile));
  assert.deepEqual(read(background), {...bg, configSha256: nextHash}); assert.deepEqual(read(capabilities), {...cap, configSha256: nextHash});
  await rollbackNativeSupervisorMigration(f.d, {transactionId: result.transactionId, authorize: true}, adapters());
  assert.deepEqual([background, capabilities].map(file => fs.readFileSync(file)), originals);
});

test('old auxiliary scope mismatch or uncertain operations block migration before any managed change', t => {
  for (const [name, value] of [['background', {schema: 1, configSha256: '0'.repeat(64), status: 'running', operations: []}],
    ['background', {schema: 1, status: 'needs_attention', operations: [{id: 'host.start', status: 'uncertain'}]}],
    ['capabilities', {schema: 1, status: 'uncertain'}]]) {
    const f = fixture(t);
    write(path.join(f.d, name + '.json'), {configSha256: sha(fs.readFileSync(f.configFile)), ...value});
    assert.throws(f.plan, /auxiliary_(config_binding_changed|operation_requires_reconciliation)/);
  }
});

test('any existing background/capability/Core lock prevents migration, releases only newly acquired locks', async t => {
  for (const locked of lockNames) {
    const f = fixture(t), plan = f.plan(), foreign = path.join(f.d, locked);
    fs.writeFileSync(foreign, 'OTHER_WORKFLOW_OWNS_THIS', {mode: 0o600});
    await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters()), /busy_or_interrupted_lock/);
    assert.equal(fs.readFileSync(foreign, 'utf8'), 'OTHER_WORKFLOW_OWNS_THIS');
    for (const name of lockNames.filter(name => name !== locked)) assert.equal(fs.existsSync(path.join(f.d, name)), false);
  }
});

test('refused interrupted rollback retains all matching locks; a second explicit recovery succeeds', async t => {
  const f = fixture(t), plan = f.plan();
  let writes = 0;
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, {...adapters(), replaceManagedFile(file, data) {
    if (++writes === 2) throw Error('injected failure'); fs.writeFileSync(file, data);
  }}), /uncertain/);
  const identities = lockNames.map(name => fs.readFileSync(path.join(f.d, name), 'utf8'));
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: plan.planId, authorize: true},
    {...adapters(), observeService: async () => ({...observedAbsent, state: 'unknown'})}), /must_be_observed_absent/);
  assert.deepEqual(lockNames.map(name => fs.readFileSync(path.join(f.d, name), 'utf8')), identities);
  await rollbackNativeSupervisorMigration(f.d, {transactionId: plan.planId, authorize: true}, adapters());
  for (const name of lockNames) assert.equal(fs.existsSync(path.join(f.d, name)), false);
});

test('replaced lock token is refused and never stolen during uncertain migration recovery', async t => {
  const f = fixture(t), plan = f.plan(); let writes = 0;
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, {...adapters(), replaceManagedFile(file, data) {
    if (++writes === 2) throw Error('injected failure'); fs.writeFileSync(file, data);
  }}), /uncertain/);
  const foreign = path.join(f.d, 'background.lock');
  const changed = {...read(foreign), token: 'FOREIGN_TOKEN'}; write(foreign, changed);
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: plan.planId, authorize: true}, adapters()), /foreign_or_interrupted_lock/);
  assert.deepEqual(read(foreign), changed);
  assert.equal(fs.existsSync(path.join(f.d, 'advance.lock')), true);
  assert.equal(fs.existsSync(path.join(f.d, 'capabilities.lock')), true);
});

test('new config-bound auxiliary state after apply blocks rollback rather than corrupting its binding', async t => {
  const f = fixture(t), plan = f.plan();
  const result = await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
  write(path.join(f.d, 'capabilities.json'), {schema: 1, status: 'updated', configSha256: sha(fs.readFileSync(f.configFile))});
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: result.transactionId, authorize: true}, adapters()), /new_auxiliary_state_refuse_rollback/);
  assert.equal(read(f.configFile).host.macTeamID, nativeApp.teamID);
});

test('rollback refuses protected credential drift even when every managed configuration still matches', async t => {
  const f = fixture(t), plan = f.plan();
  const result = await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
  fs.appendFileSync(path.join(f.baseDir, 'device', 'host.token'), '_OTHER_WORKFLOW');
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: result.transactionId, authorize: true}, adapters()), /preserved_identity_or_credentials_changed/);
  assert.equal(read(f.configFile).host.macTeamID, nativeApp.teamID);
});

test('replaced lock inode with the same token is refused during explicit interrupted recovery', async t => {
  const f = fixture(t), plan = f.plan(); let writes = 0;
  await assert.rejects(applyNativeSupervisorMigration(f.d, {plan, authorize: true}, {...adapters(), replaceManagedFile(file, data) {
    if (++writes === 2) throw Error('injected failure'); fs.writeFileSync(file, data);
  }}), /uncertain/);
  const lockFile = path.join(f.d, 'capabilities.lock'), replacement = lockFile + '.replacement';
  fs.writeFileSync(replacement, fs.readFileSync(lockFile), {mode: 0o600});
  assert.notEqual(fs.statSync(replacement).ino, fs.statSync(lockFile).ino);
  fs.renameSync(replacement, lockFile);
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: plan.planId, authorize: true}, adapters()), /lock_identity_changed/);
  for (const name of lockNames) assert.equal(fs.existsSync(path.join(f.d, name)), true);
});

test('an interrupted rollback retains ownership and can finish only on another explicit rollback request', async t => {
  const f = fixture(t), plan = f.plan(), original = [f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file));
  await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
  let writes = 0;
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: plan.planId, authorize: true},
    {...adapters(), replaceManagedFile(file, data) {
      if (++writes === 2) throw Error('injected rollback failure'); fs.writeFileSync(file, data);
    }}), /rollback_uncertain_preserve_state/);
  for (const name of lockNames) assert.equal(fs.existsSync(path.join(f.d, name)), true);
  await rollbackNativeSupervisorMigration(f.d, {transactionId: plan.planId, authorize: true}, adapters());
  assert.deepEqual([f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file)), original);
  for (const name of lockNames) assert.equal(fs.existsSync(path.join(f.d, name)), false);
});

test('shared Core desired-config validation rejects unsupported schema and unknown Host fields', t => {
  for (const mutate of [config => { config.schema = 2; }, config => { config.host.unreviewedRole = true; }, config => { delete config.host.bundle; }]) {
    const f = fixture(t); mutate(f.config); write(f.configFile, f.config);
    f.state.configSha256 = sha(fs.readFileSync(f.configFile)); write(f.stateFile, f.state);
    assert.throws(f.plan, /unsupported_deployment_schema_or_mode|invalid_configuration_fields|absolute_host_paths_required/);
  }
});

test('missing new App never blocks rollback when exact native job and plist are definitively absent', async t => {
  const f = fixture(t), plan = f.plan();
  const applied = await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
  const native = {platform: 'darwin', home: f.root, statusAgent: label => {
    assert.equal(label, 'app.styx.connector'); return {status: 'not_loaded', loaded: false};
  }, verifyLauncher() { throw Error('MISSING_NEW_APP_MUST_NOT_BE_REQUIRED_FOR_ROLLBACK'); }};
  assert.equal(observeNativeSupervisorServiceAbsence(f.serviceFile, native).installed, false);
  const result = await rollbackNativeSupervisorMigration(f.d, {transactionId: applied.transactionId, authorize: true}, native);
  assert.equal(result.status, 'rolled_back');
});

test('absence-only native observer still refuses installed plist and unknown or loaded launchd job', async t => {
  for (const state of ['installed', 'unknown', 'loaded']) {
    const f = fixture(t), plan = f.plan();
    const applied = await applyNativeSupervisorMigration(f.d, {plan, authorize: true}, adapters());
    if (state === 'installed') {
      const folder = path.join(f.root, 'Library', 'LaunchAgents'); fs.mkdirSync(folder, {recursive: true, mode: 0o700});
      fs.writeFileSync(path.join(folder, 'app.styx.connector.plist'), 'fixture owned plist', {mode: 0o600});
    }
    await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: applied.transactionId, authorize: true}, {
      platform: 'darwin', home: f.root, statusAgent: () => state === 'unknown' ? {status: 'unavailable', loaded: null} :
        state === 'loaded' ? {status: 'reported', loaded: true, pid: 123} : {status: 'not_loaded', loaded: false}
    }), /must_be_observed_absent/);
  }
});

function childWorker(t, f, operation, transactionId = '') {
  const script = path.join(f.root, 'migration-worker.mjs');
  if (!fs.existsSync(script)) fs.writeFileSync(script, `
import fs from 'node:fs';
import {once} from 'node:events';
import {planNativeSupervisorMigration,applyNativeSupervisorMigration,rollbackNativeSupervisorMigration} from ${JSON.stringify(new URL('../migration.mjs', import.meta.url).href)};
const [d,op,id]=process.argv.slice(2);
const absent={status:'reported',installed:false,state:'stopped',role:'host',action:'status',manager:'launchd-user'};
const adapters={platform:'darwin',observeService:async()=>absent,verifyLauncher(){}};
const send=message=>new Promise(resolve=>process.send(message,resolve));
if(op==='apply-live'){
 const plan=planNativeSupervisorMigration(d,{nativeApp:{path:'/Applications/Styx.app',teamID:'ABCDEFGHIJ'}},adapters);
 try{await applyNativeSupervisorMigration(d,{plan,authorize:true},{...adapters,replaceManagedFile(file,bytes){fs.writeFileSync(file,bytes);throw Error('simulate crash after first replace')}})}catch(error){await send({stage:'uncertain',transactionId:plan.planId,error:error.message})}
 setInterval(()=>{},1000);
}else{
 if(op==='rollback-hold')adapters.observeService=async()=>{await send({stage:'observing'});await once(process,'message');return absent};
 try{const result=await rollbackNativeSupervisorMigration(d,{transactionId:id,authorize:true},adapters);await send({stage:'done',status:result.status});process.exit(0)}
 catch(error){await send({stage:'refused',error:error.message});process.exit(2)}
}
`, {mode: 0o600});
  const child = spawn(process.execPath, [script, f.d, operation, transactionId], {stdio: ['ignore', 'ignore', 'pipe', 'ipc']});
  let stderr = ''; child.stderr.on('data', value => { stderr += value; });
  child.on('error', () => {});
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  return {child, async message() {
    try { return (await once(child, 'message', {signal: AbortSignal.timeout(10000)}))[0]; }
    catch (error) { throw Error('child_message_failed:' + error.message + ':' + stderr); }
  }};
}

test('actual live child owner blocks rollback; after SIGKILL the same exact dead-owner locks recover', {timeout: 20000}, async t => {
  const f = fixture(t), original = [f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file));
  const worker = childWorker(t, f, 'apply-live'), message = await worker.message();
  assert.equal(message.stage, 'uncertain');
  const real = {platform: 'darwin', observeService: async () => observedAbsent, verifyLauncher() {}};
  await assert.rejects(rollbackNativeSupervisorMigration(f.d, {transactionId: message.transactionId, authorize: true}, real), /live_or_unknown_lock_owner/);
  for (const name of lockNames) assert.equal(read(path.join(f.d, name)).ownerPid, worker.child.pid);
  const exited = once(worker.child, 'exit'); worker.child.kill('SIGKILL'); await exited;
  const result = await rollbackNativeSupervisorMigration(f.d, {transactionId: message.transactionId, authorize: true}, real);
  assert.equal(result.status, 'rolled_back');
  assert.deepEqual([f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file)), original);
});

test('actual simultaneous recovery processes admit one owner and reject the competing recovery guard', {timeout: 25000}, async t => {
  const f = fixture(t), original = [f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file));
  const writer = childWorker(t, f, 'apply-live'), interrupted = await writer.message();
  const exited = once(writer.child, 'exit'); writer.child.kill('SIGKILL'); await exited;
  const winner = childWorker(t, f, 'rollback-hold', interrupted.transactionId);
  assert.equal((await winner.message()).stage, 'observing');
  for (const name of lockNames) assert.equal(read(path.join(f.d, name)).ownerPid, winner.child.pid);
  const competing = childWorker(t, f, 'rollback', interrupted.transactionId), refused = await competing.message();
  assert.equal(refused.stage, 'refused'); assert.match(refused.error, /recovery_in_progress_or_guard_requires_inspection/);
  const done = winner.message(); winner.child.send({release: true}); assert.equal((await done).status, 'rolled_back');
  assert.deepEqual([f.configFile, f.stateFile, f.serviceFile].map(file => fs.readFileSync(file)), original);
});
