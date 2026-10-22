import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import {createHash, randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {createStyxGateway} from '../../gateway/index.mjs';
import {createGatewayHttp} from '../../gateway/http.mjs';
import {EnrollmentController} from '../../gateway/enrollment.mjs';
import {ensurePrivateDirectory} from '../../host/private-storage.mjs';
import {planDeviceIngress, verifyDeviceIngress} from '../device-ingress.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function write(file, value) { fs.writeFileSync(file, JSON.stringify(value) + '\n', {mode: 0o600}); }
async function fixture(t, handler) {
  const dir = path.join(os.tmpdir(), 'styx-ingress-' + randomUUID());
  ensurePrivateDirectory(dir);
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  const gatewayDir = path.join(dir, 'gateway'); ensurePrivateDirectory(gatewayDir);
  const key = path.join(gatewayDir, 'private-key.pem'), cert = path.join(gatewayDir, 'certificate.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-keyout', key, '-out', cert, '-subj', '/CN=Styx ingress test', '-addext', 'subjectAltName=IP:127.0.0.1'],
  {stdio: 'ignore', timeout: 12000});
  fs.chmodSync(cert, 0o600);
  let server, port;
  if (handler) {
    server = https.createServer({key: fs.readFileSync(key), cert: fs.readFileSync(cert)}, handler);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
    t.after(() => new Promise(resolve => server.close(resolve)));
  } else {
    const gateway = createStyxGateway({catalog: {version: 1, targets: []}}), hosts = [];
    const admin = path.join(gatewayDir, 'admin.token'); fs.writeFileSync(admin, randomUUID() + randomUUID(), {mode: 0o600});
    const controller = new EnrollmentController({rootDir: path.join(gatewayDir, 'enrollment'), adminTokenFile: admin,
      registry: gateway.registry, relay: gateway.relay});
    server = await createGatewayHttp(gateway, {token: randomUUID() + randomUUID(), allowedHosts: hosts, port: 0,
      tlsCertificateFile: cert, tlsPrivateKeyFile: key, enrollment: controller});
    port = server.address.port; hosts.push('127.0.0.1:' + port);
    t.after(() => server.close());
  }
  const url = 'https://127.0.0.1:' + port;
  const deploymentFile = path.join(dir, 'deployment.json'), stateFile = path.join(dir, 'state.json'), runtimeFile = path.join(gatewayDir, 'runtime.json');
  const config = {schema: 1, mode: 'create-local', gateway: {url, listenHost: '127.0.0.1'}, host: false};
  const runtime = {schema: 1, url, listenHost: '127.0.0.1', tlsCertificateFile: cert};
  write(deploymentFile, config); write(runtimeFile, runtime);
  const state = {schema: 1, mode: config.mode, configSha256: sha(fs.readFileSync(deploymentFile)), steps: [{id: 'gateway.prepare', status: 'succeeded',
    evidence: {runtime: {sha256: sha(fs.readFileSync(runtimeFile))}, certificate: {sha256: sha(fs.readFileSync(cert))}}}]};
  write(stateFile, state);
  function changeConfig(fn) {
    fn(config); state.mode = config.mode;
    write(deploymentFile, config); state.configSha256 = sha(fs.readFileSync(deploymentFile)); write(stateFile, state);
  }
  return {dir, cert, key, url, state, stateFile, deploymentFile, runtimeFile, changeConfig, config, runtime};
}

test('real Gateway TLS and unauthenticated enrollment routing are observed without issuing invitations', {timeout: 30000}, async t => {
  const f = await fixture(t);
  const before = fs.readFileSync(f.stateFile, 'utf8'), configBefore = fs.readFileSync(f.deploymentFile, 'utf8');
  const plan = planDeviceIngress(f.dir);
  assert.equal(plan.status, 'preparation_required');
  assert.equal(plan.networkExposureAuthorized, false);assert.equal(plan.remoteUsable, false);
  assert.ok(Array.isArray(plan.candidates));
  assert.equal(plan.tls.gatewayCertificate.currentlyValid, true);
  assert.equal(plan.tls.gatewayCertificate.renewalDue, true);
  const result = await verifyDeviceIngress(f.dir, {url: f.url});
  assert.equal(result.status, 'ingress_endpoint_verified');
  assert.equal(result.observationScope, 'current_machine');
  assert.equal(result.tls.identity, 'certificate_matched');
  assert.equal(result.tls.certificate.sha256, plan.tls.gatewayCertificate.sha256);
  assert.equal(result.remoteReachability, 'NOT VERIFIED'); assert.equal(result.remoteUsable, false);
  assert.equal(result.hostConnection, 'NOT VERIFIED'); assert.equal(result.accountAcceptance, 'NOT RUN');
  assert.equal(fs.readFileSync(f.stateFile, 'utf8'), before);
  assert.equal(fs.readFileSync(f.deploymentFile, 'utf8'), configBefore);
  assert.ok(!fs.existsSync(path.join(f.dir, 'invitation')));
});

test('exact HTTPS target, configured CA, origin shape and certificate pin are checked before I/O', async t => {
  let requests = 0;
  const f = await fixture(t, (_req, res) => { requests++; res.writeHead(401); res.end('{"error":"unauthorized"}'); });
  for (const options of [{url: 'https://foreign.example'}, {url: f.url + '/mcp'}, {url: f.url + '?secret=NO_ECHO'},
    {url: f.url.replace('https:', 'http:')}, {url: f.url, caFile: '/tmp/arbitrary-ca.pem'},
    {url: f.url, expectedCertificateSha256: '0'.repeat(64)}, {url: f.url, rejectUnauthorized: false}]) {
    await assert.rejects(verifyDeviceIngress(f.dir, options), error => /^device_ingress_/.test(error.message) && !error.message.includes('NO_ECHO'));
  }
  assert.equal(requests, 0);
});

test('read-only probe sends no credentials, refuses redirects and does not accept arbitrary HTTP success', async t => {
  let mode = 'good', calls = 0;
  const f = await fixture(t, (req, res) => {
    calls++; assert.equal(req.method, 'GET'); assert.equal(req.url, '/styx/enroll/pending');
    assert.equal(req.headers.authorization, undefined); assert.equal(req.headers.cookie, undefined);
    if (mode === 'redirect') { res.writeHead(302, {Location: 'https://foreign.example'}); res.end(); }
    else if (mode === 'wrong') { res.writeHead(200); res.end('{"error":"unauthorized"}'); }
    else if (mode === 'large') { res.writeHead(401); res.end('x'.repeat(9000)); }
    else { res.writeHead(401); res.end('{"error":"unauthorized"}'); }
  });
  await verifyDeviceIngress(f.dir, {url: f.url});
  mode = 'redirect'; await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url}), /redirect_refused/);
  mode = 'wrong'; await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url}), /endpoint_not_verified/);
  mode = 'large'; await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url}), /endpoint_not_verified/);
  assert.equal(calls, 4);
});

test('sealed configuration, prepared runtime and certificate evidence reject drift', async t => {
  const f = await fixture(t);
  fs.appendFileSync(f.deploymentFile, ' ');
  assert.throws(() => planDeviceIngress(f.dir), /deployment_binding_changed/);
  f.changeConfig(() => {});
  write(f.runtimeFile, {...f.runtime, url: 'https://foreign.example'});
  assert.throws(() => planDeviceIngress(f.dir), /runtime_binding_changed/);
  write(f.runtimeFile, f.runtime);
  fs.appendFileSync(f.cert, '\n');
  assert.throws(() => planDeviceIngress(f.dir), /certificate_identity_changed/);
});

test('external Gateway uses only configured TLS trust and never claims local hosting or remote readiness', async t => {
  const f = await fixture(t);
  f.changeConfig(config => { config.mode = 'join-existing'; config.gateway = {url: f.url, caFile: f.cert}; });
  const plan = planDeviceIngress(f.dir);
  assert.equal(plan.gateway, 'external'); assert.equal(plan.status, 'not_hosted');
  assert.equal(plan.listenHost, null); assert.equal(plan.networkExposureAuthorized, false);
  assert.equal(plan.tls.gatewayCertificate, undefined); assert.ok(plan.tls.configuredTrustCertificate);
  await verifyDeviceIngress(f.dir, {url: f.url, caFile: f.cert});
  await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url, expectedCertificateSha256: '0'.repeat(64)}), /certificate_identity_changed/);
  f.changeConfig(config => { delete config.gateway.caFile; });
  await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url}), /tls_or_connection_failed/);
});

test('absolute timeout covers a TLS peer that never finishes its response', async t => {
  const sockets = new Set();
  const f = await fixture(t, (req, _res) => { sockets.add(req.socket); req.socket.on('close', () => sockets.delete(req.socket)); });
  t.after(() => { for (const socket of sockets) socket.destroy(); });
  const start = Date.now();
  await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url, timeoutMs: 150}), /device_ingress_timeout/);
  assert.ok(Date.now() - start < 3000);
});

test('a migration during verification invalidates the observation instead of blessing a new target', async t => {
  let release, received;
  const requestReceived = new Promise(resolve => { received = resolve; });
  const f = await fixture(t, (_req, res) => { release = () => { res.writeHead(401); res.end('{"error":"unauthorized"}'); }; received(); });
  const verify = verifyDeviceIngress(f.dir, {url: f.url});
  await requestReceived;
  f.changeConfig(config => { config.gateway.url = 'https://127.0.0.1:9999'; });
  write(f.runtimeFile, {...f.runtime, url: f.config.gateway.url});
  f.state.steps[0].evidence.runtime.sha256 = sha(fs.readFileSync(f.runtimeFile)); write(f.stateFile, f.state);
  release();
  await assert.rejects(verify, /deployment_changed_during_verification/);
});

test('unprepared gateway plan stays actionable and cannot probe as prepared', async t => {
  const f = await fixture(t);
  fs.unlinkSync(f.runtimeFile); fs.unlinkSync(f.cert);
  const result = planDeviceIngress(f.dir);
  assert.ok(result.blockers.includes('gateway_not_prepared'));
  assert.ok(result.blockers.includes('gateway_certificate_not_prepared'));
  assert.equal(result.tls.status, 'not_prepared');
  await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url}), /gateway_preparation_required/);
});

test('an explicitly configured LAN listener remains unverified and never creates reachability or pairing consent', async t => {
  const f = await fixture(t);
  f.changeConfig(config => { config.gateway = {url: 'https://192.0.2.12:8795', listenHost: '192.0.2.12', allowRemoteHosts: true}; });
  write(f.runtimeFile, {...f.runtime, url: f.config.gateway.url, listenHost: '192.0.2.12'});
  f.state.steps[0].evidence.runtime.sha256 = sha(fs.readFileSync(f.runtimeFile)); write(f.stateFile, f.state);
  const result = planDeviceIngress(f.dir);
  assert.equal(result.status, 'configured_unverified'); assert.equal(result.networkExposureAuthorized, true);
  assert.equal(result.readiness, 'not_inferred'); assert.equal(result.remoteUsable, false);
  assert.equal(result.pairing, 'explicit_owner_authorization_required');
  assert.match(result.crossNetwork, /no_automatic_nat_traversal/);
});

test('expired local certificate is surfaced as a blocker and cannot pass TLS verification', async t => {
  const f = await fixture(t);
  const expired = path.join(f.dir, 'expired.pem');
  execFileSync('openssl', ['x509', '-in', f.cert, '-signkey', f.key, '-days', '0', '-out', expired], {stdio: 'ignore', timeout: 10000});
  // This represents a deployment initially prepared with an expired certificate,
  // so the evidence itself still matches; certificate validity must reject it.
  fs.writeFileSync(f.cert, fs.readFileSync(expired));
  f.state.steps[0].evidence.certificate.sha256 = sha(fs.readFileSync(f.cert)); write(f.stateFile, f.state);
  const plan = planDeviceIngress(f.dir);
  assert.equal(plan.tls.gatewayCertificate.currentlyValid, false);
  assert.ok(plan.blockers.includes('gateway_certificate_not_currently_valid'));
  await assert.rejects(verifyDeviceIngress(f.dir, {url: f.url}), /certificate_not_currently_valid/);
});
