import {localGatewayAddresses} from './deployment-config.mjs';
import {readAdditionalDeviceIngress} from './device-ingress-setup.mjs';
// Read-only add-device preflight. No listener changes, trust import, invitation
// issuance, discovery or credentials. A local probe is never remote acceptance.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import {createHash, X509Certificate} from 'node:crypto';
import {requirePrivateDirectory, requirePrivateFile} from '../host/private-storage.mjs';

const fail = code => { throw Error(code); };
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const absolute = value => typeof value === 'string' && path.isAbsolute(value) && path.normalize(value) === value;
function origin(value) {
  let url; try { url = new URL(value); } catch { fail('device_ingress_https_origin_required'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/')
    fail('device_ingress_https_origin_required');
  return url.origin;
}
function json(file) {
  const info = requirePrivateFile(file);
  if (info.size > 1024 * 1024) fail('device_ingress_state_too_large');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function certificate(file, privateFile) {
  if (!absolute(file)) fail('device_ingress_absolute_ca_file_required');
  const info = privateFile ? requirePrivateFile(file) : fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 1024 * 1024)
    fail('device_ingress_invalid_ca_file');
  const bytes = fs.readFileSync(file);
  let cert; try { cert = new X509Certificate(bytes); } catch { fail('device_ingress_certificate_invalid'); }
  const expiresAt = Date.parse(cert.validTo), startsAt = Date.parse(cert.validFrom);
  return {bytes, summary: {
    sha256: digest(cert.raw), validFrom: new Date(startsAt).toISOString(), validTo: new Date(expiresAt).toISOString(),
    currentlyValid: startsAt <= Date.now() && expiresAt > Date.now(),
    renewalDue: expiresAt < Date.now() + 14 * 24 * 60 * 60 * 1000
  }};
}
const loopback = host => host === 'localhost' || host === '::1' || host === '[::1]' || /^127\./.test(host ?? '');
function context(stateDir) {
  if (!absolute(stateDir)) fail('device_ingress_absolute_state_required');
  requirePrivateDirectory(stateDir);
  const file = path.join(stateDir, 'deployment.json'), config = json(file), state = json(path.join(stateDir, 'state.json'));
  const configSha256 = digest(fs.readFileSync(file));
  if (config.schema !== 1 || !['create-local', 'join-existing'].includes(config.mode) ||
      state.schema !== 1 || state.mode !== config.mode || state.configSha256 !== configSha256 || !Array.isArray(state.steps))
    fail('device_ingress_deployment_binding_changed');
  const configuredOrigin = origin(config.gateway?.url), local = config.mode === 'create-local';
  const caFile = local ? path.join(stateDir, 'gateway', 'certificate.pem') : config.gateway?.caFile;
  const runtimeFile = path.join(stateDir, 'gateway', 'runtime.json');
  let runtimePrepared = false;
  if (local && fs.existsSync(runtimeFile)) {
    const runtime = json(runtimeFile);
    if (runtime.schema !== 1 || origin(runtime.url) !== configuredOrigin ||
        runtime.listenHost !== (config.gateway.listenHost ?? '127.0.0.1') || runtime.tlsCertificateFile !== caFile)
      fail('device_ingress_runtime_binding_changed');
    const evidence = state.steps.find(step => step.id === 'gateway.prepare' && step.status === 'succeeded')?.evidence;
    if (evidence?.runtime?.sha256 && evidence.runtime.sha256 !== digest(fs.readFileSync(runtimeFile)))
      fail('device_ingress_runtime_binding_changed');
    runtimePrepared = true;
  }
  let trust;
  if (caFile && (!local || fs.existsSync(caFile))) {
    trust = certificate(caFile, local);
    const baseline = state.steps.find(step => step.id === 'gateway.prepare' && step.status === 'succeeded')?.evidence?.certificate?.sha256;
    if (local && baseline && baseline !== digest(trust.bytes)) fail('device_ingress_certificate_identity_changed');
  }
  return {config, configSha256, configuredOrigin, local, caFile, trust, runtimePrepared};
}

export function planDeviceIngress(stateDir) {
  const pending=readAdditionalDeviceIngress(stateDir);if(['preparing','running','needs_reconciliation'].includes(pending.status))return {schema:1,gateway:'unknown',status:'needs_reconciliation',blockers:['device_ingress_recovery_required'],setup:pending,remoteUsable:false,remoteReachability:'NOT VERIFIED',readiness:'not_inferred'};
  const ctx = context(stateDir), {config, configuredOrigin, local, trust, runtimePrepared} = ctx;
  const listenHost = local ? config.gateway.listenHost ?? '127.0.0.1' : null;
  const targetLoopback = loopback(new URL(configuredOrigin).hostname);
  const blockers = [];
  if (local && !runtimePrepared) blockers.push('gateway_not_prepared');
  if (local && !trust) blockers.push('gateway_certificate_not_prepared');
  if (targetLoopback || local && loopback(listenHost)) blockers.push('loopback_cannot_accept_other_computers');
  if (local && !loopback(listenHost) && config.gateway.allowRemoteHosts !== true) blockers.push('network_exposure_not_authorized');
  if (local && trust && !trust.summary.currentlyValid) blockers.push('gateway_certificate_not_currently_valid');
  const addresses=localGatewayAddresses(),entry=config.gateway.deviceIngress;
  if(local&&runtimePrepared&&trust?.summary.currentlyValid&&loopback(listenHost)){
    const setup=readAdditionalDeviceIngress(stateDir);
    const networkBlockers=addresses.length===0?['device_ingress_network_unavailable']:entry?.enabled&&!addresses.includes(entry.listenHost)?['device_ingress_address_changed']:[];
    if(['preparing','running','needs_reconciliation'].includes(setup.status))networkBlockers.push('device_ingress_recovery_required');
    return {schema:1,configuredOrigin,gateway:'local',listenHost,status:entry?.enabled?'configured_unverified':'preparation_required',
      networkExposureAuthorized:entry?.enabled===true,blockers:networkBlockers,candidates:addresses,requiresInterfaceChoice:!entry?.enabled&&addresses.length>1,
      ...(entry?{deviceEntry:{url:entry.url,listenHost:entry.listenHost,generation:entry.generation}}:{}),setup,
      remoteUsable:false,remoteReachability:'NOT VERIFIED',readiness:'not_inferred',tls:{status:'configured_unverified',gatewayCertificate:trust.summary,renewal:'NOT AUTOMATED'},
      nextAction:entry?.enabled?'open_pairing_window':'prepare_additional_entry',crossNetwork:'reachable_entrypoint_required_no_automatic_nat_traversal'};
  }
  return {
    schema: 1, configuredOrigin, gateway: local ? 'local' : 'external', listenHost,
    status: local ? (loopback(listenHost) ? 'loopback_only' : 'configured_unverified') : 'not_hosted',
    networkExposureAuthorized: local && config.gateway.allowRemoteHosts === true,
    tls: {status: trust ? 'configured_unverified' : local ? 'not_prepared' : 'system_trust_unverified',
      ...(trust ? {[local ? 'gatewayCertificate' : 'configuredTrustCertificate']: trust.summary} : {}),
      renewal: 'NOT AUTOMATED'},
    blockers, readiness: 'not_inferred', remoteUsable: false, remoteReachability: 'NOT VERIFIED',
    pairing: 'explicit_owner_authorization_required', accountAcceptance: 'NOT RUN',
    prerequisites: ['owner_authorizes_exact_network_scope', 'reachable_enrollment_and_host_connection_entrypoint',
      'joining_computer_verifies_tls_and_reachability', 'separate_owner_device_identity_and_capability_approval',
      'host_connects_and_actual_exec_or_cua_acceptance', 'certificate_renewal_and_address_changes_require_reverification'],
    crossNetwork: 'reachable_entrypoint_required_no_automatic_nat_traversal'
  };
}

export async function verifyDeviceIngress(stateDir, options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(key => !['url', 'caFile', 'expectedCertificateSha256', 'timeoutMs'].includes(key)))
    fail('device_ingress_invalid_verification_options');
  const ctx = context(stateDir), target = origin(options.url);
  if (target !== ctx.configuredOrigin) fail('device_ingress_exact_configured_origin_required');
  if (options.caFile !== undefined && options.caFile !== ctx.caFile) fail('device_ingress_configured_trust_required');
  if (ctx.local && (!ctx.runtimePrepared || !ctx.trust)) fail('device_ingress_gateway_preparation_required');
  if (ctx.local && !ctx.trust.summary.currentlyValid) fail('device_ingress_certificate_not_currently_valid');
  const timeoutMs = options.timeoutMs ?? 10000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) fail('device_ingress_invalid_timeout');
  if (options.expectedCertificateSha256 !== undefined && !/^[a-f0-9]{64}$/.test(options.expectedCertificateSha256))
    fail('device_ingress_invalid_certificate_identity');
  const baseline = ctx.local ? ctx.trust.summary.sha256 : options.expectedCertificateSha256;
  if (ctx.local && options.expectedCertificateSha256 !== undefined && options.expectedCertificateSha256 !== baseline)
    fail('device_ingress_certificate_identity_changed');
  const endpoint = new URL('/styx/enroll/join', target);
  const observed = await new Promise((resolve, reject) => {
    let peer, settled = false, timer;
    const finish = (error, result) => {
      if (settled) return; settled = true; clearTimeout(timer);
      error ? reject(Error(error)) : resolve(result);
    };
    const req = https.request(endpoint, {method: 'GET', ca: ctx.trust?.bytes, rejectUnauthorized: true,
      agent: false, headers: {Accept: 'application/json'}}, res => {
      if (res.statusCode >= 300 && res.statusCode < 400) {
        res.destroy(); finish('device_ingress_redirect_refused'); return;
      }
      let bytes = 0; const chunks = [];
      res.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 8192) { res.destroy(); finish('device_ingress_endpoint_not_verified'); }
        else chunks.push(chunk);
      });
      res.on('error', () => finish('device_ingress_endpoint_not_verified'));
      res.on('end', () => {
        let body; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
        if (!peer || res.statusCode !== 405 || body?.error !== 'method_not_allowed') {
          finish('device_ingress_endpoint_not_verified'); return;
        }
        finish(null, peer);
      });
    });
    req.on('socket', socket => socket.once('secureConnect', () => {
      try {
        const cert = new X509Certificate(socket.getPeerCertificate(true).raw);
        peer = {sha256: digest(cert.raw), validTo: new Date(cert.validTo).toISOString(),
          remoteAddress: socket.remoteAddress};
        if (baseline && baseline !== peer.sha256) {
          req.destroy(); finish('device_ingress_certificate_identity_changed');
        }
      } catch { req.destroy(); finish('device_ingress_tls_failed'); }
    }));
    req.on('error', () => finish('device_ingress_tls_or_connection_failed'));
    // Absolute deadline includes DNS, TLS and response body; not an idle timeout.
    timer = setTimeout(() => { req.destroy(); finish('device_ingress_timeout'); }, timeoutMs);
    req.end();
  });
  // Re-read sealed configuration after the await. A concurrent migration must
  // not cause an observation to be returned for a different configured target.
  const current = context(stateDir);
  if (current.configSha256 !== ctx.configSha256 || current.configuredOrigin !== target || current.caFile !== ctx.caFile ||
      (current.trust ? digest(current.trust.bytes) : null) !== (ctx.trust ? digest(ctx.trust.bytes) : null))
    fail('device_ingress_deployment_changed_during_verification');
  return {schema: 1, status: 'ingress_endpoint_verified', configuredOrigin: target,
    observedAt: new Date().toISOString(), observationScope: 'current_machine',
    tls: {status: 'verified', certificate: observed, identity: baseline ? 'certificate_matched' : 'configured_trust_verified'},
    enrollment: 'unauthenticated_join_route_observed_without_mutation', remoteReachability: 'NOT VERIFIED', remoteUsable: false,
    hostConnection: 'NOT VERIFIED', deviceApproval: 'NOT RUN', accountAcceptance: 'NOT RUN'};
}
