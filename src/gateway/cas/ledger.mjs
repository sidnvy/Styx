import {randomBytes, randomUUID} from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_BYTES = 64 * 1024;
const RUN_LIFETIME_MS = 60 * 60 * 1000;
const CLAIM_LIFETIME_MS = 30 * 1000;

function requireUuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw Error('cas_invalid_' + label);
  return value;
}
function requireRun(id) {
  return requireUuid(id, 'run_id');
}
function nonce() {
  return randomBytes(24).toString('base64url');
}
function newWake(round, now, delayMs) {
  return {
    round,
    wake_id: randomUUID(),
    consume_token: nonce(),
    due_at: now + delayMs,
    phase: 'pending',
    claim: null,
    attempt: null
  };
}
function publicView(row) {
  return {
    run_id: row.run_id,
    objective: row.objective,
    status: row.status,
    rounds: row.rounds,
    delay_ms: row.delay_ms,
    created_at: row.created_at,
    expires_at: row.expires_at,
    completed_rounds: row.consumed.length,
    wake: row.wake ? {
      round: row.wake.round,
      wake_id: row.wake.wake_id,
      due_at: row.wake.due_at,
      phase: row.wake.phase,
      attempt_status: row.wake.attempt?.status ?? null,
      failure_kind: row.wake.attempt?.failure_kind ?? null,
      host_rpc_code: row.wake.attempt?.host_rpc_code ?? null,
      dispatch_transport: row.wake.attempt?.dispatch_transport ?? null,
      primary_rpc_code: row.wake.attempt?.primary_rpc_code ?? null
    } : null,
    view: row.view ? {
      controller_id: row.view.controller_id,
      first_seen_at: row.view.first_seen_at,
      last_seen_at: row.view.last_seen_at,
      poll_count: row.view.poll_count,
      visibility: row.view.visibility,
      host_message_capable: row.view.host_message_capable,
      compat_available: row.view.compat_available
    } : null,
    view_events: (row.view_events ?? []).slice(-12)
  };
}

/**
 * Single-process, opt-in experiment ledger. A separate private directory is mandatory.
 * The CAS run outlives MCP HTTP sessions; it is NEVER identified by a tool-call owner.
 * File replacement happens before acknowledgement. An already-prepared message cannot
 * be dispatched again after restart, regardless of its later delivery uncertainty.
 */
export class CasExperimentLedger {
  constructor({directory, now = () => Date.now()}) {
    if (typeof directory !== 'string' || !path.isAbsolute(directory))
      throw Error('cas_absolute_private_directory_required');
    this.directory = directory;
    this.now = now;
    this.queue = Promise.resolve();
  }
  async init() {
    await fs.mkdir(this.directory, {recursive: true, mode: 0o700});
    const st = await fs.lstat(this.directory);
    if (!st.isDirectory() || st.isSymbolicLink() || (process.platform !== 'win32' && (st.mode & 0o077)))
      throw Error('cas_private_directory_permissions');
    return this;
  }
  serial(fn) {
    const next = this.queue.then(fn);
    this.queue = next.catch(() => {});
    return next;
  }
  filename(id) {
    return path.join(this.directory, requireRun(id) + '.json');
  }
  async load(id) {
    const file = this.filename(id);
    const st = await fs.lstat(file).catch(error => {
      if (error.code === 'ENOENT') throw Error('cas_run_not_found');
      throw error;
    });
    if (!st.isFile() || st.isSymbolicLink() || st.size > MAX_BYTES)
      throw Error('cas_run_invalid_store');
    const row = JSON.parse(await fs.readFile(file, 'utf8'));
    if (row.run_id !== id || row.version !== 1) throw Error('cas_run_invalid_store');
    return row;
  }
  async save(row) {
    const file = this.filename(row.run_id);
    const body = JSON.stringify(row);
    if (Buffer.byteLength(body) > MAX_BYTES) throw Error('cas_store_full');
    const tmp = file + '.' + randomUUID() + '.tmp';
    const handle = await fs.open(tmp, 'wx', 0o600);
    try {
      await handle.writeFile(body, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await fs.rename(tmp, file);
      if (process.platform !== 'win32') {
        const dir = await fs.open(this.directory, 'r');
        try { await dir.sync(); } finally { await dir.close(); }
      }
    } catch (error) {
      await fs.unlink(tmp).catch(() => {});
      throw error;
    }
  }
  start({objective, rounds = 2, delay_ms = 30000}) {
    return this.serial(async () => {
      if (typeof objective !== 'string' || !objective.trim() || objective.length > 1200)
        throw Error('cas_invalid_objective');
      if (!Number.isInteger(rounds) || rounds < 1 || rounds > 4)
        throw Error('cas_invalid_rounds');
      if (!Number.isInteger(delay_ms) || delay_ms < 15000 || delay_ms > 180000)
        throw Error('cas_invalid_delay');
      const now = this.now();
      const row = {
        version: 1,
        run_id: randomUUID(),
        objective: objective.trim(),
        status: 'running',
        rounds,
        delay_ms,
        created_at: now,
        expires_at: now + RUN_LIFETIME_MS,
        wake: newWake(1, now, delay_ms),
        consumed: [],
        view: null,
        view_events: []
      };
      await this.save(row);
      return publicView(row);
    });
  }
  read(run_id) {
    return this.serial(async () => publicView(await this.load(run_id)));
  }
  poll({run_id, controller_id = null, visibility = 'unknown',
    host_message_capable = null, compat_available = null, lifecycle_event = null}) {
    return this.serial(async () => {
      const row = await this.load(run_id);
      if (controller_id === null) return publicView(row);
      requireUuid(controller_id, 'controller_id');
      if (!['visible', 'hidden', 'prerender', 'unknown'].includes(visibility))
        throw Error('cas_invalid_visibility');
      if (typeof host_message_capable !== 'boolean' || typeof compat_available !== 'boolean')
        throw Error('cas_invalid_capability');
      if (lifecycle_event !== null && !['bound','visibility_change'].includes(lifecycle_event))
        throw Error('cas_invalid_lifecycle_event');
      const now = this.now();
      const old = row.view;
      const same = old?.controller_id === controller_id;
      const change = !same || old?.visibility !== visibility ||
        old?.host_message_capable !== host_message_capable ||
        old?.compat_available !== compat_available;
      const due = !same || now - old.last_seen_at >= 20000;
      if (change || due || lifecycle_event) {
        row.view = {
          controller_id, first_seen_at: same ? old.first_seen_at : now,
          last_seen_at: now, poll_count: same ? old.poll_count + 1 : 1,
          visibility, host_message_capable, compat_available
        };
        if (change || lifecycle_event) {
          row.view_events = (row.view_events ?? []).concat([{
            at: now, event: lifecycle_event ?? (same ? 'view_change' : 'new_view'),
            controller_id, visibility, host_message_capable, compat_available
          }]).slice(-16);
        }
        await this.save(row);
      }
      return publicView(row);
    });
  }
  claim({run_id, controller_id}) {
    return this.serial(async () => {
      requireUuid(controller_id, 'controller_id');
      const row = await this.load(run_id);
      if (row.status !== 'running' || !row.wake) return {claimed: false, ...publicView(row)};
      const now = this.now();
      if (now > row.expires_at) {
        row.status = 'expired';
        await this.save(row);
        return {claimed: false, ...publicView(row)};
      }
      if (row.wake.phase === 'claimed' && row.wake.claim?.expires_at <= now) {
        row.wake.phase = 'pending';
        row.wake.claim = null;
        await this.save(row);
      }
      if (row.wake.phase !== 'pending' || row.wake.due_at > now)
        return {claimed: false, ...publicView(row)};
      row.wake.phase = 'claimed';
      row.wake.claim = {controller_id, claim_id: randomUUID(), expires_at: now + CLAIM_LIFETIME_MS};
      await this.save(row);
      return {
        claimed: true, run_id, round: row.wake.round,
        wake_id: row.wake.wake_id, claim_id: row.wake.claim.claim_id
      };
    });
  }
  prepare({run_id, controller_id, claim_id}) {
    return this.serial(async () => {
      requireUuid(controller_id, 'controller_id');
      requireUuid(claim_id, 'claim_id');
      const row = await this.load(run_id);
      const wake = row.wake;
      if (row.status !== 'running' || wake?.phase !== 'claimed' ||
          wake.claim?.controller_id !== controller_id ||
          wake.claim?.claim_id !== claim_id ||
          wake.claim.expires_at <= this.now()) throw Error('cas_claim_not_current');
      const attempt_id = randomUUID();
      wake.phase = 'prepared';
      wake.attempt = {attempt_id, status: 'prepared', prepared_at: this.now()};
      await this.save(row);
      // No shell, file, browser, or Host mutation is authorized by this experiment.
      const args = {
        run_id: row.run_id, round: wake.round,
        wake_id: wake.wake_id, consume_token: wake.consume_token
      };
      const message = 'CAS safe continuation experiment, round ' + wake.round +
        '/' + row.rounds + '. Call the Styx MCP tool cas_experiment_consume with exactly ' +
        JSON.stringify(args) + '. After its result, give a short final answer. ' +
        'Do not invoke execution, filesystem, desktop or other tools for this experiment.';
      return {attempt_id, message, round: wake.round, wake_id: wake.wake_id};
    });
  }
  finish({run_id, controller_id, attempt_id, accepted, failure_kind = null,
    host_rpc_code = null, dispatch_transport = 'mcp_apps', primary_rpc_code = null}) {
    return this.serial(async () => {
      requireUuid(controller_id, 'controller_id');
      requireUuid(attempt_id, 'attempt_id');
      if (typeof accepted !== 'boolean') throw Error('cas_invalid_accepted');
      const allowedKinds = ['rpc_rejected', 'result_rejected', 'host_timeout', 'view_closed', 'compat_rejected', 'unknown'];
      if (failure_kind !== null && !allowedKinds.includes(failure_kind))
        throw Error('cas_invalid_failure_kind');
      if (host_rpc_code !== null && (!Number.isInteger(host_rpc_code) || host_rpc_code < -99999 || host_rpc_code > 99999))
        throw Error('cas_invalid_host_rpc_code');
      if (accepted && (failure_kind !== null || host_rpc_code !== null))
        throw Error('cas_invalid_accepted');
      if (!['mcp_apps','openai_compat'].includes(dispatch_transport))
        throw Error('cas_invalid_dispatch_transport');
      if (primary_rpc_code !== null &&
          (!Number.isInteger(primary_rpc_code) || primary_rpc_code < -99999 || primary_rpc_code > 99999))
        throw Error('cas_invalid_primary_rpc_code');
      if (dispatch_transport === 'openai_compat' && primary_rpc_code !== -32601)
        throw Error('cas_compat_requires_method_not_found');
      const row = await this.load(run_id);
      if (row.consumed.some(item => item.attempt_id === attempt_id))
        return {phase: 'consumed', ...publicView(row)};
      const wake = row.wake;
      if (row.status !== 'running' || !wake?.attempt ||
          wake.attempt.attempt_id !== attempt_id ||
          wake.claim?.controller_id !== controller_id ||
          !['prepared', 'dispatch_accepted', 'delivery_unknown'].includes(wake.phase))
        throw Error('cas_attempt_not_current');
      if (wake.phase === 'prepared') {
        wake.phase = accepted ? 'dispatch_accepted' : 'delivery_unknown';
        wake.attempt.status = wake.phase;
        wake.attempt.failure_kind = accepted ? null : failure_kind ?? 'unknown';
        wake.attempt.host_rpc_code = accepted ? null : host_rpc_code;
        wake.attempt.dispatch_transport = dispatch_transport;
        wake.attempt.primary_rpc_code = primary_rpc_code;
        wake.attempt.finished_at = this.now();
        await this.save(row);
      }
      return publicView(row);
    });
  }
  consume({run_id, round, wake_id, consume_token}) {
    return this.serial(async () => {
      requireUuid(wake_id, 'wake_id');
      if (typeof consume_token !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(consume_token))
        throw Error('cas_invalid_consume_token');
      const row = await this.load(run_id);
      const previous = row.consumed.find(item => item.round === round && item.wake_id === wake_id);
      if (previous) {
        if (previous.consume_token !== consume_token) throw Error('cas_consume_mismatch');
        return {consumed: true, duplicate: true, ...publicView(row)};
      }
      const wake = row.wake;
      if (row.status !== 'running' || !wake || wake.round !== round ||
          wake.wake_id !== wake_id || wake.consume_token !== consume_token ||
          !['prepared', 'dispatch_accepted', 'delivery_unknown'].includes(wake.phase))
        throw Error('cas_wake_not_prepared');
      row.consumed.push({
        round, wake_id, consume_token,
        attempt_id: wake.attempt.attempt_id, consumed_at: this.now()
      });
      if (row.consumed.length >= row.rounds) {
        row.status = 'completed';
        row.wake = null;
      } else {
        row.wake = newWake(round + 1, this.now(), row.delay_ms);
      }
      await this.save(row);
      return {consumed: true, duplicate: false, ...publicView(row)};
    });
  }
  stop({run_id}) {
    return this.serial(async () => {
      const row = await this.load(run_id);
      if (row.status === 'running') {
        row.status = 'stopped';
        await this.save(row);
      }
      return publicView(row);
    });
  }
}
