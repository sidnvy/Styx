import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {CasExperimentLedger} from '../cas/ledger.mjs';

async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'styx-cas-ledger-'));
  t.after(() => fs.rm(directory, {recursive: true, force: true}));
  let clock = Date.parse('2026-10-18T12:00:00Z');
  const now = () => clock;
  const ledger = await new CasExperimentLedger({directory, now}).init();
  return {ledger, directory, now, advance: ms => { clock += ms; }};
}

test('two rounds, exact consumption, duplicate safe, and restart-safe dispatch fence', async t => {
  const f = await fixture(t);
  const started = await f.ledger.start({objective: 'No-op two-turn test', rounds: 2, delay_ms: 15000});
  assert.equal(started.wake.phase, 'pending');
  assert.equal(started.status, 'running');
  assert.ok(!JSON.stringify(started).includes('consume_token'));
  assert.equal((await f.ledger.claim({run_id: started.run_id, controller_id: randomUUID()})).claimed, false);

  const controller = randomUUID();
  f.advance(15000);
  const claimed = await f.ledger.claim({run_id: started.run_id, controller_id: controller});
  assert.equal(claimed.claimed, true);
  assert.equal((await f.ledger.claim({run_id: started.run_id, controller_id: randomUUID()})).claimed, false);
  await assert.rejects(f.ledger.prepare({run_id: started.run_id, controller_id: randomUUID(),
    claim_id: claimed.claim_id}), /cas_claim_not_current/);

  const prepared = await f.ledger.prepare({
    run_id: started.run_id, controller_id: controller, claim_id: claimed.claim_id
  });
  assert.equal(prepared.round, 1);
  assert.match(prepared.message, /cas_experiment_consume/);
  await assert.rejects(f.ledger.prepare({
    run_id: started.run_id, controller_id: controller, claim_id: claimed.claim_id
  }), /cas_claim_not_current/);

  // A fresh Server process must not automatically resend an already-prepared wake.
  const restarted = await new CasExperimentLedger({directory: f.directory, now: f.now}).init();
  assert.equal((await restarted.claim({run_id: started.run_id, controller_id: randomUUID()})).claimed, false);
  const uncertain = await restarted.finish({
    run_id: started.run_id, controller_id: controller,
    attempt_id: prepared.attempt_id, accepted: false
  });
  assert.equal(uncertain.wake.phase, 'delivery_unknown');
  const args = JSON.parse(prepared.message.match(/with exactly (\{.*?\})\./)[1]);
  const round1 = await restarted.consume(args);
  assert.equal(round1.consumed, true);
  assert.equal(round1.duplicate, false);
  assert.equal(round1.completed_rounds, 1);
  assert.equal(round1.wake.round, 2);
  assert.equal((await restarted.consume(args)).duplicate, true);
  const lateAck = await restarted.finish({
    run_id: started.run_id, controller_id: controller,
    attempt_id: prepared.attempt_id, accepted: true
  });
  assert.equal(lateAck.phase, 'consumed');

  f.advance(15000);
  const c2 = randomUUID();
  const claim2 = await restarted.claim({run_id: started.run_id, controller_id: c2});
  assert.equal(claim2.claimed, true);
  const attempt2 = await restarted.prepare({
    run_id: started.run_id, controller_id: c2, claim_id: claim2.claim_id
  });
  await restarted.finish({
    run_id: started.run_id, controller_id: c2,
    attempt_id: attempt2.attempt_id, accepted: true
  });
  const args2 = JSON.parse(attempt2.message.match(/with exactly (\{.*?\})\./)[1]);
  const done = await restarted.consume(args2);
  assert.equal(done.status, 'completed');
  assert.equal(done.completed_rounds, 2);
  assert.equal(done.wake, null);
  assert.equal((await restarted.consume(args2)).duplicate, true);
  await assert.rejects(restarted.consume({...args2, consume_token: 'x'.repeat(32)}), /cas_consume_mismatch/);
  assert.equal((await restarted.claim({run_id: started.run_id, controller_id: c2})).claimed, false);

  const entry = await fs.stat(path.join(f.directory, started.run_id + '.json'));
  assert.equal(entry.mode & 0o077, 0);
});

test('a claimed-but-not-prepared lease can expire; a prepared wake is never reissued', async t => {
  const f = await fixture(t);
  const run = await f.ledger.start({objective: 'Test lease', delay_ms: 15000});
  const a = randomUUID(), b = randomUUID();
  f.advance(15000);
  const old = await f.ledger.claim({run_id: run.run_id, controller_id: a});
  f.advance(30001);
  const replacement = await f.ledger.claim({run_id: run.run_id, controller_id: b});
  assert.equal(replacement.claimed, true);
  assert.notEqual(replacement.claim_id, old.claim_id);
  await assert.rejects(f.ledger.prepare({
    run_id: run.run_id, controller_id: a, claim_id: old.claim_id
  }), /cas_claim_not_current/);
  await f.ledger.prepare({
    run_id: run.run_id, controller_id: b, claim_id: replacement.claim_id
  });
  f.advance(120000);
  assert.equal((await f.ledger.claim({run_id: run.run_id, controller_id: a})).claimed, false);
});

test('explicit Stop, expired Run and invalid private store fail closed', async t => {
  const f = await fixture(t);
  const run = await f.ledger.start({objective: 'Stop experiment'});
  const stopped = await f.ledger.stop({run_id: run.run_id});
  assert.equal(stopped.status, 'stopped');
  f.advance(60000);
  assert.equal((await f.ledger.claim({run_id: run.run_id, controller_id: randomUUID()})).claimed, false);
  assert.equal((await f.ledger.stop({run_id: run.run_id})).status, 'stopped');
  await assert.rejects(f.ledger.read('../../etc/passwd'), /cas_invalid_run_id/);

  const another = await f.ledger.start({objective: 'Expiry'});
  f.advance(3600001);
  const expired = await f.ledger.claim({run_id: another.run_id, controller_id: randomUUID()});
  assert.equal(expired.status, 'expired');
  assert.equal(expired.claimed, false);
  const unsafe = await fs.mkdtemp(path.join(os.tmpdir(), 'styx-cas-unsafe-'));
  t.after(() => fs.rm(unsafe, {recursive: true, force: true}));
  await fs.chmod(unsafe, 0o755);
  await assert.rejects(new CasExperimentLedger({directory: unsafe}).init(),
    /cas_private_directory_permissions/);
});
