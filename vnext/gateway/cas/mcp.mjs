import fs from 'node:fs/promises';

export const CAS_APP_URI = 'ui://styx/cas-continuation/v1';
const uuid = {type: 'string', pattern: '^[0-9a-fA-F-]{36}$'};
const string = (maxLength = 1200) => ({type: 'string', minLength: 1, maxLength});
const object = (properties, required = []) => ({
  type: 'object', properties, required, additionalProperties: false
});
const tool = (name, description, inputSchema, opts = {}) => ({
  name, description, inputSchema,
  ...(opts.readOnly ? {annotations: {readOnlyHint: true, destructiveHint: false, idempotentHint: true}} : {}),
  ...(opts.visibility || opts.view ? {
    _meta: {ui: {
      ...(opts.view ? {resourceUri: CAS_APP_URI} : {}),
      visibility: opts.visibility ?? ['model']
    }}
  } : {})
});

/**
 * This entire catalog is absent unless the operator explicitly enables the
 * isolated experiment. Model tools and App-only control tools have distinct
 * presentation contracts; no App-only call creates another card.
 */
export const CAS_TOOLS = [
  tool('cas_experiment_create',
    'Explicitly create a bounded, no-side-effect CAS model-turn continuation experiment. Never use for routine user tasks.',
    object({objective: string(), rounds: {type: 'integer', minimum: 1, maximum: 4},
      delay_ms: {type: 'integer', minimum: 15000, maximum: 180000}}, ['objective'])),
  tool('cas_experiment_present',
    'Present exactly one persistent CAS experiment controller card for a known run. Call after create and then finish the current assistant response promptly.',
    object({run_id: uuid}, ['run_id']), {view: true, visibility: ['model'], readOnly: true}),
  tool('cas_experiment_status',
    'Read the authoritative state of one CAS experiment; a dispatch-accepted status is NOT proof a model turn ran.',
    object({run_id: uuid}, ['run_id']), {readOnly: true}),
  tool('cas_experiment_consume',
    'Only in response to a CAS continuation message, exact-consume its one-time wake. Does not execute Shell, filesystem or desktop work.',
    object({run_id: uuid, round: {type: 'integer', minimum: 1, maximum: 4},
      wake_id: uuid, consume_token: string(64)},
    ['run_id', 'round', 'wake_id', 'consume_token'])),
  tool('cas_experiment_stop', 'Stop all further CAS automatic turns for a specified run.',
    object({run_id: uuid}, ['run_id'])),
  tool('cas_experiment_poll', 'App-only, read bounded run state.',
    object({run_id: uuid}, ['run_id']), {visibility: ['app'], readOnly: true}),
  tool('cas_experiment_claim', 'App-only, claim an exact due wake with one expiring controller lease.',
    object({run_id: uuid, controller_id: uuid}, ['run_id', 'controller_id']), {visibility: ['app']}),
  tool('cas_experiment_prepare', 'App-only, durably spend one dispatch attempt before Host ui/message.',
    object({run_id: uuid, controller_id: uuid, claim_id: uuid},
      ['run_id', 'controller_id', 'claim_id']), {visibility: ['app']}),
  tool('cas_experiment_finish', 'App-only, record Host acceptance or unknown delivery; never imply model execution.',
    object({run_id: uuid, controller_id: uuid, attempt_id: uuid, accepted: {type: 'boolean'}},
      ['run_id', 'controller_id', 'attempt_id', 'accepted']), {visibility: ['app']})
];

function result(value) {
  return {structuredContent: value, content: [{type: 'text', text: JSON.stringify(value)}]};
}
export async function casCall(ledger, name, args) {
  try {
    const actions = {
      cas_experiment_create: () => ledger.start(args),
      cas_experiment_present: () => ledger.read(args.run_id),
      cas_experiment_status: () => ledger.read(args.run_id),
      cas_experiment_consume: () => ledger.consume(args),
      cas_experiment_stop: () => ledger.stop(args),
      cas_experiment_poll: () => ledger.read(args.run_id),
      cas_experiment_claim: () => ledger.claim(args),
      cas_experiment_prepare: () => ledger.prepare(args),
      cas_experiment_finish: () => ledger.finish(args)
    };
    if (!Object.hasOwn(actions, name)) return null;
    const value = await actions[name]();
    return result(value);
  } catch (error) {
    // Operational errors are finite stable codes, never raw local filesystem data.
    const code = typeof error.message === 'string' && /^cas_[a-z_]+$/.test(error.message)
      ? error.message : 'cas_internal_error';
    return {isError: true, ...result({error: code})};
  }
}
export function casResourceList() {
  return {resources: [{uri: CAS_APP_URI, name: 'CAS experiment continuation',
    description: 'A bounded, optional turn-continuation research View; not a production agent.',
    mimeType: 'text/html;profile=mcp-app'}]};
}
export async function casResourceRead(uri) {
  if (uri !== CAS_APP_URI) throw Error('cas_unknown_ui_resource');
  const text = await fs.readFile(new URL('./controller.html', import.meta.url), 'utf8');
  return {contents: [{uri: CAS_APP_URI, mimeType: 'text/html;profile=mcp-app', text}]};
}
