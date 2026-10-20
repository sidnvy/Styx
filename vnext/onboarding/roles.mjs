// Derived intent, not service health or permission evidence. No separate role file.
export function deploymentRoles(config) {
  if (!['create-local','join-existing'].includes(config?.mode) ||
      (config.host !== undefined && typeof config.host?.computer !== 'boolean') ||
      (config.host === undefined && (config.mode !== 'create-local' || !config.gateway?.runtime))) throw Error('unsupported_deployment_roles');
  const local = config.mode === 'create-local';
  return {
    gateway: local ? 'local' : 'external',
    host: config.host ? 'local' : 'disabled',
    exec: config.host ? 'enabled' : 'disabled',
    computer: config.host?.computer ? 'requested' : 'disabled',
    browser: config.host?.browser?.enabled === true ? 'requested' : 'disabled',
    deviceIngress: local ? ((config.gateway?.listenHost ?? '127.0.0.1') === '127.0.0.1'
      ? 'loopback_only' : 'configured_unverified') : 'not_hosted',
    readiness: 'not_inferred'
  };
}
