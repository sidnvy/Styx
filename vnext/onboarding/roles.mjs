// Derived intent, not service health or permission evidence. No separate role file.
export function deploymentRoles(config) {
  if (!['create-local','join-existing'].includes(config?.mode) ||
      typeof config.host?.computer !== 'boolean') throw Error('unsupported_deployment_roles');
  const local = config.mode === 'create-local';
  return {
    gateway: local ? 'local' : 'external',
    host: 'local',
    exec: 'enabled',
    computer: config.host.computer ? 'requested' : 'disabled',
    deviceIngress: local ? ((config.gateway?.listenHost ?? '127.0.0.1') === '127.0.0.1'
      ? 'loopback_only' : 'configured_unverified') : 'not_hosted',
    readiness: 'not_inferred'
  };
}
