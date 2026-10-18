import path from 'node:path';

const idPattern = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const nativePaths = platform => platform === 'win32' ? path.win32 : path.posix;
function requireValue(ok, message) { if (!ok) throw new TypeError(message); }

export class TargetRegistry {
  constructor(config) {
    requireValue(plain(config) && config.version === 1, 'Unsupported target catalog');
    requireValue(Array.isArray(config.targets) && config.targets.length <= 64, 'Invalid targets');
    this.targets = new Map();
    for (const target of config.targets) {
      requireValue(plain(target) && idPattern.test(target.id ?? ''), 'Invalid target id');
      requireValue(!this.targets.has(target.id), 'Duplicate target id');
      requireValue(['host', 'environment'].includes(target.kind), 'Invalid resource kind');
      requireValue(['linux', 'darwin', 'win32'].includes(target.platform), 'Invalid platform');
      requireValue(typeof target.generation === 'string' && target.generation.length > 0,
        'Target generation required');
      requireValue(typeof target.cwd === 'string' && nativePaths(target.platform).isAbsolute(target.cwd), 'Absolute cwd required');
      requireValue(typeof target.shell === 'string' && nativePaths(target.platform).isAbsolute(target.shell), 'Absolute shell required');
      requireValue(Array.isArray(target.shells) && target.shells.includes(target.shell) &&
        target.shells.every(s => typeof s === 'string' && nativePaths(target.platform).isAbsolute(s)),
      'Explicit shell allowlist required');
      requireValue(typeof target.allowed === 'boolean', 'Host access decision required');
      const transport = target.exec;
      requireValue(plain(transport) && ['websocket', 'stdio','outbound'].includes(transport.transport),
        'Invalid executor transport');
      if (transport.transport === 'websocket') {
        requireValue(typeof transport.url === 'string' &&
          (transport.url.startsWith('ws://') || transport.url.startsWith('wss://')),
        'WebSocket URL required');
      } else if(transport.transport==='outbound') {
        const bearer = typeof transport.token_file==='string' &&
          path.isAbsolute(transport.token_file);
        const mtls = typeof transport.client_certificate_sha256==='string' &&
          /^[a-f0-9]{64}$/.test(transport.client_certificate_sha256);
        requireValue(target.kind==='host' && bearer!==mtls &&
          (transport.token_file === undefined || bearer) &&
          (transport.client_certificate_sha256===undefined || mtls),
          'Exactly one outbound Host authentication required');
      } else {
        requireValue(typeof transport.binary === 'string' &&
          nativePaths(target.platform).isAbsolute(transport.binary),
          'Absolute local binary required');
      }
      requireValue(target.env === undefined || (plain(target.env) &&
        Object.values(target.env).every(v => typeof v === 'string')), 'Invalid command environment');
      const computer = target.computer;
      if (computer !== undefined) {
        requireValue(plain(computer) && typeof computer.enabled === 'boolean',
          'Invalid computer capability');
        if (computer.enabled) {
          requireValue(['stdio','mcp-http','outbound'].includes(computer.transport), 'Invalid Cua transport');
          if (computer.transport === 'stdio') {
            requireValue(typeof computer.binary === 'string' &&
              nativePaths(target.platform).isAbsolute(computer.binary), 'Cua local binary required');
            requireValue(computer.socket === undefined || typeof computer.socket === 'string',
              'Invalid Cua socket');
          } else if(computer.transport==='outbound') {
            requireValue(target.kind==='host' && transport.transport==='outbound' &&
              (computer.max_connections===undefined ||
              (Number.isInteger(computer.max_connections) &&
                computer.max_connections>=1 && computer.max_connections<=8)),
              'Invalid outbound computer connection pool');
          } else {
            requireValue(typeof computer.url === 'string' &&
              (computer.url.startsWith('https://') || computer.url.startsWith('http://')),
              'Cua MCP endpoint required');
            requireValue(typeof computer.token_file === 'string' &&
              path.isAbsolute(computer.token_file), 'Gateway-local Cua token file required');
          }
        }
      }
      this.targets.set(target.id, Object.freeze({...target}));
    }
    requireValue(config.default_environment_id === undefined ||
      this.targets.has(config.default_environment_id), 'Unknown default target');
    this.defaultId = config.default_environment_id;
  }
  resolve(id) {
    const actual = id === undefined ? this.defaultId : id;
    if (typeof actual !== 'string') throw new Error('default_environment_required');
    const item = this.targets.get(actual);
    if (!item) throw new Error('environment_not_found');
    if (!item.allowed) throw new Error('environment_access_denied');
    return item;
  }
  list() {
    return [...this.targets.values()].filter(t => t.allowed).map(t => ({
      environment_id: t.id, kind: t.kind, platform: t.platform,
      capabilities: ['exec', ...(t.computer?.enabled ? ['computer'] : [])]
    }));
  }
}
