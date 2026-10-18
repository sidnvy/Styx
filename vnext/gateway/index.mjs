import {ExecAdapter} from '../packages/styx-exec-adapter/adapter.mjs';
import {TargetRegistry} from './registry.mjs';
import {RuntimePool} from './runtime.mjs';
import {createGatewayMcp} from './mcp.mjs';
import {CuaProvider} from './cua.mjs';
import {OutboundHostRelay} from './outbound.mjs';

export function createStyxGateway({catalog, connect, computer, gui = null}) {
  const registry = catalog instanceof TargetRegistry ? catalog : new TargetRegistry(catalog);
  const relay=new OutboundHostRelay({registry});
  const pool = new RuntimePool(registry, {connect,relay});
  const exec = new ExecAdapter({resolve: async (id, _owner) => pool.binding(id)});
  const cua = computer === undefined
    ? (registry.list().some(t => t.capabilities.includes('computer'))
      ? new CuaProvider({registry,relay}) : null)
    : computer;
  return {
    registry, pool, exec, computer: cua, gui, relay,
    serverForOwner(owner) { return createGatewayMcp({exec, computer:cua, gui, registry, owner}); },
    async closeOwner(owner) { await cua?.closeOwner?.(owner); },
    async close() {
      await cua?.close?.(); await gui?.close?.();
      await exec.cleanup(); await pool.close();await relay.close();
    }
  };
}
