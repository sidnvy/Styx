import {WorkAdmission} from '../shared/work-admission.mjs';
import {ExecError} from '../packages/styx-exec-adapter/errors.mjs';
import {ExecAdapter} from '../packages/styx-exec-adapter/adapter.mjs';
import {TargetRegistry} from './registry.mjs';
import {RuntimePool} from './runtime.mjs';
import {createGatewayMcp} from './mcp.mjs';
import {BrowserProvider} from './browser.mjs';
import {CuaProvider} from './cua.mjs';
import {OutboundHostRelay} from './outbound.mjs';

export function createStyxGateway({catalog, connect, computer, browser, gui = null, cas = null, casOnly = false, onToolResult = null}) {
  const registry = catalog instanceof TargetRegistry ? catalog : new TargetRegistry(catalog);
  const relay=new OutboundHostRelay({registry});
  const pool = new RuntimePool(registry, {connect,relay});
  const exec = new ExecAdapter({resolve: async (id, _owner) => {
    try { return await pool.binding(id); }
    catch (error) {
      if (['default_environment_required','environment_not_found','environment_access_denied'].includes(error?.message))
        throw new ExecError(error.message);
      throw error;
    }
  }});
  // Enrollment can admit the FIRST desktop-capable Host after Gateway starts.
  // Keep the provider ready but advertise its tools only when such a Host
  // is approved. Preserve the legacy fixture broker only when injected.
  const cua = computer === undefined
    ? (gui ? null : new CuaProvider({registry,relay}))
    : computer;
  const browserProvider=browser===undefined?new BrowserProvider({registry,relay}):browser;
  const uncertainTargets=new Set(),peerIds=new WeakMap();let nextPeer=0;
  const workAdmission=new WorkAdmission({observe:scope=>{
    const matches=id=>scope==='all'||id===scope,records=[...exec.sessions.values()].filter(r=>matches(r.environment));
    const peerIdentity=entry=>{if(!peerIds.has(entry))peerIds.set(entry,++nextPeer);return peerIds.get(entry)};
    const peers=[...relay.sessions.values(),...relay.browserPeers.values(),...[...relay.computerPeers.values()].flatMap(x=>[...x])].filter(p=>matches(p.id));
    const targets=registry.list().map(t=>registry.resolve(t.environment_id)).filter(t=>matches(t.id));
    return {identity:JSON.stringify([targets.map(t=>[t.id,t.generation]),peers.map(p=>[p.id,p.lane,p.generation,peerIdentity(p)]).sort()]),retained:records.length,
      unknown:scope==='all'&&!!cas||records.some(r=>r.state==='lost'||r.state==='start_unknown'||r.uncertainInput||r.runtime?.lost)||[...uncertainTargets].some(matches)};
  }});
  workAdmission.markUnknown=id=>uncertainTargets.add(id);
  return {
    workAdmission, registry, pool, exec, computer: cua, browser:browserProvider, gui, relay,
    serverForOwner(owner,{browserPrincipal,withOwner}={}) {
      if(browserPrincipal!==undefined)browserProvider?.bindPrincipal?.(owner,browserPrincipal);
      return createGatewayMcp({exec, computer:cua, browser:browserProvider, gui, registry, owner, relay, cas, casOnly, onToolResult,withOwner,workAdmission});
    },
    hasOwnerWork(owner) {
      return browserProvider?.hasOwnerWork?.(owner)||[...exec.sessions.values()].some(record => record.owner === owner && record.state !== 'lost' && !record.runtime?.lost);
    },
    async closeOwner(owner) { await cua?.closeOwner?.(owner);await browserProvider?.closeOwner?.(owner); },
    async close() {
      await cua?.close?.();await browserProvider?.close?.(); await gui?.close?.();
      await exec.cleanup(); await pool.close();await relay.close();
    }
  };
}
