// Deliberate production source closure, shared by the publisher and installer.
// Host binaries, enrollment, test fixtures and mutable source globs are absent.
export const GATEWAY_SOURCE_FILES=Object.freeze([
 'gateway/index.mjs','gateway/runtime.mjs','gateway/registry.mjs','gateway/mcp.mjs','gateway/conversation-owners.mjs',
 'gateway/cua.mjs','gateway/browser.mjs','gateway/outbound.mjs','gateway/http.mjs','gateway/enrollment.mjs',
 'gateway/cua-portable-0.36.0.json','gateway/cas/mcp.mjs','gateway/cas/controller.html',
 'packages/styx-browser-provider/contract.mjs','packages/styx-browser-provider/playwright-contract-0.0.83.json',
 'packages/styx-exec-adapter/rpc.mjs','packages/styx-exec-adapter/errors.mjs',
 'packages/styx-exec-adapter/adapter.mjs','packages/styx-exec-adapter/schema.mjs',
 'packages/styx-gui-broker/mcp.mjs','shared/private-file.mjs','shared/enrollment-protocol.mjs',
 'host/private-storage.mjs','shared/onboarding-evidence.mjs','onboarding/deployment-config.mjs',
 'onboarding/gateway-deployment-reader.mjs','onboarding/gateway-signed-runner.mjs','onboarding/tunnel-context.mjs'
]);
export const GATEWAY_ENTRYPOINT='app/onboarding/gateway-signed-runner.mjs';
const sources=new Set(GATEWAY_SOURCE_FILES.map(name=>'app/'+name));
// Locked packages may load runtime modules from directories called test/tests.
// Exclude mutable/private state, not package-author directory conventions.
const dependencyState=new Set(['node_modules','.git','.bin','.cache','.runtime','.local','profiles','sessions','credentials','__pycache__']);
export function productionDependencyPath(name){
 return !name.split('/').some(p=>dependencyState.has(p)||p.startsWith('.env')||p.endsWith('.log')||p.endsWith('.tmp'));
}
export function productionDependencyFile(name){
 return productionDependencyPath(name)&&
  (/\.(?:js|cjs|mjs|json)$/.test(name)||/^(?:.*\/)?(?:LICENSE|LICENCE|COPYING|NOTICE)(?:\.[A-Za-z0-9_-]+)?$/i.test(name));
}
export function gatewayApplicationFile(name){
 if(sources.has(name)||['app/package.json','app/package-lock.json','licenses/node-LICENSE','licenses/styx-LICENSE','provenance/gateway-build.json'].includes(name))return true;
 const dependency=/^app\/node_modules\/((?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+)\/(.+)$/.exec(name);
 // Nested package trees are copied separately at their exact locked locator.
 if(dependency){let tail=dependency[2];while(tail.startsWith('node_modules/')){const nested=/^node_modules\/(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+\/(.+)$/.exec(tail);if(!nested)return false;tail=nested[1];}return productionDependencyFile(tail);}
 return false;
}
