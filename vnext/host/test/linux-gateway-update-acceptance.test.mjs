import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {linuxGatewayUpdatePaths,linuxGatewayPreservedInventory,runLinuxGatewayUpdateAcceptance} from '../linux-gateway-update-acceptance.mjs';
const inputs={directory:'/tmp/linux-update-20261021-fixture',nodeBinary:'/tmp/payload/node',nodeLicenseFile:'/tmp/payload/LICENSE',nodeProvenanceFile:'/tmp/payload/provenance.json',sourceRoot:'/tmp/source',dependenciesRoot:'/tmp/source/node_modules'};
test('native update requires Linux x64, fresh task scope, independent absolute inputs and explicit opt-in',async()=>{
 assert.deepEqual(linuxGatewayUpdatePaths(inputs,'linux','x64'),inputs);
 const changed={...inputs,previousSourceRoot:'/tmp/previous-source'};assert.deepEqual(linuxGatewayUpdatePaths(changed,'linux','x64'),changed);
 assert.throws(()=>linuxGatewayUpdatePaths({...inputs,previousSourceRoot:'relative'},'linux','x64'),/absolute_acceptance_paths_required/);
 assert.throws(()=>linuxGatewayUpdatePaths({...inputs,previousSourceRoot:inputs.directory+'/old'},'linux','x64'),/independent_acceptance_inputs_required/);
 assert.throws(()=>linuxGatewayUpdatePaths(inputs,'win32','x64'),/linux_x64_acceptance_required/);
 assert.throws(()=>linuxGatewayUpdatePaths({...inputs,directory:'/tmp/production'},'linux','x64'),/scoped_linux_update_directory_required/);
 assert.throws(()=>linuxGatewayUpdatePaths({...inputs,nodeBinary:inputs.directory+'/node'},'linux','x64'),/independent_acceptance_inputs_required/);
 assert.throws(()=>linuxGatewayUpdatePaths({...inputs,sourceRoot:'relative'},'linux','x64'),/absolute_acceptance_paths_required/);
 const prior=process.env.STYX_RUN_LINUX_GATEWAY_UPDATE_ACCEPTANCE;delete process.env.STYX_RUN_LINUX_GATEWAY_UPDATE_ACCEPTANCE;
 try{await assert.rejects(runLinuxGatewayUpdateAcceptance({}),/explicit_linux_gateway_update_acceptance_required/);}finally{if(prior!==undefined)process.env.STYX_RUN_LINUX_GATEWAY_UPDATE_ACCEPTANCE=prior;}
});
test('preservation inventory hashes exact bytes and detects new or changed gateway credentials without exposing values',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'linux-update-20261021-inventory-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 fs.mkdirSync(path.join(root,'gateway/enrollment/tokens'),{recursive:true});fs.writeFileSync(path.join(root,'deployment.json'),'configuration');fs.writeFileSync(path.join(root,'gateway/enrollment/tokens/approved.token'),'private fixture credential');
 const first=linuxGatewayPreservedInventory(root);assert.equal(Object.keys(first).length,2);assert.match(first['gateway/enrollment/tokens/approved.token'],/^[a-f0-9]{64}$/);assert(!JSON.stringify(first).includes('private fixture'));
 fs.appendFileSync(path.join(root,'gateway/enrollment/tokens/approved.token'),'\n');assert.notDeepEqual(linuxGatewayPreservedInventory(root),first);
 fs.writeFileSync(path.join(root,'gateway/new.token'),'new');assert.equal(Object.keys(linuxGatewayPreservedInventory(root)).length,3);
 fs.symlinkSync(path.join(root,'deployment.json'),path.join(root,'gateway/foreign'));assert.throws(()=>linuxGatewayPreservedInventory(root),/unexpected_preserved_symlink/);
});
