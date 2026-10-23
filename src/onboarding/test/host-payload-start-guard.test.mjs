import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {assertHostPayloadMigrationSettled} from '../host-payload-start-guard.mjs';
import {assertGatewayRuntimeStartAllowed} from '../gateway-runtime-start-guard.mjs';
import {readDeployment} from '../core.mjs';
import {readGatewayDeployment} from '../gateway-deployment-reader.mjs';
import {readDeploymentComponents} from '../components.mjs';
function fixture(t){
 const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-payload-guard-'));fs.chmodSync(stateDir,0o700);t.after(()=>fs.rmSync(stateDir,{recursive:true,force:true}));
 const file=path.join(stateDir,'host-payload-migration.json');
 const write=value=>fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
 const record={schema:1,kind:'host-payload-migration-v1',transactionId:'a'.repeat(32),plan:{stateDir}};
 return {stateDir,file,write,record};
}
test('an interrupted Host payload transaction blocks both current role startup paths even without advance.lock',t=>{
 const f=fixture(t);
 for(const status of ['prepared','writing','rolling_back','uncertain','unknown']){
  f.write({...f.record,status});const before=fs.readFileSync(f.file);
  for(const call of [()=>assertHostPayloadMigrationSettled(f.stateDir),()=>assertGatewayRuntimeStartAllowed({stateDir:f.stateDir,ownsAdvance:true}),()=>readDeployment(f.stateDir),()=>readGatewayDeployment(f.stateDir)])assert.throws(call,/host_payload_migration_requires_recovery/);
  assert.equal(readDeploymentComponents(f.stateDir).host.status,'needs_recovery');
  assert.deepEqual(fs.readFileSync(f.file),before);assert.equal(fs.existsSync(path.join(f.stateDir,'advance.lock')),false);
 }
});
test('only bound terminal journals permit startup; malformed evidence and a recovery owner remain blocking',t=>{
 const f=fixture(t);assert.doesNotThrow(()=>assertHostPayloadMigrationSettled(f.stateDir));
 for(const status of ['applied','rolled_back']){f.write({...f.record,status});assert.doesNotThrow(()=>assertHostPayloadMigrationSettled(f.stateDir));assert.doesNotThrow(()=>assertGatewayRuntimeStartAllowed({stateDir:f.stateDir}));}
 for(const bad of ['broken JSON',{...f.record,status:'applied',plan:{stateDir:'/foreign'}},{...f.record,status:'applied',kind:'other'},{...f.record,status:'applied',transactionId:'wrong'}]){f.write(bad);assert.throws(()=>assertHostPayloadMigrationSettled(f.stateDir),/requires_recovery/)}
 f.write({...f.record,status:'rolled_back'});const guard=path.join(f.stateDir,'host-payload-migration-recovery.lock');fs.writeFileSync(guard,'owned',{mode:0o600});assert.throws(()=>assertHostPayloadMigrationSettled(f.stateDir),/requires_recovery/);assert.equal(fs.readFileSync(guard,'utf8'),'owned');fs.unlinkSync(guard);
 fs.unlinkSync(f.file);fs.symlinkSync(path.join(f.stateDir,'absent'),f.file);assert.throws(()=>assertHostPayloadMigrationSettled(f.stateDir),/requires_recovery/);
});

test('capture admission is visible as recovery before a journal exists or replaces a terminal journal',t=>{
 const f=fixture(t),lock=path.join(f.stateDir,'advance.lock');
 fs.writeFileSync(lock,JSON.stringify({kind:'other'}),{mode:0o600});
 assert.doesNotThrow(()=>assertHostPayloadMigrationSettled(f.stateDir));
 for(const prior of [null,'applied','rolled_back']){
  if(prior)f.write({...f.record,status:prior});
  fs.writeFileSync(lock,JSON.stringify({...f.record,plan:{stateDir:f.stateDir}}));
  assert.throws(()=>assertHostPayloadMigrationSettled(f.stateDir),/requires_recovery/);
  assert.equal(readDeploymentComponents(f.stateDir).host.status,'needs_recovery');
 }
});
