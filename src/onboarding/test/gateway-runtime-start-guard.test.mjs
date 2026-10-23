import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {assertGatewayRuntimeStartAllowed} from '../gateway-runtime-start-guard.mjs';
function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-gateway-start-guard-')),stateDir=path.join(root,'deployment'),baseDir=path.join(root,'runtime');for(const dir of [stateDir,baseDir])fs.mkdirSync(dir,{mode:0o700});t.after(()=>fs.rmSync(root,{recursive:true,force:true}));return {root,stateDir,baseDir};}
const write=(file,value)=>fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
test('startup guard also protects a Core Gateway without an independent runtime',t=>{
 const f=fixture(t);assert.doesNotThrow(()=>assertGatewayRuntimeStartAllowed({stateDir:f.stateDir}));
 const file=path.join(f.stateDir,'advance.lock');write(file,'');assert.throws(()=>assertGatewayRuntimeStartAllowed({stateDir:f.stateDir}),/start_requires_reconciliation/);
 assert.doesNotThrow(()=>assertGatewayRuntimeStartAllowed({...f,ownsAdvance:true}));
 const update={kind:'gateway-runtime-change',pid:process.pid};write(file,update);assert.throws(()=>assertGatewayRuntimeStartAllowed({...f,ownsAdvance:true}),/start_requires_reconciliation/);assert.equal(fs.readFileSync(file,'utf8'),JSON.stringify(update));
});
test('unfinished and malformed update journals prevent startup even after the operation lock disappears',t=>{
 const f=fixture(t),file=path.join(f.baseDir,'runtime-change.json'),record={schema:1,id:'a'.repeat(32),plan:{stateDir:f.stateDir,installRoot:path.join(f.baseDir,'install')}};
 for(const status of ['prepared','staged','committing','unknown']){write(file,{...record,status});assert.throws(()=>assertGatewayRuntimeStartAllowed(f),/start_requires_reconciliation/)}
 for(const status of ['completed','recovered']){write(file,{...record,status});assert.doesNotThrow(()=>assertGatewayRuntimeStartAllowed(f))}
 write(file,'not json');assert.throws(()=>assertGatewayRuntimeStartAllowed(f),/start_requires_reconciliation/);
 write(file,{...record,status:'completed',plan:{...record.plan,stateDir:'/foreign'}});assert.throws(()=>assertGatewayRuntimeStartAllowed(f),/start_requires_reconciliation/);
});
test('a recovery guard or uninspectable lock is retained and blocks startup',t=>{
 const f=fixture(t),file=path.join(f.stateDir,'gateway-runtime-recovery.lock');write(file,'foreign');assert.throws(()=>assertGatewayRuntimeStartAllowed(f),/start_requires_reconciliation/);assert.equal(fs.readFileSync(file,'utf8'),'foreign');fs.rmSync(file);
 const advance=path.join(f.stateDir,'advance.lock');fs.symlinkSync(path.join(f.root,'missing'),advance);assert.throws(()=>assertGatewayRuntimeStartAllowed({...f,ownsAdvance:true}),/start_requires_reconciliation/);assert.equal(fs.lstatSync(advance).isSymbolicLink(),true);
});
