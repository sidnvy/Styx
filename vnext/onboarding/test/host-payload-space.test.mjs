import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {inspectHostPayloadSpace} from '../host-payload-space.mjs';
test('budget combines copies on one actual volume but does not borrow free bytes from a second volume',t=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-space-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));for(const n of ['a','b'])fs.mkdirSync(path.join(root,n));
 const items=[{path:path.join(root,'a','runtime'),bytes:8,kind:'runtime'},{path:path.join(root,'a','stage'),bytes:8,kind:'stage'},{path:path.join(root,'b','rollback'),bytes:4,kind:'rollback'}];
 const observeVolume=p=>({volumeId:path.basename(p),blockSize:4,availableBytes:path.basename(p)==='a'?12:1000});
 assert.throws(()=>inspectHostPayloadSpace(items,{observeVolume}),e=>e.code==='host_payload_insufficient_space'&&e.budget.volumes.find(v=>v.volumeId==='a').requiredBytes===16&&e.budget.volumes.find(v=>v.volumeId==='a').shortfallBytes===4);
 const b=inspectHostPayloadSpace(items,{observeVolume:p=>({...observeVolume(p),availableBytes:1000})});assert.equal(b.volumes.length,2);assert.ok(b.volumes.every(v=>v.shortfallBytes===0));
});
