import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {createHash,randomBytes} from 'node:crypto';
import {startForegroundObservation,observeForegroundOwner} from '../foreground-observation.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
function fixture(t){const d=fs.mkdtempSync(path.join(os.tmpdir(),'styx-foreground-observation-'));fs.chmodSync(d,0o700);t.after(()=>fs.rmSync(d,{recursive:true,force:true}));fs.writeFileSync(path.join(d,'deployment.json'),'{}',{mode:0o600});fs.writeFileSync(path.join(d,'foreground.lock'),randomBytes(32).toString('hex'),{mode:0o600});return d}
const projection=()=>({schema:1,status:'connected',host:'foreground',gateway:'external',execConnection:'connected',desktopConnection:'not_requested',browserConnection:'not_requested',toolHealth:'not_verified',accountAcceptance:'NOT RUN'});
test('read-only endpoint rejects unauthenticated/Origin/mutation requests and limits its projection',async t=>{
 const d=fixture(t),owner=await startForegroundObservation({stateDir:d,configurationHash:sha('{}'),projection:()=>({...projection(),secret:'DO_NOT_EXPORT',path:'/private'})});
 try{
  const receipt=JSON.parse(fs.readFileSync(path.join(d,'foreground-observer.json'))),url=`http://127.0.0.1:${receipt.port}/status`;
  assert.equal((await fetch(url)).status,401);assert.equal((await fetch(url,{method:'POST'})).status,403);assert.equal((await fetch(url,{headers:{Origin:'https://evil.test'}})).status,403);
  const result=await observeForegroundOwner(d);assert.equal(result.status,'connected');assert.doesNotMatch(JSON.stringify(result),/DO_NOT_EXPORT|private|secret/);
 }finally{await owner.close()}
});
test('foreign listener on stale address cannot receive raw secret or forge a current response',async t=>{
 const d=fixture(t),owner=await startForegroundObservation({stateDir:d,configurationHash:sha('{}'),projection}),file=path.join(d,'foreground-observer.json'),receipt=JSON.parse(fs.readFileSync(file));await owner.close();
 let headers;const fake=http.createServer((req,res)=>{headers=req.headers;res.end(JSON.stringify({schema:1,generation:receipt.generation,configurationHash:receipt.configurationHash,challenge:req.headers['x-styx-challenge'],projection:projection(),mac:'a'.repeat(64)}))});
 await new Promise(resolve=>fake.listen(0,'127.0.0.1',resolve));receipt.port=fake.address().port;receipt.pid=process.pid;fs.writeFileSync(file,JSON.stringify(receipt),{mode:0o600});
 try{const result=await observeForegroundOwner(d);assert.equal(result.status,'needs_attention');assert.equal(result.execConnection,'not_observed');assert.ok(headers.authorization);assert.ok(!JSON.stringify(headers).includes(receipt.secret));}
 finally{await new Promise(resolve=>fake.close(resolve))}
});
test('owner rejects replaced lock and cleanup never unlinks a foreign receipt',async t=>{
 const d=fixture(t),owner=await startForegroundObservation({stateDir:d,configurationHash:sha('{}'),projection}),file=path.join(d,'foreground-observer.json'),original=fs.readFileSync(file);
 fs.unlinkSync(path.join(d,'foreground.lock'));fs.writeFileSync(path.join(d,'foreground.lock'),'foreign',{mode:0o600});assert.equal((await observeForegroundOwner(d)).status,'needs_attention');
 fs.renameSync(file,file+'.before');fs.writeFileSync(file,original,{mode:0o600});await assert.rejects(owner.close(),/receipt_changed/);assert.deepEqual(fs.readFileSync(file),original);assert.equal(fs.readFileSync(path.join(d,'foreground.lock'),'utf8'),'foreign');
});
test('legacy lock and malformed receipt are not reported stopped or auto-repaired',async t=>{
 const d=fixture(t);assert.equal((await observeForegroundOwner(d)).reason,'foreground_owned_or_interrupted_do_not_take_over');
 const file=path.join(d,'foreground-observer.json');fs.writeFileSync(file,'corrupt',{mode:0o600});assert.equal((await observeForegroundOwner(d)).reason,'foreground_observation_receipt_unavailable');assert.equal(fs.readFileSync(file,'utf8'),'corrupt');
});
