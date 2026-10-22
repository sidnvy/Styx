import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createOnboardingServer} from '../server.mjs';
import {main} from '../cli.mjs';

test('native update API authenticates mutations and cannot substitute a payload, publisher, state directory or admission token',async t=>{
 const stateDir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-handoff-api-'));t.after(()=>fs.rmSync(stateDir,{recursive:true,force:true}));
 const artifacts={bundle:path.join(stateDir,'registered-bundle'),publisherKeyFile:path.join(stateDir,'publisher.pem'),publisherSha256:'a'.repeat(64)},defaults=path.join(stateDir,'artifacts.json');fs.writeFileSync(defaults,JSON.stringify(artifacts),{mode:0o600});
 const calls=[],core={prepareHostPayloadHandoff:async args=>{calls.push(args);return{status:'awaiting_exit',ticketId:'b'.repeat(32)}}};
 const app=await createOnboardingServer({stateDir,artifactDefaultsFile:defaults,core});t.after(()=>app.close());
 const headers={Authorization:'Bearer '+new URLSearchParams(new URL(app.url).hash.slice(1)).get('session')};
 const session=await(await fetch(app.origin+'/api/session',{headers})).json();
 const post=(data,extra={})=>fetch(app.origin+'/api/host-payload/handoff/prepare',{method:'POST',headers:{...headers,Origin:app.origin,'X-Styx-CSRF':session.csrf,'Content-Type':'application/json',...extra},body:JSON.stringify(data)});
 assert.equal((await post({authorize:true},{Authorization:''})).status,401);
 assert.equal((await post({authorize:true},{'X-Styx-CSRF':''})).status,403);
 assert.equal((await post({authorize:true},{Origin:'https://untrusted.example'})).status,403);
 for(const data of [{authorize:false},{authorize:true,bundle:'/foreign'},{authorize:true,publisherSha256:'c'.repeat(64)},{authorize:true,stateDir:'/foreign'},{authorize:true,token:'secret'}])assert.equal((await post(data)).status,409);
 assert.equal(calls.length,0);const response=await post({authorize:true});assert.equal(response.status,200);assert.deepEqual(calls,[{stateDir,bundle:artifacts.bundle,authorize:true}]);
 assert.equal((await response.json()).handoff.status,'awaiting_exit');
 assert.deepEqual(await main(['host-payload-handoff-status',stateDir]),{schema:1,status:'not_started'});
});
