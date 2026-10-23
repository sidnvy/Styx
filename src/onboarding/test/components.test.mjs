import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {readDeploymentComponents} from '../components.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-components-'));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const write=(file,value)=>fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
 const keys=generateKeyPairSync('ed25519'),pem=keys.publicKey.export({type:'spki',format:'pem'}),pin=sha(keys.publicKey.export({type:'spki',format:'der'}));
 const base=path.join(dir,'host'),root=path.join(base,'install'),stateDir=path.join(dir,'state');for(const d of [base,root,path.join(root,'releases'),stateDir])fs.mkdirSync(d,{mode:0o700});
 const pub=path.join(base,'publisher.pem');write(pub,pem);
 const bundle=(name,version,key=keys,payload='fixture')=>{
  const dest=path.join(dir,name);fs.mkdirSync(dest,{mode:0o700});const bytes=JSON.stringify({schema:1,version,platform:process.platform,arch:process.arch,files:[{path:'fixture',sha256:sha(payload),size:payload.length,executable:false}]});write(path.join(dest,'manifest.json'),bytes);write(path.join(dest,'manifest.sig'),sign(null,Buffer.from(bytes),key.privateKey).toString('base64url'));write(path.join(dest,'fixture'),payload);return {bundle:dest,manifestSha256:sha(bytes)};
 };
 const initial=bundle('initial','1.0.0');fs.cpSync(initial.bundle,path.join(root,'releases/1.0.0'),{recursive:true});
 write(path.join(root,'active.json'),{schema:1,version:'1.0.0',previous:null,manifest_sha256:initial.manifestSha256});
 const config={schema:1,mode:'join-existing',gateway:{url:'https://example.invalid'},host:{baseDir:base,publisherSha256:pin}};write(path.join(stateDir,'deployment.json'),config);write(path.join(stateDir,'state.json'),{schema:1,mode:config.mode,configSha256:sha(JSON.stringify(config)),steps:[{id:'host.prepare',status:'succeeded'}]});
 const artifacts={bundle:initial.bundle,publisherKeyFile:pub,publisherSha256:pin};return {dir,base,root,stateDir,write,bundle,keys,pin,pub,artifacts};
}
function tree(dir){return fs.readdirSync(dir,{recursive:true,withFileTypes:true}).filter(e=>e.isFile()).map(e=>{const file=path.join(e.parentPath??e.path,e.name);return [file,sha(fs.readFileSync(file))]}).sort()}
test('same signed generation is aligned metadata, never a runtime or payload health claim; reads do not mutate',t=>{
 const f=fixture(t),before=tree(f.dir),r=readDeploymentComponents(f.stateDir,{artifacts:f.artifacts});assert.equal(r.host.status,'aligned');assert.equal(r.payloadIntegrity,'not_rechecked');assert.equal(r.runtimeHealth,'not_observed');assert.equal(r.mutation,'NONE');assert.deepEqual(tree(f.dir),before);
 assert.equal(readDeploymentComponents(f.stateDir).host.status,'candidate_not_supplied');
});
test('signed newer generation is update available, not upgrade-ready; version reuse is a conflict',t=>{
 const f=fixture(t),newer=f.bundle('newer','2.0.0');let r=readDeploymentComponents(f.stateDir,{artifacts:{...f.artifacts,bundle:newer.bundle}});assert.equal(r.host.status,'update_available');assert.equal(r.host.updateReadiness,'not_evaluated');
 const conflict=f.bundle('conflict','1.0.0',f.keys,'changed');r=readDeploymentComponents(f.stateDir,{artifacts:{...f.artifacts,bundle:conflict.bundle}});assert.equal(r.host.status,'same_version_conflict');
});
test('different signed publisher is explicitly reported without replacing old trust or configuration',t=>{
 const f=fixture(t),keys=generateKeyPairSync('ed25519'),candidate=f.bundle('foreign','2.0.0',keys),pub=path.join(f.dir,'new-public.pem');f.write(pub,keys.publicKey.export({type:'spki',format:'pem'}));const pin=sha(keys.publicKey.export({type:'spki',format:'der'})),before=tree(f.dir);
 const r=readDeploymentComponents(f.stateDir,{artifacts:{bundle:candidate.bundle,publisherKeyFile:pub,publisherSha256:pin}});assert.equal(r.host.status,'publisher_changed');assert.equal(r.host.requiredAction,'review_publisher_migration');assert.equal(r.host.installed.publisherSha256,f.pin);assert.deepEqual(tree(f.dir),before);assert.doesNotMatch(JSON.stringify(r),/BEGIN|token|private|baseDir/);assert.equal(JSON.stringify(r).includes(f.dir),false);
});
test('tampering and unfinished transactions never appear aligned',t=>{
 const f=fixture(t),candidate=f.bundle('candidate','2.0.0');fs.appendFileSync(path.join(candidate.bundle,'manifest.json'),' ');assert.equal(readDeploymentComponents(f.stateDir,{artifacts:{...f.artifacts,bundle:candidate.bundle}}).host.status,'candidate_unverified');
 fs.mkdirSync(path.join(f.root,'.health-update-lock'),{mode:0o700});assert.equal(readDeploymentComponents(f.stateDir,{artifacts:f.artifacts}).host.status,'needs_recovery');fs.rmdirSync(path.join(f.root,'.health-update-lock'));
 const file=path.join(f.root,'active.json'),pointer=JSON.parse(fs.readFileSync(file));pointer.manifest_sha256='0'.repeat(64);f.write(file,pointer);assert.equal(readDeploymentComponents(f.stateDir,{artifacts:f.artifacts}).host.status,'unavailable');
});
test('CLI and authenticated App API return the same Core evidence',async t=>{
 const f=fixture(t),defaults=path.join(f.dir,'artifacts.json');f.write(defaults,f.artifacts);
 const {main}=await import('../cli.mjs'),{createOnboardingServer}=await import('../server.mjs');
 const cli=await main(['components',f.stateDir,defaults]);
 const app=await createOnboardingServer({stateDir:f.stateDir,artifactDefaultsFile:defaults});t.after(()=>app.close());
 const unauthorized=await fetch(app.origin+'/api/components');assert.equal(unauthorized.status,401);
 const token=new URL(app.url).hash.slice(9),response=await fetch(app.origin+'/api/components',{headers:{Authorization:'Bearer '+token,Origin:app.origin}});assert.equal(response.status,200);assert.deepEqual((await response.json()).components,cli);
});
