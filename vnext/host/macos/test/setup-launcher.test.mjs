import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {previewLayout,previewSigningIdentity,setupStorage} from '../setup-launcher.mjs';
function fixture(){
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'styx-preview-launcher-'))),resources=path.join(root,'Styx.app/Contents/Resources');
 fs.mkdirSync(resources,{recursive:true});for(const p of['runtime/node','onboarding/vnext/onboarding/server.mjs','publisher.pem']){fs.mkdirSync(path.dirname(path.join(resources,p)),{recursive:true});fs.writeFileSync(path.join(resources,p),'test-only')}
 fs.mkdirSync(path.join(resources,'host-bundle'));fs.writeFileSync(path.join(resources,'artifact-defaults.json'),JSON.stringify({bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256:'a'.repeat(64)}));
 return{root,resources,close(){fs.rmSync(root,{recursive:true,force:true})}};
}
test('relocatable bundle layout resolves only fixed contained resources without global paths',()=>{
 const f=fixture();try{const layout=previewLayout(f.resources);assert.equal(layout.artifacts.bundle,path.join(f.resources,'host-bundle'));assert.equal(layout.node,path.join(f.resources,'runtime/node'));
  const defaults=path.join(f.resources,'artifact-defaults.json');fs.writeFileSync(defaults,JSON.stringify({bundle:'../outside',publisherKeyFile:'publisher.pem',publisherSha256:'a'.repeat(64)}));assert.throws(()=>previewLayout(f.resources),/artifact_locations/);
 }finally{f.close()}
});
test('bundle redirects and extra credential-bearing defaults are rejected',()=>{
 const f=fixture();try{
  const publisher=path.join(f.resources,'publisher.pem');fs.unlinkSync(publisher);fs.writeFileSync(path.join(f.root,'outside.pem'),'outside');fs.symlinkSync(path.join(f.root,'outside.pem'),publisher);assert.throws(()=>previewLayout(f.resources),/redirect/);
  fs.unlinkSync(publisher);fs.writeFileSync(publisher,'public');fs.writeFileSync(path.join(f.resources,'artifact-defaults.json'),JSON.stringify({bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256:'a'.repeat(64),token:'must-not-copy'}));assert.throws(()=>previewLayout(f.resources),/defaults_invalid/);
 }finally{f.close()}
});
test('native signature verification precedes preview identity acceptance and requires exact ad-hoc bundle CDHash',()=>{
 const layout={app:'/Applications/Styx.app'};let calls=[];
 const run=(_command,args)=>{calls.push(args);return{status:0,stderr:'Identifier=app.styx.host\nSignature=adhoc\nCDHash='+ 'b'.repeat(40)+'\n'}};
 assert.deepEqual(previewSigningIdentity(layout,{run}),{path:layout.app,cdhash:'b'.repeat(40)});assert.deepEqual(calls[0],['--verify','--deep','--strict',layout.app]);
 assert.throws(()=>previewSigningIdentity(layout,{run:()=>({status:1})}),/signature_invalid/);
 for(const bad of['Identifier=other\nSignature=adhoc\nCDHash='+'b'.repeat(40),'Identifier=app.styx.host\nAuthority=Developer ID\nCDHash='+'b'.repeat(40),'Identifier=app.styx.host\nSignature=adhoc\nCDHash=invalid'])assert.throws(()=>previewSigningIdentity(layout,{run:()=>({status:0,stderr:bad})}),/identity_required/);
});
test('settings state is owner-private outside read-only bundle and never hardens/reuses broad state',{skip:process.platform==='win32'},()=>{
 const f=fixture();try{
  const home=path.join(f.root,'home');fs.mkdirSync(path.join(home,'Library/Application Support'),{recursive:true});
  const storage=setupStorage(home);assert.equal(storage.root,path.join(home,'Library/Application Support/Styx/Setup'));assert.equal(fs.statSync(storage.root).mode&0o077,0);assert.equal(fs.existsSync(storage.stateDir),false);assert.equal(storage.root.includes('Styx.app'),false);
  fs.chmodSync(storage.root,0o755);assert.throws(()=>setupStorage(home),/private_state/);assert.equal(fs.statSync(storage.root).mode&0o777,0o755);
 }finally{f.close()}
});
