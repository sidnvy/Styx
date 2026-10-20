import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {generateKeyPairSync,createHash,verify,constants} from 'node:crypto';
import {capabilityPayload} from '../../shared/enrollment-protocol.mjs';
import {changeDeploymentCapabilities,readDeploymentCapabilities} from '../capabilities.mjs';
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-capabilities-'));fs.chmodSync(dir,0o700);t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,'deployment.json'),'{}',{mode:0o600});
 const keys=generateKeyPairSync('rsa',{modulusLength:3072});
 const publicKey=keys.publicKey.export({type:'spki',format:'pem'}),key=keys.privateKey.export({type:'pkcs8',format:'pem'});
 const identity={device_id:'styx-'+'a'.repeat(24),fingerprint:createHash('sha256').update(keys.publicKey.export({type:'spki',format:'der'})).digest('hex')};
 const host={host_id:identity.device_id,token_file:'unchanged',exec:{binary:'unchanged'}};
 const hostFile=path.join(dir,'host.json');fs.writeFileSync(hostFile,JSON.stringify(host),{mode:0o600});
 let generation=0,enabled=false,running=true;const calls=[];
 const ops={prepare:()=>({identity,key,publicKey,host:JSON.parse(fs.readFileSync(hostFile)),hostFile,computer:{enabled:true,binary:'/verified/cua',connections:1},owner:{},serviceConfigFile:'fixed'}),
  hostStatus:async()=>({status:'reported',state:running?'running':'stopped',installed:true}),
  hostControl:async(d,{action})=>{calls.push(action);running=action==='start';return {status:'reported',state:running?'running':'stopped'}},
  owner:async(owner,command,args)=>{
   if(command==='devices')return [{...identity,status:'approved',generation:String(generation),capabilities:{exec:true,computer:enabled}}];
   const body=args[0];assert.equal(body.generation,String(generation));assert.ok(verify('sha256',Buffer.from(capabilityPayload(body)),{key:publicKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(body.signature,'base64url')));
   enabled=body.enable_computer;generation++;calls.push('computer.'+enabled);
   return {status:'updated',...identity,generation:String(generation),capabilities:{exec:true,computer:enabled}};
  }};
 return {dir,hostFile,ops,calls};
}
test('local capability enable and disable preserve identity and exec config without reenrollment',async t=>{
 const f=fixture(t);
 const enabled=await changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops);
 assert.equal(enabled.status,'updated');assert.equal(enabled.computer,true);
 assert.deepEqual(f.calls,['computer.false','stop','computer.true','start']);
 let host=JSON.parse(fs.readFileSync(f.hostFile));assert.equal(host.exec.binary,'unchanged');assert.equal(host.token_file,'unchanged');assert.equal(host.computer.enabled,true);
 f.calls.length=0;await changeDeploymentCapabilities(f.dir,{authorize:true,computer:false},f.ops);
 assert.deepEqual(f.calls,['computer.false','stop','start']);host=JSON.parse(fs.readFileSync(f.hostFile));assert.equal(host.computer,undefined);
 assert.equal(readDeploymentCapabilities(f.dir).computer,false);
});
test('lost capability response stops local Host, disables its config and never replays uncertain transaction',async t=>{
 const f=fixture(t),owner=f.ops.owner;
 f.ops.owner=async(...args)=>{const result=await owner(...args);if(args[1]==='capabilities'&&args[2][0].enable_computer)throw Error('lost_response');return result};
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/lost_response/);
 assert.equal(f.calls.at(-1),'computer.false');assert.equal(f.calls.at(-2),'stop');assert.equal(JSON.parse(fs.readFileSync(f.hostFile)).computer,undefined);
 assert.equal(readDeploymentCapabilities(f.dir).status,'uncertain');assert.equal(readDeploymentCapabilities(f.dir).computer,false);const n=f.calls.length;
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/uncertain_requires_reconciliation/);assert.equal(f.calls.length,n);
});
test('no permission means no state or native mutation',async t=>{
 const f=fixture(t);await assert.rejects(changeDeploymentCapabilities(f.dir,{computer:true},f.ops),/authorization_required/);
 assert.equal(f.calls.length,0);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false);
});
test('capability scope is checked before owned foreground stops and explicit resume is recorded',async t=>{
 const f=fixture(t);f.ops.readForeground=()=>({status:'connected'});
 f.ops.stopOwnedForeground=async()=>{const j=JSON.parse(fs.readFileSync(path.join(f.dir,'capabilities.json')));assert.equal(j.phase,'stop_owned_foreground');assert.equal(j.status,'running');f.calls.push('owned.stop');return {status:'stopped',foregroundRestartRequired:true}};
 const result=await changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops);assert.equal(result.foregroundRestartRequired,true);assert.equal(f.calls[0],'owned.stop');assert.equal(f.calls.filter(x=>x==='owned.stop').length,1);
});
test('unknown external owner or failed scope cannot stop foreground or mutate capabilities',async t=>{
 const f=fixture(t);let stopped=0;f.ops.stopOwnedForeground=async()=>{stopped++;return {status:'stopped'}};f.ops.readForeground=()=>({status:'needs_attention'});
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/foreground_owned_or_interrupted/);assert.equal(stopped,0);assert.equal(f.calls.length,0);
 f.ops.readForeground=()=>({status:'connected'});f.ops.prepare=()=>{throw Error('scope_refused')};await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,computer:true},f.ops),/scope_refused/);assert.equal(stopped,0);assert.equal(f.calls.length,0);
});


test('existing deployment Browser changes stop before state, identity, desktop or service mutation',async t=>{
 const f=fixture(t),before=fs.readFileSync(f.hostFile);
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:true},f.ops),/browser_capability_migration_not_implemented_preserve_existing_identity/);
 await assert.rejects(changeDeploymentCapabilities(f.dir,{authorize:true,browser:false,computer:false},f.ops),/browser_capability_migration_not_implemented/);
 await assert.rejects(changeDeploymentCapabilities(f.dir,{browser:true},f.ops),/explicit_browser_capability_authorization_required/);
 assert.equal(f.calls.length,0);assert.deepEqual(fs.readFileSync(f.hostFile),before);assert.equal(fs.existsSync(path.join(f.dir,'capabilities.json')),false);
});
