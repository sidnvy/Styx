import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {enableDeploymentBackground,readDeploymentBackground} from '../background.mjs';
function fixture(t,{mode='create-local'}={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'styx-background-'));fs.chmodSync(dir,0o700);
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,'deployment.json'),'{}\n',{mode:0o600});
 const calls=[];let gatewayInstalled=false,gatewayRunning=false,hostInstalled=false,hostRunning=false,foreground=true;
 const ops={
  read:()=>({mode,steps:[{id:'host.doctor',status:'succeeded'}],gatewayRuntime:{status:foreground?'running':'not_owned_by_current_process'}}),
  host:async(d,{action})=>{calls.push('host.'+action);if(action==='install')hostInstalled=true;if(action==='start')hostRunning=true;
   return {status:'reported',installed:hostInstalled,state:hostRunning?'running':'stopped'}},
  gateway:async(d,{action})=>{calls.push('gateway.'+action);if(action==='install')gatewayInstalled=true;if(action==='start')gatewayRunning=true;
   return {...(!gatewayInstalled?{status:'not_installed'}:{}),active:gatewayRunning?'active':'inactive',enabled:gatewayRunning?'enabled':'disabled',pid:gatewayRunning?123:null}},
  stopForeground:async()=>{calls.push('foreground.stop');foreground=false;return {status:'stopped'}},
  hostConnection:async()=>({status:'observed',online:hostRunning}),
  verifyGateway:async()=>{calls.push('gateway.verify');return {status:'gateway_verified'}},sleep:async()=>{}
 };
 return {dir,ops,calls};
}
test('one authorization hands off Gateway then starts Host without claiming account or desktop readiness',async t=>{
 const f=fixture(t);const result=await enableDeploymentBackground(f.dir,{authorize:true},f.ops);
 assert.equal(result.status,'running');assert.equal(result.accountAcceptance,'NOT RUN');assert.equal(result.hostHealth,'not_checked');assert.equal(result.hostConnection,'exec_connected');
 assert.ok(f.calls.indexOf('gateway.install')<f.calls.indexOf('foreground.stop'));
 assert.ok(f.calls.indexOf('foreground.stop')<f.calls.indexOf('gateway.start'));
 assert.ok(f.calls.indexOf('gateway.verify')<f.calls.indexOf('host.start'));
 assert.equal(fs.statSync(path.join(f.dir,'background.json')).mode&0o077,0);
 assert.ok(!JSON.stringify(result).includes(f.dir));
 const first=f.calls.length;await enableDeploymentBackground(f.dir,{authorize:true},f.ops);
 assert.ok(!f.calls.slice(first).some(x=>/\.(start|install|stop)$/.test(x)));
});
test('remote Host mode never installs or controls an external Gateway',async t=>{
 const f=fixture(t,{mode:'join-existing'});const result=await enableDeploymentBackground(f.dir,{authorize:true},f.ops);
 assert.equal(result.gateway,'external');assert.ok(!f.calls.some(x=>x.startsWith('gateway.')||x==='foreground.stop'));
});
test('missing authorization or doctor readiness stops before native mutations',async t=>{
 const f=fixture(t);
 await assert.rejects(enableDeploymentBackground(f.dir,{},f.ops),/authorization_required/);assert.equal(f.calls.length,0);
 f.ops.read=()=>({steps:[]});await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/doctor_required/);assert.equal(f.calls.length,0);
});
test('uncertain native start persists intent and cannot be replayed after retry',async t=>{
 const f=fixture(t),gateway=f.ops.gateway;
 f.ops.gateway=async(d,o)=>{if(o.action==='start'){f.calls.push('gateway.start');throw Error('private native output')}return gateway(d,o)};
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/uncertain_no_replay/);
 const first=f.calls.length;
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/uncertain_requires_reconciliation/);
 assert.equal(f.calls.length,first);assert.equal(readDeploymentBackground(f.dir).status,'needs_attention');
 assert.ok(!fs.readFileSync(path.join(f.dir,'background.json'),'utf8').includes('private native output'));
});
test('loaded or unknown Host is never reported as background running',async t=>{
 const f=fixture(t,{mode:'join-existing'});f.ops.host=async()=>({status:'reported',installed:true,state:'loaded'});
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/host_service_not_running/);
 assert.equal(readDeploymentBackground(f.dir).status,'needs_attention');
});
test('failed authenticated Gateway readiness does not start Host',async t=>{
 const f=fixture(t);f.ops.verifyGateway=async()=>{throw Error('not ready')};
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/connection_not_ready/);
 assert.ok(!f.calls.includes('host.start'));assert.equal(readDeploymentBackground(f.dir).status,'needs_attention');
});
test('journal scope and concurrent operation locks fail closed',async t=>{
 const f=fixture(t);await enableDeploymentBackground(f.dir,{authorize:true},f.ops);
 fs.writeFileSync(path.join(f.dir,'deployment.json'),'{"changed":true}');
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/scope_changed/);
 fs.writeFileSync(path.join(f.dir,'background.lock'),'',{mode:0o600});
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/busy_or_interrupted_lock/);
});

import {observeDeploymentBackground} from '../background.mjs';
test('fresh observation detects a stopped service without rewriting recorded success',async t=>{
 const f=fixture(t);await enableDeploymentBackground(f.dir,{authorize:true},f.ops);
 const before=fs.readFileSync(path.join(f.dir,'background.json'),'utf8');
 const result=await observeDeploymentBackground(f.dir,{
  read:f.ops.read,plan:()=>({service:{configFile:'fixed-private-descriptor'}}),
  hostStatus:async({serviceConfigFile})=>{assert.equal(serviceConfigFile,'fixed-private-descriptor');return {status:'reported',installed:true,state:'stopped'}},
  gateway:f.ops.gateway,hostConnection:f.ops.hostConnection
 });
 assert.equal(result.observation,'current');assert.equal(result.status,'needs_attention');assert.equal(result.host,'not_running');
 assert.equal(fs.readFileSync(path.join(f.dir,'background.json'),'utf8'),before);
 assert.equal(readDeploymentBackground(f.dir).observation,'last_recorded');
});

test('existing connected foreground Host blocks all service mutations and Gateway handoff',async t=>{
 const f=fixture(t);f.ops.hostConnection=async()=>({status:'observed',online:true});
 const result=await enableDeploymentBackground(f.dir,{authorize:true},f.ops);
 assert.equal(result.status,'needs_attention');assert.equal(result.reason,'foreground_host_handoff_required');
 assert.deepEqual(f.calls,['host.status']);assert.deepEqual(result.operations,[]);
});
test('OS process running without an Exec relay connection does not pass background readiness',async t=>{
 const f=fixture(t);f.ops.hostConnection=async()=>({status:'observed',online:false});
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/host_exec_connection_not_ready/);
 const result=readDeploymentBackground(f.dir);assert.equal(result.host,'running');assert.equal(result.hostConnection,'not_connected');assert.equal(result.status,'needs_attention');
});
test('unknown owner connection status cannot trigger background mutations',async t=>{
 const f=fixture(t);f.ops.hostConnection=async()=>{throw Error('host_connection_observation_unavailable')};
 await assert.rejects(enableDeploymentBackground(f.dir,{authorize:true},f.ops),/host_connection_observation_unavailable/);assert.deepEqual(f.calls,['host.status']);
});
test('Gateway-only handoff and observation never call Host adapters or connection probes',async t=>{
 const f=fixture(t);f.ops.read=()=>({mode:'create-local',roles:{host:'disabled'},steps:[],gatewayRuntime:{status:'not_owned_by_current_process'}});
 const forbidden=async()=>{throw Error('Host adapter must not be reached')};f.ops.host=forbidden;f.ops.hostConnection=forbidden;
 const result=await enableDeploymentBackground(f.dir,{authorize:true},f.ops);assert.equal(result.status,'running');assert.equal(result.host,'disabled');assert.equal(result.hostConnection,'not_applicable');
 assert.ok(f.calls.every(x=>x.startsWith('gateway.')));
 const observation=await observeDeploymentBackground(f.dir,{read:f.ops.read,hostStatus:forbidden,hostConnection:forbidden,gateway:f.ops.gateway});
 assert.equal(observation.status,'running');assert.equal(observation.host,'disabled');assert.equal(observation.hostConnection,'not_applicable');
});
