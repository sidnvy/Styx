import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {WorkAdmission} from '../../shared/work-admission.mjs';
import {prepareHostUpdateAdmission,commitHostUpdateAdmission,cancelHostUpdateAdmission} from '../host-update-admission.mjs';
import {changeManagedDeploymentCapabilities} from '../capability-lifecycle.mjs';
function fixture(t,{retained=0,unknown=false,observation='current_process',status='connected'}={}){
 const stateDir='/tmp/styx-capability-lifecycle-'+randomUUID(),events=[];
 const gateway=new WorkAdmission(),host=new WorkAdmission({observe:()=>({identity:'host-generation',retained,unknown})});
 let actualHost=host,ticket,stopped=false;
 const scope=()=>({gateway,localHost:actualHost,ownsGateway:true,requiresLocalHost:true});
 const lifecycle={
  read:()=>({status,observation,host:status==='using_service'?'service':'foreground'}),
  prepare:(_d,{purpose})=>{const result=prepareHostUpdateAdmission({stateDir,purpose},scope());ticket=result.ticketId;return result;},
  commit:(_d,{ticketId})=>{prepareHostUpdateAdmission({stateDir,purpose:'host-update',ticketId},scope());return commitHostUpdateAdmission({stateDir,ticketId});},
  cancel:(_d,{ticketId})=>{const r=cancelHostUpdateAdmission({stateDir,ticketId});ticket=null;events.push('cancel');return r;},
  stop:()=>{assert(host.tickets.size===1&&[...host.tickets.values()][0].committed);assert.equal(gateway.status(ticket).status,'ready');stopped=true;events.push('stopHost');return {status:'stopped'};},
  change:()=>{assert(stopped||status==='not_running');assert.throws(()=>gateway.enter('device','exec'),/device_in_maintenance/);events.push('change');return {status:'updated',transactionId:'a'.repeat(32)};},
  start:()=>{assert.equal(host.tickets.size,0);assert.equal(gateway.tickets.size,0);events.push('resumeHost');return {status:'connected',host:'foreground'};}
 };
 t.after(()=>{if(ticket)cancelHostUpdateAdmission({stateDir,ticketId:ticket});});
 return {stateDir,host,gateway,events,lifecycle,replaceOwner(){actualHost=new WorkAdmission()},run:()=>changeManagedDeploymentCapabilities(stateDir,{authorize:true,computer:true},{lifecycle})};
}
test('owned connected Host is quiesced under real two-sided admission; Gateway fence releases before resume',async t=>{
 const f=fixture(t);const result=await f.run();assert.equal(result.foregroundResumed,true);assert.deepEqual(f.events,['stopHost','change','cancel','resumeHost']);assert.equal(f.gateway.tickets.size,0);assert.equal(f.host.tickets.size,0);
});
test('retained work, unknown outcome and active work never stop a Host',async t=>{
 for(const mode of ['retained','unknown','active']){const f=fixture(t,{retained:mode==='retained'?1:0,unknown:mode==='unknown'});let release;if(mode==='active')release=f.host.enter('device','exec');await assert.rejects(f.run(),mode==='unknown'?/work_state_unknown/:/work_in_progress/);release?.();assert.deepEqual(f.events,['cancel']);assert.equal(f.gateway.tickets.size,0);assert.equal(f.host.tickets.size,0);}
});
test('real owner replacement between prepare and commit denies stopping either runtime',async t=>{
 const f=fixture(t),commit=f.lifecycle.commit;f.lifecycle.commit=(...args)=>{f.replaceOwner();return commit(...args)};await assert.rejects(f.run(),/maintenance_owner_changed/);assert.deepEqual(f.events,['cancel']);
});
test('transaction failure stays stopped without auto-replay or restart and releases old fences',async t=>{
 const f=fixture(t);f.lifecycle.change=()=>{f.events.push('change');throw Error('capability_uncertain_requires_reconciliation')};await assert.rejects(f.run(),/capability_uncertain/);assert.deepEqual(f.events,['stopHost','change','cancel']);assert.equal(f.gateway.tickets.size,0);
});
test('independent services and foreign ownership are never adopted',async t=>{
 for(const options of [{status:'using_service'},{observation:'other_process'}]){const f=fixture(t,options);await assert.rejects(f.run(),/foreground_not_owned_or_unsafe/);assert.deepEqual(f.events,[]);assert.equal(f.host.tickets.size,0);}
});
test('already stopped selection uses only canonical offline transaction; invalid authorization has no lifecycle effects',async t=>{
 const f=fixture(t,{status:'not_running'});f.lifecycle.change=(_d,selection)=>{assert.equal(selection.authorize,true);return {status:'updated'}};assert.equal((await f.run()).status,'updated');assert.deepEqual(f.events,[]);await assert.rejects(changeManagedDeploymentCapabilities(f.stateDir,{computer:true},{lifecycle:f.lifecycle}),/explicit_desktop/);assert.deepEqual(f.events,[]);
});
test('a finishing response drains through the admission fence before changing capabilities',async t=>{
 const f=fixture(t),release=f.host.enter('device','computer'),prepare=f.lifecycle.prepare;
 let drained=false;
 f.lifecycle.prepare=(...args)=>{const result=prepare(...args);assert.throws(()=>f.host.enter('device','computer'),/device_in_maintenance/);if(!drained){drained=true;setTimeout(release,30)}return result;};
 await f.run();assert.deepEqual(f.events,['stopHost','change','cancel','resumeHost']);
});
test('an unresolved transaction result cannot restart the Host',async t=>{
 const f=fixture(t);f.lifecycle.change=()=>({status:'uncertain'});await assert.rejects(f.run(),/capability_uncertain_requires_reconciliation/);assert.deepEqual(f.events,['stopHost','cancel']);
});
