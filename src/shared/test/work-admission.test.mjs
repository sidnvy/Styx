import test from 'node:test';
import assert from 'node:assert/strict';
import {WorkAdmission,createHostWorkAdmission,observeOwnedHostSettlement,verifyOwnedHostSettlement} from '../work-admission.mjs';
import {prepareHostUpdateAdmission,readHostUpdateAdmission,commitHostUpdateAdmission,cancelHostUpdateAdmission} from '../../onboarding/host-update-admission.mjs';
const ticket='a'.repeat(32);
const ownedFresh=id=>createHostWorkAdmission(id,{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'b'.repeat(32),lanes:['exec','computer','browser']});
test('fence precedes observation; active and unsettled work wait; continuation stays admitted',()=>{
 let retained=1,identity='one';const a=new WorkAdmission({observe:()=>({identity,retained,unknown:false})}),done=a.enter('one','exec');
 assert.equal(a.begin({ticketId:ticket}).status,'waiting');assert.throws(()=>a.enter('two','exec'),/maintenance/);
 const read=a.enter('one','exec',{continuation:true});done();assert.equal(a.status(ticket).status,'waiting');retained=0;assert.equal(a.status(ticket).status,'waiting');read();assert.equal(a.commit(ticket).status,'ready');assert.throws(()=>a.enter('one','computer'),/maintenance/);
 identity='two';assert.equal(a.status(ticket).status,'unknown');assert.throws(()=>a.commit(ticket),/not_settled/);a.cancel(ticket);a.enter('one','exec')();
});
test('Host-only admits terminal execution independently of result drain and Gateway owner credentials',()=>{
 const a=ownedFresh('host'),p=a.openPeer('exec');p.ready();p.request({id:1,method:'process/start',params:{processId:'process'}});p.response({id:1,result:{processId:'process'}});
 assert.equal(a.begin({ticketId:ticket}).status,'waiting');assert.throws(()=>p.request({id:2,method:'process/start',params:{processId:'other'}}),/maintenance/);
 p.request({id:3,method:'process/read',params:{processId:'process'}});p.response({id:3,result:{exited:true,closed:true,exitCode:0,nextSeq:4,chunks:[{seq:1,stream:'stdout',chunk:'cmVzdWx0'}]}});assert.equal(a.status(ticket).status,'ready');
 p.request({id:4,method:'process/read',params:{processId:'process'}});assert.equal(a.status(ticket).status,'waiting');p.response({id:4,result:{exited:true,closed:true,exitCode:0,nextSeq:4,chunks:[]}});assert.equal(a.commit(ticket).status,'ready');p.close();assert.equal(a.status(ticket).status,'unknown');
});
test('Host terminal notifications require the owning peer, exit and later EOF; no polling is required',()=>{
 const a=ownedFresh('host'),p=a.openPeer('exec'),other=a.openPeer('exec');p.ready();
 p.request({id:1,method:'process/start',params:{processId:'p'}});p.response({id:1,result:{processId:'p'}});
 const event=(method,seq,extra={})=>({method,params:{processId:'p',seq,...extra}});
 a.begin({ticketId:ticket});
 other.response(event('process/exited',2,{exitCode:0}));other.response(event('process/closed',3));assert.equal(a.status(ticket).status,'waiting');
 p.response(event('process/exited',2,{exitCode:0}));assert.equal(a.status(ticket).status,'waiting');
 p.response(event('process/closed',3));assert.equal(a.commit(ticket).status,'ready');a.cancel(ticket);
 p.close();assert.equal(a.begin({ticketId:ticket}).status,'ready');a.cancel(ticket);
});
test('malformed or contradictory terminal evidence cannot admit unfinished Host work',()=>{
 for(const events of [
  [{method:'process/exited',params:{processId:'p',seq:2,exitCode:'0'}}],
  [{method:'process/exited',params:{processId:'p',seq:2,exitCode:0}},{method:'process/closed',params:{processId:'p',seq:1}}],
  [{method:'process/exited',params:{processId:'p',seq:2,exitCode:0}},{method:'process/exited',params:{processId:'p',seq:2,exitCode:1}}]
 ]){
  const a=ownedFresh('host'),p=a.openPeer('exec');p.ready();p.request({id:1,method:'process/start',params:{processId:'p'}});p.response({id:1,result:{processId:'p'}});
  for(const event of events)p.response(event);assert.equal(a.begin({ticketId:ticket}).status,'unknown');
 }
});
test('lost execution outcome never becomes ready on a new peer',()=>{
 const a=ownedFresh('host');const p=a.openPeer('exec');p.ready();p.request({id:1,method:'process/start',params:{processId:'p'}});p.close();a.openPeer('exec').ready();assert.equal(a.begin({ticketId:ticket}).status,'unknown');
});
test('coordinator reuses update ticket for Quit and checks every owned scope before commit',()=>{
 const a=new WorkAdmission(),b=ownedFresh('host');b.openPeer('exec').ready();const active=a.enter('remote','browser'),stateDir='/tmp/styx-admission-coordinator';
 const p=prepareHostUpdateAdmission({stateDir,purpose:'host-update'},{gateway:{workAdmission:a},localHost:b,ownsGateway:true});assert.equal(p.status,'waiting');
 assert.equal(prepareHostUpdateAdmission({stateDir,purpose:'quit'},{gateway:{workAdmission:a},localHost:b,ownsGateway:true}).ticketId,p.ticketId);assert.throws(()=>commitHostUpdateAdmission({stateDir,ticketId:p.ticketId}),/not_settled/);active();assert.equal(readHostUpdateAdmission({stateDir,ticketId:p.ticketId}).status,'ready');assert.equal(commitHostUpdateAdmission({stateDir,ticketId:p.ticketId}).exitAuthorized,true);cancelHostUpdateAdmission({stateDir,ticketId:p.ticketId});a.enter('remote','browser')();
 assert.throws(()=>prepareHostUpdateAdmission({stateDir,purpose:'quit'},{localHost:null}),/unsupported/);
 const fresh=prepareHostUpdateAdmission({stateDir,purpose:'quit'},{requiresLocalHost:false,allowEmpty:true});assert.equal(fresh.status,'ready');cancelHostUpdateAdmission({stateDir,ticketId:fresh.ticketId});
});

test('terminal Browser/Cua errors release work; loss with pending request remains unknown',()=>{
 for(const lane of ['computer','browser']){
  const a=ownedFresh('host');a.openPeer('exec').ready();const p=a.openPeer(lane);
  p.request({id:1,method:'tools/call',params:{}});p.response({id:1,result:{isError:true,content:[]}});assert.equal(a.begin({ticketId:ticket}).status,'ready');a.cancel(ticket);
  p.request({id:2,method:'tools/call',params:{}});p.response({id:2,error:{code:-32602,message:'invalid parameters'}});assert.equal(a.begin({ticketId:ticket}).status,'ready');a.cancel(ticket);
  p.request({id:3,method:'tools/call',params:{}});p.close();assert.equal(a.begin({ticketId:ticket}).status,'unknown');
 }
});

test('owned offline Host can quit without first connecting; its fence still rejects new work',()=>{
 const stateDir='/tmp/styx-offline-owned-quit',a=ownedFresh('host');
 const idle=prepareHostUpdateAdmission({stateDir,purpose:'quit'},{localHost:a});
 assert.equal(idle.status,'ready');assert.equal(commitHostUpdateAdmission({stateDir,ticketId:idle.ticketId}).exitAuthorized,true);
 for(const lane of ['exec','browser','computer']){
  const peer=a.openPeer(lane);
  assert.throws(()=>peer.request({id:1,method:lane==='exec'?'process/start':'tools/call',params:{processId:'blocked'}}),/device_in_maintenance/);
  peer.close();
 }
 cancelHostUpdateAdmission({stateDir,ticketId:idle.ticketId});
});
test('failed initial connections with no dispatched work remain safely empty; explicit uncertainty does not',()=>{
 const a=ownedFresh('host');
 for(let i=0;i<3;i++){const p=a.openPeer('exec');p.close();}
 assert.equal(a.begin({ticketId:ticket}).status,'ready');assert.equal(a.commit(ticket).status,'ready');a.cancel(ticket);
 a.markUnknown();assert.equal(a.begin({ticketId:ticket}).status,'unknown');assert.throws(()=>a.commit(ticket),/not_settled/);
});
test('work dispatched before readiness is tracked, retained and never cleared by reconnect',()=>{
 const a=ownedFresh('host'),p=a.openPeer('exec');
 p.request({id:1,method:'process/start',params:{processId:'p'}});p.response({id:1,result:{processId:'p'}});
 assert.equal(a.begin({ticketId:ticket}).status,'waiting');assert.equal(a.status(ticket).retained,1);a.cancel(ticket);
 p.close();a.openPeer('exec').ready();assert.equal(a.begin({ticketId:ticket}).status,'unknown');assert.throws(()=>a.commit(ticket),/not_settled/);
});

test('missing coverage remains unknown after ready; malformed or unregistered coverage is not trusted',()=>{
 const a=createHostWorkAdmission('unverified');a.openPeer('exec').ready();assert.equal(a.begin({ticketId:ticket}).status,'unknown');assert.throws(()=>a.commit(ticket),/not_settled/);
 assert.throws(()=>createHostWorkAdmission('host',{runtime:'adopted'}),/coverage_contract/);
 const b=createHostWorkAdmission('host',{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'c'.repeat(32),lanes:['exec']});
 assert.throws(()=>b.openPeer('browser'),/lane_not_covered/);assert.equal(b.begin({ticketId:ticket}).status,'unknown');
});
test('a peer replacement after prepare invalidates commit and still cannot dispatch through the fence',()=>{
 const a=ownedFresh('host'),old=a.openPeer('exec');assert.equal(a.begin({ticketId:ticket}).status,'ready');old.close();const next=a.openPeer('exec');next.ready();
 assert.equal(a.status(ticket).reason,'work_peer_changed');assert.throws(()=>a.commit(ticket),/not_settled/);
 assert.throws(()=>next.request({id:1,method:'process/start',params:{processId:'blocked'}}),/maintenance/);
 a.cancel(ticket);assert.equal(a.begin({ticketId:ticket}).status,'ready');
});

test('owned settlement proof is private, fenced, complete and revoked by changed peers or cancellation',()=>{
 const a=ownedFresh('host'),p=a.openPeer('computer');a.begin({ticketId:ticket});
 const proof=observeOwnedHostSettlement(a,ticket),verify=value=>verifyOwnedHostSettlement(value,{deviceId:'host',lanes:['computer','browser'],ticketId:ticket});
 assert.equal(verify(proof),true);assert.equal(verify({...proof}),false);assert.equal(verify(JSON.parse(JSON.stringify(proof))),false);
 assert.equal(verifyOwnedHostSettlement(proof,{deviceId:'other',lanes:['computer'],ticketId:ticket}),false);
 a.cancel(ticket);assert.equal(verify(proof),false);a.begin({ticketId:ticket});assert.equal(verify(proof),false);
 const fresh=observeOwnedHostSettlement(a,ticket);p.close();assert.equal(verify(fresh),false);
 const partial=createHostWorkAdmission('host',{runtime:'fresh_owned',scope:'complete_from_creation',ownerGeneration:'c'.repeat(32),lanes:['exec']});partial.begin({ticketId:ticket});
 assert.equal(verifyOwnedHostSettlement(observeOwnedHostSettlement(partial,ticket),{deviceId:'host',lanes:['computer'],ticketId:ticket}),false);
 for(const controller of [new WorkAdmission(),createHostWorkAdmission('host')]){controller.begin({ticketId:ticket});assert.throws(()=>observeOwnedHostSettlement(controller,ticket),/unavailable/)}
 const scoped=ownedFresh('host');scoped.begin({ticketId:ticket,scope:'host'});assert.throws(()=>observeOwnedHostSettlement(scoped,ticket),/unavailable/);
});
test('terminal local response settles GUI work, malformed or disconnected pending work does not',()=>{
 for(const outcome of ['terminal','malformed','lost']){
  const a=ownedFresh('host'),p=a.openPeer('computer');p.request({id:1,method:'tools/call'});
  if(outcome==='terminal')p.response({id:1,result:{content:[]}});
  if(outcome==='malformed')p.response({id:1});
  p.close();assert.equal(a.begin({ticketId:ticket}).status,outcome==='terminal'?'ready':'unknown');
  if(outcome!=='terminal')assert.throws(()=>observeOwnedHostSettlement(a,ticket),/unavailable/);
 }
});

test('joint settlement proof binds both actual fences and rejects Gateway ticket recreation',()=>{
 const host=ownedFresh('host'),gateway=new WorkAdmission();host.begin({ticketId:ticket});gateway.begin({ticketId:ticket});
 const proof=observeOwnedHostSettlement(host,ticket,{gatewayAdmission:gateway});
 const options={deviceId:'host',lanes:['computer'],ticketId:ticket,gatewayAdmission:gateway};
 assert.equal(verifyOwnedHostSettlement(proof,options),true);
 assert.equal(verifyOwnedHostSettlement(observeOwnedHostSettlement(host,ticket),options),false);
 gateway.cancel(ticket);assert.equal(verifyOwnedHostSettlement(proof,options),false);gateway.begin({ticketId:ticket});assert.equal(verifyOwnedHostSettlement(proof,options),false);
});
