import test from 'node:test';
import assert from 'node:assert/strict';
import {WorkAdmission,createHostWorkAdmission} from '../work-admission.mjs';
import {prepareHostUpdateAdmission,readHostUpdateAdmission,commitHostUpdateAdmission,cancelHostUpdateAdmission} from '../../onboarding/host-update-admission.mjs';
const ticket='a'.repeat(32);
test('fence precedes observation; active and unsettled work wait; continuation stays admitted',()=>{
 let retained=1,identity='one';const a=new WorkAdmission({observe:()=>({identity,retained,unknown:false})}),done=a.enter('one','exec');
 assert.equal(a.begin({ticketId:ticket}).status,'waiting');assert.throws(()=>a.enter('two','exec'),/maintenance/);
 const read=a.enter('one','exec',{continuation:true});done();assert.equal(a.status(ticket).status,'waiting');retained=0;assert.equal(a.status(ticket).status,'waiting');read();assert.equal(a.commit(ticket).status,'ready');assert.throws(()=>a.enter('one','computer'),/maintenance/);
 identity='two';assert.equal(a.status(ticket).status,'unknown');assert.throws(()=>a.commit(ticket),/not_settled/);a.cancel(ticket);a.enter('one','exec')();
});
test('Host-only admits terminal execution independently of result drain and Gateway owner credentials',()=>{
 const a=createHostWorkAdmission('host'),p=a.openPeer('exec');p.ready();p.request({id:1,method:'process/start',params:{processId:'process'}});p.response({id:1,result:{processId:'process'}});
 assert.equal(a.begin({ticketId:ticket}).status,'waiting');assert.throws(()=>p.request({id:2,method:'process/start',params:{processId:'other'}}),/maintenance/);
 p.request({id:3,method:'process/read',params:{processId:'process'}});p.response({id:3,result:{exited:true,closed:true,exitCode:0,nextSeq:4,chunks:[{seq:1,stream:'stdout',chunk:'cmVzdWx0'}]}});assert.equal(a.status(ticket).status,'ready');
 p.request({id:4,method:'process/read',params:{processId:'process'}});assert.equal(a.status(ticket).status,'waiting');p.response({id:4,result:{exited:true,closed:true,exitCode:0,nextSeq:4,chunks:[]}});assert.equal(a.commit(ticket).status,'ready');p.close();assert.equal(a.status(ticket).status,'unknown');
});
test('Host terminal notifications require the owning peer, exit and later EOF; no polling is required',()=>{
 const a=createHostWorkAdmission('host'),p=a.openPeer('exec'),other=a.openPeer('exec');p.ready();
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
  const a=createHostWorkAdmission('host'),p=a.openPeer('exec');p.ready();p.request({id:1,method:'process/start',params:{processId:'p'}});p.response({id:1,result:{processId:'p'}});
  for(const event of events)p.response(event);assert.equal(a.begin({ticketId:ticket}).status,'unknown');
 }
});
test('lost execution outcome never becomes ready on a new peer; never observed old runtime is unknown',()=>{
 const a=createHostWorkAdmission('host');assert.equal(a.begin({ticketId:ticket}).status,'unknown');a.cancel(ticket);const p=a.openPeer('exec');p.ready();p.request({id:1,method:'process/start',params:{processId:'p'}});p.close();a.openPeer('exec').ready();assert.equal(a.begin({ticketId:ticket}).status,'unknown');
});
test('coordinator reuses update ticket for Quit and checks every owned scope before commit',()=>{
 const a=new WorkAdmission(),b=createHostWorkAdmission('host');b.openPeer('exec').ready();const active=a.enter('remote','browser'),stateDir='/tmp/styx-admission-coordinator';
 const p=prepareHostUpdateAdmission({stateDir,purpose:'host-update'},{gateway:{workAdmission:a},localHost:b,ownsGateway:true});assert.equal(p.status,'waiting');
 assert.equal(prepareHostUpdateAdmission({stateDir,purpose:'quit'},{gateway:{workAdmission:a},localHost:b,ownsGateway:true}).ticketId,p.ticketId);assert.throws(()=>commitHostUpdateAdmission({stateDir,ticketId:p.ticketId}),/not_settled/);active();assert.equal(readHostUpdateAdmission({stateDir,ticketId:p.ticketId}).status,'ready');assert.equal(commitHostUpdateAdmission({stateDir,ticketId:p.ticketId}).exitAuthorized,true);cancelHostUpdateAdmission({stateDir,ticketId:p.ticketId});a.enter('remote','browser')();
 assert.throws(()=>prepareHostUpdateAdmission({stateDir,purpose:'quit'},{localHost:null}),/unsupported/);
 const fresh=prepareHostUpdateAdmission({stateDir,purpose:'quit'},{requiresLocalHost:false,allowEmpty:true});assert.equal(fresh.status,'ready');cancelHostUpdateAdmission({stateDir,ticketId:fresh.ticketId});
});

test('terminal Browser/Cua errors release work; loss with pending request remains unknown',()=>{
 for(const lane of ['computer','browser']){
  const a=createHostWorkAdmission('host');a.openPeer('exec').ready();const p=a.openPeer(lane);
  p.request({id:1,method:'tools/call',params:{}});p.response({id:1,result:{isError:true,content:[]}});assert.equal(a.begin({ticketId:ticket}).status,'ready');a.cancel(ticket);
  p.request({id:2,method:'tools/call',params:{}});p.response({id:2,error:{code:-32602,message:'invalid parameters'}});assert.equal(a.begin({ticketId:ticket}).status,'ready');a.cancel(ticket);
  p.request({id:3,method:'tools/call',params:{}});p.close();assert.equal(a.begin({ticketId:ticket}).status,'unknown');
 }
});
