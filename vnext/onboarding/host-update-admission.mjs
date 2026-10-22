import path from 'node:path';
import {randomBytes} from 'node:crypto';
// In-memory ownership matches the App/Core lifetimes it protects. A restarted
// owner cannot adopt an old permission to shut down or claim work was drained.
const tickets=new Map();
const valid=d=>typeof d==='string'&&path.isAbsolute(d)&&path.normalize(d)===d;
const assert=(ok,why)=>{if(!ok)throw Error(why)};
const key=({stateDir,ticketId})=>{assert(valid(stateDir)&&/^[a-f0-9]{32}$/.test(ticketId??''),'maintenance_scope_invalid');const t=tickets.get(stateDir);assert(t?.ticketId===ticketId,'maintenance_ticket_unavailable');return t};
export function prepareHostUpdateAdmission({stateDir,purpose,ticketId}={}, {gateway,localHost,ownsGateway=false,requiresLocalHost=true,allowEmpty=false}={}){
 assert(valid(stateDir)&&['quit','host-update'].includes(purpose),'maintenance_scope_invalid');
 const prior=tickets.get(stateDir);if(prior){assert(ticketId===undefined||ticketId===prior.ticketId,'maintenance_already_owned');return readHostUpdateAdmission({stateDir,ticketId:prior.ticketId})}
 const controllers=[...(ownsGateway?[gateway?.workAdmission??gateway]:[]),...(requiresLocalHost?[localHost]:[])];
 assert((controllers.length>0||allowEmpty===true)&&controllers.every(c=>c&&['begin','status','commit','cancel'].every(k=>typeof c[k]==='function')),'maintenance_observation_unsupported');
 const unique=[...new Set(controllers)],id=ticketId??randomBytes(16).toString('hex'),acquired=[];
 try{for(const c of unique){c.begin({ticketId:id,scope:'all'});acquired.push(c)}tickets.set(stateDir,{ticketId:id,purpose,controllers:unique});return readHostUpdateAdmission({stateDir,ticketId:id})}
 catch(error){for(const c of acquired)c.cancel(id);throw error}
}
export function readHostUpdateAdmission(options){const t=key(options),parts=t.controllers.map(c=>c.status(t.ticketId));return{schema:1,ticketId:t.ticketId,purpose:t.purpose,status:parts.some(x=>x.status==='unknown')?'unknown':parts.some(x=>x.status==='waiting')?'waiting':'ready',active:parts.reduce((n,x)=>n+(x.active??0),0),retained:parts.reduce((n,x)=>n+(x.retained??0),0),observations:parts};}
export function commitHostUpdateAdmission(options){const t=key(options),status=readHostUpdateAdmission(options);assert(status.status==='ready','maintenance_work_not_settled');for(const c of t.controllers)c.commit(t.ticketId);return{...readHostUpdateAdmission(options),exitAuthorized:true};}
export function cancelHostUpdateAdmission(options){const t=key(options);for(const c of t.controllers)c.cancel(t.ticketId);tickets.delete(options.stateDir);return{schema:1,status:'cancelled',ticketId:t.ticketId};}
