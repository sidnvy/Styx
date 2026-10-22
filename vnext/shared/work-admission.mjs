// Process-owned maintenance fence. This is lifecycle admission, not tool routing.
// Enter is synchronous and must precede the first await or native dispatch.
export class WorkAdmission {
 constructor({observe=()=>({identity:'stable',retained:0,unknown:false})}={}){this.observe=observe;this.active=new Map();this.tickets=new Map();this.next=0;}
 enter(deviceId,lane,{continuation=false}={}){
  if(typeof deviceId!=='string'||!deviceId)throw Error('maintenance_target_unknown');
  if(!continuation&&[...this.tickets.values()].some(t=>t.scope==='all'||t.scope===deviceId))throw Error('device_in_maintenance');
  const id=++this.next;this.active.set(id,{deviceId,lane});let released=false;
  return()=>{if(!released){released=true;this.active.delete(id)}};
 }
 begin({ticketId,scope='all'}){
  if(typeof ticketId!=='string'||!/^[a-f0-9]{32}$/.test(ticketId)||typeof scope!=='string'||!scope)throw Error('maintenance_ticket_invalid');
  const prior=this.tickets.get(ticketId);if(prior){if(prior.scope!==scope)throw Error('maintenance_scope_changed');return this.status(ticketId)}
  if([...this.tickets.values()].some(t=>scope==='all'||t.scope==='all'||t.scope===scope))throw Error('maintenance_already_owned');
  // Fence first, then observe without yielding. New work cannot cross the check.
  const ticket={scope,identity:null,committed:false};this.tickets.set(ticketId,ticket);
  try{ticket.identity=this.observe(scope).identity;return this.status(ticketId)}catch(error){this.tickets.delete(ticketId);throw error}
 }
 status(ticketId){
  const t=this.tickets.get(ticketId);if(!t)throw Error('maintenance_ticket_unavailable');
  let observed;try{observed=this.observe(t.scope)}catch{return{status:'unknown',reason:'work_observation_unavailable',ticketId,scope:t.scope}};
  const active=[...this.active.values()].filter(a=>t.scope==='all'||a.deviceId===t.scope).length;
  if(observed.identity!==t.identity||observed.unknown)return{status:'unknown',reason:observed.identity!==t.identity?'work_peer_changed':'work_outcome_unknown',ticketId,scope:t.scope,active,retained:observed.retained??0};
  if(!Number.isSafeInteger(observed.retained)||observed.retained<0)return{status:'unknown',reason:'work_observation_unavailable',ticketId,scope:t.scope};
  return{status:active||observed.retained?'waiting':'ready',ticketId,scope:t.scope,active,retained:observed.retained,committed:t.committed};
 }
 commit(ticketId){const status=this.status(ticketId);if(status.status!=='ready')throw Error('maintenance_work_not_settled');this.tickets.get(ticketId).committed=true;return this.status(ticketId)}
 cancel(ticketId){if(!this.tickets.has(ticketId))throw Error('maintenance_ticket_unavailable');this.tickets.delete(ticketId);return{status:'cancelled',ticketId}}
}

// Host-only deployments cannot depend on the remote Gateway's admin token.
// Observe the existing authenticated protocol at the actual local dispatch point.
export function createHostWorkAdmission(deviceId){
 const peers=new Map(),processes=new Map();let sequence=0,unknown=false,execObserved=false;
 const admission=new WorkAdmission({observe:()=>({identity:[...peers.keys()].sort().join(','),retained:processes.size,unknown:unknown||!execObserved})});
 admission.openPeer=lane=>{
  const id=String(++sequence),requests=new Map();peers.set(id,lane);let closed=false;
  return{
   ready(){if(lane==='exec')execObserved=true},
   request(message){
    if(closed)throw Error('maintenance_peer_closed');
    const work=lane==='exec'?message.method==='process/start':message.method==='tools/call';
    const tracked=work||lane==='exec'&&['process/read','process/write','process/terminate'].includes(message.method);
    if(!tracked||message.id===undefined)return;
    const release=admission.enter(deviceId,lane,{continuation:lane==='exec'&&!work});
    const processId=message.params?.processId;
    if(work&&lane==='exec'){if(typeof processId!=='string'||processes.has(processId)){release();throw Error('maintenance_process_identity_unknown')}processes.set(processId,{peer:id,state:'starting'})}
    if(requests.has(message.id)){unknown=true;release();throw Error('maintenance_duplicate_request')}
    requests.set(message.id,{release,method:message.method,processId});
   },
   response(message){
    const request=requests.get(message.id);if(!request)return;
    requests.delete(message.id);request.release();const process=processes.get(request.processId);
    // A valid terminal tool error is completed work, not a lost reply.
    if(lane!=='exec')return
    if(request.method==='process/start'){
     // Match ExecAdapter's existing process/start RpcFault rejection contract.
     // Transport loss takes close() instead and retains the uncertain process.
     if(message.error){processes.delete(request.processId);return}
     if(message.result?.processId!==request.processId){unknown=true;return}if(process)process.state='running';
    }
    if(request.method==='process/read'){
     const r=message.result;if(message.error||!r){unknown=true;return}
     if(r.exited===true&&r.closed===true&&Array.isArray(r.chunks)&&r.chunks.length===0)processes.delete(request.processId);
    }
   },
   close(){if(closed)return;closed=true;if(requests.size||[...processes.values()].some(p=>p.peer===id))unknown=true;for(const r of requests.values())r.release();requests.clear();peers.delete(id)}
  };
 };
 admission.markUnknown=()=>{unknown=true};
 return admission;
}
