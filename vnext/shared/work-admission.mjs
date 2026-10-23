const ownedControllers=new WeakMap(),settlementProofs=new WeakMap();
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
export function createHostWorkAdmission(deviceId,coverage){
 // Only the lifecycle owner may attest coverage before starting its connectors.
 // An omitted contract stays unverified, including after transport ready.
 const complete=coverage!==undefined;
 if(complete&&(!coverage||Object.keys(coverage).sort().join(',')!=='lanes,ownerGeneration,runtime,scope'||
  coverage.runtime!=='fresh_owned'||coverage.scope!=='complete_from_creation'||
  !/^[a-f0-9]{32}$/.test(coverage.ownerGeneration??'')||!Array.isArray(coverage.lanes)||
  !coverage.lanes.includes('exec')||new Set(coverage.lanes).size!==coverage.lanes.length||
  coverage.lanes.some(lane=>!['exec','computer','browser'].includes(lane))))throw Error('invalid_work_coverage_contract');
 const ownerGeneration=complete?coverage.ownerGeneration:'unverified',lanes=new Set(coverage?.lanes??[]);
 const peers=new Map(),processes=new Map();let sequence=0,unknown=false;
 // This controller observes only this owner's freshly created local connectors;
 // it does not adopt independent runtimes. A Gateway that never connected cannot
 // have dispatched work here. Actual lost requests/outcomes remain sticky unknown.
 // Output handles belong to their callers until drained. They are not running
 // work once this authenticated Exec peer proves both process exit and EOF.
 // Admission does not read, consume, or delete any native output.
 const admission=new WorkAdmission({observe:()=>({identity:ownerGeneration+':'+[...peers.keys()].sort().join(','),retained:[...processes.values()].filter(p=>!p.executionSettled).length,unknown:unknown||!complete})});
 admission.openPeer=lane=>{
  if(complete&&!lanes.has(lane)){unknown=true;throw Error('work_lane_not_covered')}
  const id=String(++sequence),requests=new Map();peers.set(id,lane);let closed=false;
  return{
   ready(){/* Transport readiness is not evidence of dispatched work. */},
   request(message){
    if(closed)throw Error('maintenance_peer_closed');
    const work=lane==='exec'?message.method==='process/start':message.method==='tools/call';
    const tracked=work||lane==='exec'&&['process/read','process/write','process/terminate'].includes(message.method);
    if(!tracked||message.id===undefined)return;
    const release=admission.enter(deviceId,lane,{continuation:lane==='exec'&&!work});
    const processId=message.params?.processId;
    if(work&&lane==='exec'){if(typeof processId!=='string'||processes.has(processId)){release();throw Error('maintenance_process_identity_unknown')}processes.set(processId,{peer:id,state:'starting',executionSettled:false})}
    if(requests.has(message.id)){unknown=true;release();throw Error('maintenance_duplicate_request')}
    requests.set(message.id,{release,method:message.method,processId});
   },
   response(message){
    if(lane==='exec'&&message.id===undefined&&['process/exited','process/closed'].includes(message.method)){
     const p=message.params,process=processes.get(p?.processId);
     if(!process||process.peer!==id)return;
     if(!Number.isSafeInteger(p.seq)||p.seq<1||(message.method==='process/exited'&&!Number.isSafeInteger(p.exitCode))){unknown=true;return}
     if(message.method==='process/exited'){
      if(process.exitedSeq!==undefined&&(process.exitedSeq!==p.seq||process.exitCode!==p.exitCode)){unknown=true;return}
      process.exitedSeq=p.seq;process.exitCode=p.exitCode;
     }else{
      if(process.closedSeq!==undefined&&process.closedSeq!==p.seq){unknown=true;return}
      process.closedSeq=p.seq;
     }
     if(process.exitedSeq!==undefined&&process.closedSeq!==undefined){
      if(process.closedSeq<=process.exitedSeq){unknown=true;return}
      process.executionSettled=true;
     }
     return;
    }
    const request=requests.get(message.id);if(!request)return;
    const terminal=message.method===undefined&&
      ((message.error===undefined&&message.result&&typeof message.result==='object'&&!Array.isArray(message.result))||
       (message.result===undefined&&message.error&&Number.isInteger(message.error.code)&&typeof message.error.message==='string'));
    if(!terminal){unknown=true;return}
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
     if(typeof r.exited!=='boolean'||typeof r.closed!=='boolean'||!Array.isArray(r.chunks)||!Number.isSafeInteger(r.nextSeq)||r.nextSeq<1||(r.exited&&!Number.isSafeInteger(r.exitCode))||(r.closed&&!r.exited)){unknown=true;return}
     if(process?.peer===id&&r.exited&&r.closed){process.executionSettled=true;if(r.chunks.length===0)processes.delete(request.processId)}
    }
   },
   close(){if(closed)return;closed=true;if(requests.size||[...processes.values()].some(p=>p.peer===id&&!p.executionSettled))unknown=true;for(const r of requests.values())r.release();requests.clear();for(const [key,p]of processes)if(p.peer===id&&p.executionSettled)processes.delete(key);peers.delete(id)}
  };
 };
 if(complete)ownedControllers.set(admission,{deviceId,ownerGeneration,lanes});
 admission.markUnknown=()=>{unknown=true};
 return admission;
}

// In-process evidence only. Serialized fields are descriptive, never authority.
export function observeOwnedHostSettlement(controller,ticketId,{gatewayAdmission}={}){
 const owner=ownedControllers.get(controller),fence=controller?.tickets?.get(ticketId);
 if(!owner||!fence||fence.scope!=='all'||controller.status(ticketId).status!=='ready')throw Error('owned_host_settlement_unavailable');
 const gatewayFence=gatewayAdmission?.tickets?.get(ticketId);
 if(gatewayAdmission&&(!gatewayFence||gatewayFence.scope!=='all'))throw Error('owned_host_settlement_unavailable');
 const proof=Object.freeze({deviceId:owner.deviceId,ownerGeneration:owner.ownerGeneration,ticketId});
 settlementProofs.set(proof,{controller,owner,fence,gatewayAdmission,gatewayFence,identity:controller.observe('all').identity});return proof;
}
export function verifyOwnedHostSettlement(proof,{deviceId,lanes,ticketId,gatewayAdmission}={}){
 const record=settlementProofs.get(proof);if(!record)return false;
 const {controller,owner,fence,identity}=record;
 if(record.gatewayAdmission!==gatewayAdmission||(gatewayAdmission&&(gatewayAdmission.tickets?.get(ticketId)!==record.gatewayFence||record.gatewayFence.scope!=='all')))return false;
 if(deviceId!==owner.deviceId||ticketId!==proof.ticketId||!Array.isArray(lanes)||!lanes.length||lanes.some(l=>!owner.lanes.has(l))||
    controller.tickets.get(ticketId)!==fence||fence.scope!=='all')return false;
 try{return controller.status(ticketId).status==='ready'&&controller.observe('all').identity===identity}catch{return false}
}
