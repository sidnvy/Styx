// Owner-local orchestration only. Never register this API as an MCP tool.
import {initLocalIdentity,requestEnrollment,claimEnrollment} from '../host/enroll.mjs';
const assert=(value,code)=>{if(!value)throw Error(code)};
const ID=/^styx-[a-f0-9]{24}$/;
const FP=/^[a-f0-9]{64}$/;
export function pairingScope(config,platform){
 let url;try{url=new URL(config?.gateway_url)}catch{throw Error('pairing_https_origin_required')}
 assert(url.protocol==='https:'&&!url.username&&!url.password&&!url.search&&!url.hash&&['','/'].includes(url.pathname),'pairing_https_origin_required');
 assert(['linux','darwin','win32'].includes(platform),'pairing_platform_required');
 return Object.freeze({gateway_url:url.origin,label:config.label,platform,cwd:config.cwd,shell:config.shell,computer_requested:config.computer_requested===true});
}
export function publicPairingRequest(result,scope){
 assert(ID.test(result?.device_id)&&FP.test(result?.fingerprint)&&/^[a-f0-9]{32}$/.test(result?.request_id)&&result.status==='pending','invalid_pairing_public_identity');
 return {device_id:result.device_id,request_id:result.request_id,fingerprint:result.fingerprint,status:'pending',scope};
}
export function publicPairingClaim(result){
 assert(result?.status==='ready_to_connect'&&ID.test(result.device_id)&&result.capabilities?.exec===true&&typeof result.capabilities.computer==='boolean','invalid_pairing_claim');
 return {status:'ready_to_connect',device_id:result.device_id,capabilities:{exec:true,computer:result.capabilities.computer}};
}
export function createLocalPairingTransport(config){
 const cfg=structuredClone(config),scope=pairingScope(cfg,process.platform);
 return Object.freeze({kind:'local',scope,
  async request(invitation){const identity=initLocalIdentity(cfg);const result=await requestEnrollment(cfg,invitation);assert(result.fingerprint===identity.fingerprint&&result.device_id===identity.device_id,'local_pairing_identity_changed');return publicPairingRequest(result,scope)},
  async claim(){return publicPairingClaim(await claimEnrollment(cfg))}
 });
}
export async function pairDevice({controller,transport,authorization,ttlSeconds=60}={}){
 assert(authorization?.approve===true,'explicit_owner_pairing_authorization_required');
 assert(['local','ssh'].includes(transport?.kind)&&typeof transport.request==='function'&&typeof transport.claim==='function','trusted_pairing_transport_required');
 assert(typeof authorization.enable_computer==='boolean','explicit_computer_authorization_required');
 const expected=pairingScope(authorization,authorization.platform);
 for(const key of Object.keys(expected))assert(expected[key]===transport.scope?.[key],'pairing_authorization_scope_mismatch');
 assert(!authorization.enable_computer||expected.computer_requested,'pairing_computer_not_requested');
 assert(Number.isInteger(ttlSeconds)&&ttlSeconds>=60&&ttlSeconds<=600,'invalid_pairing_ttl');
 const invite=controller.invite({ttl_seconds:ttlSeconds});let pending;
 try{pending=publicPairingRequest(await transport.request(invite.invitation),expected)}catch{throw Error('pairing_request_failed_no_approval')}
 const registered=controller.listPending().find(item=>item.request_id===pending.request_id);
 assert(registered&&registered.device_id===pending.device_id&&registered.fingerprint===pending.fingerprint,'pairing_trusted_identity_mismatch');
 for(const key of ['label','platform','cwd','shell','computer_requested'])assert(registered[key]===expected[key],'pairing_pending_scope_mismatch');
 controller.approve({request_id:pending.request_id,fingerprint:pending.fingerprint,enable_computer:authorization.enable_computer});
 try{const result=publicPairingClaim(await transport.claim());assert(result.device_id===pending.device_id&&result.capabilities.computer===authorization.enable_computer,'pairing_claim_scope_mismatch');return {...result,fingerprint:pending.fingerprint}}
 catch{return {status:'needs_owner_attention',phase:'claim_uncertain',device_id:pending.device_id,fingerprint:pending.fingerprint}}
}
