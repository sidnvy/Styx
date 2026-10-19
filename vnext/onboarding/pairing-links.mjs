// Owner-local pairing material only. No public endpoint, shortcode directory,
// model administration, or automatic device fingerprint approval.
import fs from 'node:fs';
import path from 'node:path';
import {X509Certificate,createHash} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
const assert=(v,c)=>{if(!v)throw Error(c)};
const MAX_LINK=32768,MAX_CA=12000;
function origin(value){let u;try{u=new URL(value)}catch{throw Error('pairing_gateway_origin_invalid')};assert(u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&!u.hash&&['','/'].includes(u.pathname),'pairing_gateway_origin_invalid');return u.origin}
function certificate(pem){
 assert(typeof pem==='string'&&Buffer.byteLength(pem)<=MAX_CA&&/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/.test(pem),'pairing_certificate_invalid');
 let cert;try{cert=new X509Certificate(pem)}catch{throw Error('pairing_certificate_invalid')}
 assert(Date.parse(cert.validFrom)<=Date.now()&&Date.parse(cert.validTo)>Date.now(),'pairing_certificate_expired');
 return createHash('sha256').update(cert.raw).digest('hex');
}
function validate(data){
 assert(data&&typeof data==='object'&&!Array.isArray(data)&&!Object.keys(data).some(k=>!['schema','origin','invitation','expiresAt','caPem'].includes(k)),'pairing_link_schema_invalid');
 assert(data.schema===1&&typeof data.origin==='string'&&data.origin===origin(data.origin),'pairing_link_schema_invalid');
 assert(typeof data.invitation==='string'&&/^[A-Za-z0-9_-]{43}$/.test(data.invitation)&&Buffer.from(data.invitation,'base64url').toString('base64url')===data.invitation,'pairing_invitation_invalid');
 assert(Number.isSafeInteger(data.expiresAt)&&data.expiresAt>Date.now()&&data.expiresAt<=Date.now()+600000,'pairing_link_expired_or_invalid');
 if(data.caPem!==undefined)certificate(data.caPem);
 return data;
}
function decode(link){
 assert(typeof link==='string'&&Buffer.byteLength(link)<=MAX_LINK,'pairing_link_size_invalid');
 let u;try{u=new URL(link)}catch{throw Error('pairing_link_invalid')}
 assert(u.protocol==='styx:'&&u.host==='join'&&!u.username&&!u.password&&!u.port&&!u.pathname&&!u.search&&/^#[A-Za-z0-9_-]+$/.test(u.hash),'pairing_link_invalid');
 const encoded=u.hash.slice(1),bytes=Buffer.from(encoded,'base64url');assert(bytes.toString('base64url')===encoded,'pairing_link_invalid');
 let text,data;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);data=JSON.parse(text)}catch{throw Error('pairing_link_invalid')}
 assert(JSON.stringify(data)===text,'pairing_link_noncanonical');return validate(data);
}
export function inspectPairingLink(link){
 const data=decode(link);return {origin:data.origin,expiresAt:data.expiresAt,...(data.caPem?{caSha256:certificate(data.caPem)}:{}),requiresCertificateApproval:Boolean(data.caPem)};
}
export function createPairingLink({controller,gatewayOrigin,approved,caPem,ttlSeconds=60}={}){
 assert(approved===true,'explicit_owner_pairing_link_authorization_required');
 const gateway=origin(gatewayOrigin);if(caPem!==undefined)certificate(caPem);
 assert(Number.isSafeInteger(ttlSeconds)&&ttlSeconds>=60&&ttlSeconds<=600,'pairing_link_ttl_invalid');
 const invite=controller.invite({ttl_seconds:ttlSeconds});
 const data=validate({schema:1,origin:gateway,invitation:invite.invitation,expiresAt:invite.expires_at,...(caPem!==undefined?{caPem}:{})});
 const link='styx://join#'+Buffer.from(JSON.stringify(data)).toString('base64url');assert(Buffer.byteLength(link)<=MAX_LINK,'pairing_link_size_invalid');
 // This link is a one-use secret intended only for the owner's selected device.
 // Callers must not put it in server logs, query strings or public state views.
 return {link,...inspectPairingLink(link)};
}
export function acceptPairingLink(link,{stateDir,approvedGatewayOrigin,approvedCaSha256}={}){
 const data=decode(link);assert(origin(approvedGatewayOrigin)===data.origin,'pairing_gateway_confirmation_mismatch');
 const caSha256=data.caPem?certificate(data.caPem):undefined;
 assert(caSha256?approvedCaSha256===caSha256:approvedCaSha256===undefined,'pairing_certificate_confirmation_mismatch');
 assert(typeof stateDir==='string'&&path.isAbsolute(stateDir)&&path.normalize(stateDir)===stateDir,'pairing_private_state_required');
 requirePrivateDirectory(path.dirname(stateDir));assert(!fs.existsSync(stateDir),'pairing_state_already_exists');
 // Claim a fresh directory atomically. Existing state is never reused/hardened.
 try{fs.mkdirSync(stateDir,{mode:0o700})}catch{throw Error('pairing_state_creation_refused')}
 try{
  // Inspect actual native ownership/DACL before writing any invitation. A
  // non-inheriting Windows parent may yield a broad leaf; reject, never harden.
  requirePrivateDirectory(stateDir);
  const invitationFile=path.join(stateDir,'invitation');fs.writeFileSync(invitationFile,data.invitation+'\n',{flag:'wx',mode:0o600});requirePrivateFile(invitationFile);
  let gatewayCaFile;
  if(data.caPem){gatewayCaFile=path.join(stateDir,'gateway-ca.pem');fs.writeFileSync(gatewayCaFile,data.caPem,{flag:'wx',mode:0o600});requirePrivateFile(gatewayCaFile)}
  const configFile=path.join(stateDir,'pairing.json');fs.writeFileSync(configFile,JSON.stringify({schema:1,gatewayOrigin:data.origin,expiresAt:data.expiresAt,invitationFile,...(gatewayCaFile?{gatewayCaFile,caSha256}:{})},null,2)+'\n',{flag:'wx',mode:0o600});requirePrivateFile(configFile);
 }catch{
  // A failed/uncertain import is not replayed and never erases unexpected files.
  throw Error('pairing_material_write_failed_inspect_private_state');
 }
 return {status:'pairing_material_saved',origin:data.origin,expiresAt:data.expiresAt,customCertificateApproved:Boolean(caSha256)};
}
