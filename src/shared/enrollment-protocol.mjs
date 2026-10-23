import {createHash} from 'node:crypto';
// Public device enrollment signing envelope. This is shared by Gateway and
// native Host, and has NO access to keys, filesystem, network or permissions.
const JOIN_FIELDS = Object.freeze([
  'invitation','device_id','label','platform','cwd','shell',
  'computer_requested','public_key_pem'
]);
export function joinPayload(body) {
  // Append only when present: legacy devices retain their exact v1 payload.
  const fields=Object.hasOwn(body,'browser_requested')?[...JOIN_FIELDS,'browser_requested']:JOIN_FIELDS;
  return JSON.stringify(Object.fromEntries(fields.map(k=>[k,body[k]])));
}

// Separate domain and exact revision prevent reusing enrollment or stale consent.
export function capabilityPayload(body){
 if(Object.hasOwn(body,'enable_browser'))return JSON.stringify(['styx-device-capabilities-v2',body.device_id,body.fingerprint,body.generation,
  {browser:body.enable_browser,...(Object.hasOwn(body,'enable_computer')?{computer:body.enable_computer}:{})}]);
 return JSON.stringify(['styx-device-capabilities-v1',body.device_id,body.fingerprint,body.generation,body.enable_computer]);
}

// A public comparison fingerprint, not a connection key or new authentication
// protocol. TLS and signed enrollment remain authoritative. The display binds
// the current request to both the Gateway certificate and device public key.
export function pairingComparisonCode({gatewayOrigin,certificateSha256,requestId,deviceFingerprint}){
 const url=new URL(gatewayOrigin);
 if(url.protocol!=='https:'||url.origin!==gatewayOrigin||! /^[a-f0-9]{64}$/.test(certificateSha256)||! /^[a-f0-9]{32}$/.test(requestId)||! /^[a-f0-9]{64}$/.test(deviceFingerprint))throw Error('invalid_pairing_comparison_scope');
 return createHash('sha256').update(JSON.stringify(['styx-pairing-comparison-v1',gatewayOrigin,certificateSha256,requestId,deviceFingerprint])).digest('hex').slice(0,16).toUpperCase().match(/.{4}/g).join('-');
}
