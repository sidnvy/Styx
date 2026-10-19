// Public device enrollment signing envelope. This is shared by Gateway and
// native Host, and has NO access to keys, filesystem, network or permissions.
const JOIN_FIELDS = Object.freeze([
  'invitation','device_id','label','platform','cwd','shell',
  'computer_requested','public_key_pem'
]);
export function joinPayload(body) {
  return JSON.stringify(Object.fromEntries(JOIN_FIELDS.map(k=>[k,body[k]])));
}

// Separate domain and exact revision prevent reusing enrollment or stale consent.
export function capabilityPayload(body){
 return JSON.stringify(['styx-device-capabilities-v1',body.device_id,body.fingerprint,body.generation,body.enable_computer]);
}
