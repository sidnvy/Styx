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
