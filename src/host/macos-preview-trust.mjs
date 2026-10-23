// Explicit local preview trust, injected by the packaged launcher only. Ad-hoc
// registrations pin exact bytes; certificate registrations pin the persistent
// signer and stable DR across builds. Neither is Developer ID/notarization trust.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {localCertificatePin,verifyLocalCertificate} from './macos-local-signing.mjs';
// This compares verified identities without observing or changing the machine.
// A prior certificate registration is an upgrade boundary, not a suggestion
// that a newly launched bundle may replace with its own self-declared signer.
export function assertMacPreviewContinuity(registered,current){
 const fail=code=>{throw Error(code)};
 const pin=value=>{
  if(!value||typeof value!=='object'||!('certificateSha1' in value||'certificateSha256' in value))return null;
  return localCertificatePin({schema:1,certificateSha1:value.certificateSha1,certificateSha256:value.certificateSha256});
 };
 const priorPin=pin(registered),currentPin=pin(current);
 if(registered===undefined)return {migrationRequired:false};
 if(!registered||typeof registered!=='object'||Array.isArray(registered)||!current||typeof current!=='object'||Array.isArray(current)||
    typeof registered.path!=='string'||!path.isAbsolute(registered.path)||path.normalize(registered.path)!==registered.path||
    /[\x00-\x1f\x7f]/.test(registered.path)||current.path!==registered.path)fail('mac_preview_registered_path_changed');
 if(priorPin&&(!currentPin||priorPin.certificateSha1!==currentPin.certificateSha1||priorPin.certificateSha256!==currentPin.certificateSha256))fail('mac_preview_registered_certificate_changed');
 return {migrationRequired:!priorPin&&!!currentPin};
}
export function verifyMacPreviewApp(value,{run=spawnSync,platform=process.platform}={}){
 if(platform!=='darwin'||!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['path','cdhash','certificateSha1','certificateSha256'].includes(k))||typeof value.path!=='string'||!path.isAbsolute(value.path)||path.normalize(value.path)!==value.path||path.basename(value.path)!=='Styx.app'||!/^[a-f0-9]{40}$/.test(value.cdhash??''))throw Error('invalid_adhoc_preview_trust');
 const st=fs.lstatSync(value.path);if(!st.isDirectory()||st.isSymbolicLink()||fs.realpathSync(value.path)!==value.path)throw Error('regular_preview_app_required');
 const checked=run('/usr/bin/codesign',['--verify','--deep','--strict',value.path],{encoding:'utf8',timeout:15000,stdio:['ignore','pipe','pipe']});
 if(checked.error||checked.status!==0)throw Error('adhoc_preview_signature_invalid');
 const result=run('/usr/bin/codesign',['-d','--verbose=4',value.path],{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']});
 const text=String(result.stderr??'');
 const current=/^CDHash=([a-f0-9]{40})$/m.exec(text)?.[1];
 if(result.error||result.status!==0||!/^Identifier=app\.styx\.host$/m.test(text)||!current)throw Error('adhoc_preview_identity_mismatch');
 if(value.certificateSha1!==undefined||value.certificateSha256!==undefined){
  if(/^Signature=adhoc$/m.test(text))throw Error('local_preview_certificate_required');
  verifyLocalCertificate(value.path,{schema:1,certificateSha1:value.certificateSha1,certificateSha256:value.certificateSha256},{run});
  return {path:value.path,cdhash:current,certificateSha1:value.certificateSha1,certificateSha256:value.certificateSha256,trust:'local_certificate_preview_not_notarized'};
 }
 if(!/^Signature=adhoc$/m.test(text)||current!==value.cdhash)throw Error('adhoc_preview_identity_mismatch');
 return {path:value.path,cdhash:value.cdhash,trust:'local_adhoc_preview_not_notarized'};
}
