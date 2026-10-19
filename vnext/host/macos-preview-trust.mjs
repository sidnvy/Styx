// Explicit local ad-hoc preview trust, injected by the packaged launcher only.
// It proves bundle consistency with the current launcher's verified CDHash, not
// a Developer ID publisher or notarization. The production Team ID path is separate.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
export function verifyMacPreviewApp(value,{run=spawnSync,platform=process.platform}={}){
 if(platform!=='darwin'||!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!['path','cdhash'].includes(k))||typeof value.path!=='string'||!path.isAbsolute(value.path)||path.normalize(value.path)!==value.path||path.basename(value.path)!=='Styx.app'||!/^[a-f0-9]{40}$/.test(value.cdhash??''))throw Error('invalid_adhoc_preview_trust');
 const st=fs.lstatSync(value.path);if(!st.isDirectory()||st.isSymbolicLink()||fs.realpathSync(value.path)!==value.path)throw Error('regular_preview_app_required');
 const checked=run('/usr/bin/codesign',['--verify','--deep','--strict',value.path],{encoding:'utf8',timeout:15000,stdio:['ignore','pipe','pipe']});
 if(checked.error||checked.status!==0)throw Error('adhoc_preview_signature_invalid');
 const result=run('/usr/bin/codesign',['-d','--verbose=4',value.path],{encoding:'utf8',timeout:10000,stdio:['ignore','pipe','pipe']});
 const text=String(result.stderr??'');
 if(result.error||result.status!==0||!/^Identifier=app\.styx\.host$/m.test(text)||!/^Signature=adhoc$/m.test(text)||!new RegExp('^CDHash='+value.cdhash+'$','m').test(text))throw Error('adhoc_preview_identity_mismatch');
 return {path:value.path,cdhash:value.cdhash,trust:'local_adhoc_preview_not_notarized'};
}
