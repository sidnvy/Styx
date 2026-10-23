// Explicit signed native Host supervisor. This selects a process parent; code
// signing checks alone do not establish macOS TCC responsibility attribution.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
const assert=(ok,code)=>{if(!ok)throw Error(code)};
export const MAC_HOST_APP='/Applications/Styx.app';
export const MAC_HOST_BUNDLE_ID='app.styx.host';
export function macNativeAppRequirement(nativeApp){
 assert(nativeApp&&typeof nativeApp==='object'&&!Array.isArray(nativeApp)&&Object.keys(nativeApp).length===2&&Object.keys(nativeApp).every(k=>['path','teamID'].includes(k)),'invalid_native_app');
 assert(nativeApp.path===MAC_HOST_APP,'fixed_native_app_path_required');
 assert(/^[A-Z0-9]{10}$/.test(nativeApp.teamID??''),'native_app_team_identity_required');
 return `=anchor apple generic and identifier "${MAC_HOST_BUNDLE_ID}" and certificate leaf[subject.OU] = "${nativeApp.teamID}"`;
}
export function verifiedMacNativeLauncher(nativeApp,{run=execFileSync,filesystem=fs}={}){
 const requirement=macNativeAppRequirement(nativeApp);
 const executable=path.join(nativeApp.path,'Contents/MacOS/Styx');
 for(const [file,directory] of [[nativeApp.path,true],[path.dirname(executable),true],[executable,false]]){
  const st=filesystem.lstatSync(file);
  assert(!st.isSymbolicLink()&&(directory?st.isDirectory():st.isFile()),'native_app_regular_bundle_required');
 }
 assert(filesystem.realpathSync(executable)===executable,'native_app_redirect_refused');
 filesystem.accessSync(executable,fs.constants.X_OK);
 try{run('/usr/bin/codesign',['--verify','--deep','--strict','-R',requirement,nativeApp.path],{encoding:'utf8',timeout:15000,stdio:['ignore','pipe','pipe']})}
 catch{throw Error('native_app_signature_invalid')}
 return executable;
}
export function macNativeHostArguments({executable,teamID,nodeBinary,installRoot,hostConfigFile,trustPublicKeyFile}){
 assert(executable===path.join(MAC_HOST_APP,'Contents/MacOS/Styx')&&/^[A-Z0-9]{10}$/.test(teamID??''),'invalid_native_launcher_identity');
 for(const file of [nodeBinary,installRoot,hostConfigFile,trustPublicKeyFile])assert(typeof file==='string'&&path.isAbsolute(file)&&path.normalize(file)===file&&!/[\u0000-\u001f\u007f-\u009f\ud800-\udfff\ufffe\uffff]/u.test(file),'invalid_native_launcher_path');
 assert(nodeBinary.startsWith(installRoot+path.sep),'native_launcher_signed_node_required');
 return [executable,'--host-service',teamID,nodeBinary,installRoot,hostConfigFile,trustPublicKeyFile];
}
// An observation of launcher wiring is deliberately weaker than permission or
// desktop readiness. The native chain must be measured on each supported build.
export function macHostExecutionIdentity({nativeApp}={}){
 if(nativeApp===undefined)return {launcher:'legacy_node',nativeResponsibility:'not_established',tccAttribution:'NOT RUN'};
 macNativeAppRequirement(nativeApp);
 return {launcher:'signed_native_supervisor',bundleID:MAC_HOST_BUNDLE_ID,teamID:nativeApp.teamID,nativeResponsibility:'configured_unverified',tccAttribution:'NOT RUN'};
}
