// Existing trusted POSIX SSH targets only; no installation or host-key acceptance.
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createPublicKey} from 'node:crypto';
import {requirePrivateFile} from '../host/private-storage.mjs';
import {pairingScope,publicPairingRequest,publicPairingClaim} from './pairing.mjs';
const assert=(v,c)=>{if(!v)throw Error(c)};
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
const REMOTE=`import fs from 'node:fs';import path from 'node:path';import {pathToFileURL} from 'node:url';
try{let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>32768)throw Error()}
const data=JSON.parse(input);const root=data.installRoot;
const {activeRelease}=await import(pathToFileURL(path.join(root,'installer.mjs')).href);
const active=activeRelease(root,data.publisherPublicKey);if(!active)throw Error();
const mod=await import(pathToFileURL(path.join(active.release_root,'host','enroll.mjs')).href);
let answer;if(data.action==='request'){const identity=mod.initLocalIdentity(data.config);const result=await mod.requestEnrollment(data.config,data.invitation);if(identity.fingerprint!==result.fingerprint||identity.device_id!==result.device_id)throw Error();answer={device_id:identity.device_id,fingerprint:identity.fingerprint,request_id:result.request_id,status:'pending',platform:process.platform}}
else if(data.action==='claim'){const r=await mod.claimEnrollment(data.config);answer={status:r.status,device_id:r.device_id,capabilities:r.capabilities,platform:process.platform}}else throw Error();
process.stdout.write(JSON.stringify(answer));}catch{process.stderr.write('styx_trusted_ssh_pairing_failed');process.exitCode=2}`;
function regularTrusted(file,{privateFile=false}={}){
 assert(typeof file==='string'&&path.isAbsolute(file),'absolute_ssh_trust_file_required');
 if(privateFile){requirePrivateFile(file);return}
 const info=fs.lstatSync(file);assert(info.isFile()&&!info.isSymbolicLink(),'ssh_trust_file_not_regular');
 if(process.platform!=='win32')assert(info.uid===process.getuid()&&!(info.mode&0o022),'ssh_trust_file_not_owner_controlled');
 else requirePrivateFile(file);
}
export function sshBootstrapPlan(target){
 assert(target&&['linux','darwin'].includes(target.platform),'trusted_posix_ssh_target_required');
 assert(typeof target.host==='string'&&/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(target.host),'invalid_ssh_host');
 assert(typeof target.user==='string'&&/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(target.user),'invalid_ssh_user');
 assert(Number.isInteger(target.port??22)&&(target.port??22)>0&&(target.port??22)<=65535,'invalid_ssh_port');
 for(const file of [target.nodeBinary,target.installRoot])assert(typeof file==='string'&&file.startsWith('/')&&!/[\x00-\x1f\x7f]/.test(file)&&path.posix.normalize(file)===file,'absolute_trusted_remote_path_required');
 try{assert(typeof target.publisherPublicKey==='string'&&/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*$/.test(target.publisherPublicKey),'trusted_publisher_public_key_required');assert(createPublicKey(target.publisherPublicKey).asymmetricKeyType==='ed25519','trusted_publisher_public_key_required')}catch{throw Error('trusted_publisher_public_key_required')}
 regularTrusted(target.knownHostsFile);if(target.identityFile)regularTrusted(target.identityFile,{privateFile:true});
 assert(typeof target.sshBinary==='string'&&path.isAbsolute(target.sshBinary),'absolute_trusted_ssh_binary_required');
 const args=['-F',process.platform==='win32'?'NUL':'/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+target.knownHostsFile,'-o','GlobalKnownHostsFile='+(process.platform==='win32'?'NUL':'/dev/null'),'-o','ClearAllForwardings=yes','-o','ForwardAgent=no','-o','PermitLocalCommand=no','-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=10','-o','NumberOfPasswordPrompts=0','-p',String(target.port??22),'-l',target.user];
 if(target.identityFile)args.push('-o','IdentitiesOnly=yes','-i',target.identityFile);
 args.push('--',target.host,'exec '+quote(target.nodeBinary)+' --input-type=module -e '+quote(REMOTE));
 return {command:target.sshBinary,args};
}
async function execute(plan,payload){
 return await new Promise((resolve,reject)=>{let done=false,out='',bytes=0,child;
 const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);error?reject(Error(error)):resolve(value)};
 const timer=setTimeout(()=>{child?.kill();finish('ssh_pairing_timeout_uncertain')},30000);
 try{child=spawn(plan.command,plan.args,{stdio:['pipe','pipe','ignore'],windowsHide:true});child.stdout.on('data',data=>{bytes+=data.length;if(bytes>16384){child.kill();finish('ssh_pairing_reply_limit')}else out+=data});child.on('error',()=>finish('ssh_pairing_transport_failed'));child.stdin.on('error',()=>{child.kill();finish('ssh_pairing_transport_uncertain')});child.on('close',code=>{if(code!==0)return finish('ssh_pairing_remote_failed');try{finish(null,JSON.parse(out))}catch{finish('ssh_pairing_invalid_reply')}});child.stdin.end(JSON.stringify(payload));}catch{finish('ssh_pairing_transport_failed')}
 });
}
// Prerequisite: owner has independently verified the remote Node executable
// and stable installer at these paths. This is pairing transport, not a remote
// installer or trust bootstrap. The pinned publisher key additionally verifies
// the complete active release before its enrollment module is imported.
export function createSshPairingTransport(target,config){
 const cfg=structuredClone(config),remote=structuredClone(target),scope=pairingScope(cfg,remote.platform);sshBootstrapPlan(remote);
 const run=async(action,invitation)=>{const result=await execute(sshBootstrapPlan(remote),{action,invitation,config:cfg,installRoot:remote.installRoot,publisherPublicKey:remote.publisherPublicKey});assert(result.platform===scope.platform,'ssh_pairing_platform_mismatch');return result};
 return Object.freeze({kind:'ssh',scope,async request(invitation){return publicPairingRequest(await run('request',invitation),scope)},async claim(){return publicPairingClaim(await run('claim'))}});
}
