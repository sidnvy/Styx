import {assertHostPayloadMigrationSettled} from './host-payload-start-guard.mjs';
// Read-only package/installed-generation reconciliation. This never adopts a
// publisher, starts/stops a process, or treats signed metadata as runtime health.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value;
const version=value=>/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value??'');
const fail=()=>{throw Error('component_evidence_invalid')};
function regular(file,limit=1024*1024){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink()||s.size>limit)fail();return fs.readFileSync(file);}
function privateJson(file){requirePrivateFile(file);return JSON.parse(regular(file));}
function publisher(file,expected){
 if(!absolute(file)||!/^[a-f0-9]{64}$/.test(expected??''))fail();
 const key=createPublicKey(regular(file,65536));
 if(key.asymmetricKeyType!=='ed25519'||sha(key.export({type:'spki',format:'der'}))!==expected)fail();
 return key;
}
function manifest(root,key){
 if(!absolute(root))fail();const s=fs.lstatSync(root);if(!s.isDirectory()||s.isSymbolicLink())fail();
 const bytes=regular(path.join(root,'manifest.json')),sig=regular(path.join(root,'manifest.sig'),1024).toString().trim();
 if(!/^[A-Za-z0-9_-]{80,100}$/.test(sig)||!verify(null,bytes,key,Buffer.from(sig,'base64url')))fail();
 const value=JSON.parse(bytes);
 if(value.schema!==1||!version(value.version)||value.platform!==process.platform||value.arch!==process.arch||!Array.isArray(value.files)||!value.files.length||value.files.length>4096)fail();
 return {version:value.version,manifestSha256:sha(bytes)};
}
function unsettled(stateDir,root){
 for(const file of [path.join(stateDir,'host-update-recovery.lock'),...['.health-update-lock','.health-operation-lock','.health-recovery-guard'].map(n=>path.join(root,n))]){
  try{fs.lstatSync(file);return true}catch(error){if(error.code!=='ENOENT')return true}
 }
 const file=path.join(stateDir,'host-update.json');
 if(fs.existsSync(file)){const record=privateJson(file);if(record.schema!==1||!['completed','recovered'].includes(record.phase))return true}
 return false;
}
export function readDeploymentComponents(stateDir,{artifacts}={}){
 const evidence={schema:1,observation:'signed_manifests',payloadIntegrity:'not_rechecked',runtimeHealth:'not_observed',mutation:'NONE'};
 const result=host=>({...evidence,host});
 if(!absolute(stateDir))throw Error('absolute_state_directory_required');
 if(!fs.existsSync(stateDir))return result({status:'not_configured'});
 try{
  requirePrivateDirectory(stateDir);
  try{assertHostPayloadMigrationSettled(stateDir)}catch{return result({status:'needs_recovery',requiredAction:'rollback_host_payload_migration'})}
  const configFile=path.join(stateDir,'deployment.json');if(!fs.existsSync(configFile))return result({status:'not_configured'});
  requirePrivateFile(configFile);const bytes=regular(configFile),config=JSON.parse(bytes),state=privateJson(path.join(stateDir,'state.json'));
  if(config.schema!==1||state.schema!==1||state.configSha256!==sha(bytes)||state.mode!==config.mode)fail();
  if(!config.host)return result({status:'not_configured'});
  if(!state.steps?.some(s=>s.id==='host.prepare'&&s.status==='succeeded'))return result({status:'not_prepared'});
  const h=config.host;if(!absolute(h.baseDir))fail();requirePrivateDirectory(h.baseDir);
  const root=path.join(h.baseDir,'install');requirePrivateDirectory(root);
  const keyFile=path.join(h.baseDir,'publisher.pem');requirePrivateFile(keyFile);
  const key=publisher(keyFile,h.publisherSha256),pointer=privateJson(path.join(root,'active.json'));
  if(pointer.schema!==1||!version(pointer.version))fail();
  const current=manifest(path.join(root,'releases',pointer.version),key);
  if(current.manifestSha256!==pointer.manifest_sha256)fail();
  const installed={...current,publisherSha256:h.publisherSha256};
  if(unsettled(stateDir,root))return result({status:'needs_recovery',installed});
  if(!artifacts)return result({status:'candidate_not_supplied',installed});
  let bundled;
  try{bundled={...manifest(artifacts.bundle,publisher(artifacts.publisherKeyFile,artifacts.publisherSha256)),publisherSha256:artifacts.publisherSha256}}
  catch{return result({status:'candidate_unverified',installed})}
  const status=bundled.publisherSha256!==installed.publisherSha256?'publisher_changed':
   bundled.manifestSha256===installed.manifestSha256?'aligned':
   bundled.version===installed.version?'same_version_conflict':'update_available';
  return result({status,installed,bundled,
   ...(status==='publisher_changed'?{requiredAction:'review_publisher_migration'}:{}),
   ...(status==='update_available'?{requiredAction:'review_host_update',updateReadiness:'not_evaluated'}:{})});
 }catch{return result({status:'unavailable'})}
}
