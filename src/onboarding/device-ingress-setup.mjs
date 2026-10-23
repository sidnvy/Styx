// Controlled, additive network authorization. It never rewrites the primary
// Gateway/Host identity or restores a pairing database from a snapshot.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomBytes,X509Certificate} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {localGatewayAddresses,validateDeployment} from './deployment-config.mjs';
import {readGatewayDeployment} from './gateway-deployment-reader.mjs';
import {deploymentDeviceIngress} from './device-ingress-config.mjs';
import {requirePrivateFile,requirePrivateDirectory,ensurePrivateDirectory,openPrivateFile,writePrivateFile} from '../host/private-storage.mjs';
const fail=code=>{throw Error(code)},kind='additional-device-ingress-v1';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex'),encode=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
const journalFile=d=>path.join(d,'device-ingress-setup.json');
const lockNames=['device-ingress.lock','advance.lock','background.lock','capabilities.lock','onboarding-plugin.lock','account-acceptance.lock'];
function exact(value,names){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!names.includes(k)))fail('device_ingress_invalid_options')}
function bytes(file){if(requirePrivateFile(file).size>2*1024*1024)fail('device_ingress_state_too_large');return fs.readFileSync(file)}
const read=file=>JSON.parse(bytes(file));
function atomic(file,data){const temp=file+'.'+randomBytes(8).toString('hex')+'.tmp',fd=openPrivateFile(temp);try{fs.writeFileSync(fd,data);fs.fsyncSync(fd)}finally{fs.closeSync(fd)}try{fs.renameSync(temp,file);if(process.platform!=='win32'){const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}}}finally{if(fs.existsSync(temp))fs.unlinkSync(temp)}}
const recoveryGuard=d=>path.join(d,'device-ingress-recovery.lock');
function guardPresent(d){try{fs.lstatSync(recoveryGuard(d));return true}catch(error){return error.code!=='ENOENT'}}
function noRecoveryGuard(d){if(guardPresent(d))fail('device_ingress_recovery_guard_requires_inspection')}
function lock(d,id,recover=false,onClaim=()=>{}){
 const held=[];
 const matches=item=>{const current=requirePrivateFile(item.file);return current.ino===item.identity.ino&&current.dev===item.identity.dev&&bytes(item.file).equals(item.data)};
 const assertOwnership=()=>{for(const item of held)if(!matches(item))fail('device_ingress_lock_changed');if(!recover)noRecoveryGuard(d)};
 const release=()=>{
  let changed=false;
  for(const item of [...held].reverse()){
   try{if(matches(item))fs.unlinkSync(item.file);else changed=true}catch{changed=true}finally{fs.closeSync(item.fd)}
  }
  held.length=0;if(changed)fail('device_ingress_lock_changed');
 };
 const acquire=file=>{
  const fd=openPrivateFile(file),identity=fs.fstatSync(fd),data=encode({schema:1,kind,transactionId:id,pid:process.pid,token:randomBytes(32).toString('hex')});
  held.push({fd,file,identity,data});fs.writeFileSync(fd,data);fs.fsyncSync(fd);
 };
 try{
  // This fresh exclusive outer guard is never reclaimed. An interrupted or
  // unknown guard needs a separately reviewed owner-inspection path; ordinary
  // retry/rollback deliberately leaves it in place, even when its PID is dead.
  if(recover){try{acquire(recoveryGuard(d))}catch(error){if(error.code==='EEXIST')fail('device_ingress_recovery_guard_requires_inspection');throw error}}
  else noRecoveryGuard(d);
  for(const name of lockNames){const file=path.join(d,name);
   if(recover&&fs.existsSync(file)){
    const original=bytes(file),record=JSON.parse(original);if(record.kind!==kind||record.transactionId!==id||!Number.isSafeInteger(record.pid)||record.pid<1)fail('device_ingress_lock_owner_unknown');
    let dead=false;try{process.kill(record.pid,0)}catch(error){dead=error.code==='ESRCH'}
    if(!dead)fail('device_ingress_lock_owner_alive_or_unknown');assertOwnership();if(!bytes(file).equals(original))fail('device_ingress_lock_changed');fs.unlinkSync(file);
   }
   acquire(file);assertOwnership();if(name==='device-ingress.lock')onClaim(assertOwnership);
  }
  release.assertOwnership=assertOwnership;return release;
 }catch(error){try{release()}catch{fail('device_ingress_lock_changed')}throw error}
}
function persist(d,j){const root=path.join(d,'device-ingress-transactions');ensurePrivateDirectory(root);atomic(path.join(root,j.id+'.json'),encode(j));atomic(journalFile(d),encode(j));}
function context(d){
 const ctx=readGatewayDeployment(d),configFile=path.join(d,'deployment.json'),configBytes=bytes(configFile),stateFile=path.join(d,'state.json'),state=read(stateFile);
 if(!configBytes.equals(encode(ctx.config)))fail('device_ingress_canonical_configuration_required');
 if(state.steps.some(x=>['running','uncertain'].includes(x.status))||[...(state.maintenance??[]),...(state.gatewayMaintenance??[])].some(x=>['running','uncertain'].includes(x.status)))fail('device_ingress_management_requires_reconciliation');
 for(const base of [ctx.config.host?.baseDir,ctx.config.gateway.runtime?.baseDir].filter(Boolean))for(const name of ['.health-update-lock','.health-operation-lock','.health-recovery-guard'])if(fs.existsSync(path.join(base,'install',name)))fail('device_ingress_runtime_update_in_progress');
 const files=[{name:'deployment',file:configFile,before:configBytes},{name:'state',file:stateFile,before:bytes(stateFile)}];
 for(const name of ['background','capabilities']){const file=path.join(d,name+'.json');if(!fs.existsSync(file))continue;const value=read(file);if(value.configSha256!==state.configSha256||['running','uncertain','configuring','rolling_back'].includes(value.status)||value.operations?.some(x=>['running','uncertain'].includes(x.status)))fail('device_ingress_auxiliary_requires_reconciliation');files.push({name,file,before:bytes(file)})}
 const preserve=[ctx.runtime.tlsCertificateFile,ctx.runtime.tlsPrivateKeyFile,ctx.runtime.modelTokenFile,ctx.runtime.adminTokenFile,path.join(d,'gateway/runtime.json'),path.join(d,'gateway/owner.json')];
 if(ctx.config.host){const base=ctx.config.host.baseDir;for(const name of ['device/identity.pem','device/identity.json','device/host.json','device/host.token','enrollment.json','gateway-ca.pem']){const file=path.join(base,name);if(fs.existsSync(file))preserve.push(file)}}
 for(const file of [path.join(d,'onboarding-plugin.json'),path.join(d,'tunnel/connection.json')])if(fs.existsSync(file))preserve.push(file);
 return {...ctx,state,files,preserved:preserve.map(file=>({file,sha256:sha(bytes(file))}))};
}
const samePreserved=journal=>{for(const item of journal.preserved)if(sha(bytes(item.file))!==item.sha256)fail('device_ingress_preserved_identity_changed')};
function project(journal){return {schema:1,status:journal.status,phase:journal.phase,transactionId:journal.id,generation:journal.descriptor?.generation,url:journal.descriptor?.url,remoteReachability:'NOT VERIFIED',accountAcceptance:'NOT RUN',...(journal.reason?{reason:journal.reason}:{})}}
function recoveryJournal(d){
 let pointer=fs.existsSync(journalFile(d))?read(journalFile(d)):null;
 const file=path.join(d,'device-ingress.lock');if(!fs.existsSync(file))return pointer;
 const owner=read(file);if(owner.kind!==kind||!/^[a-f0-9]{32}$/.test(owner.transactionId??''))fail('device_ingress_lock_owner_unknown');
 if(pointer?.id===owner.transactionId)return pointer;
 const history=path.join(d,'device-ingress-transactions',owner.transactionId+'.json');
 if(fs.existsSync(history))return read(history);
 // This durable primary claim precedes the first intent write. No shared
 // configuration or listener is mutated before that intent exists.
 return {schema:1,kind,id:owner.transactionId,status:'preparing',phase:'claim',files:[],preserved:[]};
}
export function readAdditionalDeviceIngress(d){
 requirePrivateDirectory(d);if(guardPresent(d))return {schema:1,status:'needs_reconciliation',phase:'recovery_guard',reason:'device_ingress_recovery_guard_requires_inspection',remoteReachability:'NOT VERIFIED',accountAcceptance:'NOT RUN'};const j=recoveryJournal(d);if(!j)return {schema:1,status:'not_started'};return project(j);
}
function assertJournal(d,j){
 if(j.schema!==1||j.kind!==kind||!/^[a-f0-9]{32}$/.test(j.id??'')||!Array.isArray(j.files)||!Array.isArray(j.preserved)||!j.descriptor)fail('device_ingress_invalid_journal');
 const allowed=new Map(['deployment','state','background','capabilities'].map(name=>[name,path.join(d,name==='deployment'?'deployment.json':name+'.json')]));
 if(j.files.length<2||new Set(j.files.map(x=>x.name)).size!==j.files.length||!j.files.some(x=>x.name==='deployment')||!j.files.some(x=>x.name==='state'))fail('device_ingress_invalid_journal');
 for(const item of j.files){if(item.file!==allowed.get(item.name)||typeof item.before!=='string'||typeof item.after!=='string'||sha(Buffer.from(item.before,'base64'))!==item.beforeSha256||sha(Buffer.from(item.after,'base64'))!==item.afterSha256)fail('device_ingress_invalid_journal');const digest=sha(bytes(item.file));if(digest!==item.beforeSha256&&digest!==item.afterSha256)fail('device_ingress_recovery_scope_changed')}
 const before=JSON.parse(Buffer.from(j.files.find(x=>x.name==='deployment').before,'base64')),after=JSON.parse(Buffer.from(j.files.find(x=>x.name==='deployment').after,'base64'));
 validateDeployment(before,{checkNetwork:false});validateDeployment(after,{checkNetwork:false});delete before.gateway.deviceIngress;delete after.gateway.deviceIngress;if(!encode(before).equals(encode(after)))fail('device_ingress_journal_changed_other_configuration');
 const configured=JSON.parse(Buffer.from(j.files.find(x=>x.name==='deployment').after,'base64'));if(JSON.stringify(deploymentDeviceIngress(d,configured))!==JSON.stringify(j.descriptor))fail('device_ingress_invalid_journal');
 samePreserved(j);
}
function restore(j,side,assertOwnership){for(const item of j.files){assertOwnership();atomic(item.file,Buffer.from(item[side],'base64'));}}
export async function prepareAdditionalDeviceIngress(d,options={},operations={}){
 exact(options,['authorize','listenHost','port']);if(options.authorize!==true)fail('explicit_device_ingress_authorization_required');
 if(typeof operations.command!=='function')fail('device_ingress_gateway_required');
 requirePrivateDirectory(d);noRecoveryGuard(d);let previous=fs.existsSync(journalFile(d))?read(journalFile(d)):null;
 if(previous&&!['applied','rolled_back'].includes(previous.status))fail('device_ingress_recovery_required');
 const id=randomBytes(16).toString('hex'),intent={schema:1,kind,id,status:'preparing',phase:'checking',files:[],preserved:[]};let j;
 const previousBytes=fs.existsSync(journalFile(d))?bytes(journalFile(d)):null;
 const release=lock(d,id,false,assertOwnership=>{assertOwnership();if(previousBytes?!bytes(journalFile(d)).equals(previousBytes):fs.existsSync(journalFile(d)))fail('device_ingress_scope_changed');persist(d,intent)});
 const command=(...args)=>{release.assertOwnership();return operations.command(...args)};
 const persistOwned=journal=>{release.assertOwnership();persist(d,journal)};
 try{
  const ctx=context(d),existing=ctx.config.gateway.deviceIngress;
  const capability=await command('status');release.assertOwnership();if(capability?.supported!==true)fail('device_ingress_gateway_upgrade_required');
  const addresses=(operations.addresses??localGatewayAddresses)();
  let listenHost=options.listenHost??existing?.listenHost;if(listenHost===undefined){if(addresses.length!==1)fail(addresses.length?'device_ingress_select_interface':'device_ingress_network_unavailable');listenHost=addresses[0]}
  if(!addresses.includes(listenHost)||listenHost==='0.0.0.0'||listenHost.startsWith('127.'))fail('device_ingress_exact_owned_interface_required');
  if(existing?.enabled){
   if(listenHost!==existing.listenHost||options.port!==undefined&&Number(new URL(existing.url).port)!==options.port)fail('device_ingress_address_change_requires_review');
   const descriptor=deploymentDeviceIngress(d,ctx.config);
   if(capability.generation===existing.generation&&capability.status==='listening'){intent.status='rolled_back';intent.phase='no_change';persistOwned(intent);if(previousBytes)atomic(journalFile(d),previousBytes);return {...capability,remoteReachability:'NOT VERIFIED'};}
   j={schema:1,kind,id,status:'running',phase:'listen',descriptor,preserved:ctx.preserved,files:ctx.files.map(item=>({...item,before:item.before.toString('base64'),beforeSha256:sha(item.before),after:item.before.toString('base64'),afterSha256:sha(item.before)}))};persistOwned(j);
   await command('prepare',descriptor);const result=await command('enable',{generation:existing.generation});if(result?.status!=='listening')fail('device_ingress_listener_not_confirmed');j.status='applied';j.phase='listening';persistOwned(j);return {...result,remoteReachability:'NOT VERIFIED'};
  }
  const port=options.port??Number(new URL(ctx.config.gateway.url).port);if(!Number.isInteger(port)||port<1024||port>65535)fail('device_ingress_invalid_port');
  const generation=randomBytes(16).toString('hex'),root=path.join(d,'gateway','device-ingress');ensurePrivateDirectory(root);const directory=path.join(root,generation);ensurePrivateDirectory(directory,{exclusive:true});
  const key=path.join(directory,'private-key.pem'),cert=path.join(directory,'certificate.pem');writePrivateFile(key,'');writePrivateFile(cert,'');
  (operations.openssl??execFileSync)(ctx.config.gateway.openssl,['req',...(ctx.config.gateway.opensslConfig?['-config',ctx.config.gateway.opensslConfig]:[]),'-x509','-newkey','rsa:2048','-nodes','-sha256','-days','30','-keyout',key,'-out',cert,'-subj','/CN=Styx device connection','-addext','subjectAltName=IP:'+listenHost],{stdio:'ignore',timeout:20000});
  if(process.platform!=='win32'){fs.chmodSync(key,0o600);fs.chmodSync(cert,0o600)}requirePrivateFile(key);requirePrivateFile(cert);
  const certificateSha256=sha(new X509Certificate(bytes(cert)).raw),next=structuredClone(ctx.config);next.gateway.deviceIngress={schema:1,enabled:true,generation,url:'https://'+listenHost+':'+port,listenHost,certificateSha256};validateDeployment(next,{checkNetwork:false});
  const configBytes=encode(next),configSha256=sha(configBytes),nextState=structuredClone(ctx.state);nextState.configSha256=configSha256;
  if(nextState.onboardingDecisions?.background?.configSha256===ctx.state.configSha256)nextState.onboardingDecisions.background.configSha256=configSha256;
  const descriptor=deploymentDeviceIngress(d,next);
  j={schema:1,kind,id,status:'running',phase:'prepared',at:new Date().toISOString(),descriptor,preserved:ctx.preserved,files:ctx.files.map(item=>{
   const after=item.name==='deployment'?configBytes:item.name==='state'?encode(nextState):encode({...JSON.parse(item.before),configSha256});return {...item,before:item.before.toString('base64'),beforeSha256:sha(item.before),after:after.toString('base64'),afterSha256:sha(after)};
  })};
  persistOwned(j);samePreserved(j);await command('prepare',descriptor);j.phase='configuration';persistOwned(j);restore(j,'after',release.assertOwnership);j.phase='listen';persistOwned(j);
  const result=await command('enable',{generation});if(result?.status!=='listening'||result.generation!==generation||result.ingress?.certificate_sha256!==certificateSha256)fail('device_ingress_listener_not_confirmed');
  samePreserved(j);j.status='applied';j.phase='listening';persistOwned(j);
  return {...result,transactionId:id,remoteReachability:'NOT VERIFIED',accountAcceptance:'NOT RUN'};
 }catch(error){if(j){j.status='needs_reconciliation';j.reason='device_ingress_incomplete_no_automatic_replay';persistOwned(j);}else{intent.status='rolled_back';intent.phase='no_shared_change';persistOwned(intent);if(previousBytes)atomic(journalFile(d),previousBytes);}throw error}
 finally{release()}
}
export async function recoverAdditionalDeviceIngress(d,options={},operations={}){
 exact(options,['authorize','action']);if(options.authorize!==true||!['retry','rollback'].includes(options.action)||typeof operations.command!=='function')fail('explicit_device_ingress_recovery_required');
 noRecoveryGuard(d);const j=recoveryJournal(d);if(!j||!['preparing','running','needs_reconciliation','applied'].includes(j.status))fail('device_ingress_not_recoverable');if(j.status!=='preparing')assertJournal(d,j);
 const release=lock(d,j.id,true);
 const command=(...args)=>{release.assertOwnership();return operations.command(...args)};
 const persistOwned=journal=>{release.assertOwnership();persist(d,journal)};
 try{
  const current=recoveryJournal(d);if(JSON.stringify(current)!==JSON.stringify(j))fail('device_ingress_recovery_scope_changed');
  if(j.status==='preparing'){j.status='rolled_back';j.phase='no_shared_change';persistOwned(j);return project(j)}
  assertJournal(d,j);
  // First reconcile metadata to its known after image so the same owner API can
  // operate even if a previous process stopped between config/state renames.
  restore(j,'after',release.assertOwnership);
  const status=await command('status');if(status?.supported!==true)fail('device_ingress_gateway_upgrade_required');
  if(options.action==='rollback'){
   const generation=j.descriptor.generation,recovery=status.recovery?.generation;
   if(status.generation!==undefined&&status.generation!==generation||status.recovery!==undefined&&recovery!==generation)fail('device_ingress_runtime_generation_changed');
   // A startup retry can own the descriptor before material() has produced a
   // prepared generation. Retire that epoch before revoking its configuration.
   if(status.generation===generation||recovery===generation)await command('disable',{generation});
   else if(status.status!=='absent')fail('device_ingress_runtime_generation_changed');
   restore(j,'before',release.assertOwnership);j.status='rolled_back';j.phase='rolled_back';
  }else{
   if(status.generation!==j.descriptor.generation||status.status!=='listening'){await command('prepare',j.descriptor);const result=await command('enable',{generation:j.descriptor.generation});if(result?.status!=='listening')fail('device_ingress_listener_not_confirmed')}
   j.status='applied';j.phase='listening';
  }
  samePreserved(j);delete j.reason;persistOwned(j);return project(j);
 }catch(error){j.status='needs_reconciliation';j.reason='device_ingress_recovery_incomplete';persistOwned(j);throw error}
 finally{release()}
}
