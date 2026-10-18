// Bounded native acceptance for the trusted-local signed service updater.
// This script is never invoked by ordinary CI and cannot target existing units.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,sign} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {buildHostRelease} from './build-host-release.mjs';
import {runManagedLinuxPilot,pilotOptions} from './managed-linux-pilot.mjs';
import {systemdUser,statusUserService} from './linux-service.mjs';
import {activeRelease,verifySignedRelease} from './installer.mjs';
import {updateServiceRelease,recoverServiceUpdate,inspectServiceUpdate} from './service-update.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const assert=(ok,why)=>{if(!ok)throw Error(why)};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const ALTERNATE={version:'22.23.2',archive_sha256:'d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307',
  binary_sha256:'3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327',
  license_sha256:'c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4'};
const STABLE=['private-storage.mjs','installer.mjs','launch.mjs','node'];
export function updatePilotOptions(raw){
  const options=pilotOptions(raw);
  assert(/^styx-rc[0-9]{8}-owned-[a-z0-9]{1,12}\.service$/.test(options.unitName),
    'fresh_suffixed_update_pilot_unit_required');
  assert(typeof raw.alternateNodeBinary==='string'&&path.isAbsolute(raw.alternateNodeBinary),'absolute_alternate_node_required');
  return {...options,alternateNodeBinary:raw.alternateNodeBinary};
}
// Both generations contain unchanged fixed official runtime binaries. Distinct
// signed launcher comments make an actual prior-bootstrap restoration observable.
function buildVariant(options,alternateNodeBinary){
  const source=options.destination+'.source';fs.mkdirSync(source,{mode:0o700});
  for(const folder of ['host','shared','licenses'])
    fs.cpSync(path.join(root,folder),path.join(source,folder),{recursive:true});
  fs.mkdirSync(path.join(source,'packages/styx-exec-adapter'),{recursive:true,mode:0o700});
  for(const name of ['rpc.mjs','errors.mjs'])
    fs.copyFileSync(path.join(root,'packages/styx-exec-adapter',name),path.join(source,'packages/styx-exec-adapter',name));
  fs.mkdirSync(path.join(source,'node_modules'),{mode:0o700});
  fs.cpSync(path.join(root,'node_modules/ws'),path.join(source,'node_modules/ws'),{recursive:true});
  fs.appendFileSync(path.join(source,'host/launch.mjs'),'\n// Signed native transaction acceptance generation: '+options.version+'\n');
  const result=buildHostRelease({...options,sourceRoot:source});
  if(options.version.endsWith('-2')){
    // Test-only publisher fixture. Production buildHostRelease still permits
    // only its unchanged official Node22.23.3 pin.
    for(const [input,output] of [[alternateNodeBinary,'bin/node'],
      [path.join(path.dirname(alternateNodeBinary),'LICENSE'),'licenses/node-LICENSE'],
      [path.join(path.dirname(alternateNodeBinary),'node-provenance.json'),'provenance/node.json']])
      fs.copyFileSync(input,path.join(options.destination,output));
    fs.chmodSync(path.join(options.destination,'bin/node'),0o700);
    const file=path.join(options.destination,'manifest.json');
    const manifest=JSON.parse(fs.readFileSync(file,'utf8'));
    manifest.upstream.node=ALTERNATE.version;
    manifest.acceptance_fixture='alternate official runtime; not a supported production distribution';
    for(const entry of manifest.files){
      const member=path.join(options.destination,entry.path);
      entry.sha256=hash(member);entry.size=fs.statSync(member).size;
    }
    const bytes=JSON.stringify(manifest,null,2)+'\n';
    fs.writeFileSync(file,bytes);
    fs.writeFileSync(path.join(options.destination,'manifest.sig'),
      sign(null,Buffer.from(bytes),fs.readFileSync(options.privateKeyFile)).toString('base64url')+'\n');
  }
  return result;
}
function stableSnapshot(installRoot){
  return {pointer:hash(path.join(installRoot,'active.json')),
    files:Object.fromEntries(STABLE.map(name=>[name,hash(path.join(installRoot,name))]))};
}
function expectedStable(installRoot,publicKeyPem,version){
  const verified=verifySignedRelease(path.join(installRoot,'releases',version),publicKeyPem);
  return Object.fromEntries(STABLE.map(name=>{
    const member=name==='node'?'bin/node':'host/'+name;
    const entry=verified.manifest.files.find(file=>file.path===member);
    assert(entry,'signed_stable_member_missing');return [name,entry.sha256];
  }));
}
async function exerciseTransactions(context){
  const {installRoot,unitName,publicKeyPem,release1,release2,ready,closeClient,
    gateway,target,receipt,setPhase,saveReceipt}=context;
  receipt.kind='linux-native-signed-service-update-pilot';
  receipt.evidence.successful_update_transaction='NOT RUN';
  receipt.evidence.unhealthy_candidate_rollback_transaction='NOT RUN';
  receipt.evidence.uncertain_timeout_no_replay='NOT RUN';
  receipt.evidence.explicit_stopped_recovery='NOT RUN';
  receipt.evidence.runtime_version_change='NOT RUN';
  receipt.runtime.candidate_node=ALTERNATE.version;
  receipt.runtime.candidate_distribution='test-only signed fixture';
  receipt.binary_sha256.candidate_node=ALTERNATE.binary_sha256;
  receipt.alternate_runtime_provenance=ALTERNATE;
  receipt.update_transactions=[];
  const oldHashes=expectedStable(installRoot,publicKeyPem,release1);
  const newHashes=expectedStable(installRoot,publicKeyPem,release2);
  assert(oldHashes['launch.mjs']!==newHashes['launch.mjs'],'native_pilot_bootstrap_generations_must_differ');
  assert(oldHashes.node!==newHashes.node,'native_pilot_official_node_versions_must_differ');
  async function stopped(){
    const end=Date.now()+15000;
    do{
      const s=statusUserService(unitName);
      if(s.active!=='active'&&s.pid===0&&s.enabled!=='enabled'&&!gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===0)return true;
      await sleep(100);
    }while(Date.now()<end);
    throw Error('owned_update_service_did_not_stop');
  }
  const initialEnabled=statusUserService(unitName).enabled==='enabled';
  async function operatorStop(){
    await closeClient();
    // Persistently inhibit login/reboot activation before any offline write.
    execFileSync('/usr/bin/systemctl',['--user','disable','--now',unitName],
      {stdio:'ignore',timeout:25000});
    await stopped();assert(statusUserService(unitName).enabled!=='enabled','owned_update_service_still_enabled');
    return true;
  }
  function restoreEnabled(){
    assert(!fs.existsSync(path.join(installRoot,'.health-update-lock')),'uncertain_update_must_remain_disabled');
    if(initialEnabled)systemdUser(unitName,'enable');
  }
  function assertSelected(version,expected){
    assert(activeRelease(installRoot,publicKeyPem).version===version,'native_update_active_version_mismatch');
    assert(JSON.stringify(stableSnapshot(installRoot).files)===JSON.stringify(expected),'native_update_stable_bytes_mismatch');
  }
  async function transact(version,mode){
    const calls={stop:0,start:0,health:0},versions=[];let lateFinish;
    const result=await updateServiceRelease({installRoot,version,publicKeyPem,
      timeoutMs:mode==='timeout'?3000:15000,
      stopService:async()=>{calls.stop++;return operatorStop()},
      startService:async()=>{calls.start++;systemdUser(unitName,'start');return statusUserService(unitName).active==='active'},
      checkHealth:async check=>{
        calls.health++;await ready(check.version);
        const actual=execFileSync('/proc/'+statusUserService(unitName).pid+'/exe',['--version'],{encoding:'utf8',timeout:5000}).trim();
        assert(actual===(check.version===release2?'v22.23.2':'v22.23.3'),'native_service_mapped_runtime_version_mismatch');
        versions.push({phase:check.phase,release:check.version,node:actual});
        if(check.version===version&&mode==='unhealthy')return false;
        if(check.version===version&&mode==='timeout')return new Promise(resolve=>{lateFinish=resolve});
        return true;
      }});
    return {result,calls,lateFinish,versions};
  }
  setPhase('successful_update_transaction');
  const success=await transact(release2,'healthy');
  assert(success.result.status==='activated','native_update_transaction_not_activated');
  assertSelected(release2,newHashes);restoreEnabled();
  receipt.evidence.runtime_version_change='PASS';
  receipt.evidence.successful_update_transaction='PASS';receipt.evidence.signed_upgrade='PASS';
  receipt.update_transactions.push({scenario:'healthy_candidate',status:'PASS',outcome:success.result.status,
    callbacks:success.calls,service_runtime_observations:success.versions,selected_version:release2,stable_matches_signed_generation:true,
    startup_disabled_before_switch:true,initial_enabled_state_restored_only_after_terminal:true});saveReceipt();

  setPhase('unhealthy_candidate_rollback_transaction');
  const beforeRollback=stableSnapshot(installRoot);
  const rejected=await transact(release1,'unhealthy');
  assert(rejected.result.status==='rolled_back','native_unhealthy_candidate_not_rolled_back');
  assertSelected(release2,newHashes);
  assert(JSON.stringify(stableSnapshot(installRoot))===JSON.stringify(beforeRollback),'native_rollback_did_not_restore_exact_previous_state');
  restoreEnabled();
  receipt.evidence.unhealthy_candidate_rollback_transaction='PASS';receipt.evidence.signed_rollback='PASS';
  receipt.update_transactions.push({scenario:'observed_unhealthy_candidate',status:'PASS',outcome:rejected.result.status,
    callbacks:rejected.calls,service_runtime_observations:rejected.versions,selected_version:release2,exact_previous_pointer_restored:true,
    distinct_previous_launcher_restored:true,previous_signed_helper_installer_and_node_restored:true,
    healthy_previous_native_exec_observed:true,startup_disabled_before_switch:true,
    initial_enabled_state_restored_only_after_terminal:true});saveReceipt();

  setPhase('uncertain_timeout_no_replay');
  const beforeUncertain=stableSnapshot(installRoot);
  const uncertain=await transact(release1,'timeout');
  assert(uncertain.result.status==='needs_recovery','native_timeout_must_be_explicitly_uncertain');
  assert(fs.existsSync(path.join(installRoot,'.health-update-lock')),'native_uncertain_lock_not_retained');
  assert(typeof uncertain.lateFinish==='function','native_timeout_did_not_reach_owned_health_boundary');
  assert(statusUserService(unitName).enabled!=='enabled','uncertain_update_was_reenabled');
  const held=stableSnapshot(installRoot),callsBefore=JSON.stringify(uncertain.calls);
  uncertain.lateFinish(true);await sleep(100);
  assert(JSON.stringify(uncertain.calls)===callsBefore,'native_uncertain_operation_was_replayed');
  assert(JSON.stringify(stableSnapshot(installRoot))===JSON.stringify(held),'native_late_probe_changed_uncertain_state');
  const journal=inspectServiceUpdate({installRoot,transactionId:uncertain.result.transactionId});
  assert(journal&&typeof journal==='object','native_uncertain_journal_unavailable');
  receipt.evidence.uncertain_timeout_no_replay='PASS';
  receipt.update_transactions.push({scenario:'health_completion_timeout',status:'PASS',outcome:uncertain.result.status,
    callbacks:uncertain.calls,service_runtime_observations:uncertain.versions,lock_retained:true,durable_journal_observed:true,startup_remained_disabled:true,
    late_health_completion_did_not_mutate_or_replay:true});saveReceipt();

  setPhase('explicit_stopped_recovery');await operatorStop();
  const recovered=await recoverServiceUpdate({installRoot,transactionId:uncertain.result.transactionId,
    publicKeyPem,confirmStopped:async()=>{const s=statusUserService(unitName);return s.active!=='active'&&s.pid===0&&s.enabled!=='enabled'}});
  assert(recovered.status==='recovered_stopped','native_explicit_recovery_did_not_leave_service_stopped');
  assertSelected(release2,newHashes);
  assert(JSON.stringify(stableSnapshot(installRoot))===JSON.stringify(beforeUncertain),'native_recovery_did_not_restore_exact_previous_state');
  assert(statusUserService(unitName).active!=='active'&&statusUserService(unitName).pid===0,'native_recovery_restarted_without_operator');
  systemdUser(unitName,'start');await ready(release2);
  assert(execFileSync('/proc/'+statusUserService(unitName).pid+'/exe',['--version'],{encoding:'utf8',timeout:5000}).trim()==='v22.23.2','native_recovered_runtime_version_mismatch');
  restoreEnabled();
  receipt.evidence.explicit_stopped_recovery='PASS';
  receipt.update_transactions.push({scenario:'operator_confirmed_stopped_recovery',status:'PASS',outcome:recovered.status,
    exact_previous_pointer_restored:true,distinct_previous_launcher_restored:true,
    previous_signed_helper_installer_and_node_restored:true,recovery_did_not_start_service:true,
    explicit_operator_start_native_exec_healthy:true,initial_enabled_state_restored_only_after_terminal:true});saveReceipt();
}
export async function runManagedLinuxUpdatePilot(raw,{optIn=process.env.STYX_RUN_MANAGED_LINUX_UPDATE_PILOT}={}){
  assert(optIn==='1','managed_update_pilot_requires_explicit_opt_in');
  const options=updatePilotOptions(raw),binary=options.alternateNodeBinary;
  const st=fs.lstatSync(binary);assert(st.isFile()&&!st.isSymbolicLink()&&hash(binary)===ALTERNATE.binary_sha256,'alternate_node_binary_mismatch');
  const provenance=JSON.parse(fs.readFileSync(path.join(path.dirname(binary),'node-provenance.json'),'utf8'));
  for(const field of ['version','archive_sha256','binary_sha256','license_sha256'])
    assert(provenance[field]===ALTERNATE[field],'alternate_node_provenance_mismatch');
  assert(provenance.platform==='linux'&&provenance.arch==='x64'&&
    hash(path.join(path.dirname(binary),'LICENSE'))===ALTERNATE.license_sha256,'alternate_node_license_or_platform_mismatch');
  return runManagedLinuxPilot(options,{optIn:'1',buildRelease:opts=>buildVariant(opts,binary),updateAcceptance:exerciseTransactions});
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const [file]=process.argv.slice(2);assert(file&&path.isAbsolute(file),'absolute_update_pilot_config_required');
    const result=await runManagedLinuxUpdatePilot(JSON.parse(fs.readFileSync(file,'utf8')));
    console.log(JSON.stringify(result));process.exitCode=result.status==='PASS'?0:1;
  }catch(error){console.log(JSON.stringify({status:'BLOCKED',reason:String(error.message).slice(0,120)}));process.exitCode=2}
}
