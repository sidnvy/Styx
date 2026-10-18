// Opt-in managed service + native Exec sampling. No repeated GUI observations.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {performance} from 'node:perf_hooks';
import {fileURLToPath} from 'node:url';
import {runManagedLinuxPilot,pilotOptions} from './managed-linux-pilot.mjs';
import {statusUserService} from './linux-service.mjs';

const assert=(ok,why)=>{if(!ok)throw Error(why)};
export function managedSoakOptions(raw={}){
  const pilot=pilotOptions(raw),durationSeconds=raw.durationSeconds??86400,intervalSeconds=raw.intervalSeconds??60;
  assert(/^styx-rc[0-9]{8}-owned-soak[a-z0-9]{1,8}\.service$/.test(pilot.unitName),'fresh_managed_soak_unit_required');
  assert(Number.isSafeInteger(durationSeconds)&&durationSeconds>=1&&durationSeconds<=172800,'bounded_managed_soak_duration_required');
  assert(Number.isSafeInteger(intervalSeconds)&&intervalSeconds>=1&&intervalSeconds<=3600,'bounded_managed_soak_interval_required');
  return {...pilot,durationSeconds,intervalSeconds};
}
const SAFE_ERRORS=new Set(['managed_pilot_aborted','managed_native_exec_readback_failed',
  'managed_soak_initial_unit_not_confirmed','managed_soak_unit_not_active_enabled',
  'managed_soak_unexpected_service_restart','managed_soak_transport_disconnected',
  'managed_soak_process_not_owned','managed_soak_proc_resources_unavailable',
  'managed_soak_certificate_window_too_short','managed_soak_sample_failed']);
export function managedSoakErrorCode(error,{aborted=false}={}){
  return aborted?'managed_pilot_aborted':SAFE_ERRORS.has(error?.message)?error.message:'managed_soak_sample_failed';
}
export function assertManagedSoakCertificateWindow(notAfter,durationSeconds,now=Date.now()){
  assert(Number.isFinite(notAfter)&&notAfter>=now+(durationSeconds+3600)*1000,
    'managed_soak_certificate_window_too_short');
}
function wait(ms,signal){
  return new Promise((resolve,reject)=>{
    const abort=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);reject(Error('managed_pilot_aborted'))};
    const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve()},Math.max(0,ms));
    signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  });
}
function durable(file,value){
  const fd=fs.openSync(file+'.new','w',0o600);
  try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
  fs.renameSync(file+'.new',file);
  const dir=fs.openSync(path.dirname(file),'r');try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}
}
function append(file,value){
  const fd=fs.openSync(file,'a',0o600);
  try{fs.writeSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
}
const numeric=value=>/^\d+$/.test(value??'')&&Number.isSafeInteger(Number(value))?Number(value):null;
function resources(unitName,pid,installRoot){
  assert(fs.realpathSync('/proc/'+pid+'/exe')===path.join(installRoot,'node'),'managed_soak_process_not_owned');
  const status=fs.readFileSync('/proc/'+pid+'/status','utf8');
  const rss=/^VmRSS:\s+(\d+) kB$/m.exec(status),threads=/^Threads:\s+(\d+)$/m.exec(status);
  assert(rss&&threads,'managed_soak_proc_resources_unavailable');
  const unit=execFileSync('/usr/bin/systemctl',['--user','show',unitName,
    '--property=MemoryCurrent,CPUUsageNSec,TasksCurrent','--no-pager'],{encoding:'utf8',timeout:13000});
  const fields=Object.fromEntries(unit.trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)]}));
  return {main_rss_bytes:Number(rss[1])*1024,main_threads:Number(threads[1]),
    cgroup_memory_current_bytes:numeric(fields.MemoryCurrent),
    cgroup_cpu_usage_nanoseconds:numeric(fields.CPUUsageNSec),cgroup_tasks:numeric(fields.TasksCurrent)};
}
export async function runManagedServiceSoak(raw,{optIn=process.env.STYX_RUN_MANAGED_SERVICE_SOAK,signal}={}){
  assert(optIn==='1','managed_service_soak_requires_explicit_opt_in');
  const options=managedSoakOptions(raw);
  return runManagedLinuxPilot(options,{optIn:'1',signal,tlsDays:3,updateAcceptance:async context=>{
    const {unitName,directory,installRoot,sampleExec,certificateNotAfter,gateway,target,receipt,setPhase,saveReceipt}=context;
    assertManagedSoakCertificateWindow(certificateNotAfter,options.durationSeconds);
    setPhase('managed_service_exec_sampling');receipt.kind='linux-managed-service-exec-soak';
    receipt.evidence.managed_service_exec_sampling='NOT RUN';
    receipt.evidence.managed_service_exec_soak_24h='NOT RUN';
    receipt.evidence.full_gui_session_soak_24h='NOT RUN';
    const original=statusUserService(unitName),began=performance.now();
    assert(original.status==='reported'&&original.load==='loaded'&&original.active==='active'&&original.pid>1&&original.enabled==='enabled',
      'managed_soak_initial_unit_not_confirmed');
    const soak={schema:1,status:'NOT RUN',phase:'running',driver_pid:receipt.driver_pid,
      node:receipt.node,revision:receipt.revision,unit_name:unitName,duration_seconds:options.durationSeconds,
      interval_seconds:options.intervalSeconds,passed_samples:0,elapsed_seconds:0,
      started_at:new Date().toISOString(),initial_main_pid:original.pid,initial_restarts:original.restarts,
      scope:'owned user service + native Exec over private HTTPS/WSS; no periodic GUI calls',
      full_gui_session_soak_24h:'NOT RUN',tls_certificate_validity_days:3,
      tls_not_after:new Date(certificateNotAfter).toISOString(),tls_required_duration_safety_margin_seconds:3600};
    receipt.soak=soak;
    const receiptFile=path.join(directory,'managed-soak.json'),samplesFile=path.join(directory,'managed-soak-samples.jsonl');
    function persist(){durable(receiptFile,soak);saveReceipt()}
    persist();
    try{
      while(true){
        if(signal?.aborted)throw Error('managed_pilot_aborted');
        const current=statusUserService(unitName),sample={at:new Date().toISOString(),sample:soak.passed_samples+1,
          status:'NOT RUN',elapsed_seconds:Math.floor((performance.now()-began)/1000),main_pid:current.pid,restarts:current.restarts};
        try{
          assert(current.status==='reported'&&current.load==='loaded'&&current.active==='active'&&current.enabled==='enabled',
            'managed_soak_unit_not_active_enabled');
          assert(current.pid===original.pid&&current.restarts===original.restarts,'managed_soak_unexpected_service_restart');
          assert(gateway.relay.connected(target)&&gateway.relay.computerConnected(target)===1,'managed_soak_transport_disconnected');
          const callBegan=performance.now();await sampleExec('STYX_SERVICE_SOAK_'+soak.passed_samples);
          sample.native_exec_latency_ms=Math.round(performance.now()-callBegan);
          Object.assign(sample,resources(unitName,current.pid,installRoot));
          sample.exec_wss_connected=true;sample.computer_wss_slots=1;sample.status='PASS';
        }catch(error){sample.status=signal?.aborted?'BLOCKED':'FAIL';sample.reason=managedSoakErrorCode(error,{aborted:signal?.aborted});append(samplesFile,sample);throw Error(sample.reason)}
        append(samplesFile,sample);soak.passed_samples++;
        soak.elapsed_seconds=Math.floor((performance.now()-began)/1000);soak.last_sample=sample;persist();
        if(performance.now()-began>=options.durationSeconds*1000)break;
        const next=Math.min(began+options.durationSeconds*1000,began+soak.passed_samples*options.intervalSeconds*1000);
        await wait(next-performance.now(),signal);
      }
      soak.status='PASS';soak.phase='completed';receipt.evidence.managed_service_exec_sampling='PASS';
      if(options.durationSeconds>=86400&&performance.now()-began>=86400000)
        receipt.evidence.managed_service_exec_soak_24h='PASS';
    }catch(error){
      soak.status=signal?.aborted?'BLOCKED':'FAIL';soak.phase='stopped';
      soak.reason=managedSoakErrorCode(error,{aborted:signal?.aborted});
      receipt.evidence.managed_service_exec_sampling=soak.status;throw Error(soak.reason);
    }finally{
      soak.elapsed_seconds=Math.floor((performance.now()-began)/1000);soak.completed_at=new Date().toISOString();persist();
    }
  }});
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const abort=new AbortController();process.once('SIGINT',()=>abort.abort());process.once('SIGTERM',()=>abort.abort());
  try{
    const [file]=process.argv.slice(2);assert(file&&path.isAbsolute(file),'absolute_managed_soak_config_required');
    const result=await runManagedServiceSoak(JSON.parse(fs.readFileSync(file,'utf8')),{signal:abort.signal});
    console.log(JSON.stringify(result));process.exitCode=result.status==='PASS'?0:result.status==='BLOCKED'?2:1;
  }catch(error){console.log(JSON.stringify({status:'BLOCKED',reason:abort.signal.aborted?'managed_pilot_aborted':'managed_soak_setup_failed'}));process.exitCode=2}
}
