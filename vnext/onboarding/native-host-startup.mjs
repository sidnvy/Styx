// A platform installer replaces the App; Core reconciles its bundled Host
// before opening connections. This decision neither installs nor grants trust.
// Failed/interrupted work is never replayed merely because the App reopened.
export async function nativeHostStartupDecision(stateDir,{artifacts,core}={}){
 if(!artifacts?.bundle)return {status:'continue'};
 try{
  const deployment=await core.readDeployment(stateDir);
  const steps=deployment.steps??[];
  const enrollmentComplete=steps.some(s=>['host.claim','host.pair'].includes(s.id)&&s.status==='succeeded');
  const blocked=reason=>({status:'reconciliation_required',observation:'current_process',reason,automaticUpdate:false});
  // Prepared files (and even a token written during claim) are not completed
  // enrollment. Preserve the existing join path until its durable claim settles.
  if(steps.some(s=>s.id==='host.prepare')&&!enrollmentComplete){
   const prior=await core.readHostPayloadHandoff({stateDir});
   if(prior?.status!=='not_started'&&!(prior?.status==='cancelled'&&prior.phase==='preflight_only'))
    return blocked('host_payload_requires_review');
   return {status:'continue',phase:'enrollment_incomplete'};
  }
  const components=await core.readDeploymentComponents(stateDir,{artifacts});
  const host=components?.host;
  if(['not_configured','not_prepared','aligned'].includes(host?.status))return {status:'continue'};
  if(host?.status!=='update_available')return blocked('host_payload_requires_review');
  const handoff=await core.readHostPayloadHandoff({stateDir});
  const previous=handoff?.status;
  if(previous!=='not_started'&&previous!=='applied_stopped')return blocked('host_payload_requires_review');
  // A completed migration still reporting the same mismatch is inconsistent,
  // not permission to loop through the same transaction on every launch.
  if(previous==='applied_stopped'&&handoff.target?.manifestSha256===host.bundled?.manifestSha256)
   return blocked('host_payload_requires_review');
  if(!/^[a-f0-9]{64}$/.test(host.bundled?.manifestSha256??''))return blocked('host_payload_requires_review');
  return {status:'reconciliation_required',observation:'current_process',reason:'host_payload_update_required',automaticUpdate:true};
 }catch{return {status:'reconciliation_required',observation:'current_process',reason:'host_payload_requires_review',automaticUpdate:false};}
}
