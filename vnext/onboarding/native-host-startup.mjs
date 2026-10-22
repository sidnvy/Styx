// A platform installer replaces the App; Core reconciles its bundled Host
// before opening connections. This decision neither installs nor grants trust.
// Failed/interrupted work is never replayed merely because the App reopened.
export async function nativeHostStartupDecision(stateDir,{artifacts,core}={}){
 if(!artifacts?.bundle)return {status:'continue'};
 try{
  const components=await core.readDeploymentComponents(stateDir,{artifacts});
  const host=components?.host;
  if(['not_configured','not_prepared','aligned'].includes(host?.status))return {status:'continue'};
  const blocked=reason=>({status:'reconciliation_required',observation:'current_process',reason,automaticUpdate:false});
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
