// A single owner decision covers this fixed local workflow. No shell commands,
// remote enrollment, background startup or account actions can be added by UI.
const LOCAL_STEPS = Object.freeze(['gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.doctor']);
// This observation may be repeated only by a new, explicitly authorized call.
// Installation, identity creation and pairing never use this exception.
export const isRetryableLocalCheck = step => step?.id==='host.doctor' && step.status==='blocked';
export async function completeLocalSetup(api, stateDir, approval) {
  if (!approval || Object.keys(approval).some(k=>!['approve','gatewayUrl','label','enableComputer','enableBrowser'].includes(k)) || approval.approve !== true)
    throw Error('explicit_local_setup_approval_required');
  const plan = await api.planDeployment(stateDir);
  const scope = plan.ownerPairingScope;
  if (!scope || ['gatewayUrl','label','enableComputer'].some(k=>approval[k]!==scope[k]) || (scope.enableBrowser===true&&typeof approval.enableBrowser!=='boolean') || approval.enableBrowser!==undefined&&typeof approval.enableBrowser!=='boolean' || (approval.enableBrowser===true)!==(scope.enableBrowser===true))
    throw Error('local_setup_scope_changed');
  const localSteps=[...((plan.steps??[]).some(s=>s.id==='gateway.runtime.prepare')?['gateway.runtime.prepare']:[]),...LOCAL_STEPS];
  let state = await api.readDeployment(stateDir);
  if (state.mode !== 'create-local' || localSteps.some(id=>!state.steps.some(s=>s.id===id)))
    throw Error('local_setup_workflow_required');
  const interrupted = state.steps.find(s=>localSteps.includes(s.id)&&!['pending','succeeded'].includes(s.status)&&!isRetryableLocalCheck(s));
  if (interrupted) return {status:'needs_attention',step:interrupted.id};
  // A reopened App may have lost its foreground process while durable setup
  // steps remain valid. Start the same scoped Gateway, never recreate identity.
  if (state.steps.find(s=>s.id==='gateway.start').status==='succeeded' &&
      state.steps.find(s=>s.id==='host.doctor').status!=='succeeded' &&
      state.gatewayRuntime?.status!=='running') {
    try { await api.startDeploymentGateway(stateDir); }
    catch { return {status:'needs_attention',step:'gateway.start'}; }
  }
  // Never turn a generic resume into replay of interrupted or failed mutations.
  for (const id of localSteps) {
    const step = state.steps.find(s=>s.id===id);
    if (step.status==='succeeded') continue;
    if (step.status!=='pending'&&!isRetryableLocalCheck(step)) return {status:'needs_attention',step:id};
    await api.advanceDeployment(stateDir,{authorize:[id],...(id==='host.pair'?{ownerApproval:approval}:{})});
    state=await api.readDeployment(stateDir);
    if (state.steps.find(s=>s.id===id)?.status!=='succeeded') return {status:'needs_attention',step:id};
  }
  if(typeof api.setLocalDeploymentDefault==='function')await api.setLocalDeploymentDefault(stateDir);
  return {status:'local_preparation_complete',account:'not_verified',desktop:'not_verified',background:'not_enabled_by_this_workflow'};
}
