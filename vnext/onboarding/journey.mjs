// Read-only onboarding projection. Configuration, process observations, MCP proof
// and the owner's account attestation remain distinct sources of evidence.
import fs from 'node:fs';
import path from 'node:path';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
import {observeDeploymentBackground} from './background.mjs';
import {readDeploymentCapabilities} from './capabilities.mjs';

export const ONBOARDING_LINKS=Object.freeze({platformTunnels:'https://platform.openai.com/settings/organization/tunnels',chatgpt:'https://chatgpt.com/plugins',tunnelGuide:'https://developers.openai.com/api/docs/guides/secure-mcp-tunnels'});
const choose=(v,allowed,fallback)=>allowed.includes(v)?v:fallback;
const LOCAL=new Set(['gateway.runtime.prepare','gateway.prepare','gateway.start','gateway.verify','host.prepare','host.pair','host.invite','host.request','host.claim','host.doctor']);
const step=(id,status,reason,nextAction='none')=>({id,status,reason,nextAction});

// This observer deliberately cannot claim ownership of another App's child.
// In particular a lock file or configured autoStart is not a live connection.
export function readOnboardingTunnel(stateDir){
 const root=path.join(stateDir,'tunnel'),file=path.join(root,'connection.json');
 if(!fs.existsSync(root))return {status:'not_configured',transport:'not_observed',observation:'configuration_only'};
 try{
  requirePrivateDirectory(root);
  if(!fs.existsSync(file))return {status:'not_configured',transport:'not_observed',observation:'configuration_only'};
  if(requirePrivateFile(file).size>65536)throw Error('invalid_tunnel_state');
  const value=JSON.parse(fs.readFileSync(file,'utf8'));
  if(value.schema!==1||typeof value.autoStart!=='boolean'||!/^tunnel_[A-Za-z0-9_-]{8,128}$/.test(value.tunnelId)||!/^key-[a-f0-9]{32}$/.test(value.keyFile))throw Error('invalid_tunnel_state');
  requirePrivateFile(path.join(root,value.keyFile));
  return {status:'configured',transport:'not_observed',observation:'configuration_only'};
 }catch{return {status:'unknown',transport:'not_observed',observation:'configuration_only'}}
}

// Acceptance endpoints may carry a safe, fixed challenge. Journey/diagnostics
// never carry it, nor the connection credential, raw config or raw error text.
export function publicAcceptance(value,{includeChallenge=false}={}){
 const proof=value?.requestProof?.status==='verified',confirmed=value?.targetChatConfirmation?.status==='user_confirmed';
 const desktop=choose(value?.desktop?.status,['not_required','pending','verified'],'pending');
 const complete=proof&&confirmed&&['verified','not_required'].includes(desktop)&&value?.complete===true;
 const out={schema:1,status:choose(value?.status,['not_started','acceptance_expired','acceptance_context_changed','awaiting_chat_request','request_observed','user_confirmed_with_mcp_evidence'],'unavailable'),
  requestProof:{status:proof?'verified':'pending',source:proof?'authenticated_mcp_exec_result':'not_observed'},
  targetChatConfirmation:{status:confirmed?'user_confirmed':'pending',source:confirmed?'user_attested':'not_recorded',providerIdentity:'not_verified'},desktop:{status:desktop},complete};
 if(includeChallenge){
  const c=value?.challenge;
  // Only the Core's scoped, fixed challenge is accepted here; no raw evidence.
  out.challenge=c&&/^[a-f0-9]{32}$/.test(c.id??'')&&Number.isSafeInteger(c.expiresAt)&&typeof c.prompt==='string'&&c.prompt.length<8192&&typeof c.command==='string'&&c.command.length<2048&&typeof c.environmentId==='string'&&/^[A-Za-z0-9_.-]{1,160}$/.test(c.environmentId)?{id:c.id,expiresAt:c.expiresAt,prompt:c.prompt,command:c.command,environmentId:c.environmentId,...(/^STYX_GUI_[a-f0-9]{32}$/.test(c.desktopValue??'')?{desktopValue:c.desktopValue}:{})}:null;
 }
 return out;
}
export function publicConnectionHandoff(value){return {status:value?.status==='available'?'available':'unavailable',authentication:'bearer',credentialAvailable:value?.credentialAvailable===true,requiresTargetAccountAction:true};}

export function projectOnboardingJourney({deployment,background,foreground,capabilities,tunnel,acceptance,connectionHandoff,preference,permissionObservation,plugin,deploymentUnavailable=false}={}){
 const joined=deployment?.mode==='join-existing',local=deployment?.mode==='create-local';
 const roles=deployment?.roles??{},hasHost=roles.host==='local';
 // A capability change edits enrolled Host/Gateway capabilities, preserving the
 // original deployment. Its requested intent is not an OS grant or readiness.
 const changedComputer=capabilities?.status==='updated'&&capabilities?.phase==='complete'&&typeof capabilities.computer==='boolean'?capabilities.computer:['running','uncertain'].includes(capabilities?.status)&&typeof capabilities.requestedComputer==='boolean'?capabilities.requestedComputer:null;
 const desktopRequested=hasHost&&(changedComputer??roles.computer==='requested');
 const localSteps=(deployment?.steps??[]).filter(s=>LOCAL.has(s.id));
 const prepared=!!deployment&&localSteps.length>0&&localSteps.every(s=>s.status==='succeeded');
 const uncertain=localSteps.some(s=>['failed','uncertain','blocked'].includes(s.status));
 const current=background?.observation==='current';
 const f={status:choose(foreground?.status,['started','connected','using_service','stopping','needs_attention','not_running'],'not_running'),observation:'current_process',execConnection:choose(foreground?.execConnection,['connected','connecting','disconnected','not_connected','not_observed','not_required'],'not_observed'),desktopConnection:choose(foreground?.desktopConnection,['connected','connecting','disconnected','not_observed','not_requested','session_unavailable_or_unobserved'],'not_observed'),toolHealth:'not_verified'};
 const foregroundReady=f.status==='connected'&&f.execConnection==='connected'||!hasHost&&f.status==='started';
 const exec=current&&background.hostConnection==='exec_connected'||foregroundReady&&hasHost?'connected':localSteps.some(s=>s.id==='host.doctor'&&s.status==='succeeded')?'preflight_passed':hasHost?'not_ready':'not_requested';
 const a=publicAcceptance(acceptance),handoff=publicConnectionHandoff(connectionHandoff);
 const pluginState=plugin?{required:plugin.required===true,profileSaved:plugin.profileSaved===true,mode:plugin.selection?.mode==='reuse'?'reuse':'create',exportStatus:choose(plugin.export?.status,['not_exported','exported','stale'],'not_exported'),upload:plugin.accountActions?.upload==='user_confirmed'?'user_confirmed':'not_observed',installation:plugin.accountActions?.installation==='user_confirmed'?'user_confirmed':'not_observed',providerIdentity:'not_verified'}:null;
 const pluginReady=!pluginState||pluginState.required===false||pluginState.profileSaved&&pluginState.installation==='user_confirmed';
 const sessionUnavailable=current&&['session_unavailable','no_interactive_session'].includes(background.desktop)||['started','connected'].includes(f.status)&&f.desktopConnection==='session_unavailable_or_unobserved';
 const currentNativeDesktopGrants=permissionObservation?.source==='current_native_app_preflight'&&permissionObservation.accessibility==='granted'&&permissionObservation.screenRecording==='granted';
 const currentDesktopConnection=['started','connected'].includes(f.status)&&f.desktopConnection==='connected'||current&&background.desktop==='running';
 const desktop=!desktopRequested?'not_requested':sessionUnavailable?'session_unavailable':a.desktop.status==='verified'&&currentNativeDesktopGrants&&currentDesktopConnection?'verified':'not_verified';
 const p=preference?.configurationBound===true?choose(preference.background,['foreground','login'],'not_decided'):'not_decided';
 const loginReady=current&&background.status==='running'&&(!hasHost||background.host==='running')&&(!local||background.gateway==='running')&&(!hasHost||!local||background.hostConnection==='exec_connected');
 const b={status:current?background.status==='running'&&!loginReady?'needs_attention':choose(background.status,['running','needs_attention','not_configured','unknown'],'unknown'):'not_observed',observation:current?'current':'not_observed',preference:p,startup:'current_user_login',systemBootWithoutLogin:'not_configured',appExit:p==='foreground'?'connection_may_stop':'not_verified'};
 const t={status:choose(tunnel?.status,['running','configured','not_configured','interrupted','unknown'],'not_configured'),transport:choose(tunnel?.transport,['ready','starting','unavailable','not_running','not_observed'],'not_observed'),observation:tunnel?.observation==='configuration_only'?'configuration_only':'current_app'};
 const nativePermission=key=>!desktopRequested?'not_required':permissionObservation?.source==='current_native_app_preflight'?choose(permissionObservation[key],['granted','denied'],'not_observed'):'not_observed';
 const permissions=[{id:'accessibility',label:'辅助功能',status:nativePermission('accessibility')},{id:'screen_recording',label:'屏幕录制',status:nativePermission('screenRecording')},{id:'automation',label:'应用脚本自动化',status:'not_required',reason:'explicit_app_scripts_may_require_separate_authorization'}];
 const permissionsGranted=permissions.slice(0,2).every(p=>p.status==='granted');
 const permissionsDenied=permissions.some(p=>p.status==='denied');
 const steps=[];
 steps.push(step('local_setup',deploymentUnavailable?'blocked':!deployment?'active':uncertain?'needs_attention':prepared?'completed':'active',deploymentUnavailable?'deployment_unavailable':!deployment?'deployment_not_created':uncertain?'local_step_requires_reconciliation':prepared?'local_preparation_complete':'local_preparation_incomplete',deploymentUnavailable||uncertain?'inspect_local_state':!deployment?'create_local_setup':prepared?'none':'complete_local_setup'));
 // A successful desktop challenge is historical execution evidence, not a
 // fresh AX/Screen Recording query. Only the separate current native hook counts.
 steps.push(step('system_permissions',!desktopRequested?'not_required':sessionUnavailable?'blocked':permissionsGranted?'completed':'pending',!desktopRequested?'desktop_not_requested':sessionUnavailable?'interactive_session_unavailable':permissionsGranted?'native_permission_preflight_granted_desktop_test_separate':permissionsDenied?'native_permissions_require_user_authorization_and_restart':'permissions_native_state_not_observed',desktopRequested&&!permissionsGranted?'review_system_permissions':'none'));
 steps.push(step('background',!deployment?'pending':p==='foreground'?foregroundReady?'completed':f.status==='needs_attention'?'needs_attention':f.status==='started'?'active':'pending':p==='login'&&b.status==='running'?'completed':p==='login'?'needs_attention':'pending',p==='foreground'?foregroundReady?'app_must_remain_open_connection_may_stop_on_exit':f.status==='needs_attention'?'foreground_requires_reconciliation':f.status==='started'?'foreground_connection_starting':'foreground_connection_required':p==='login'&&b.status==='running'?'login_components_currently_running':p==='login'?'login_components_not_confirmed_running':'background_choice_required',p==='foreground'?foregroundReady?'continue_with_app_open':f.status==='needs_attention'?'inspect_local_state':'start_deployment_foreground':p==='login'&&b.status!=='running'?'enable_login_background':p==='not_decided'?'choose_background_preference':'none'));
 if(joined){for(const id of ['external_entry','chat_connection','chat_request_proof','target_chat_confirmation'])steps.push(step(id,'not_required','handoff_on_gateway_owner','return_to_gateway_owner'));}
 else{
  const ownerSupported=!deployment||local&&hasHost;
  steps.push(step('external_entry',!ownerSupported?'blocked':t.transport==='ready'?'completed':t.status==='not_configured'?'pending':t.status==='interrupted'?'needs_attention':'active',!ownerSupported?'owned_gateway_and_host_required':t.transport==='ready'?'local_tunnel_transport_ready_account_association_unverified':t.status==='not_configured'?'platform_tunnel_and_runtime_permission_required':'tunnel_transport_not_ready',!ownerSupported?'inspect_local_state':t.transport==='ready'?'none':t.status==='not_configured'?'configure_platform_tunnel':t.status==='unknown'?'inspect_local_state':t.observation==='configuration_only'?'observe_tunnel_in_app':'start_tunnel'));
  steps.push(step('chat_connection',!ownerSupported?'blocked':a.requestProof.status==='verified'&&pluginReady?'completed':'pending',!ownerSupported?'owned_gateway_and_host_required':!pluginReady?'plugin_profile_export_and_account_installation_required':a.requestProof.status==='verified'?'authenticated_mcp_request_observed_provider_identity_unverified':'target_workspace_plugin_and_authentication_require_user_action',!ownerSupported?'inspect_local_state':a.requestProof.status==='verified'&&pluginReady?'none':!pluginReady?'configure_or_reuse_plugin':handoff.status==='available'?'prepare_connection_handoff':'add_chatgpt_plugin'));
  steps.push(step('chat_request_proof',!ownerSupported?'blocked':a.requestProof.status==='verified'&&['verified','not_required'].includes(a.desktop.status)?'completed':'pending',!ownerSupported?'owned_gateway_and_host_required':a.requestProof.status==='verified'&&a.desktop.status==='pending'?'desktop_mcp_readback_pending':a.requestProof.status==='verified'?'mcp_exec_result_observed':'actual_target_chat_mcp_request_required',!ownerSupported?'inspect_local_state':a.requestProof.status==='verified'&&['verified','not_required'].includes(a.desktop.status)?'none':a.status==='not_started'||a.status==='unavailable'||a.status.startsWith('acceptance_')?'begin_chat_acceptance':'run_acceptance_in_target_chat'));
  steps.push(step('target_chat_confirmation',!ownerSupported?'blocked':a.complete?'completed':'pending',!ownerSupported?'owned_gateway_and_host_required':a.complete?'user_attested_with_mcp_evidence_provider_identity_unverified':'separate_owner_confirmation_after_real_chat_test_required',!ownerSupported?'inspect_local_state':a.complete?'none':a.requestProof.status==='verified'&&['verified','not_required'].includes(a.desktop.status)?'confirm_target_chat':'run_acceptance_in_target_chat'));
 }
 const incomplete=steps.find(s=>!['completed','not_required'].includes(s.status));
 const issues=steps.filter(s=>['blocked','needs_attention'].includes(s.status)).map(s=>s.reason);
 return {schema:1,status:issues.length?'needs_attention':!incomplete?'complete':'awaiting_user',currentStep:incomplete?.id??null,steps,readiness:{exec:{status:exec,reason:exec==='connected'?'authenticated_exec_lane_observed_not_command_health':exec==='preflight_passed'?'historical_host_doctor_not_live_health':'exec_readiness_not_verified'},desktop:{status:desktop,reason:desktop==='verified'?'actual_mcp_cua_and_local_readback':desktop==='session_unavailable'?'interactive_session_unavailable':desktop==='not_requested'?'desktop_not_requested':a.desktop.status==='verified'?'historical_desktop_proof_not_current_readiness':'desktop_observation_and_operation_not_verified'}},permissions,permissionObservation:{source:permissionObservation?.source==='current_native_app_preflight'?'current_native_app_preflight':'not_observed',tccResponsibility:'NOT RUN'},background:b,foreground:f,tunnel:t,connectionHandoff:handoff,plugin:pluginState,acceptance:a,account:{status:a.complete?'user_attested_with_mcp_evidence':'not_verified',providerIdentity:'not_verified'},externalAccount:{requiresPlatformTunnelPermission:!joined,requiresTargetWorkspaceAssociation:!joined,requiresPluginSetup:!joined,browser:'reuse_existing_login_or_sign_in',automaticOAuthCallback:false,links:ONBOARDING_LINKS},diagnostics:{canRetry:!deploymentUnavailable&&!uncertain,reason:issues[0]??(incomplete?'user_action_or_observation_required':'completed_with_user_attestation')}};
}

export async function readOnboardingJourney(stateDir,{core,backgroundRead=observeDeploymentBackground,tunnelRead=readOnboardingTunnel}={}){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir)||path.normalize(stateDir)!==stateDir)throw Error('absolute_state_directory_required');
 const api=core??await import('./core.mjs');
 let deployment,deploymentUnavailable=false;
 try{deployment=await api.readDeployment(stateDir)}catch{deploymentUnavailable=fs.existsSync(stateDir)}
 const observe=async fn=>{try{return await fn()}catch{return null}};
 // Missing deployment cannot authorize process probes or create local state.
 const background=deployment?await observe(()=>backgroundRead(stateDir)):null;
 const tunnel=deployment?(await observe(()=>tunnelRead(stateDir))??{status:'unknown',transport:'not_observed'}):null;
 const acceptance=deployment&&typeof api.readDeploymentAcceptance==='function'?await observe(()=>api.readDeploymentAcceptance(stateDir)):null;
 const connectionHandoff=deployment&&typeof api.readDeploymentConnectionHandoff==='function'?await observe(()=>api.readDeploymentConnectionHandoff(stateDir)):null;
 const preference=deployment&&typeof api.readDeploymentOnboardingPreference==='function'?await observe(()=>api.readDeploymentOnboardingPreference(stateDir)):null;
 const permissionObservation=deployment&&typeof api.readDeploymentPermissions==='function'?await observe(()=>api.readDeploymentPermissions(stateDir)):null;
 const foreground=deployment&&typeof api.readDeploymentForeground==='function'?await observe(()=>api.readDeploymentForeground(stateDir)):null;
 const capabilities=deployment?await observe(()=>readDeploymentCapabilities(stateDir)):null;
 const plugin=deployment&&typeof api.readDeploymentPlugin==='function'?(await observe(()=>api.readDeploymentPlugin(stateDir))??{required:deployment.mode!=='join-existing',profileSaved:false}):null;
 return projectOnboardingJourney({deployment,background,foreground,capabilities,tunnel,acceptance,connectionHandoff,preference,permissionObservation,plugin,deploymentUnavailable});
}
export async function readOnboardingDiagnostics(stateDir,options){
 const j=await readOnboardingJourney(stateDir,options);
 return {schema:1,status:j.status,readOnly:true,checks:j.steps.map(({id,status,reason,nextAction})=>({id,status,reason,nextAction})),readiness:j.readiness,permissions:j.permissions,permissionObservation:j.permissionObservation,background:j.background,foreground:j.foreground,tunnel:j.tunnel,plugin:j.plugin,acceptance:j.acceptance,account:j.account,canRetry:j.diagnostics.canRetry,reason:j.diagnostics.reason};
}
