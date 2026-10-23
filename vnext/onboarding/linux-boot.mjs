// Read-only deployment projection. Linger is OS policy, never another role config.
import {linuxUserManagerStatus} from '../host/linux-service.mjs';

export async function readDeploymentLinuxBoot(stateDir,operations={}){
 if(process.platform!=='linux')return {schema:1,status:'not_applicable',reason:'linux_only'};
 const {observeDeploymentBackground}=await import('./background.mjs');
 const observed=await observeDeploymentBackground(stateDir,operations);
 return observed.linuxBoot;
}

export function projectLinuxBoot(stateDir,deployment,observed,{manager=linuxUserManagerStatus(),uid=process.getuid()}={}){
 const roles={};const plan=[];
 for(const [role,requested] of [['gateway',deployment.mode==='create-local'],['host',deployment.roles?.host!=='disabled']]){
  if(!requested){roles[role]={startup:'not_applicable'};continue;}
  const state=observed[role],persistence=observed[role+'Persistence'];
  const startup=state==='not_installed'?'not_installed':!['running','not_running'].includes(state)?'unknown':persistence==='disabled'?'disabled':persistence==='enabled'?'configured_unverified':'unknown';
  roles[role]={startup,currentProcess:state??'unknown',toolHealth:'not_checked'};
  // Never turn an unknown/mismatched service into a proposed installation.
  // Commands remain explicit existing Core actions; nothing is applied here.
  if(startup==='not_installed')plan.push({kind:'core',command:[role+'-service',stateDir,'install','--authorize'],condition:'complete_role_preparation_first',effect:'install_owned_user_service',recovery:[role+'-service',stateDir,'stop','--authorize'],recoveryEffect:'stop_and_disable_preserving_installed_service_and_identity'});
  if(['not_installed','disabled'].includes(startup))plan.push({kind:'core',command:[role+'-service',stateDir,'start','--authorize'],condition:'explicitly_choose_background_startup',effect:'enable_and_start_owned_user_service',rollback:[role+'-service',stateDir,'stop','--authorize']});
 }
 const linger=manager.systemBootWithoutLogin==='configured'?'enabled':manager.systemBootWithoutLogin==='not_configured'?'disabled':'unknown';
 if(linger==='disabled')plan.unshift({kind:'os_policy',command:['loginctl','enable-linger',String(uid)],effect:'keep_this_users_service_manager_running_without_login',scope:'all_services_of_this_user',authorization:'system_policy_may_require_administrator',rollback:['loginctl','disable-linger',String(uid)],rollbackCondition:'only_if_enabled_by_this_operation_and_no_other_service_relies_on_it'});
 const requested=Object.values(roles).filter(r=>r.startup!=='not_applicable');
 const missing=linger==='disabled'||requested.some(r=>['not_installed','disabled'].includes(r.startup));
 const unknown=linger==='unknown'||requested.some(r=>r.startup==='unknown');
 return {schema:1,status:missing?'not_configured':unknown?'unknown':'configured_unverified',
  scope:'owning_user_systemd_services',linger,roles,plan,
  desktop:{computerUse:'requires_active_unlocked_graphical_session',headedBrowser:'requires_graphical_session',headlessBrowser:'independent_of_graphical_session_not_verified_here'},
  remainingChecks:['home_and_runtime_paths_available_before_login','network_and_credentials_available','real_logout_and_reboot_acceptance'],
  physicalPreloginAcceptance:'NOT RUN',accountAcceptance:'NOT RUN',mutation:'NOT RUN'};
}
