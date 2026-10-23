import fs from 'node:fs';
import {requirePrivateFile,requirePrivateDirectory,writePrivateFile} from '../host/private-storage.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createDeployment,readDeployment,planDeployment,advanceDeployment,startDeploymentGateway,stopDeploymentGateway,controlDeploymentHostService,controlDeploymentService,inspectDeployment} from './core.mjs';
import {readOnboardingJourney,readOnboardingDiagnostics,publicAcceptance} from './journey.mjs';
function privateJson(file){if(!path.isAbsolute(file)||requirePrivateFile(file).size>1024*1024)throw Error('invalid_private_cli_input');return JSON.parse(fs.readFileSync(file,'utf8'));}
export async function main(args){
 const [cmd,...rest]=args;
 if(cmd==='linux-boot'&&rest.length===1){const {readDeploymentLinuxBoot}=await import('./linux-boot.mjs');return readDeploymentLinuxBoot(rest[0]);}
 if(cmd==='linux-session'&&rest.length===0){
  const {resolveLinuxDesktopSession}=await import('../host/linux-desktop.mjs');
  const {linuxUserManagerStatus}=await import('../host/linux-service.mjs');
  const session=resolveLinuxDesktopSession();
  return {schema:1,status:session.available?'session_observed':'unavailable',
   ...(session.available?{session:{id:session.id,type:session.type}}:{reason:session.reason}),
   computerUse:'not_verified',userManager:linuxUserManagerStatus()};
 }
 if(cmd==='browser-select'&&rest.length===3&&['chrome','msedge','auto'].includes(rest[1])&&rest[2]==='--authorize'){
  const {changeDeploymentCapabilities}=await import('./capabilities.mjs');
  return changeDeploymentCapabilities(rest[0],{authorize:true,browser:true,browserChannel:rest[1],persistLogin:true});
 }
 if(cmd==='foreground'&&rest.length===2&&rest[1]==='--authorize'){
  const api=await import('./core.mjs');let finish,requested=false;
  const done=new Promise(resolve=>{finish=resolve}),stop=()=>{requested=true;finish()},keepAlive=setInterval(()=>{},5000);
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
  try{
   await api.startDeploymentForeground(rest[0],{authorize:true});
   process.stderr.write('Styx foreground connection started. Keep this terminal open; Ctrl-C stops this process-owned connection.\n');
   if(!requested)await done;
  }finally{clearInterval(keepAlive);process.off('SIGINT',stop);process.off('SIGTERM',stop);await api.stopDeploymentForeground(rest[0]);await api.stopDeploymentGateway(rest[0]);}
  return {schema:1,status:'stopped',identityMutation:'NOT RUN',serviceMutation:'NOT RUN'};
 }
 // Tunnel credentials and executable pins enter only through private files.
 if(cmd==='tunnel-configure'&&rest.length===3&&rest[2]==='--authorize'){
  const {configureCliTunnel}=await import('./cli-tunnel.mjs');return configureCliTunnel(rest[0],rest[1],{authorize:true});
 }
 if(cmd==='tunnel-status'&&rest.length===1){const {readCliTunnel}=await import('./cli-tunnel.mjs');return readCliTunnel(rest[0]);}
 if(cmd==='tunnel-run'&&(rest.length===2&&rest[1]==='--authorize'||rest.length===3&&rest[2]==='--authorize')){
  const {runCliTunnel}=await import('./cli-tunnel.mjs');
  try{return await runCliTunnel(rest[0],rest.length===3?rest[1]:undefined,{authorize:true});}
  catch(error){if(['packaged_tunnel_client_unavailable','packaged_tunnel_client_invalid'].includes(error.message))return {schema:1,status:'blocked',reason:error.message,accountAcceptance:'NOT RUN'};throw error;}
 }
 if(cmd==='tunnel-service'&&[2,3].includes(rest.length)){
  const [stateDir,action,flag]=rest;
  if(!['install','status','start','stop','uninstall'].includes(action)||(flag!==undefined&&flag!=='--authorize')||(action!=='status'&&flag!=='--authorize'))throw Error('explicit_fixed_tunnel_service_authorization_required');
  const {controlLinuxTunnelService}=await import('./linux-tunnel-service.mjs');return controlLinuxTunnelService(stateDir,{action,authorize:flag==='--authorize'});
 }
 if(cmd==='app-lifecycle'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentAppLifecycle(rest[0]);}
 if(cmd==='app-login'&&rest.length===3&&['on','off'].includes(rest[1])&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.controlDeploymentAppLifecycle(rest[0],{authorize:true,action:'login',enabled:rest[1]==='on'});}
 if(cmd==='plugin'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentPlugin(rest[0]);}
 if(['plugin-profile','plugin-record'].includes(cmd)&&rest.length===3&&rest[2]==='--authorize'){
  const input=privateJson(rest[1]);const api=await import('./core.mjs');return api[cmd==='plugin-profile'?'setDeploymentPluginProfile':'recordDeploymentPluginAction'](rest[0],{...input,authorize:true});
 }
 if(cmd==='plugin-export'&&rest.length===3&&rest[2]==='--authorize'){
  const output=rest[1];if(!path.isAbsolute(output)||path.normalize(output)!==output||fs.existsSync(output)||path.extname(output)!=='.zip')throw Error('fresh_plugin_zip_output_required');requirePrivateDirectory(path.dirname(output));
  const api=await import('./core.mjs'),result=await api.exportDeploymentPlugin(rest[0],{authorize:true});writePrivateFile(output,result.archive);requirePrivateFile(output);
  return {schema:1,status:'exported_not_uploaded',file:output,sha256:result.sha256,verificationSource:result.verificationSource,accountInstallation:'NOT RUN',accountConnection:'NOT RUN'};
 }
 if(cmd==='browser'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentBrowser(rest[0]);}
 if(cmd==='browser-prepare'&&(rest.length===2&&rest[1]==='--authorize'||rest.length===3&&rest[1]==='--recover'&&rest[2]==='--authorize')){const api=await import('./core.mjs');return api.prepareDeploymentBrowser(rest[0],{authorize:true,...(rest.length===3?{recover:true}:{})});}
 if(cmd==='journey'&&rest.length===1)return readOnboardingJourney(rest[0]);
 if(cmd==='diagnostics'&&rest.length===1)return readOnboardingDiagnostics(rest[0]);
 if(cmd==='acceptance'&&rest.length===1){const api=await import('./core.mjs');return publicAcceptance(await api.readDeploymentAcceptance(rest[0]),{includeChallenge:true});}
 if(cmd==='acceptance-begin'&&rest.length===2&&rest[1]==='--authorize'){
  if(process.platform==='linux'){
   const {runLinuxDesktopAcceptance}=await import('./linux-desktop-acceptance.mjs');
   const result=await runLinuxDesktopAcceptance(rest[0],{authorize:true},{onChallenge:value=>{
    process.stdout.write(JSON.stringify(publicAcceptance(value,{includeChallenge:true}))+'\n');
    process.stderr.write('Keep this terminal open for the owned desktop acceptance window. Ctrl-C cancels; submit only after the chat observes the entered value.\n');
   }});
   if(!result.challenge){process.exitCode=2;return result;}
   return publicAcceptance(result,{includeChallenge:true});
  }
  const api=await import('./core.mjs');return publicAcceptance(await api.beginDeploymentAcceptance(rest[0],{authorize:true}),{includeChallenge:true});
 }
 if(cmd==='acceptance-confirm'&&rest.length===3&&rest[2]==='--authorize'){
  const input=privateJson(rest[1]);if(!input||Object.keys(input).some(k=>!['challengeId','observedInTargetChat'].includes(k))||input.observedInTargetChat!==true)throw Error('explicit_target_chat_confirmation_required');
  const api=await import('./core.mjs');return publicAcceptance(await api.confirmDeploymentAcceptance(rest[0],{...input,authorize:true}),{includeChallenge:true});
 }
 if(cmd==='onboarding-background-choice'&&rest.length===3&&['foreground','login'].includes(rest[1])&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.setDeploymentOnboardingPreference(rest[0],{background:rest[1],authorize:true});}
 if(cmd==='mac-signing-status'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentMacSigningRegistration(rest[0]);}
 if(cmd==='mac-signing-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planDeploymentMacSigningRegistration(rest[0],{app:privateJson(rest[1])});}
 if(cmd==='mac-signing-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyDeploymentMacSigningRegistration(rest[0],{authorize:true,plan:privateJson(rest[1])});}
 if(cmd==='mac-signing-rollback'&&rest.length===2&&rest[1]==='--authorize'){const api=await import('./core.mjs');return api.rollbackDeploymentMacSigningRegistration(rest[0],{authorize:true});}
 if(cmd==='handoff'&&rest.length===3&&rest[2]==='--authorize'){
  const output=rest[1];if(!path.isAbsolute(output)||path.normalize(output)!==output||fs.existsSync(output))throw Error('fresh_private_output_required');requirePrivateDirectory(path.dirname(output));
  const api=await import('./core.mjs'),handoff=await api.prepareDeploymentConnectionHandoff(rest[0],{authorize:true});
  writePrivateFile(output,JSON.stringify(handoff)+'\n');requirePrivateFile(output);
  return {schema:1,status:'prepared',privateHandoffFile:output,expiresAt:handoff.expiresAt,requiresTargetAccountAction:true};
 }
 if(cmd==='help'&&rest.length===0)return {schema:1,commands:['linux-boot STATE','join-recover STATE PRIVATE_PAIRING_JSON --authorize','join-rollback STATE TRANSACTION --authorize','tunnel-configure STATE PRIVATE_CONNECTION_JSON --authorize','tunnel-status STATE','tunnel-run STATE --authorize','tunnel-run STATE PRIVATE_CLIENT_JSON --authorize','tunnel-service STATE install|status|start|stop|uninstall [--authorize]','device-ingress-prepare STATE [EXACT_IPV4] --authorize','device-ingress-status STATE','device-ingress-recover STATE retry|rollback --authorize','pairing-close STATE --authorize','linux-session','browser-select STATE chrome|msedge|auto --authorize','mac-signing-status STATE','mac-signing-plan STATE PRIVATE_APP_JSON','mac-signing-apply STATE PRIVATE_PLAN --authorize','mac-signing-rollback STATE --authorize','app-lifecycle STATE','app-login STATE on|off --authorize','browser STATE','browser-prepare STATE [--recover] --authorize','plugin STATE','plugin-profile STATE PRIVATE_PROFILE_JSON --authorize','plugin-export STATE FRESH_ZIP --authorize','plugin-record STATE PRIVATE_ACTION_JSON --authorize','create CONFIG STATE','plan STATE','status STATE','inspect STATE','journey STATE','diagnostics STATE','onboarding-background-choice STATE foreground|login --authorize','handoff STATE PRIVATE_OUTPUT --authorize','acceptance STATE','acceptance-begin STATE --authorize','acceptance-confirm STATE PRIVATE_APPROVAL_JSON --authorize','advance STATE STEP...','resume STATE STEP...','local-setup STATE --approve-local-device','background STATE --authorize','foreground STATE --authorize','host-service STATE ACTION [--authorize]','gateway-service STATE ACTION [--authorize]','foreground-status STATE','ingress-change-plan STATE EXACT_IPV4','ingress-change-apply STATE PRIVATE_PLAN --authorize','ingress-change-rollback STATE TRANSACTION --authorize','device-ingress STATE','verify-ingress STATE HTTPS_ORIGIN','devices STATE','revoke-device STATE DEVICE --authorize','set-default STATE DEVICE --authorize','pending STATE --authorize','approve STATE PRIVATE_JSON --authorize','pairing-link STATE PRIVATE_OUTPUT --authorize','inspect-link PRIVATE_LINK','accept-link PRIVATE_LINK PRIVATE_APPROVAL_JSON --authorize','capabilities STATE [computer-on|computer-off|browser-on|browser-off --authorize]','capabilities-rollback STATE TRANSACTION --authorize','components STATE [PRIVATE_ARTIFACTS_JSON]','host-payload-handoff-prepare STATE --authorize','host-payload-handoff-execute STATE TICKET --authorize','host-payload-handoff-cancel STATE TICKET --authorize','host-payload-handoff-status STATE','host-publisher-transition-plan STATE BUNDLE PRIVATE_REVIEW_JSON','host-payload-plan STATE BUNDLE','host-payload-apply STATE PRIVATE_PLAN --authorize','host-payload-rollback STATE TRANSACTION --authorize','host-payload-status STATE','host-update-plan STATE BUNDLE','host-update-apply STATE PRIVATE_PLAN --authorize','host-update-recover STATE TRANSACTION --authorize','host-rollback-plan STATE','host-update-status STATE [TRANSACTION]','runtime-plan STATE BUNDLE','runtime-rollback-plan STATE','runtime-apply STATE PRIVATE_PLAN --authorize','runtime-change-status STATE','runtime-recover STATE TRANSACTION --authorize','native-migration-plan STATE TEAM_ID','native-migration-apply STATE PRIVATE_PLAN --authorize','native-migration-rollback STATE TRANSACTION --authorize','serve STATE']};
 if(cmd==='devices'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentDevices(rest[0]);}
 if(cmd==='revoke-device'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.revokeDeploymentDevice(rest[0],{deviceId:rest[1],authorize:true});}
 if(cmd==='set-default'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.setDeploymentDefault(rest[0],{deviceId:rest[1],authorize:true});}
 if(cmd==='pending'&&rest.length===2&&rest[1]==='--authorize'){const api=await import('./core.mjs');return api.listDeploymentPending(rest[0],{authorize:true});}
 if(cmd==='approve'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.approveDeploymentPending(rest[0],{...privateJson(rest[1]),authorize:true});}
 if(cmd==='pairing-link'&&rest.length===3&&rest[2]==='--authorize'){
  const output=rest[1];if(!path.isAbsolute(output)||path.normalize(output)!==output||fs.existsSync(output))throw Error('fresh_private_output_required');requirePrivateDirectory(path.dirname(output));
  const api=await import('./core.mjs');const {link,...summary}=await api.createDeploymentPairingLink(rest[0],{authorize:true});writePrivateFile(output,link+'\n');requirePrivateFile(output);return {...summary,privateLinkFile:output};
 }
 if(cmd==='inspect-link'&&rest.length===1){requirePrivateFile(rest[0]);if(fs.statSync(rest[0]).size>32768)throw Error('pairing_link_size_invalid');const {inspectPairingLink}=await import('./core.mjs');return inspectPairingLink(fs.readFileSync(rest[0],'utf8').trim());}
 if(cmd==='accept-link'&&rest.length===3&&rest[2]==='--authorize'){requirePrivateFile(rest[0]);if(fs.statSync(rest[0]).size>32768)throw Error('pairing_link_size_invalid');const {acceptPairingLink}=await import('./core.mjs');return acceptPairingLink(fs.readFileSync(rest[0],'utf8').trim(),privateJson(rest[1]));}
 if(cmd==='join-recover'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.recoverDeploymentJoin(rest[0],{authorize:true,pairingFile:rest[1]});}
 if(cmd==='join-rollback'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.rollbackDeploymentJoin(rest[0],{authorize:true,transactionId:rest[1]});}
 if(cmd==='create'&&rest.length===2)return createDeployment(rest[0],{stateDir:rest[1]});
 if(cmd==='status'&&rest.length===1)return readDeployment(rest[0]);
 if(cmd==='components'&&[1,2].includes(rest.length)){const {readDeploymentComponents}=await import('./core.mjs');return readDeploymentComponents(rest[0],rest[1]?{artifacts:privateJson(rest[1])}:{});}
 if(cmd==='host-payload-handoff-prepare'&&rest.length===2&&rest[1]==='--authorize'){const api=await import('./core.mjs');return api.prepareHostPayloadHandoff({stateDir:rest[0],authorize:true});}
 if(['host-payload-handoff-execute','host-payload-handoff-cancel'].includes(cmd)&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api[cmd.endsWith('-execute')?'executeHostPayloadHandoff':'cancelHostPayloadHandoff']({stateDir:rest[0],ticketId:rest[1],authorize:true});}
 if(cmd==='host-payload-handoff-status'&&rest.length===1){const api=await import('./core.mjs');return api.readHostPayloadHandoff({stateDir:rest[0]});}
 if(cmd==='host-publisher-transition-plan'&&rest.length===3){const api=await import('./core.mjs');return api.planHostPublisherTransition({stateDir:rest[0],bundle:rest[1],publisherReview:privateJson(rest[2])});}
 if(cmd==='host-payload-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planHostPayloadMigration({stateDir:rest[0],bundle:rest[1]});}
 if(cmd==='host-payload-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyHostPayloadMigration({stateDir:rest[0],plan:privateJson(rest[1]),authorize:true});}
 if(cmd==='host-payload-rollback'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.rollbackHostPayloadMigration({stateDir:rest[0],transactionId:rest[1],authorize:true});}
 if(cmd==='host-payload-status'&&rest.length===1){const api=await import('./core.mjs');return api.readHostPayloadMigration({stateDir:rest[0]});}
 if(cmd==='host-update-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planHostUpdate({stateDir:rest[0],bundle:rest[1]});}
 if(cmd==='host-rollback-plan'&&rest.length===1){const api=await import('./core.mjs');return api.planHostUpdate({stateDir:rest[0],rollback:true});}
 if(cmd==='host-update-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyHostUpdate({stateDir:rest[0],plan:privateJson(rest[1]),authorize:true});}
 if(cmd==='host-update-recover'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.recoverHostUpdate({stateDir:rest[0],transactionId:rest[1],authorize:true});}
 if(cmd==='host-update-status'&&[1,2].includes(rest.length)){const api=await import('./core.mjs');return api.readHostUpdate({stateDir:rest[0],...(rest[1]?{transactionId:rest[1]}:{})});}
 if(cmd==='runtime-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planGatewayRuntimeChange({stateDir:rest[0],bundle:rest[1]});}
 if(cmd==='runtime-rollback-plan'&&rest.length===1){const api=await import('./core.mjs');return api.planGatewayRuntimeChange({stateDir:rest[0],rollback:true});}
 if(cmd==='runtime-change-status'&&rest.length===1){const api=await import('./core.mjs');return api.readGatewayRuntimeChange({stateDir:rest[0]});}
 if(cmd==='runtime-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyGatewayRuntimeChange({stateDir:rest[0],plan:privateJson(rest[1]),authorize:true});}
 if(cmd==='runtime-recover'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.recoverGatewayRuntimeChange({stateDir:rest[0],transactionId:rest[1],authorize:true});}
 if(cmd==='native-migration-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planNativeSupervisorMigration(rest[0],{nativeApp:{path:'/Applications/Styx.app',teamID:rest[1]}});}
 if(cmd==='native-migration-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyNativeSupervisorMigration(rest[0],{plan:privateJson(rest[1]),authorize:true});}
 if(cmd==='native-migration-rollback'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.rollbackNativeSupervisorMigration(rest[0],{transactionId:rest[1],authorize:true});}
 if(cmd==='foreground-status'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentForeground(rest[0]);}
 if(cmd==='ingress-change-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planDeviceIngressChange(rest[0],{listenHost:rest[1]});}
 if(cmd==='ingress-change-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyDeviceIngressChange(rest[0],{plan:privateJson(rest[1]),authorize:true});}
 if(cmd==='ingress-change-rollback'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.rollbackDeviceIngressChange(rest[0],{transactionId:rest[1],authorize:true});}
 if(cmd==='device-ingress-prepare'&&[2,3].includes(rest.length)&&rest.at(-1)==='--authorize'){const api=await import('./core.mjs');return api.prepareDeploymentDeviceIngress(rest[0],{authorize:true,...(rest.length===3?{listenHost:rest[1]}:{})});}
 if(cmd==='device-ingress-status'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentDeviceIngressSetup(rest[0]);}
 if(cmd==='device-ingress-recover'&&rest.length===3&&rest[2]==='--authorize'&&['retry','rollback'].includes(rest[1])){const api=await import('./core.mjs');return api.recoverDeploymentDeviceIngress(rest[0],{authorize:true,action:rest[1]});}
 if(cmd==='pairing-close'&&rest.length===2&&rest[1]==='--authorize'){const api=await import('./core.mjs');return api.closeDeploymentPairingWindow(rest[0],{authorize:true});}
 if(cmd==='device-ingress'&&rest.length===1){const {planDeviceIngress}=await import('./core.mjs');return planDeviceIngress(rest[0]);}
 if(cmd==='verify-ingress'&&rest.length===2){const {verifyDeviceIngress}=await import('./core.mjs');return verifyDeviceIngress(rest[0],{url:rest[1]});}
 if(cmd==='inspect'&&rest.length===1)return inspectDeployment(rest[0]);
 if(cmd==='background'&&rest.length===2&&rest[1]==='--authorize'){const {enableDeploymentBackground}=await import('./background.mjs');return enableDeploymentBackground(rest[0],{authorize:true});}
 if(cmd==='local-setup'&&rest.length===2&&rest[1]==='--approve-local-device'){const api=await import('./core.mjs');const {completeLocalSetup}=await import('./local-setup.mjs');return completeLocalSetup(api,rest[0],{approve:true,...planDeployment(rest[0]).ownerPairingScope});}
 if(cmd==='capabilities-rollback'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.rollbackDeploymentCapabilities(rest[0],{transactionId:rest[1],authorize:true});}
 if(cmd==='capabilities'&&rest.length===1){const {readDeploymentCapabilities}=await import('./capabilities.mjs');return readDeploymentCapabilities(rest[0]);}
 if(cmd==='capabilities'&&rest.length===3&&['computer-on','computer-off','browser-on','browser-off'].includes(rest[1])&&rest[2]==='--authorize'){const {changeDeploymentCapabilities}=await import('./capabilities.mjs');return changeDeploymentCapabilities(rest[0],{[rest[1].startsWith('browser-')?'browser':'computer']:rest[1].endsWith('-on'),authorize:true});}
 if(cmd==='plan'&&rest.length===1)return planDeployment(rest[0]);
 if(['advance','resume'].includes(cmd)&&rest.length>=2){
  const approve=rest.includes('--approve-local-device');
  if(rest.filter(x=>x==='--approve-local-device').length>1)throw Error('duplicate_owner_approval_flag');
  const authorize=rest.slice(1).filter(x=>x!=='--approve-local-device');
  if(approve&&!authorize.includes('host.pair'))throw Error('owner_approval_requires_host_pair_step');
  const ownerApproval=approve?{approve:true,...planDeployment(rest[0]).ownerPairingScope}:undefined;
  return advanceDeployment(rest[0],{authorize,ownerApproval});
 }
 if(['host-service','gateway-service'].includes(cmd)&&[2,3].includes(rest.length)){
  const [stateDir,action,flag]=rest;
  const allowed=cmd==='host-service'?['install','status','start','stop']:['install','status','start','stop','enable','disable','uninstall'];
  if(!allowed.includes(action)||(flag!==undefined&&flag!=='--authorize')||(action!=='status'&&flag!=='--authorize'))throw Error('explicit_fixed_service_authorization_required');
  if(cmd==='host-service')return controlDeploymentHostService(stateDir,{action,authorize:true});
  return controlDeploymentService(stateDir,{role:'gateway',action,authorize:flag==='--authorize'});
 }
 if(cmd==='mac-login-recovery'&&[2,3].includes(rest.length)){
  const [configFile,action,flag]=rest;
  if(flag!==undefined&&flag!=='--authorize')throw Error('invalid_authorization_flag');
  const fs=await import('node:fs');const {requirePrivateFile}=await import('../host/private-storage.mjs');requirePrivateFile(configFile);
  const {controlMacLoginRecovery}=await import('./macos-login-recovery.mjs');
  return controlMacLoginRecovery(JSON.parse(fs.readFileSync(configFile,'utf8')),{action,authorize:flag==='--authorize'});
 }
 if(cmd==='serve'&&rest.length===1){const r=await startDeploymentGateway(rest[0]);for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>stopDeploymentGateway(rest[0]).then(()=>process.exit(0)));return r;}
 throw Error('usage_create_CONFIG_STATE_or_status_plan_STATE_or_advance_resume_STATE_STEP_or_serve_STATE');
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=await main(process.argv.slice(2));console.log(JSON.stringify(result,null,2));if(['blocked','uncertain','needs_attention','not_implemented','recovery_required','needs_recovery','needs_reconciliation'].includes(result.status)||result.steps?.some(s=>['blocked','uncertain'].includes(s.status)))process.exitCode=2;}
 catch{console.error('Styx onboarding failed. Inspect private state locally; no secret or raw command output is printed.');process.exitCode=2;}
}
