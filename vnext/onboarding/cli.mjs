import fs from 'node:fs';
import {requirePrivateFile,requirePrivateDirectory} from '../host/private-storage.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createDeployment,readDeployment,planDeployment,advanceDeployment,startDeploymentGateway,stopDeploymentGateway,controlDeploymentHostService,controlDeploymentService,inspectDeployment} from './core.mjs';
function privateJson(file){if(!path.isAbsolute(file)||requirePrivateFile(file).size>1024*1024)throw Error('invalid_private_cli_input');return JSON.parse(fs.readFileSync(file,'utf8'));}
export async function main(args){
 const [cmd,...rest]=args;
 if(cmd==='help'&&rest.length===0)return {schema:1,commands:['create CONFIG STATE','plan STATE','status STATE','inspect STATE','advance STATE STEP...','resume STATE STEP...','local-setup STATE --approve-local-device','background STATE --authorize','host-service STATE ACTION [--authorize]','gateway-service STATE ACTION [--authorize]','device-ingress STATE','verify-ingress STATE HTTPS_ORIGIN','devices STATE','set-default STATE DEVICE --authorize','pending STATE --authorize','approve STATE PRIVATE_JSON --authorize','pairing-link STATE PRIVATE_OUTPUT --authorize','inspect-link PRIVATE_LINK','accept-link PRIVATE_LINK PRIVATE_APPROVAL_JSON --authorize','capabilities STATE [computer-on|computer-off --authorize]','host-update-plan STATE BUNDLE','host-rollback-plan STATE','host-update-status STATE [TRANSACTION]','runtime-plan STATE BUNDLE','runtime-rollback-plan STATE','runtime-apply STATE PRIVATE_PLAN --authorize','runtime-change-status STATE','runtime-recover STATE TRANSACTION --authorize','native-migration-plan STATE TEAM_ID','native-migration-apply STATE PRIVATE_PLAN --authorize','native-migration-rollback STATE TRANSACTION --authorize','serve STATE']};
 if(cmd==='devices'&&rest.length===1){const api=await import('./core.mjs');return api.readDeploymentDevices(rest[0]);}
 if(cmd==='set-default'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.setDeploymentDefault(rest[0],{deviceId:rest[1],authorize:true});}
 if(cmd==='pending'&&rest.length===2&&rest[1]==='--authorize'){const api=await import('./core.mjs');return api.listDeploymentPending(rest[0],{authorize:true});}
 if(cmd==='approve'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.approveDeploymentPending(rest[0],{...privateJson(rest[1]),authorize:true});}
 if(cmd==='pairing-link'&&rest.length===3&&rest[2]==='--authorize'){
  const output=rest[1];if(!path.isAbsolute(output)||path.normalize(output)!==output||fs.existsSync(output))throw Error('fresh_private_output_required');requirePrivateDirectory(path.dirname(output));
  const api=await import('./core.mjs');const {link,...summary}=await api.createDeploymentPairingLink(rest[0],{authorize:true});fs.writeFileSync(output,link+'\n',{flag:'wx',mode:0o600});requirePrivateFile(output);return {...summary,privateLinkFile:output};
 }
 if(cmd==='inspect-link'&&rest.length===1){requirePrivateFile(rest[0]);if(fs.statSync(rest[0]).size>32768)throw Error('pairing_link_size_invalid');const {inspectPairingLink}=await import('./core.mjs');return inspectPairingLink(fs.readFileSync(rest[0],'utf8').trim());}
 if(cmd==='accept-link'&&rest.length===3&&rest[2]==='--authorize'){requirePrivateFile(rest[0]);if(fs.statSync(rest[0]).size>32768)throw Error('pairing_link_size_invalid');const {acceptPairingLink}=await import('./core.mjs');return acceptPairingLink(fs.readFileSync(rest[0],'utf8').trim(),privateJson(rest[1]));}
 if(cmd==='create'&&rest.length===2)return createDeployment(rest[0],{stateDir:rest[1]});
 if(cmd==='status'&&rest.length===1)return readDeployment(rest[0]);
 if(cmd==='host-update-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planHostUpdate({stateDir:rest[0],bundle:rest[1]});}
 if(cmd==='host-rollback-plan'&&rest.length===1){const api=await import('./core.mjs');return api.planHostUpdate({stateDir:rest[0],rollback:true});}
 if(cmd==='host-update-status'&&[1,2].includes(rest.length)){const api=await import('./core.mjs');return api.readHostUpdate({stateDir:rest[0],...(rest[1]?{transactionId:rest[1]}:{})});}
 if(cmd==='runtime-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planGatewayRuntimeChange({stateDir:rest[0],bundle:rest[1]});}
 if(cmd==='runtime-rollback-plan'&&rest.length===1){const api=await import('./core.mjs');return api.planGatewayRuntimeChange({stateDir:rest[0],rollback:true});}
 if(cmd==='runtime-change-status'&&rest.length===1){const api=await import('./core.mjs');return api.readGatewayRuntimeChange({stateDir:rest[0]});}
 if(cmd==='runtime-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyGatewayRuntimeChange({stateDir:rest[0],plan:privateJson(rest[1]),authorize:true});}
 if(cmd==='runtime-recover'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.recoverGatewayRuntimeChange({stateDir:rest[0],transactionId:rest[1],authorize:true});}
 if(cmd==='native-migration-plan'&&rest.length===2){const api=await import('./core.mjs');return api.planNativeSupervisorMigration(rest[0],{nativeApp:{path:'/Applications/Styx.app',teamID:rest[1]}});}
 if(cmd==='native-migration-apply'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.applyNativeSupervisorMigration(rest[0],{plan:privateJson(rest[1]),authorize:true});}
 if(cmd==='native-migration-rollback'&&rest.length===3&&rest[2]==='--authorize'){const api=await import('./core.mjs');return api.rollbackNativeSupervisorMigration(rest[0],{transactionId:rest[1],authorize:true});}
 if(cmd==='device-ingress'&&rest.length===1){const {planDeviceIngress}=await import('./core.mjs');return planDeviceIngress(rest[0]);}
 if(cmd==='verify-ingress'&&rest.length===2){const {verifyDeviceIngress}=await import('./core.mjs');return verifyDeviceIngress(rest[0],{url:rest[1]});}
 if(cmd==='inspect'&&rest.length===1)return inspectDeployment(rest[0]);
 if(cmd==='background'&&rest.length===2&&rest[1]==='--authorize'){const {enableDeploymentBackground}=await import('./background.mjs');return enableDeploymentBackground(rest[0],{authorize:true});}
 if(cmd==='local-setup'&&rest.length===2&&rest[1]==='--approve-local-device'){const api=await import('./core.mjs');const {completeLocalSetup}=await import('./local-setup.mjs');return completeLocalSetup(api,rest[0],{approve:true,...planDeployment(rest[0]).ownerPairingScope});}
 if(cmd==='capabilities'&&rest.length===1){const {readDeploymentCapabilities}=await import('./capabilities.mjs');return readDeploymentCapabilities(rest[0]);}
 if(cmd==='capabilities'&&rest.length===3&&['computer-on','computer-off'].includes(rest[1])&&rest[2]==='--authorize'){const {changeDeploymentCapabilities}=await import('./capabilities.mjs');return changeDeploymentCapabilities(rest[0],{computer:rest[1]==='computer-on',authorize:true});}
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
 if(cmd==='serve'&&rest.length===1){const r=await startDeploymentGateway(rest[0]);for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>stopDeploymentGateway(rest[0]).then(()=>process.exit(0)));return r;}
 throw Error('usage_create_CONFIG_STATE_or_status_plan_STATE_or_advance_resume_STATE_STEP_or_serve_STATE');
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=await main(process.argv.slice(2));console.log(JSON.stringify(result,null,2));if(['blocked','uncertain','needs_attention','not_implemented','recovery_required','needs_recovery'].includes(result.status)||result.steps?.some(s=>['blocked','uncertain'].includes(s.status)))process.exitCode=2;}
 catch{console.error('Styx onboarding failed. Inspect private state locally; no secret or raw command output is printed.');process.exitCode=2;}
}
