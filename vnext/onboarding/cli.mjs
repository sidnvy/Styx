import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createDeployment,readDeployment,planDeployment,advanceDeployment,startDeploymentGateway,stopDeploymentGateway} from './core.mjs';
export async function main(args){
 const [cmd,...rest]=args;
 if(cmd==='create'&&rest.length===2)return createDeployment(rest[0],{stateDir:rest[1]});
 if(cmd==='status'&&rest.length===1)return readDeployment(rest[0]);
 if(cmd==='plan'&&rest.length===1)return planDeployment(rest[0]);
 if(['advance','resume'].includes(cmd)&&rest.length>=2){
  const approve=rest.includes('--approve-local-device');
  if(rest.filter(x=>x==='--approve-local-device').length>1)throw Error('duplicate_owner_approval_flag');
  const authorize=rest.slice(1).filter(x=>x!=='--approve-local-device');
  if(approve&&!authorize.includes('host.pair'))throw Error('owner_approval_requires_host_pair_step');
  const ownerApproval=approve?{approve:true,...planDeployment(rest[0]).ownerPairingScope}:undefined;
  return advanceDeployment(rest[0],{authorize,ownerApproval});
 }
 if(cmd==='serve'&&rest.length===1){const r=await startDeploymentGateway(rest[0]);for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>stopDeploymentGateway(rest[0]).then(()=>process.exit(0)));return r;}
 throw Error('usage_create_CONFIG_STATE_or_status_plan_STATE_or_advance_resume_STATE_STEP_or_serve_STATE');
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=await main(process.argv.slice(2));console.log(JSON.stringify(result,null,2));if(result.steps?.some(s=>['blocked','uncertain'].includes(s.status)))process.exitCode=2;}
 catch{console.error('Styx onboarding failed. Inspect private state locally; no secret or raw command output is printed.');process.exitCode=2;}
}
