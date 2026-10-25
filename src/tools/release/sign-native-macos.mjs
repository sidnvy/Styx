// Build-time only: reuse the original App signing policy, never accept caller commands.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {normalizeMacLocalSigning, verifyMacLocalSigning, macLocalSigningPlan} from '../../host/build-macos-app.mjs';

const need=(ok,code)=>{if(!ok)throw Error(code)};
const report={schema:1,status:'FAIL',sign_actual_wait:false,verify_actual_wait:false,
  notarization:'NOT_RUN',platform_acceptance:false};
try {
  need(process.platform==='darwin' && process.argv.length===4,'native_macos_arguments_required');
  const [configuration,binary]=process.argv.slice(2);
  const boundedFile=(file,max)=>{
    need(path.isAbsolute(file)&&path.normalize(file)===file&&!/[\x00-\x1f\x7f]/.test(file),'canonical_path_required');
    const st=fs.lstatSync(file);
    need(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1&&st.size<=max,'bounded_regular_file_required');
    return st;
  };
  boundedFile(configuration,4096); boundedFile(binary,1024*1024*1024);
  need(path.basename(binary)==='styx','fixed_native_cli_required');
  const raw=fs.readFileSync(configuration),local=normalizeMacLocalSigning(JSON.parse(raw));
  need(local.identitySha1==='cb50cee601419f28b43756f4fc8aefdbf60abae2' &&
    local.certificateSha256==='90792ed11f23a00f0107450dbc184f992016569ca188454cfa286fe0022c2c1e',
    'original_macos_identity_required');
  report.certificate=verifyMacLocalSigning(local);
  // This logical App never exists. It chooses the SAME eventual packaged CLI
  // identifier/designated requirement; only the plan's exact final path is relocated.
  const app=path.join(path.dirname(binary),'Styx.app');
  const logical=path.join(app,'Contents/Resources/native/bin/styx');
  const plan=macLocalSigningPlan({app,localSigning:local,files:[logical],sealApp:false});
  need(plan.length===2,'fixed_sign_verify_plan_required');
  report.identifier=plan[0][1][plan[0][1].indexOf('--identifier')+1];
  for(let i=0;i<plan.length;i++){
    const [command,args]=plan[i];
    need(command==='/usr/bin/codesign'&&args.at(-1)===logical &&
      args.filter(value=>value===logical).length===1,'fixed_codesign_target_required');
    const actual=[...args.slice(0,-1),binary],kind=i===0?'sign':'verify';
    report[kind+'_command']=[command,...actual];
    try {
      execFileSync(command,actual,{stdio:['ignore','pipe','pipe'],timeout:15000,maxBuffer:1024*1024});
      report[kind+'_actual_wait']=true; report[kind+'_exit_code']=0;
    } catch(error) {
      report[kind+'_actual_wait']=true;
      report[kind+'_exit_code']=Number.isInteger(error.status)?error.status:null;
      report[kind+'_outcome']='UNKNOWN';
      throw Error('original_codesign_child_not_successful');
    }
  }
  need(fs.readFileSync(configuration).equals(raw),'signing_configuration_changed');
  need(JSON.stringify(verifyMacLocalSigning(local))===JSON.stringify(report.certificate),'original_certificate_changed');
  report.status='PASS';
} catch(error) { report.error=/^[a-z0-9_]+$/.test(error.message)?error.message:'macos_signing_helper_failed'; }
process.stdout.write(JSON.stringify(report)+'\n');
process.exitCode=report.status==='PASS'?0:1;
