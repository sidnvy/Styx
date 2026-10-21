// Local and CI release checks share one entrypoint. Native/account gates are
// deliberately separate: a fixture or successful command cannot satisfy them.
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
export const dependencyRoots=Object.freeze(['.','packages/styx-exec-adapter','packages/styx-gui-broker','packages/styx-browser-provider']);
export function runQuality(directory,{root=ROOT,run=spawnSync,revision=()=>execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim()}={}){
  if(!path.isAbsolute(directory)||fs.existsSync(directory))throw Error('fresh_absolute_quality_output_required');
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const hashes=()=>Object.fromEntries(dependencyRoots.map(folder=>{
    const file=path.join(root,folder,'package-lock.json');
    return [folder,createHash('sha256').update(fs.readFileSync(file)).digest('hex')];
  }));
  const receipt={schema:1,kind:'engineering_quality',revision:revision(),node:process.version,platform:process.platform,
    startedAt:new Date().toISOString(),checks:[],gates:{physicalDesktop:'NOT RUN',coldInstall:'NOT RUN',reboot:'NOT RUN',chatgpt:'NOT RUN',soak:'NOT RUN'}};
  let initial;
  const execute=(name,command,args,cwd,extension='log')=>{
    const log=name+'.'+extension;
    let result;
    try{result=run(command,args,{cwd,encoding:'utf8',timeout:name==='fixtures'?900000:120000,maxBuffer:32*1024*1024,
      // Only fixed npm subcommands/flags below use a Windows command shim.
      shell:process.platform==='win32'&&command==='npm.cmd'});}catch{result={status:null,error:{code:'runner_failed'}};}
    fs.writeFileSync(path.join(directory,log),(result.stdout??'')+(result.stderr??''),{mode:0o600});
    const record={name,status:result.status===0&&!result.error?'PASS':'FAIL',exitCode:result.status??null,log};
    if(result.error)record.reason=result.error.code??'command_failed';
    if(name==='fixtures'&&record.status==='PASS'){
      try{
        const evidence=JSON.parse(fs.readFileSync(path.join(directory,'fixtures/receipt.json'),'utf8'));
        if(evidence.status!=='PASS'||evidence.tier!=='fixtures'||!evidence.suites?.length)throw Error();
        record.suites=evidence.suites.map(({name,status,pass,fail,skipped})=>({name,status,pass,fail,skipped}));
      }catch{record.status='FAIL';record.reason='missing_or_failed_fixture_evidence';}
    }
    receipt.checks.push(record);
  };
  try{
    initial=hashes();receipt.lockfiles=initial;
    const npm=process.platform==='win32'?'npm.cmd':'npm';
    for(const [index,folder]of dependencyRoots.entries()){
      const cwd=path.join(root,folder);
      execute('dependency-tree-'+index,npm,['ls','--all','--json'],cwd,'json');
      execute('dependency-audit-'+index,npm,['audit','--package-lock-only','--audit-level=moderate','--json','--fetch-timeout=30000','--fetch-retries=0'],cwd,'json');
      execute('sbom-'+index,npm,['sbom','--package-lock-only','--sbom-format','cyclonedx'],cwd,'json');
    }
    execute('fixtures',process.execPath,[path.join(root,'ci/acceptance.mjs'),'fixtures',path.join(directory,'fixtures')],root);
    if(JSON.stringify(initial)!==JSON.stringify(hashes()))receipt.checks.push({name:'lockfile-stability',status:'FAIL',reason:'inputs_changed_during_check'});
    else receipt.checks.push({name:'lockfile-stability',status:'PASS'});
  }catch{receipt.checks.push({name:'quality-inputs',status:'FAIL',reason:'required_input_unavailable'});}
  receipt.status=receipt.checks.length&&receipt.checks.every(c=>c.status==='PASS')?'PASS':'FAIL';
  receipt.completedAt=new Date().toISOString();
  fs.writeFileSync(path.join(directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const directory=path.resolve(process.argv[2]??'acceptance/quality');const result=runQuality(directory);console.log(JSON.stringify(result,null,2));process.exitCode=result.status==='PASS'?0:1;}
  catch{console.error('Quality checks require a fresh output directory and locked dependencies.');process.exitCode=1;}
}
