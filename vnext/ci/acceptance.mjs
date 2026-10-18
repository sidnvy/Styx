// CI receipts distinguish protocol/fixture checks from native acceptance.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const root=fileURLToPath(new URL('../',import.meta.url));
export function summarizeTap(output,exitCode) {
  const counters={};
  for(const name of ['tests','pass','fail','cancelled','skipped','todo']) {
    const match=new RegExp('^# '+name+' (\\d+)\\r?$','m').exec(output);
    counters[name]=match?Number(match[1]):null;
  }
  // A successful exit without a complete test summary is not evidence.
  const complete=Object.values(counters).every(Number.isInteger) &&
    counters.tests>0 && counters.pass+counters.fail+counters.cancelled+
    counters.skipped+counters.todo===counters.tests;
  const status=exitCode!==0||!complete||counters.fail||counters.cancelled
    ?'FAIL':counters.pass===0?'NOT RUN':'PASS';
  return {status,...counters};
}
export function runAcceptance(tier,directory) {
  if(!['fixtures','native-exec'].includes(tier))throw Error('unknown_acceptance_tier');
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const files=dir=>fs.readdirSync(path.join(root,dir)).filter(x=>x.endsWith('.test.mjs'))
    .sort().map(x=>dir+'/'+x);
  const suites=tier==='fixtures'?[
    ['gateway',files('gateway/test')],
    ['exec-contract',['packages/styx-exec-adapter/test/unit.test.mjs',
      'packages/styx-exec-adapter/test/windows.test.mjs']],
    ['gui-broker',files('packages/styx-gui-broker/test')],
    ['host',files('host/test')],
    ['plugin',files('plugin/test')]
  ]:[['native-exec',[
    'packages/styx-exec-adapter/test/integration.test.mjs',
    'gateway/test/live.test.mjs','gateway/test/outbound.test.mjs']]];
  let revision=null,workingTree=null;
  try{
    revision=execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim();
    workingTree=execFileSync('git',['status','--porcelain'],{cwd:root,encoding:'utf8'}).trim()
      ?'modified':'clean';
  }catch{}
  const receipt={schema:1,tier,revision,working_tree:workingTree,platform:process.platform,arch:process.arch,
    os_release:os.release(),node:process.version,started_at:new Date().toISOString(),
    suites:[],gates:{native_gui:'NOT RUN',physical_host:'NOT RUN',
      cold_install:'NOT RUN',chatgpt:'NOT RUN',soak_24h:'NOT RUN',
      publisher_signed_distribution:'NOT RUN'}};
  if(tier==='native-exec'&&(process.platform!=='linux'||process.arch!=='x64'||
      !fs.existsSync(path.join(root,'packages/styx-exec-adapter/.runtime/codex')))) {
    receipt.status='BLOCKED';receipt.reason='pinned_linux_x64_executor_required';
  }else{
    for(const [name,tests] of suites){
      const env={...process.env,DO_NOT_TRACK:'1',STYX_LIVE_CUA_TEST:'0',
        STYX_LIVE_CUA_GUI_TEST:'0',STYX_LIVE_EXEC_TEST:tier==='native-exec'?'1':'0'};
      const result=spawnSync(process.execPath,['--test','--test-concurrency=1',
        '--test-timeout=180000','--test-reporter=tap',...tests],{
        cwd:root,env,encoding:'utf8',timeout:300000,maxBuffer:32*1024*1024});
      const output=(result.stdout??'')+(result.stderr??'');
      const log=name+'.tap';fs.writeFileSync(path.join(directory,log),output,{mode:0o600});
      receipt.suites.push({name,...summarizeTap(result.stdout??'',result.status),log,
        ...(result.error?{execution_error:result.error.code}:{}),exit_code:result.status});
    }
    receipt.status=receipt.suites.some(x=>x.status==='FAIL')?'FAIL':
      receipt.suites.some(x=>x.status==='NOT RUN')?'NOT RUN':'PASS';
  }
  receipt.completed_at=new Date().toISOString();
  fs.writeFileSync(path.join(directory,'receipt.json'),JSON.stringify(receipt,null,2)+'\n',
    {mode:0o600});
  return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [tier,directory]=process.argv.slice(2);
  if(!directory)throw Error('acceptance_output_directory_required');
  const receipt=runAcceptance(tier,path.resolve(directory));
  console.log(JSON.stringify(receipt,null,2));
  process.exitCode=receipt.status==='PASS'?0:receipt.status==='BLOCKED'?2:1;
}
