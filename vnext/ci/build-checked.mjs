// Publisher/developer entrypoint. Low-level builders remain available for
// fixtures; a distributed preview uses this checked entrypoint and its receipts.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {runQuality} from './quality.mjs';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
async function builder(platform){
  if(platform==='linux')return (await import('../host/build-linux-cli.mjs')).buildLinuxCli;
  if(platform==='windows')return (await import('../host/build-windows-app.mjs')).buildWindowsApp;
  throw Error('unsupported_preview_platform');
}
export async function buildChecked(platform,configuration,directory,{root=ROOT,quality=runQuality,load=builder}={}){
  if(!['linux','windows'].includes(platform)||!configuration||typeof configuration!=='object'||Array.isArray(configuration))throw Error('invalid_checked_build');
  if(!path.isAbsolute(directory)||fs.existsSync(directory))throw Error('fresh_absolute_build_evidence_required');
  // Never validate one checkout and then build a different source/dependency tree.
  if(configuration.sourceRoot!==undefined&&path.resolve(configuration.sourceRoot)!==path.resolve(root))throw Error('checked_source_mismatch');
  if(configuration.dependenciesRoot!==undefined&&path.resolve(configuration.dependenciesRoot)!==path.resolve(root,'node_modules'))throw Error('checked_dependencies_mismatch');
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const receipt={schema:1,platform,status:'FAIL',quality:'NOT RUN',build:'NOT RUN',productAcceptance:'NOT RUN'};
  try{
    const checked=quality(path.join(directory,'quality'),{root});receipt.quality=checked.status;
    if(checked.status!=='PASS'){receipt.reason='quality_gate_failed';return receipt;}
    const build=await load(platform);
    receipt.build=build({...configuration,sourceRoot:root});
    receipt.status=receipt.build.compiled===false?'STAGED':'PASS';
    // PASS means this build step passed, not that a clean-machine install,
    // publisher trust, desktop permissions or a chat account was accepted.
    return receipt;
  }catch{receipt.reason=receipt.quality==='PASS'?'preview_build_failed':'quality_execution_failed';return receipt;}
  finally{fs.writeFileSync(path.join(directory,'build-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const [platform,input,output]=process.argv.slice(2);
    if(!input||!output||!path.isAbsolute(input))throw Error();
    const result=await buildChecked(platform,JSON.parse(fs.readFileSync(input,'utf8')),path.resolve(output));
    console.log(JSON.stringify(result,null,2));process.exitCode=result.status==='FAIL'?1:0;
  }catch{console.error('Checked preview build needs linux|windows, an absolute build configuration, and a fresh evidence directory.');process.exitCode=1;}
}
