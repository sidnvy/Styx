// Compile the production Swift source closure as an unsigned STYX_TESTING app.
// This is CI scratch output, not an installer, signer or permission workflow.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {appInfoPlist,macNativeSwiftSources,macSwiftBuildArguments} from '../build-macos-app.mjs';
const brand=fileURLToPath(new URL('../../assets/brand/',import.meta.url));
const fail=code=>{throw Error(code)};
const absolute=value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value&&!/[\x00-\x1f\x7f]/.test(value);
export function compileMacTestingApp(output,{platform=process.platform,arch=process.arch,run=execFileSync}={}){
 if(platform!=='darwin')fail('native_macos_compile_required');
 if(!absolute(output)||fs.existsSync(output))fail('fresh_absolute_native_ci_output_required');
 const inputs=macNativeSwiftSources(),app=path.join(output,'Styx.app'),contents=path.join(app,'Contents'),binary=path.join(contents,'MacOS/Styx'),entry=path.join(output,'main.swift'),moduleCachePath=path.join(output,'module-cache');
 fs.mkdirSync(output,{mode:0o700});
 fs.mkdirSync(path.dirname(binary),{recursive:true});
 const resources=path.join(contents,'Resources/brand');fs.mkdirSync(resources,{recursive:true});
 fs.writeFileSync(path.join(contents,'Info.plist'),appInfoPlist('0.0.0'),{flag:'wx'});
 for(const name of ['styx-icon-light-source.jpg','styx-icon-dark-source.jpg'])fs.copyFileSync(path.join(brand,name),path.join(resources,name),fs.constants.COPYFILE_EXCL);
 fs.copyFileSync(inputs.source,entry,fs.constants.COPYFILE_EXCL);
 const sdkPath=String(run('/usr/bin/xcrun',['--sdk','macosx','--show-sdk-path'],{encoding:'utf8',timeout:10000})).trim();
 const args=macSwiftBuildArguments({source:entry,additionalSources:inputs.additionalSources,output:binary,arch,sdkPath,moduleCachePath});
 // Retain the product target, frameworks, optimization and warning policy.
 args.splice(1,0,'-D','STYX_TESTING');fs.mkdirSync(moduleCachePath,{mode:0o700});
 run('/usr/bin/xcrun',args,{stdio:'inherit',timeout:180000});
 const stat=fs.lstatSync(binary);if(!stat.isFile()||stat.isSymbolicLink())fail('native_ci_binary_required');
 const receipt={schema:1,kind:'unsigned_native_testing_compile',app,binary,source:inputs.source,additionalSources:inputs.additionalSources,sdkPath,target:args[args.indexOf('-target')+1],testing:true,productUI:true,signing:'NOT RUN',tcc:'NOT RUN',deployment:'NOT RUN'};
 fs.writeFileSync(path.join(output,'compile-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{if(process.argv.length!==3)fail('single_native_ci_output_required');console.log(JSON.stringify(compileMacTestingApp(process.argv[2])))}
 catch(error){console.error('Styx native CI compile: '+error.message);process.exitCode=2}
}
