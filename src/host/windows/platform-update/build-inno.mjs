import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const here=path.dirname(fileURLToPath(import.meta.url));
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const assert=(value,code)=>{if(!value)throw Error(code);};
export function buildInno(config){
  assert(process.platform==='win32','native_windows_required');
  const {packageDirectory,compiler,outputDirectory,version,expectedPackageSha256,stateDirectory,
    productId='Styx.Desktop',productName='Styx',installFolder='Styx'}=config;
  for(const value of [packageDirectory,compiler,outputDirectory,...(stateDirectory?[stateDirectory]:[])])assert(typeof value==='string'&&path.isAbsolute(value)&&!/["\r\n{}]/.test(value),'absolute_safe_build_path_required');
  for(const value of [productId,productName,installFolder])assert(typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9 .-]{0,63}$/.test(value)&&!value.endsWith('.'),'safe_product_identity_required');
  assert(/^\d+\.\d+\.\d+\.\d+$/.test(version)&&/^[a-f0-9]{64}$/.test(expectedPackageSha256),'reviewed_build_identity_required');
  assert(!fs.existsSync(outputDirectory),'fresh_output_required');
  const pin=JSON.parse(fs.readFileSync(path.join(here,'toolchain.json'),'utf8'));
  assert(hash(compiler)===pin.compilerSha256,'inno_compiler_changed');
  const manifest=path.join(packageDirectory,'windows-package.json');
  const verify=()=>{assert(hash(manifest)===expectedPackageSha256,'reviewed_package_changed');execFileSync(path.join(packageDirectory,'runtime/node.exe'),[path.join(packageDirectory,'install-windows-preview.mjs'),'verify'],{cwd:packageDirectory,encoding:'utf8',windowsHide:true,maxBuffer:4*1024*1024});assert(JSON.parse(fs.readFileSync(manifest)).compiled===true,'compiled_package_required');};
  verify();fs.mkdirSync(outputDirectory);
  const gate=path.join(outputDirectory,'StyxInstallGate.exe'),script=path.join(here,'product.iss');
  const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
  execFileSync(csc,['/nologo','/warn:4','/warnaserror+','/target:exe','/platform:anycpu','/optimize+','/reference:System.Web.Extensions.dll','/out:'+gate,path.join(here,'InstallGate.cs')],{windowsHide:true,stdio:'pipe'});
  const defines={SourceDir:packageDirectory,OutputDir:outputDirectory,ProductVersion:version,PackageHash:expectedPackageSha256,GateFile:gate,ProductId:productId,ProductName:productName,InstallFolder:installFolder,AppParameters:stateDirectory?'--state-dir ""'+stateDirectory+'""':''};
  const log=execFileSync(compiler,[...Object.entries(defines).map(([key,value])=>`/D${key}=${value}`),script],{windowsHide:true,encoding:'utf8',maxBuffer:8*1024*1024});
  fs.writeFileSync(path.join(outputDirectory,'compiler.log'),log);verify();
  const installer=path.join(outputDirectory,`StyxSetup-${version}.exe`);
  const receipt={schema:1,status:'BUILT_NOT_INSTALLED',engine:pin.compiler,version,productId,productName,installFolder,packageSha256:expectedPackageSha256,compilerSha256:hash(compiler),scriptSha256:hash(script),gateSha256:hash(gate),installerSha256:hash(installer),installer,stateDirectory:stateDirectory??'existing default external Core state',scope:'current-user',hostRuntimeUpgrade:'Core startup reconciliation; not performed by installer',authenticode:'NOT SIGNED'};
  fs.writeFileSync(path.join(outputDirectory,'build-receipt.json'),JSON.stringify(receipt,null,2)+'\n');return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{console.log(JSON.stringify(buildInno(JSON.parse(fs.readFileSync(process.argv[2],'utf8').replace(/^\uFEFF/,''))),null,2));}catch(error){console.error(error.message);process.exitCode=1;}
}
