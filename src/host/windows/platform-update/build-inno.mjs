import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {verifyNativeWindowsRuntimeInput} from '../../build-windows-app.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const assert=(value,code)=>{if(!value)throw Error(code);};
const originalPublisher='f524e2e87f4cda2bc2b52d448233ae347b05c00730374f6b379a8aafe1cc2566';
function verifyNativePackage(root,expected){
 const inventory=JSON.parse(fs.readFileSync(path.join(root,'windows-package.json'),'utf8'));
 assert(inventory.schema===1&&inventory.nativeRuntime===true&&inventory.compiled===true&&inventory.arch==='x64'&&inventory.sourceProvenance?.status==='SAME_REVISION_TRACKED_ARCHIVE_BOUND'&&inventory.sourceProvenance.sourceRevision===inventory.sourceRevision&&/^[a-f0-9]{40}$/.test(inventory.sourceRevision??''),'native_compiled_same_revision_package_required');
 const rows=new Map(),actual=[];let nodes=0;
 for(const row of inventory.files){assert(typeof row.path==='string'&&row.path.length<512&&!/[\\:\x00-\x1f]/.test(row.path)&&row.path.split('/').every(x=>x&&x!=='.'&&x!=='..')&&!rows.has(row.path.toLowerCase())&&/^[a-f0-9]{64}$/.test(row.sha256)&&Number.isSafeInteger(row.size)&&row.size>=0&&row.size<=1073741824,'native_outer_member_invalid');rows.set(row.path.toLowerCase(),row);}
 const walk=(directory,relative='')=>{const st=fs.lstatSync(directory);assert(st.isDirectory()&&!st.isSymbolicLink(),'native_outer_redirected');for(const name of fs.readdirSync(directory)){const rel=relative?relative+'/'+name:name,file=path.join(directory,name),info=fs.lstatSync(file);assert(++nodes<=8192&&!info.isSymbolicLink(),'native_outer_redirected_or_budget');if(info.isDirectory())walk(file,rel);else{assert(info.isFile()&&info.nlink===1,'native_outer_member_invalid');if(rel==='windows-package.json')continue;const row=rows.get(rel.toLowerCase());assert(row&&row.path===rel&&info.size===row.size&&hash(file)===row.sha256,'native_outer_member_changed');actual.push(rel);}}};walk(root);assert(actual.length===rows.size,'native_outer_inventory_incomplete');
 for(const name of ['runtime','vnext','install-windows-preview.mjs'])assert(!fs.existsSync(path.join(root,name)),'native_legacy_installer_forbidden');
 const runtime=verifyNativeWindowsRuntimeInput({payloadDir:path.join(root,'native'),publisherFile:path.join(root,'native-publisher.pem'),expectedPublisher:originalPublisher},'x64');
 assert(runtime.manifest.source.revision===inventory.sourceRevision,'native_runtime_source_revision_mismatch');
 const descriptor=JSON.parse(fs.readFileSync(path.join(root,'windows-runtime.json'),'utf8')).nativeRuntime;
 assert(descriptor?.schema===1&&descriptor.cli==='native/bin/styx.exe'&&descriptor.payload==='native'&&descriptor.publisher==='native-publisher.pem'&&descriptor.publisherSpkiSha256===originalPublisher&&descriptor.cliSha256===runtime.cliSha256&&descriptor.manifestSha256===runtime.manifestSha256,'native_runtime_descriptor_changed');
 assert(hash(path.join(root,'windows-package.json'))===expected,'reviewed_package_changed');
 const raw=execFileSync(path.join(root,'native/bin/styx.exe'),['release','verify','--payload-dir',path.join(root,'native'),'--publisher-file',path.join(root,'native-publisher.pem'),'--expected-publisher',originalPublisher,'--json'],{cwd:root,encoding:'utf8',windowsHide:true,maxBuffer:2*1024*1024,timeout:150000});
 const report=JSON.parse(raw);assert(report.schema===1&&report.scope==='runtime_candidate'&&report.manifest_sha256===runtime.manifestSha256&&report.publisher_spki_sha256===originalPublisher&&report.source_revision===inventory.sourceRevision&&report.target==='x86_64-pc-windows-msvc'&&report.installed===false&&report.runtime_launched===false,'native_original_reader_report_mismatch');
 assert(hash(path.join(root,'windows-package.json'))===expected&&hash(path.join(root,'native/bin/styx.exe'))===runtime.cliSha256,'native_reader_inputs_changed');
 return {sourceRevision:inventory.sourceRevision,sourceProvenance:inventory.sourceProvenance,manifestSha256:runtime.manifestSha256,readerActualWait:true,readerExitCode:0};
}
export function buildInno(config){
  assert(process.platform==='win32','native_windows_required');
  const {packageDirectory,compiler,outputDirectory,version,expectedPackageSha256,stateDirectory,legacyComparison=false,
    productId='Styx.Desktop',productName='Styx',installFolder='Styx'}=config;
  for(const value of [packageDirectory,compiler,outputDirectory,...(stateDirectory?[stateDirectory]:[])])assert(typeof value==='string'&&path.isAbsolute(value)&&!/["\r\n{}]/.test(value),'absolute_safe_build_path_required');
  for(const value of [productId,productName,installFolder])assert(typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9 .-]{0,63}$/.test(value)&&!value.endsWith('.'),'safe_product_identity_required');
  assert(/^\d+\.\d+\.\d+\.\d+$/.test(version)&&/^[a-f0-9]{64}$/.test(expectedPackageSha256),'reviewed_build_identity_required');
  assert(!fs.existsSync(outputDirectory),'fresh_output_required');
  const pin=JSON.parse(fs.readFileSync(path.join(here,'toolchain.json'),'utf8'));
  assert(hash(compiler)===pin.compilerSha256,'inno_compiler_changed');
  const manifest=path.join(packageDirectory,'windows-package.json');
  assert(hash(manifest)===expectedPackageSha256,'reviewed_package_changed');
  const native=JSON.parse(fs.readFileSync(manifest,'utf8')).nativeRuntime===true;
  assert(native?!legacyComparison:legacyComparison===true,'explicit_legacy_comparison_required');
  let nativeVerification=null;
  const verify=()=>{assert(hash(manifest)===expectedPackageSha256,'reviewed_package_changed');if(native){nativeVerification=verifyNativePackage(packageDirectory,expectedPackageSha256);return;}execFileSync(path.join(packageDirectory,'runtime/node.exe'),[path.join(packageDirectory,'install-windows-preview.mjs'),'verify'],{cwd:packageDirectory,encoding:'utf8',windowsHide:true,maxBuffer:4*1024*1024});assert(JSON.parse(fs.readFileSync(manifest)).compiled===true,'compiled_package_required');};
  verify();fs.mkdirSync(outputDirectory);
  const gate=path.join(outputDirectory,'StyxInstallGate.exe'),script=path.join(here,'product.iss');
  const csc=path.join(process.env.WINDIR,'Microsoft.NET/Framework64/v4.0.30319/csc.exe');
  execFileSync(csc,['/nologo','/warn:4','/warnaserror+','/target:exe','/platform:anycpu','/optimize+','/reference:System.Web.Extensions.dll','/out:'+gate,path.join(here,'InstallGate.cs')],{windowsHide:true,stdio:'pipe'});
  const defines={NativePackage:native?'1':'0',SourceDir:packageDirectory,OutputDir:outputDirectory,ProductVersion:version,PackageHash:expectedPackageSha256,GateFile:gate,ProductId:productId,ProductName:productName,InstallFolder:installFolder,AppParameters:stateDirectory?'--state-dir ""'+stateDirectory+'""':''};
  const log=execFileSync(compiler,[...Object.entries(defines).map(([key,value])=>`/D${key}=${value}`),script],{windowsHide:true,encoding:'utf8',maxBuffer:8*1024*1024});
  fs.writeFileSync(path.join(outputDirectory,'compiler.log'),log);verify();
  const installer=path.join(outputDirectory,`StyxSetup-${version}.exe`);
  const receipt={schema:1,status:'BUILT_NOT_INSTALLED',engine:pin.compiler,version,productId,productName,installFolder,packageSha256:expectedPackageSha256,compilerSha256:hash(compiler),scriptSha256:hash(script),gateSha256:hash(gate),installerSha256:hash(installer),installer,stateDirectory:stateDirectory??'existing default external Core state',scope:'current-user',nativeVerification,coreManagementRuntime:native?'fixed_rust_cli_no_node_core':'explicit_legacy_comparison',hostRuntimeUpgrade:native?'NOT RUN: compatible live original App handoff implemented; old or closed installation bridge remains blocked':'legacy comparison only',authenticode:'NOT SIGNED',installation:'NOT RUN',nativeUpgrade:native?'LIVE_ORIGINAL_OWNER_HANDOFF_IMPLEMENTED_NATIVE_ACCEPTANCE_PENDING_OLD_CLOSED_BLOCKED':'legacy_comparison',nativeUninstall:native?'LIVE_ORIGINAL_OWNER_HANDOFF_IMPLEMENTED_NATIVE_ACCEPTANCE_PENDING_OLD_CLOSED_BLOCKED':'legacy_comparison'};
  fs.writeFileSync(path.join(outputDirectory,'build-receipt.json'),JSON.stringify(receipt,null,2)+'\n');return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{console.log(JSON.stringify(buildInno(JSON.parse(fs.readFileSync(process.argv[2],'utf8').replace(/^\uFEFF/,''))),null,2));}catch(error){console.error(error.message);process.exitCode=1;}
}
