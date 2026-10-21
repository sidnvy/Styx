// Offline portable native Windows preview. No installer or startup mutation.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey} from 'node:crypto';
import {verifySignedRelease} from './installer.mjs';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const hash=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const assert=(ok,code)=>{if(!ok)throw Error(code)};
function copy(source,destination){const s=fs.lstatSync(source);assert(!s.isSymbolicLink(),'redirected_package_input');if(s.isDirectory()){fs.mkdirSync(destination,{recursive:true});for(const name of fs.readdirSync(source)){if(['.git','.DS_Store','.bin','test','tests','__pycache__'].includes(name))continue;copy(path.join(source,name),path.join(destination,name));}}else{assert(s.isFile(),'regular_package_member_required');fs.copyFileSync(source,destination);}}
export function buildWindowsApp({sourceRoot,output,nodeBinary,opensslBinary,hostBundle,publisherKeyFile,publisherSha256,tunnelBinary,arch='x64'}={}){
 for(const p of [sourceRoot,output,nodeBinary])assert(typeof p==='string'&&path.isAbsolute(p),'absolute_package_paths_required');
 assert(!fs.existsSync(output),'fresh_package_output_required');
 assert(['x64','arm64'].includes(arch),'supported_windows_arch_required');
 assert(fs.existsSync(path.join(sourceRoot,'node_modules','@modelcontextprotocol','sdk','package.json')),'production_dependencies_required');
 assert(fs.readFileSync(nodeBinary).subarray(0,2).toString()==='MZ','windows_node_executable_required');
 if(hostBundle||publisherKeyFile||publisherSha256){assert(hostBundle&&publisherKeyFile&&/^[a-f0-9]{64}$/.test(publisherSha256??''),'complete_signed_artifact_inputs_required');const pem=fs.readFileSync(publisherKeyFile),key=createPublicKey(pem);assert(key.asymmetricKeyType==='ed25519','invalid_release_signing_key');const fingerprint=createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex');assert(fingerprint===publisherSha256,'publisher_pin_mismatch');verifySignedRelease(hostBundle,pem,{platform:'win32',arch});}
 fs.mkdirSync(output);fs.mkdirSync(path.join(output,'runtime'));
 copy(nodeBinary,path.join(output,'runtime','node.exe'));
 const nodeNotices=[];for(const name of ['LICENSE','node-provenance.json','node-upstream.json']){const adjacent=path.join(path.dirname(nodeBinary),name);if(fs.existsSync(adjacent)){copy(adjacent,path.join(output,'runtime',name));nodeNotices.push(name);}}
 const appSource=path.join(sourceRoot,'host','windows');copy(path.join(appSource,'Styx.cs'),path.join(output,'Styx.cs'));copy(path.join(appSource,'SessionProbe.cs'),path.join(output,'SessionProbe.cs'));copy(path.join(appSource,'build.ps1'),path.join(output,'build.ps1'));
 copy(path.join(sourceRoot,'assets','brand','styx-logo.png'),path.join(output,'styx-logo.png'));
 const target=path.join(output,'vnext');fs.mkdirSync(target);
 for(const name of ['onboarding','gateway','host','shared','packages','plugin','assets','licenses','node_modules'])if(fs.existsSync(path.join(sourceRoot,name)))copy(fs.realpathSync(path.join(sourceRoot,name)),path.join(target,name));
 for(const name of ['package.json','package-lock.json'])if(fs.existsSync(path.join(sourceRoot,name)))copy(fs.realpathSync(path.join(sourceRoot,name)),path.join(target,name));
 const manifest={schema:1,node:{path:'runtime/node.exe',sha256:hash(nodeBinary)}};
 if(opensslBinary){copy(opensslBinary,path.join(output,'runtime','openssl.exe'));manifest.openssl={path:'runtime/openssl.exe',sha256:hash(opensslBinary)};}
 if(tunnelBinary){copy(tunnelBinary,path.join(output,'runtime','tunnel-client.exe'));manifest.tunnel={path:'runtime/tunnel-client.exe',sha256:hash(tunnelBinary)};}
 if(hostBundle){copy(hostBundle,path.join(output,'host-bundle'));copy(publisherKeyFile,path.join(output,'publisher.pem'));verifySignedRelease(path.join(output,'host-bundle'),fs.readFileSync(path.join(output,'publisher.pem')),{platform:'win32',arch});manifest.artifacts={bundle:'host-bundle',publisherKeyFile:'publisher.pem',publisherSha256};}
 fs.writeFileSync(path.join(output,'windows-runtime.json'),JSON.stringify(manifest,null,2)+'\n');
 let compiled=false;if(process.platform==='win32'){const csc=path.join(process.env.WINDIR,'Microsoft.NET','Framework64','v4.0.30319','csc.exe');execFileSync(csc,['/nologo','/target:winexe','/platform:anycpu','/optimize+','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll','/out:'+path.join(output,'StyxPreview.exe'),path.join(output,'Styx.cs')],{stdio:'pipe'});execFileSync(csc,['/nologo','/target:exe','/platform:anycpu','/optimize+','/out:'+path.join(output,'StyxSessionProbe.exe'),path.join(output,'SessionProbe.cs')],{stdio:'pipe'});manifest.desktopProbe={path:'StyxSessionProbe.exe',sha256:hash(path.join(output,'StyxSessionProbe.exe'))};fs.writeFileSync(path.join(output,'windows-runtime.json'),JSON.stringify(manifest,null,2)+'\n');compiled=true;}
 const receipt={schema:1,status:compiled?'built':'staged_native_compile_required',artifact:output,compiled,sourceSha256:hash(path.join(appSource,'Styx.cs')),nodeSha256:manifest.node.sha256,nodeValidation:'windows_executable_format_check_only',nodeUpstreamVerification:'not_performed_by_this_builder',nodeNoticesIncluded:nodeNotices,signedHostBundleIncluded:!!hostBundle,tlsHelperIncluded:!!opensslBinary,tunnelIncluded:!!tunnelBinary,desktopAcceptance:'NOT RUN',chatgptAcceptance:'NOT RUN',startupMutation:'NOT RUN'};
 fs.writeFileSync(path.join(output,'build-receipt.json'),JSON.stringify(receipt,null,2)+'\n');return receipt;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){try{const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));console.log(JSON.stringify(buildWindowsApp(config)));}catch{console.error('Windows package build failed. Check the explicit offline inputs.');process.exitCode=2;}}
