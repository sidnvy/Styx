// Portable Linux CLI preview. Uses the same onboarding Core and signed runtime
// installers; building never installs a service or creates a device identity.
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createHash,createPublicKey} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {buildGatewayRelease} from '../onboarding/gateway-release.mjs';
import {verifySignedRelease} from './installer.mjs';
const ROOT=fileURLToPath(new URL('../',import.meta.url));
const hash=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Error(code)};
function regular(file){const s=fs.lstatSync(file);if(!s.isFile()||s.isSymbolicLink())fail('regular_cli_input_required');return file;}
function copy(from,to){regular(from);fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});fs.copyFileSync(from,to,fs.constants.COPYFILE_EXCL);fs.chmodSync(to,0o600);}
function tree(from,to){const s=fs.lstatSync(from);if(s.isSymbolicLink())fail('cli_symlink_forbidden');if(s.isDirectory()){fs.mkdirSync(to,{mode:0o700});for(const n of fs.readdirSync(from))tree(path.join(from,n),path.join(to,n));}else copy(from,to);}
function tracked(sourceRoot){const repo=execFileSync('git',['-C',sourceRoot,'rev-parse','--show-toplevel'],{encoding:'utf8'}).trim();return execFileSync('git',['-C',sourceRoot,'ls-files','--full-name','-z'],{encoding:'utf8',maxBuffer:8*1024*1024}).split('\0').filter(Boolean).map(n=>path.relative(sourceRoot,path.join(repo,n)).split(path.sep).join('/'));}
export function cliProductSource(name){
 if(name==='docs/linux-cli-preview.md')return true;
 if(name.split('/').some(p=>['test','tests','fixtures','node_modules','.runtime','windows','macos'].includes(p)))return false;
 return /^(onboarding|gateway|host|shared|packages\/styx-(exec-adapter|gui-broker|browser-provider))\/.+\.mjs$/.test(name)||
 /^(onboarding\/ui\/.+\.(js|html|css)|gateway\/.+\.(json|html)|packages\/styx-[^/]+\/(package(?:-lock)?\.json|playwright-contract-0\.0\.83\.json)|plugin\/(package\.mjs|archive\.mjs|plugin\.json|skills\/.+\.md)|assets\/brand\/styx-logo\.png|licenses\/.+|package(?:-lock)?\.json)$/.test(name);
}
export function buildLinuxCli({destination,version,privateKeyFile,nodeBinary,sourceRoot=ROOT,dependenciesRoot=path.join(sourceRoot,'node_modules'),hostBundle,tunnelBinary,tunnelNoticesDir}={}){
 if(process.platform!=='linux'||process.arch!=='x64')fail('linux_x64_native_build_required');
 for(const p of [destination,privateKeyFile,nodeBinary,sourceRoot,dependenciesRoot])if(typeof p!=='string'||!path.isAbsolute(p)||path.normalize(p)!==p)fail('absolute_cli_paths_required');
 if(fs.existsSync(destination))fail('fresh_cli_output_required');
 const nodeDir=path.dirname(nodeBinary),provenance=JSON.parse(fs.readFileSync(regular(path.join(nodeDir,'node-provenance.json'))));
 if(provenance.schema!==1||provenance.component!=='node'||provenance.platform!=='linux'||provenance.arch!=='x64'||provenance.version!=='22.23.3'||provenance.archive_sha256!=='df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de'||provenance.binary_sha256!==hash(fs.readFileSync(regular(nodeBinary)))||provenance.license_sha256!==hash(fs.readFileSync(regular(path.join(nodeDir,'LICENSE')))))fail('pinned_cli_node_provenance_required');
 if(execFileSync(nodeBinary,['--version'],{encoding:'utf8',timeout:7000}).trim()!=='v22.23.3')fail('pinned_cli_node_version_required');
 const pub=createPublicKey(fs.readFileSync(privateKeyFile)),pem=pub.export({type:'spki',format:'pem'}),pin=hash(pub.export({type:'spki',format:'der'}));
 if(tunnelBinary){if(!path.isAbsolute(tunnelBinary)||execFileSync(regular(tunnelBinary),['--version'],{encoding:'utf8',timeout:7000}).trim().split(/\s+/).every(x=>x!=='0.0.17'))fail('pinned_tunnel_client_version_required');if(!tunnelNoticesDir||!path.isAbsolute(tunnelNoticesDir)||!fs.lstatSync(tunnelNoticesDir).isDirectory())fail('tunnel_client_licenses_required');}
 if(hostBundle)verifySignedRelease(hostBundle,pem,{platform:'linux',arch:'x64'});
 fs.mkdirSync(destination,{mode:0o700});
 try{
  const gateway=buildGatewayRelease({destination:path.join(destination,'gateway-bundle'),version,privateKeyFile,nodeBinary,nodeLicenseFile:path.join(nodeDir,'LICENSE'),sourceRoot,dependenciesRoot});
  const app=path.join(destination,'app');fs.mkdirSync(app,{mode:0o700});
  const sources=tracked(sourceRoot).filter(cliProductSource).sort();
  for(const name of sources)copy(path.join(sourceRoot,name),path.join(app,name));
  if(!sources.includes('docs/linux-cli-preview.md'))fail('tracked_cli_instructions_required');
  copy(path.join(sourceRoot,'docs/linux-cli-preview.md'),path.join(destination,'README.md'));
  tree(path.join(destination,'gateway-bundle/app/node_modules'),path.join(app,'node_modules'));
  // Browser runtime remains optional. Its independently signed Host closure is
  // authoritative; copy only that already verified closure for foreground Core.
  if(hostBundle){tree(hostBundle,path.join(destination,'host-bundle'));const browserDeps=path.join(hostBundle,'packages/styx-browser-provider/node_modules');if(fs.existsSync(browserDeps))tree(browserDeps,path.join(app,'packages/styx-browser-provider/node_modules'));}
  copy(nodeBinary,path.join(destination,'runtime/node'));fs.chmodSync(path.join(destination,'runtime/node'),0o700);
  copy(path.join(nodeDir,'LICENSE'),path.join(destination,'runtime/LICENSE'));
  copy(path.join(nodeDir,'node-provenance.json'),path.join(destination,'runtime/node-provenance.json'));
  if(tunnelBinary){copy(tunnelBinary,path.join(destination,'runtime/tunnel-client'));fs.chmodSync(path.join(destination,'runtime/tunnel-client'),0o700);fs.mkdirSync(path.join(destination,'licenses'),{mode:0o700});tree(tunnelNoticesDir,path.join(destination,'licenses/tunnel-client'));fs.writeFileSync(path.join(destination,'runtime/tunnel-client.json'),JSON.stringify({schema:1,path:'tunnel-client',sha256:hash(fs.readFileSync(tunnelBinary)),version:'0.0.17'})+'\n',{mode:0o600});}
  fs.writeFileSync(path.join(destination,'publisher.pem'),pem,{mode:0o600});
  fs.writeFileSync(path.join(destination,'styx'),'#!/bin/sh\nset -eu\nHERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec "$HERE/runtime/node" "$HERE/app/onboarding/cli.mjs" "$@"\n',{mode:0o700});
  const receipt={schema:1,component:'linux-cli-preview',version,platform:'linux',arch:'x64',publisherSha256:pin,gateway,hostBundleIncluded:!!hostBundle,tunnelClientIncluded:!!tunnelBinary,tunnelClientVersion:tunnelBinary?'0.0.17':null,sourceFiles:sources.length,node:provenance,identityCreated:false,serviceMutation:'NOT RUN',nativeAcceptance:'NOT RUN',chatAccountAcceptance:'NOT RUN',distributionTrust:'publisher_provided_preview_not_public_release'};
  fs.writeFileSync(path.join(destination,'build-receipt.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});return receipt;
 }catch(e){fs.rmSync(destination,{recursive:true,force:true});throw e;}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const result=buildLinuxCli(JSON.parse(fs.readFileSync(regular(process.argv[2]),'utf8')));console.log(JSON.stringify(result));}catch(e){console.error('Styx Linux CLI preview: '+e.message);process.exitCode=2;}
}
