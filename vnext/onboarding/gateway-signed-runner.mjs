// Installed signed application entrypoint. Verify the whole active release
// with the trusted stable installer before importing its application/deps.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPublicKey} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {activeRelease,verifySignedRelease} from '../../../../installer.mjs';
import {requirePrivateFile,requirePrivateDirectory} from '../../../../private-storage.mjs';
const fail=code=>{throw Error(code)};
const stateDir=process.argv[2];
try{
 if(process.argv.length!==3||typeof stateDir!=='string'||!path.isAbsolute(stateDir)||path.normalize(stateDir)!==stateDir)fail('state_directory_required');
 requirePrivateDirectory(stateDir);const configFile=path.join(stateDir,'deployment.json');requirePrivateFile(configFile);
 if(fs.statSync(configFile).size>1024*1024)fail('state_file_too_large');
 const config=JSON.parse(fs.readFileSync(configFile,'utf8')),base=config.gateway?.runtime?.baseDir;
 const here=fileURLToPath(import.meta.url),installRoot=path.resolve(path.dirname(here),'../../../..');
 if(typeof base!=='string'||path.join(base,'install')!==installRoot)fail('gateway_application_install_binding_changed');
 const pub=path.join(base,'publisher.pem');requirePrivateFile(pub);const pem=fs.readFileSync(pub,'utf8');
 if(createHash('sha256').update(createPublicKey(pem).export({type:'spki',format:'der'})).digest('hex')!==config.gateway.runtime.publisherSha256)fail('publisher_fingerprint_mismatch');
 const active=activeRelease(installRoot,pem);if(!active||path.join(active.release_root,'app/onboarding/gateway-signed-runner.mjs')!==here)fail('gateway_application_generation_changed');
 const verified=verifySignedRelease(active.release_root,pem);if(verified.manifest.component!=='gateway-application'||verified.manifest.entrypoint!=='app/onboarding/gateway-signed-runner.mjs')fail('signed_gateway_application_required');
 const {readGatewayDeployment}=await import('./gateway-deployment-reader.mjs');
 const {runtime,catalog}=readGatewayDeployment(stateDir);
 const [{createStyxGateway},{createGatewayHttp},{EnrollmentController}]=await Promise.all([import('../gateway/index.mjs'),import('../gateway/http.mjs'),import('../gateway/enrollment.mjs')]);
 const gateway=createStyxGateway({catalog});
 const enrollment=new EnrollmentController({rootDir:runtime.enrollmentDir,adminTokenFile:runtime.adminTokenFile,registry:gateway.registry,relay:gateway.relay});
 let handle;try{handle=await createGatewayHttp(gateway,{token:fs.readFileSync(runtime.modelTokenFile,'utf8').trim(),host:runtime.listenHost,port:Number(new URL(runtime.url).port),allowedHosts:[new URL(runtime.url).host],tlsCertificateFile:runtime.tlsCertificateFile,tlsPrivateKeyFile:runtime.tlsPrivateKeyFile,enrollment});}catch(e){await gateway.close();throw e;}
 let stopping=false;const stop=()=>{if(stopping)return;stopping=true;handle.close().then(()=>process.exit(0),()=>process.exit(2));};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);process.stdout.write('Styx signed Gateway running.\n');
}catch{process.stderr.write('Styx signed Gateway startup failed; inspect private deployment state.\n');process.exitCode=2;}
