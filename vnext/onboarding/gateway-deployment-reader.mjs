import {deploymentDeviceIngress} from './device-ingress-config.mjs';
// Read-only Core configuration/evidence checks for the contained Gateway app.
import fs from 'node:fs';
import path from 'node:path';
import {createHash,createPrivateKey,X509Certificate} from 'node:crypto';
import {validateDeployment} from './deployment-config.mjs';
import {requirePrivateDirectory,requirePrivateFile} from '../host/private-storage.mjs';
const fail=code=>{throw Error(code)};
const sum=file=>createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function read(file){requirePrivateFile(file);if(fs.statSync(file).size>1024*1024)fail('state_file_too_large');return JSON.parse(fs.readFileSync(file,'utf8'));}
export function readGatewayDeployment(stateDir){
 if(typeof stateDir!=='string'||!path.isAbsolute(stateDir)||path.normalize(stateDir)!==stateDir)fail('absolute_state_directory_required');
 requirePrivateDirectory(stateDir);const deploymentFile=path.join(stateDir,'deployment.json'),config=read(deploymentFile),state=read(path.join(stateDir,'state.json'));
 validateDeployment(config,{checkNetwork:false});
 if(config.mode!=='create-local'||state.schema!==1||state.mode!==config.mode||state.configSha256!==sum(deploymentFile)||!Array.isArray(state.steps))fail('invalid_gateway_deployment_state');
 const prepared=state.steps.find(s=>s.id==='gateway.prepare'&&s.status==='succeeded');if(!prepared)fail('gateway_prepare_required');
 if(config.gateway.runtime&&!state.steps.some(s=>s.id==='gateway.runtime.prepare'&&s.status==='succeeded'))fail('gateway_runtime_preparation_required');
 const root=path.join(stateDir,'gateway');requirePrivateDirectory(root);
 const runtimeFile=path.join(root,'runtime.json'),cert=path.join(root,'certificate.pem'),ownerFile=path.join(root,'owner.json');
 for(const [key,file] of [['runtime',runtimeFile],['certificate',cert],['ownerConfiguration',ownerFile]]){
  const evidence=prepared.evidence?.[key];if(evidence?.path!==file||evidence.sha256!==sum(file))fail('completed_gateway_evidence_changed');
 }
 const runtime=read(runtimeFile),expected={schema:1,url:config.gateway.url,listenHost:config.gateway.listenHost??'127.0.0.1',tlsCertificateFile:cert,tlsPrivateKeyFile:path.join(root,'private-key.pem'),modelTokenFile:path.join(root,'model.token'),adminTokenFile:path.join(root,'admin.token'),enrollmentDir:path.join(root,'enrollment'),catalogFile:path.join(root,'targets.json')};
 if(Object.keys(runtime).length!==Object.keys(expected).length||Object.entries(expected).some(([key,value])=>runtime[key]!==value))fail('gateway_runtime_identity_binding_changed');
 const owner=read(ownerFile);if(owner.gateway_url!==config.gateway.url||owner.gateway_ca_file!==cert||owner.admin_token_file!==runtime.adminTokenFile)fail('owner_gateway_binding_changed');
 for(const file of [cert,runtime.tlsPrivateKeyFile,runtime.modelTokenFile,runtime.adminTokenFile,runtime.catalogFile])requirePrivateFile(file);
 const certificate=new X509Certificate(fs.readFileSync(cert));
 if(!certificate.checkPrivateKey(createPrivateKey(fs.readFileSync(runtime.tlsPrivateKeyFile))))fail('gateway_tls_identity_changed');
 return {config,runtime,deviceIngress:deploymentDeviceIngress(stateDir,config),catalog:read(runtime.catalogFile),configurationSha256:state.configSha256,certificateSha256:sum(cert)};
}
