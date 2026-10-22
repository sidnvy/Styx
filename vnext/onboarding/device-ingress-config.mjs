// Derived paths only. deployment.json remains the network authorization.
import path from 'node:path';
export function deploymentDeviceIngress(stateDir,config){
 const value=config.gateway?.deviceIngress;if(!value?.enabled)return null;
 const root=path.join(stateDir,'gateway','device-ingress',value.generation);
 return {generation:value.generation,url:value.url,listenHost:value.listenHost,certificateSha256:value.certificateSha256,
  tlsCertificateFile:path.join(root,'certificate.pem'),tlsPrivateKeyFile:path.join(root,'private-key.pem')};
}
