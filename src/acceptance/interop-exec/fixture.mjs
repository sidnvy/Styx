// Acceptance-only calls into the immutable original functions. No source edits,
// network enrollment, approval, service setup or simulated successful doctor.
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const [root,operation,input]=process.argv.slice(2);
if(operation==='identity'){
 const {initLocalIdentity}=await import(pathToFileURL(path.join(root,'host/enroll.mjs')));
 const record=initLocalIdentity(JSON.parse(fs.readFileSync(input,'utf8')));
 process.stdout.write(JSON.stringify(record)+'\n');
}else if(operation==='validate'){
 const {validateDeployment}=await import(pathToFileURL(path.join(root,'onboarding/deployment-config.mjs')));
 const {normalizeConnector}=await import(pathToFileURL(path.join(root,'host/connect.mjs')));
 const {deployment,host}=JSON.parse(fs.readFileSync(input,'utf8'));
 validateDeployment(deployment,{checkNetwork:false});normalizeConnector(host);
 process.stdout.write(JSON.stringify({legacy_desired_schema:true,legacy_connector_schema:true,network_pairing:'NOT_RUN',service_setup:'NOT_RUN'})+'\n');
}else throw Error('unsupported fixture operation');
