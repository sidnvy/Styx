import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {enrollmentHttpRequest} from '../host/enroll.mjs';

function privateToken(file){
  if(!file||!path.isAbsolute(file))throw Error('admin_token_file_required');
  const stat=fs.lstatSync(file);
  if(!stat.isFile()||stat.isSymbolicLink()||
    (process.platform!=='win32'&&(stat.mode&0o077)))
    throw Error('admin_token_file_permissions');
  const value=fs.readFileSync(file,'utf8').trim();
  if(!/^[A-Za-z0-9_-]{32,}$/.test(value))throw Error('invalid_admin_token');
  return value;
}
export async function ownerCommand(config,cmd,args=[]) {
  const token=privateToken(config.admin_token_file);
  if(typeof config.gateway_url!=='string'||!config.gateway_url.startsWith('https://'))
    throw Error('trusted_gateway_https_required');
  const remote={
    gateway_url:config.gateway_url,
    gateway_ca_file:config.gateway_ca_file
  };
  let route,data;
  switch(cmd){
    case 'invite':
      route='invitations';data={ttl_seconds:Number(args[0]??600)};break;
    case 'pending':route='pending';break;
    case 'devices':route='devices';break;
    case 'approve':
      if(!args[0]||!args[1])throw Error('approve_requires_request_id_and_fingerprint');
      if(args.length>3|| (args[2]!==undefined&&args[2]!=='computer'))
        throw Error('invalid_approval_capability');
      route='approve';
      data={request_id:args[0],fingerprint:args[1],
        enable_computer:args[2]==='computer'};
      break;
    case 'set-default':
      if(args.length!==1||typeof args[0]!=='string')throw Error('default_device_id_required');
      route='set-default';data={device_id:args[0]};break;
    case 'capabilities':
      if(args.length!==1||!args[0]||typeof args[0]!=='object'||Array.isArray(args[0]))throw Error('signed_capability_request_required');
      route='capabilities';data=args[0];break;
    case 'recover':
      if(args.length!==3||args.some(x=>!x))
        throw Error('recover_requires_device_id_fingerprint_and_generation');
      route='recover';data={device_id:args[0],fingerprint:args[1],generation:args[2]};break;
    case 'revoke':
      if(!args[0]||args.length!==1)throw Error('revoke_requires_device_id');
      route='revoke';data={device_id:args[0]};break;
    default:throw Error('unsupported_owner_command');
  }
  return (await enrollmentHttpRequest(remote,route,data,{adminToken:token})).body;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [configFile,command,...args]=process.argv.slice(2);
  if(!configFile||!command){
    process.stderr.write(
      'Usage: node gateway/enroll-admin.mjs /private/admin.json '+
      'invite|pending|devices|approve|revoke|recover [args]\n');
    process.exit(2);
  }
  try{
    const config=JSON.parse(fs.readFileSync(path.resolve(configFile),'utf8'));
    const result=await ownerCommand(config,command,args);
    // Invitation code is intentionally shown to owner once. Keep output
    // private and use a local/QR transfer; never put it in model prompt logs.
    process.stdout.write(JSON.stringify(result,null,2)+'\n');
  }catch(e){
    process.stderr.write('Styx owner enrollment: '+e.message+'\n');
    process.exitCode=2;
  }
}
