import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {ensurePrivateDirectory,requirePrivateDirectory,requirePrivateFile,writePrivateFile} from '../../host/private-storage.mjs';
const LIMIT=16*1024*1024;
const principalPattern=/^[a-f0-9]{64}$/;
function filename(root,principal){
  if(!principalPattern.test(principal??''))throw Error('browser_profile_owner_required');
  requirePrivateDirectory(root);
  const folder=path.join(root,'login-state');ensurePrivateDirectory(folder);
  return path.join(folder,principal+'.json');
}
function validate(state){
  if(!state||!Array.isArray(state.cookies)||!Array.isArray(state.origins))throw Error('browser_login_state_invalid');
  for(const origin of state.origins){let url;try{url=new URL(origin.origin)}catch{throw Error('browser_login_state_invalid')}
    if(!['http:','https:'].includes(url.protocol)||url.origin!==origin.origin)throw Error('browser_login_state_invalid');
  }
  return state;
}
export function readLoginState(root,principal){
  const file=filename(root,principal);let info;
  try{info=fs.lstatSync(file)}catch(e){if(e.code==='ENOENT')return null;throw e;}
  requirePrivateFile(file);if(info.size>LIMIT)throw Error('browser_login_state_limit');
  return validate(JSON.parse(fs.readFileSync(file,'utf8')));
}
export function writeLoginState(root,principal,state){
  const file=filename(root,principal),data=JSON.stringify(validate(state));
  if(Buffer.byteLength(data)>LIMIT)throw Error('browser_login_state_limit');
  if(fs.existsSync(file))requirePrivateFile(file);
  const temp=file+'.'+randomBytes(12).toString('hex')+'.tmp';
  try{writePrivateFile(temp,data);fs.renameSync(temp,file);}finally{if(fs.existsSync(temp))fs.unlinkSync(temp);}
}
