import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {requirePrivateDirectory,requirePrivateFile,openPrivateFile} from '../host/private-storage.mjs';

// A separate local capability authenticates the app-owned Tunnel ingress.
// It is never exported in a plugin or sent to OpenAI, and is not a user identity.
export function tunnelContext(stateDir,{create=false}={}) {
 const root=path.join(stateDir,'gateway'),file=path.join(root,'tunnel-context.token');
 requirePrivateDirectory(root);
 if(create&&!fs.existsSync(file)) {
  let fd;
  try{fd=openPrivateFile(file,0o600);fs.writeFileSync(fd,randomBytes(32).toString('hex'));}
  catch(error){if(error.code!=='EEXIST')throw error;}
  finally{if(fd!==undefined)fs.closeSync(fd);}
 }
 if(!fs.existsSync(file))return null;
 const st=requirePrivateFile(file);if(st.size!==64)throw Error('invalid_tunnel_context');
 const token=fs.readFileSync(file,'utf8');if(!/^[a-f0-9]{64}$/.test(token))throw Error('invalid_tunnel_context');
 return {file,token};
}
