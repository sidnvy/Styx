// Explicit native test, fresh ephemeral state only. Never opens the installed App.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createOnboardingServer} from '../../../onboarding/server.mjs';
const [binary,screenshot]=process.argv.slice(2);
if(process.platform!=='darwin'||!path.isAbsolute(binary??'')||!path.isAbsolute(screenshot??''))throw Error('native_test_paths_required');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'styx-webkit-acceptance-'));fs.chmodSync(root,0o700);
const server=await createOnboardingServer({stateDir:path.join(root,'deployment'),core:{readDeployment(){throw Error('fresh')},planDeployment(){return {steps:[]}}}});
try{
 const bootstrap=path.join(root,'session');fs.writeFileSync(bootstrap,server.url,{mode:0o600});
 const child=spawn(binary,['--setup-window-fixture',bootstrap,screenshot],{stdio:['ignore','inherit','inherit']});
 const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve)});
 if(code!==0)throw Error('native_webkit_acceptance_failed');
}finally{await server.close();fs.rmSync(root,{recursive:true,force:true})}
