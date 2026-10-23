// Internal supervisor: stdin EOF binds the upstream client to its owning App.
// No CLI API, shell, logs, or persisted PID is used to terminate a process.
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
let child,stopping=false,timer;
const lockToken=process.argv[5];
function release(){
 try{const file=path.join(process.cwd(),'owner.lock');const st=fs.lstatSync(file);if(/^[a-f0-9]{48}$/.test(lockToken??'')&&st.isFile()&&!st.isSymbolicLink()&&fs.readFileSync(file,'utf8')===lockToken)fs.unlinkSync(file);}catch{}
}
function stop(){
 if(stopping)return;stopping=true;
 if(!child){process.exit(0);return;}
 child.kill('SIGTERM');timer=setTimeout(()=>child.kill('SIGKILL'),2000);
}
try{
 const [binary,pin,json]=process.argv.slice(2),args=JSON.parse(json);
 const st=fs.lstatSync(binary);
 if(!st.isFile()||st.isSymbolicLink()||!Array.isArray(args)||args.some(x=>typeof x!=='string')||createHash('sha256').update(fs.readFileSync(binary)).digest('hex')!==pin)throw Error('invalid_runner_input');
 child=spawn(binary,args,{cwd:process.cwd(),env:process.env,stdio:'ignore',windowsHide:true});
 child.once('error',()=>{release();process.exit(2);});
 child.once('exit',code=>{clearTimeout(timer);release();process.exit(stopping?0:code??1);});
 process.stdin.on('end',stop);process.stdin.on('error',stop);process.stdin.resume();
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
}catch{release();process.exit(2);}
