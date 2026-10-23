import {spawn} from 'node:child_process';
import {EventEmitter} from 'node:events';
import {StringDecoder} from 'node:string_decoder';
import {fileURLToPath} from 'node:url';
import {GuiError} from './broker.mjs';
export class SdkClient {
 constructor({python,pythonPath,socket,timeoutMs=10000}) {
  this.seq=0;this.pending=new Map();this.events=new EventEmitter();this.closed=false;this.timeoutMs=timeoutMs;
  this.child=spawn(python,[fileURLToPath(new URL('./sdk-client.py',import.meta.url)),socket],{
   env:{PATH:'/usr/bin:/bin:/opt/homebrew/bin',PYTHONPATH:pythonPath,PYTHONDONTWRITEBYTECODE:'1'},stdio:['pipe','pipe','pipe']});
  this.child.stderr.resume();let buffer='';const decoder=new StringDecoder('utf8');
  this.child.stdout.on('data',bytes=>{
   buffer+=decoder.write(bytes);
   if(Buffer.byteLength(buffer)>3000000){this.fail();this.child.kill();return;}
   let i;while((i=buffer.indexOf('\n'))>=0){
    const line=buffer.slice(0,i);buffer=buffer.slice(i+1);
    try{const r=JSON.parse(line),p=this.pending.get(r.id);if(p){clearTimeout(p.timer);this.pending.delete(r.id);
      r.error?p.reject(new GuiError('driver_request_failed')):p.resolve(r.result);}}
    catch{this.fail();this.child.kill();}
   }
  });
  this.exit=new Promise(resolve=>this.child.once('close',resolve));
  this.child.on('error',()=>this.fail());this.child.stdin.on('error',()=>this.fail());
  this.child.on('close',()=>this.fail());
 }
 onClose(fn){this.events.on('close',fn);}
 fail(){if(this.closed)return;this.closed=true;
  for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new GuiError('connection_closed',true));}
  this.pending.clear();this.events.emit('close');
 }
 call(name,args={}){
  if(this.closed)return Promise.reject(new GuiError('connection_closed',true));
  const id=++this.seq;
  return new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>{this.fail();this.child.kill();},this.timeoutMs);
   this.pending.set(id,{resolve,reject,timer});
   this.child.stdin.write(JSON.stringify({id,name,arguments:args})+'\n');
  });
 }
 async close(){
  this.fail();this.child.stdin.end();
  const timer=setTimeout(()=>this.child.kill('SIGKILL'),1000);
  await this.exit;clearTimeout(timer);
 }
}
